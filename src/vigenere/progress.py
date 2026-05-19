"""Live progress reporting for the solver pipeline.

The solver calls into a :class:`ProgressReporter`; consumers choose one of:

* :class:`NullProgressReporter` — silent (default; suitable for tests,
  benchmarks, library use).
* :class:`RichProgressReporter` — uses ``rich.Live`` to render a live
  panel with: current stage, an item-level progress bar, the running
  best key + score, and a snippet of the best decryption so far. Falls
  back gracefully when stdout isn't a TTY (no flicker, periodic prints).

API:

    with reporter:
        reporter.stage("Beam search", total=20)
        for ...:
            ...
            reporter.advance(best_key=..., best_score=..., snippet=...)
        reporter.finish_stage()

        reporter.stat("keylen posterior top", [(7, 0.42), ...])

It is safe to call any method on a :class:`NullProgressReporter` without
side effects.
"""
from __future__ import annotations

import sys
import time
from contextlib import contextmanager
from threading import RLock
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ProgressReporter(Protocol):
    def __enter__(self) -> "ProgressReporter": ...
    def __exit__(self, exc_type, exc, tb) -> None: ...
    def stage(self, name: str, total: int | None = None) -> None: ...
    def advance(
        self,
        n: int = 1,
        *,
        best_key: str | None = None,
        best_score: float | None = None,
        snippet: str | None = None,
        note: str | None = None,
    ) -> None: ...
    def finish_stage(self) -> None: ...
    def stat(self, name: str, value: Any) -> None: ...
    def log(self, msg: str) -> None: ...
    def posterior(self, items: list[tuple[int, float]], top: int = 12) -> None: ...


class NullProgressReporter:
    """No-op reporter; used when progress is disabled."""

    def __enter__(self): return self
    def __exit__(self, *_): pass
    def stage(self, name: str, total: int | None = None) -> None: pass
    def advance(self, n: int = 1, **kwargs) -> None: pass
    def finish_stage(self) -> None: pass
    def stat(self, name: str, value: Any) -> None: pass
    def log(self, msg: str) -> None: pass
    def posterior(self, items: list[tuple[int, float]], top: int = 12) -> None: pass


class RichProgressReporter:
    """Live, multi-line panel using ``rich``.

    Shows the current stage with a progress bar (when ``total`` is known)
    and a side panel with the running-best key, score, and the first few
    lines of the best decryption.

    If the terminal isn't a TTY (e.g. captured by pytest), rendering is
    suppressed and stats are printed once per stage as plain lines.
    """

    def __init__(self, *, file=None, force_tty: bool | None = None) -> None:
        from rich.console import Console

        self._lock = RLock()
        self._console = Console(file=file or sys.stderr, force_terminal=force_tty)
        self._tty = self._console.is_terminal
        self._live = None
        self._progress = None
        self._task_id = None
        self._stage_name = ""
        self._stage_started = 0.0
        self._best_key: str | None = None
        self._best_score: float | None = None
        self._snippet: str = ""
        self._note: str = ""
        self._stats: list[tuple[str, Any]] = []
        self._posterior: list[tuple[int, float]] = []
        self._total_start = 0.0

    # ----- context management -----
    def __enter__(self) -> "RichProgressReporter":
        self._total_start = time.perf_counter()
        if self._tty:
            from rich.live import Live
            self._live = Live(
                self._render(),
                console=self._console,
                refresh_per_second=8,
                transient=False,
            )
            self._live.__enter__()
        else:
            self._console.print("[dim]vigenere solver: progress (non-TTY mode)[/dim]")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._live is not None:
            try:
                self._live.update(self._render())
            finally:
                self._live.__exit__(exc_type, exc, tb)
                self._live = None
        elapsed = time.perf_counter() - self._total_start
        self._console.print(f"[green]done[/green] in {elapsed:.2f}s "
                            f"key=[bold]{self._best_key or '?'}[/bold] "
                            f"score={self._best_score:.3f}"
                            if self._best_score is not None else
                            f"[green]done[/green] in {elapsed:.2f}s")

    # ----- stages -----
    def stage(self, name: str, total: int | None = None) -> None:
        with self._lock:
            self._stage_name = name
            self._stage_started = time.perf_counter()
            self._note = ""
            if self._tty:
                from rich.progress import (
                    BarColumn, Progress, SpinnerColumn,
                    TextColumn, TimeElapsedColumn,
                )
                self._progress = Progress(
                    SpinnerColumn(),
                    TextColumn("[bold blue]{task.description}"),
                    BarColumn(bar_width=None),
                    TextColumn("{task.completed}/{task.total}"),
                    TimeElapsedColumn(),
                )
                self._progress.start()
                self._task_id = self._progress.add_task(name, total=total or 1)
                self._refresh()
            else:
                self._console.print(f"[stage] {name}"
                                    + (f" (n={total})" if total else ""))

    def advance(
        self, n: int = 1, *,
        best_key: str | None = None,
        best_score: float | None = None,
        snippet: str | None = None,
        note: str | None = None,
    ) -> None:
        with self._lock:
            if best_key is not None:
                self._best_key = best_key
            if best_score is not None:
                if self._best_score is None or best_score > self._best_score:
                    self._best_score = best_score
            if snippet is not None:
                self._snippet = snippet
            if note is not None:
                self._note = note
            if self._progress is not None and self._task_id is not None:
                self._progress.update(self._task_id, advance=n)
                self._refresh()

    def finish_stage(self) -> None:
        with self._lock:
            dt = time.perf_counter() - self._stage_started
            if self._progress is not None and self._task_id is not None:
                # Mark task as completed
                task = self._progress.tasks[self._task_id]
                if task.total and task.completed < task.total:
                    self._progress.update(self._task_id, completed=task.total)
                self._refresh()
                self._progress.stop()
                self._progress = None
                self._task_id = None
            if not self._tty:
                self._console.print(f"  -> {self._stage_name}: {dt:.2f}s")

    def stat(self, name: str, value: Any) -> None:
        with self._lock:
            self._stats.append((name, value))
            if not self._tty:
                self._console.print(f"  [stat] {name}: {value}")
            else:
                self._refresh()

    def log(self, msg: str) -> None:
        with self._lock:
            self._console.print(f"  [log] {msg}")
            if self._tty and self._live is not None:
                self._refresh()

    def posterior(self, items: list[tuple[int, float]], top: int = 12) -> None:
        with self._lock:
            self._posterior = list(items)[:top]
            if not self._tty:
                rows = ", ".join(f"k={k}:{p:.3f}" for k, p in self._posterior)
                self._console.print(f"  [posterior] {rows}")
            else:
                self._refresh()

    # ----- rendering -----
    def _refresh(self) -> None:
        if self._live is not None:
            self._live.update(self._render())

    def _render(self):
        from rich.console import Group
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text

        # Best decryption
        snippet_lines = self._snippet.splitlines()[:4] if self._snippet else []
        snippet_text = "\n".join(snippet_lines) if snippet_lines \
            else "[dim](no decryption yet)[/dim]"
        best_panel = Panel(
            Text.from_markup(
                f"[bold]key[/bold]   : [magenta]{self._best_key or '(unknown)'}[/magenta]\n"
                f"[bold]score[/bold] : "
                + (f"{self._best_score:.4f}" if self._best_score is not None else "—")
                + "\n[bold]plaintext snippet[/bold]:\n"
                + snippet_text
            ),
            title="best so far",
            border_style="green",
        )

        # Posterior distribution
        if self._posterior:
            ptbl = Table(show_header=True, box=None, padding=(0, 1),
                         header_style="bold magenta")
            ptbl.add_column("k", justify="right", style="cyan", no_wrap=True)
            ptbl.add_column("prob", justify="right", style="white")
            ptbl.add_column("distribution", no_wrap=True)
            max_p = max(p for _, p in self._posterior) or 1.0
            for k, p in self._posterior:
                bar_len = max(1, int((p / max_p) * 30))
                bar = "█" * bar_len
                ptbl.add_row(str(k), f"{p:.4f}",
                             f"[green]{bar}[/green]")
            posterior_panel = Panel(ptbl, title="key-length posterior",
                                    border_style="magenta")
        else:
            posterior_panel = None

        # Stats table
        if self._stats:
            stats_tbl = Table(show_header=False, box=None, padding=(0, 1))
            stats_tbl.add_column(style="cyan", no_wrap=True)
            stats_tbl.add_column()
            for name, value in self._stats[-8:]:
                stats_tbl.add_row(name, str(value))
            stats_panel = Panel(stats_tbl, title="stats", border_style="blue")
        else:
            stats_panel = Panel("[dim](no stats yet)[/dim]", title="stats",
                                border_style="blue")

        elements: list = []
        if self._progress is not None:
            elements.append(self._progress)
        if self._note:
            elements.append(Text.from_markup(f"[yellow]{self._note}[/yellow]"))
        elements.append(best_panel)
        if posterior_panel is not None:
            elements.append(posterior_panel)
        elements.append(stats_panel)
        return Group(*elements)


def make_reporter(kind: str | None) -> ProgressReporter:
    """Factory.

    ``kind`` is one of: ``"rich"``, ``"plain"`` (alias for rich on non-tty),
    ``"none"``/``None``.
    """
    if not kind or kind == "none":
        return NullProgressReporter()
    if kind in ("rich", "plain", "auto"):
        try:
            return RichProgressReporter()
        except ImportError:  # pragma: no cover
            return NullProgressReporter()
    raise ValueError(f"unknown progress kind: {kind!r}")
