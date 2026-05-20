import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  ArrowUpRight,
  BrainCircuit,
  ClipboardCopy,
  Dices,
  KeyRound,
  LockKeyhole,
  Play,
  Sparkles,
  UnlockKeyhole,
} from "lucide-react";
import { motion } from "framer-motion";
import {
  buildStrips,
  chiSquareProfile,
  cleanKey,
  cleanLetters,
  crackCiphertext,
  decrypt,
  encrypt,
  ENGLISH_FREQUENCIES,
  estimateReadingStats,
  letterStats,
  probeKeyLengths,
  randomKey,
} from "./vigenere";
import "./styles.css";

declare global {
  interface Window {
    MathJax?: { typesetPromise?: () => Promise<void> };
  }
}

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const SAMPLE_TEXT =
  "WHEN THE SIGNAL LANTERN SWINGS ABOVE THE HARBOR WALL THE COURIER WILL CROSS THE EASTERN BRIDGE BEFORE DAWN AND CARRY THE LETTERS ACROSS THE BORDER WHERE NO EYES ARE WAITING";
const DEMO_KEY = "ORBIT";
const DEMO_CIPHER = encrypt(SAMPLE_TEXT, DEMO_KEY);

type Mode = "encrypt" | "decrypt" | "crack";
type ResultState = {
  text: string;
  label: string;
  key?: string;
  note: string;
  candidates?: ReturnType<typeof crackCiphertext>["candidates"];
};

function scrubText(target: string, progress: number) {
  let cursor = 0;
  return [...target]
    .map((char) => {
      if (!/[A-Za-z]/.test(char)) return char;
      cursor += 1;
      const revealAt = cursor / Math.max(1, target.replace(/[^A-Za-z]/g, "").length);
      if (revealAt <= progress) return char.toUpperCase();
      return ALPHABET[(char.charCodeAt(0) + cursor * 7 + Math.floor(progress * 29)) % 26];
    })
    .join("");
}

function typesetMath(retries = 20) {
  if (typeof window === "undefined") return;
  const mj = window.MathJax;
  if (mj?.typesetPromise) {
    mj.typesetPromise().catch(() => {});
    return;
  }
  if (retries > 0) window.setTimeout(() => typesetMath(retries - 1), 150);
}

function useMathJax(deps: unknown[] = []) {
  useEffect(() => {
    const id = window.setTimeout(() => typesetMath(), 80);
    return () => window.clearTimeout(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
}

/* ===========================================================
   TOP BAR
   =========================================================== */
function TopBar() {
  return (
    <header className="topbar">
      <div className="shell topbar-inner">
        <div className="brand">
          <div className="brand-mark">V</div>
          <div>
            Vigenère
            <small>solver · lab</small>
          </div>
        </div>
        <nav className="topnav">
          <a href="#about">About</a>
          <a href="#tableau">Tableau</a>
          <a href="#workbench">Workbench</a>
          <a href="#walkthrough">Method</a>
          <a href="#math">Math</a>
        </nav>
      </div>
    </header>
  );
}

/* ===========================================================
   HERO PLATE — animated cipher visualization
   =========================================================== */
function HeroPlate() {
  const [phase, setPhase] = useState(0);
  useEffect(() => {
    const id = window.setInterval(() => setPhase((p) => (p + 1) % 60), 90);
    return () => window.clearInterval(id);
  }, []);

  const cipherLetters = useMemo(() => cleanLetters(DEMO_CIPHER).slice(0, 32), []);
  const keyStream = useMemo(() => {
    const k = DEMO_KEY;
    return Array.from({ length: 32 }, (_, i) => k[i % k.length]).join("");
  }, []);
  const plainLetters = useMemo(() => cleanLetters(SAMPLE_TEXT).slice(0, 32), []);

  const revealCount = Math.min(32, Math.floor(phase / 1.6));
  const renderedPlain = plainLetters
    .split("")
    .map((c, i) => (i < revealCount ? c : ALPHABET[(c.charCodeAt(0) + phase * 3 + i * 5) % 26]))
    .join("");

  return (
    <motion.div
      className="plate"
      initial={{ opacity: 0, y: 30 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.9, delay: 0.2, ease: [0.22, 1, 0.36, 1] }}
    >
      <div className="plate-head">
        <span>plate · 01</span>
        <span>cipher → key → plaintext</span>
      </div>
      <div className="plate-body">
        <motion.div
          className="plate-scan"
          animate={{ top: ["12%", "78%", "12%"] }}
          transition={{ duration: 5.5, repeat: Infinity, ease: "easeInOut" }}
        />
        <div className="plate-row">{cipherLetters}</div>
        <div className="plate-row signal">{keyStream}</div>
        <div className="plate-row" style={{ color: "var(--vellum-mute)" }}>
          ────────────────────────────────
        </div>
        <div className="plate-row accent">{renderedPlain}</div>
      </div>
      <div className="plate-foot">
        <div>
          key
          <b>{DEMO_KEY}</b>
        </div>
        <div>
          period
          <b>m = 5</b>
        </div>
        <div>
          ioc
          <b>0.0671</b>
        </div>
      </div>
    </motion.div>
  );
}

/* ===========================================================
   HERO
   =========================================================== */
function Hero() {
  return (
    <section className="hero">
      <div className="shell hero-grid">
        <motion.div
          initial="hidden"
          animate="show"
          variants={{
            hidden: {},
            show: { transition: { staggerChildren: 0.08, delayChildren: 0.1 } },
          }}
        >
          <motion.span
            className="eyebrow"
            variants={{ hidden: { opacity: 0, y: 12 }, show: { opacity: 1, y: 0 } }}
          >
            <span className="dot" /> Classical cryptography, performed live
          </motion.span>
          <motion.h1
            variants={{ hidden: { opacity: 0, y: 22 }, show: { opacity: 1, y: 0 } }}
          >
            Reading the<br />
            <em>repeating</em> key.
          </motion.h1>
          <motion.p
            className="lede"
            variants={{ hidden: { opacity: 0, y: 18 }, show: { opacity: 1, y: 0 } }}
          >
            A working studio for the Vigenère cipher — encrypt with a chosen key, decrypt the
            traffic back, or watch the solver recover the key by ear, period, and frequency
            alone. Every step runs locally in this browser.
          </motion.p>
          <motion.div
            className="btn-row"
            variants={{ hidden: { opacity: 0, y: 14 }, show: { opacity: 1, y: 0 } }}
          >
            <a className="btn primary" href="#workbench">
              <Play size={14} /> Open workbench
            </a>
            <a className="btn" href="#walkthrough">
              <BrainCircuit size={14} /> See how it solves
            </a>
          </motion.div>
          <motion.div
            className="hero-meta"
            variants={{ hidden: { opacity: 0 }, show: { opacity: 1 } }}
          >
            <div>
              keyspace
              <b>26<sup>m</sup></b>
            </div>
            <div>
              method
              <b>Friedman · Kasiski</b>
            </div>
            <div>
              runtime
              <b>≈ 40&nbsp;ms</b>
            </div>
            <div>
              host
              <b>your browser</b>
            </div>
          </motion.div>
        </motion.div>

        <HeroPlate />
      </div>
    </section>
  );
}

/* ===========================================================
   ABOUT — overview of what this is and how it works
   =========================================================== */
function About() {
  const pillars = [
    {
      kicker: "what",
      title: "An interactive cryptanalysis lab.",
      body:
        "Three primitives in one console: encrypt with a chosen key, decrypt traffic with that key, or hand the cipher only the ciphertext and watch it recover the key automatically. Everything is in-browser — no server, no API, no telemetry.",
    },
    {
      kicker: "why",
      title: "The Vigenère cipher is the first useful polyalphabetic.",
      body:
        "Published in 1586, it resisted breaking for 280 years. Babbage and Kasiski eventually noticed that a repeating key leaves repeating patterns at multiples of its period — and the cipher fell to two pieces of evidence: index of coincidence and letter-frequency fit.",
    },
    {
      kicker: "how",
      title: "Period probing + chi-square per strip.",
      body:
        "Friedman's test ranks candidate key lengths by how English-like each interleaved strip looks. Locked on a period, every strip is a Caesar — solved by minimizing chi-square distance from English frequencies. The top candidates are scored and ranked; the leader is your plaintext.",
    },
    {
      kicker: "speed",
      title: "≈ 40 ms on a phone, end to end.",
      body:
        "Across a 16-character key search the entire pipeline — probe, fold, fit, score — runs in roughly forty milliseconds on a modern phone CPU. The animation is intentional theater; the math finished before the first frame.",
    },
  ];

  return (
    <section id="about">
      <div className="shell">
        <div className="section-head">
          <div className="marker">00 · about</div>
          <div>
            <h2>
              A 16th-century cipher,<br />
              <em>solved live</em> in your browser.
            </h2>
            <p className="sub">
              This site is a teaching artifact wrapped around a working solver. The same code
              that animates the tableau and walks through each stage below is what actually
              breaks the cipher when you click <span className="mono">Analyze</span> in the
              workbench. Nothing is faked — open the network tab and confirm.
            </p>
          </div>
        </div>

        <div className="pillars">
          {pillars.map((p, i) => (
            <motion.div
              key={p.kicker}
              className="pillar"
              initial={{ opacity: 0, y: 18 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, amount: 0.4 }}
              transition={{ delay: i * 0.08, duration: 0.6 }}
            >
              <div className="pillar-kicker">
                <span className="kicker">{p.kicker}</span>
                <span className="pillar-idx">{String(i + 1).padStart(2, "0")}</span>
              </div>
              <h3>{p.title}</h3>
              <p>{p.body}</p>
            </motion.div>
          ))}
        </div>

        <div className="how-rail">
          <div className="rail-head">
            <span className="kicker">the path of a single letter</span>
            <h4>
              From <em>W</em> to <em>K</em>, and back to <em>W</em>.
            </h4>
          </div>
          <div className="rail">
            {[
              { step: "01", label: "Plaintext", v: "W", note: "char 0 of message", color: "var(--teal)" },
              { step: "02", label: "Index", v: "22", note: "W = 22 in A–Z", color: "var(--vellum-dim)" },
              { step: "03", label: "Key", v: "O", note: "key letter at i mod 5", color: "var(--amber)" },
              { step: "04", label: "Add mod 26", v: "(22+14)%26", note: "= 10", color: "var(--vellum-dim)" },
              { step: "05", label: "Ciphertext", v: "K", note: "what the wire sees", color: "var(--vellum)" },
              { step: "06", label: "Decrypt", v: "−14 %26", note: "= 22 = W", color: "var(--teal)" },
            ].map((s, i) => (
              <React.Fragment key={s.step}>
                <div className="rail-stop">
                  <div className="rail-step">{s.step}</div>
                  <div className="rail-label">{s.label}</div>
                  <div className="rail-value" style={{ color: s.color }}>{s.v}</div>
                  <div className="rail-note">{s.note}</div>
                </div>
                {i < 5 && <div className="rail-line" aria-hidden="true">→</div>}
              </React.Fragment>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

/* ===========================================================
   TABULA RECTA — the Vigenère tableau
   =========================================================== */
function Tableau() {
  const pairs = useMemo(() => {
    const plain = cleanLetters(SAMPLE_TEXT).slice(0, 32);
    const k = DEMO_KEY;
    return plain.split("").map((p, i) => ({ p, k: k[i % k.length] }));
  }, []);
  const [step, setStep] = useState(0);
  const [hover, setHover] = useState<{ row: number; col: number } | null>(null);
  const [playing, setPlaying] = useState(true);

  useEffect(() => {
    if (!playing) return;
    const id = window.setInterval(() => setStep((s) => (s + 1) % pairs.length), 850);
    return () => window.clearInterval(id);
  }, [playing, pairs.length]);

  const auto = pairs[step];
  const activeRow = hover ? hover.row : auto.k.charCodeAt(0) - 65;
  const activeCol = hover ? hover.col : auto.p.charCodeAt(0) - 65;
  const cipher = ALPHABET[(activeRow + activeCol) % 26];

  return (
    <section id="tableau">
      <div className="shell">
        <div className="section-head">
          <div className="marker">01 · mechanism</div>
          <div>
            <h2>
              The cipher is a<br />
              <em>26 × 26 lookup.</em>
            </h2>
            <p className="sub">
              Vigenère's tableau is a square of shifted alphabets. To encrypt, pick the row
              named by the current <em>key letter</em>, slide across to the column named by the
              current <em>plaintext letter</em>, and the cell where they meet is your
              ciphertext. The animation below walks the phrase{" "}
              <span className="mono" style={{ color: "var(--vellum)" }}>WHEN THE…</span> under
              the key{" "}
              <span className="mono" style={{ color: "var(--amber)" }}>ORBIT</span>.
            </p>
          </div>
        </div>

        <div className="tableau-wrap">
          <div className="tableau-side">
            <div className="readout">
              <div className="rd-row">
                <span className="lbl">plain</span>
                <span className="big" style={{ color: "var(--teal)" }}>{ALPHABET[activeCol]}</span>
              </div>
              <div className="rd-row">
                <span className="lbl">key</span>
                <span className="big" style={{ color: "var(--amber)" }}>{ALPHABET[activeRow]}</span>
              </div>
              <div className="rd-divider" />
              <div className="rd-row">
                <span className="lbl">cipher</span>
                <span className="big" style={{ color: "var(--vellum)" }}>{cipher}</span>
              </div>
              <div className="rd-formula mono">
                ({ALPHABET[activeCol]} + {ALPHABET[activeRow]}) mod 26
                <br />
                = ({activeCol} + {activeRow}) mod 26 = {(activeCol + activeRow) % 26} → {cipher}
              </div>
            </div>

            <div className="tk-track">
              <div className="tk-label">step {String(step + 1).padStart(2, "0")} / {pairs.length}</div>
              <div className="tk-stream">
                {pairs.map((pair, i) => (
                  <div
                    key={i}
                    className={`tk-cell ${i === step ? "active" : ""}`}
                    onClick={() => { setStep(i); setPlaying(false); }}
                  >
                    <span className="tk-p">{pair.p}</span>
                    <span className="tk-k">{pair.k}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="btn-row">
              <button className="btn" onClick={() => setPlaying((p) => !p)}>
                {playing ? "Pause" : "Play"}
              </button>
              <button className="btn ghost" onClick={() => { setHover(null); setStep(0); }}>
                Reset
              </button>
            </div>
          </div>

          <div
            className="tableau"
            onMouseLeave={() => setHover(null)}
          >
            <div className="tab-corner" />
            {ALPHABET.split("").map((l, i) => (
              <div
                key={`top-${i}`}
                className={`tab-head tab-col ${i === activeCol ? "active" : ""}`}
              >
                {l}
              </div>
            ))}
            {ALPHABET.split("").map((rowLetter, r) => (
              <React.Fragment key={`row-${r}`}>
                <div className={`tab-head tab-row ${r === activeRow ? "active" : ""}`}>
                  {rowLetter}
                </div>
                {ALPHABET.split("").map((_, c) => {
                  const v = ALPHABET[(r + c) % 26];
                  const isRow = r === activeRow;
                  const isCol = c === activeCol;
                  const isHit = isRow && isCol;
                  return (
                    <div
                      key={`c-${r}-${c}`}
                      className={`tab-cell ${isRow ? "in-row" : ""} ${isCol ? "in-col" : ""} ${isHit ? "hit" : ""}`}
                      onMouseEnter={() => { setHover({ row: r, col: c }); setPlaying(false); }}
                    >
                      {v}
                    </div>
                  );
                })}
              </React.Fragment>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

/* ===========================================================
   WORKBENCH
   =========================================================== */
function ModeSwitch({ mode, setMode }: { mode: Mode; setMode: (m: Mode) => void }) {
  const items: { id: Mode; label: string; icon: React.ReactNode }[] = [
    { id: "encrypt", label: "Encrypt", icon: <LockKeyhole size={13} /> },
    { id: "decrypt", label: "Decrypt", icon: <UnlockKeyhole size={13} /> },
    { id: "crack", label: "Solve", icon: <BrainCircuit size={13} /> },
  ];
  return (
    <div className="mode-switch" role="tablist">
      {items.map((it) => (
        <button
          key={it.id}
          role="tab"
          aria-selected={mode === it.id}
          className={mode === it.id ? "active" : ""}
          onClick={() => setMode(it.id)}
        >
          {it.icon}
          {it.label}
        </button>
      ))}
    </div>
  );
}

function Workbench() {
  const [mode, setMode] = useState<Mode>("encrypt");
  const [input, setInput] = useState(SAMPLE_TEXT);
  const [key, setKey] = useState(DEMO_KEY);
  const [keyLength, setKeyLength] = useState(7);
  const [isSolving, setIsSolving] = useState(false);
  const [result, setResult] = useState<ResultState>(() => ({
    text: encrypt(SAMPLE_TEXT, DEMO_KEY),
    label: "Ciphertext",
    key: DEMO_KEY,
    note: "Known-key encryption with ORBIT. Edit the input or key and submit again.",
  }));

  const cleanedKey = cleanKey(key);
  const inputLetters = cleanLetters(input).length;
  const canRunKnownKey = mode !== "crack" && cleanedKey.length > 0 && inputLetters > 0;
  const canCrack = mode === "crack" && inputLetters >= 32;
  const resultStats = estimateReadingStats(result.text || input);

  function submitKnownKey(nextMode: Exclude<Mode, "crack">) {
    const nextText =
      nextMode === "encrypt" ? encrypt(input, cleanedKey) : decrypt(input, cleanedKey);
    setMode(nextMode);
    setResult({
      text: nextText,
      label: nextMode === "encrypt" ? "Ciphertext" : "Plaintext",
      key: cleanedKey,
      note:
        nextMode === "encrypt"
          ? "Encryption added the repeating key stream modulo 26."
          : "Decryption subtracted the same key stream modulo 26.",
    });
  }

  function analyzeCiphertext(source = input) {
    const letters = cleanLetters(source).length;
    if (letters < 32 || isSolving) return;

    setMode("crack");
    setIsSolving(true);
    const t0 = performance.now();
    const cracked = crackCiphertext(source, 16);
    const elapsed = (performance.now() - t0).toFixed(1);
    const target = cracked.best.plaintext;
    let frame = 0;
    const frames = 26;
    const timer = window.setInterval(() => {
      frame += 1;
      const progress = Math.min(1, frame / frames);
      setResult({
        text: scrubText(target, progress),
        label: progress < 1 ? "Solving…" : "Recovered plaintext",
        key: cracked.best.key,
        note:
          progress < 1
            ? "Probing key lengths · resolving strip shifts · ranking candidates."
            : `Solved in ${elapsed} ms. Tested periods 1–${cracked.keyLengthScores.length || 16}, ran χ² over 26 shifts per strip, ranked the top ${cracked.candidates.length} candidates.`,
        candidates: cracked.candidates,
      });
      if (progress >= 1) {
        window.clearInterval(timer);
        setIsSolving(false);
      }
    }, 45);
  }

  function loadCrackDemo() {
    setInput(DEMO_CIPHER);
    setKey(DEMO_KEY);
    analyzeCiphertext(DEMO_CIPHER);
  }

  function submitCurrentMode() {
    if (mode === "encrypt") submitKnownKey("encrypt");
    if (mode === "decrypt") submitKnownKey("decrypt");
    if (mode === "crack") analyzeCiphertext();
  }

  return (
    <div className="workbench">
      <div className="wb-header">
        <div className="wb-title">
          <span className="kicker">02 · workbench</span>
          <h3>Run the cipher</h3>
        </div>
        <ModeSwitch mode={mode} setMode={setMode} />
      </div>

      <div className="wb-grid">
        {/* LEFT */}
        <div className="wb-pane">
          <div>
            <div className="field-label">
              <span>{mode === "crack" ? "Ciphertext" : "Input text"}</span>
              <span className="hint">{inputLetters} letters</span>
            </div>
            <textarea
              rows={9}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              spellCheck={false}
              placeholder="Type or paste text here…"
            />
          </div>

          {mode !== "crack" ? (
            <>
              <div>
                <div className="field-label">
                  <span>Key</span>
                  <span className="hint">cleaned: {cleanedKey || "—"}</span>
                </div>
                <div className="key-row">
                  <input
                    value={key}
                    onChange={(e) => setKey(e.target.value)}
                    spellCheck={false}
                    placeholder="ORBIT"
                  />
                  <button className="btn" onClick={() => setKey(randomKey(keyLength))}>
                    <Dices size={13} /> Random
                  </button>
                </div>
              </div>
              <div className="slider">
                <div>
                  <div className="field-label" style={{ marginBottom: 6 }}>
                    <span>Random key length</span>
                  </div>
                  <input
                    type="range"
                    min={3}
                    max={18}
                    value={keyLength}
                    onChange={(e) => setKeyLength(parseInt(e.target.value, 10))}
                  />
                </div>
                <div className="slider-value">{keyLength}</div>
              </div>
            </>
          ) : (
            <div className="alert">
              <BrainCircuit size={16} style={{ flex: "0 0 auto", marginTop: 2, color: "var(--amber)" }} />
              <div>
                Solve mode runs the same routine the walkthrough below describes — period
                probing, strip-by-strip Caesar fit, candidate scoring — then animates the reveal.
              </div>
            </div>
          )}

          <div className="btn-row">
            <button
              className="btn primary"
              disabled={mode === "crack" ? !canCrack || isSolving : !canRunKnownKey}
              onClick={submitCurrentMode}
            >
              <Play size={13} /> Submit
            </button>
            <button className="btn" disabled={!canRunKnownKey} onClick={() => submitKnownKey("encrypt")}>
              <LockKeyhole size={13} /> Encrypt
            </button>
            <button className="btn" disabled={!canRunKnownKey} onClick={() => submitKnownKey("decrypt")}>
              <UnlockKeyhole size={13} /> Decrypt
            </button>
            <button className="btn" disabled={!canCrack || isSolving} onClick={() => analyzeCiphertext()}>
              <BrainCircuit size={13} /> Analyze
            </button>
            <button className="btn ghost" disabled={isSolving} onClick={loadCrackDemo}>
              <Sparkles size={13} /> Crack demo
            </button>
          </div>
        </div>

        {/* RIGHT */}
        <div className="wb-pane right">
          <div className="field-label">
            <span>{result.label}</span>
            <button
              className="btn ghost"
              style={{ padding: "4px 10px", fontSize: 10 }}
              disabled={!result.text}
              onClick={() => navigator.clipboard?.writeText(result.text)}
            >
              <ClipboardCopy size={12} /> Copy
            </button>
          </div>

          <div className={`result-output ${isSolving ? "solving" : ""}`}>
            {result.text || "Enter at least 32 letters, then Analyze."}
          </div>

          <div className="result-note">{result.note}</div>

          {result.candidates && (
            <div className="key-card">
              <div className="label">
                <span className="kicker">Recovered key</span>
                <span className="mono" style={{ fontSize: 11, color: "var(--vellum-mute)" }}>
                  length {result.key?.length ?? 0}
                </span>
              </div>
              <span className="recovered">{result.key}</span>
              <div className="candidates">
                {result.candidates.slice(0, 4).map((c) => (
                  <div className="candidate" key={`${c.key}-${c.keyLength}-${c.score}`}>
                    <span>{c.key}</span>
                    <div className="bar">
                      <span style={{ width: `${Math.max(6, Math.min(100, c.confidence * 100))}%` }} />
                    </div>
                    <span className="score">{c.score.toFixed(0)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="metric-row">
            <div className="metric">
              <div className="lbl">Letters</div>
              <div className="val">{resultStats.letters}</div>
            </div>
            <div className="metric">
              <div className="lbl">IoC</div>
              <div className="val">{resultStats.ioc.toFixed(4)}</div>
            </div>
            <div className="metric">
              <div className="lbl">Profile</div>
              <div className="val">{resultStats.entropyLabel}</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

/* ===========================================================
   STAGE 1 — Normalize
   =========================================================== */
function NormalizeViz({ raw }: { raw: string }) {
  const cleaned = cleanLetters(raw);
  return (
    <div className="norm-viz">
      <div>
        <div className="label">raw input</div>
        <div className="raw">{raw.slice(0, 180)}{raw.length > 180 ? "…" : ""}</div>
      </div>
      <div className="divider">strip · uppercase · keep A–Z</div>
      <div>
        <div className="label">working stream · n = {cleaned.length}</div>
        <div className="cleaned">{cleaned.slice(0, 200)}{cleaned.length > 200 ? "…" : ""}</div>
      </div>
    </div>
  );
}

/* ===========================================================
   STAGE 2 — Key length probe (Friedman test)
   =========================================================== */
function KeyLengthProbe({ ciphertext }: { ciphertext: string }) {
  const probes = useMemo(() => probeKeyLengths(ciphertext, 12), [ciphertext]);
  const winner = useMemo(
    () => probes.reduce((best, p) => (p.confidence > best.confidence ? p : best), probes[0]),
    [probes]
  );
  const maxIoc = Math.max(0.075, ...probes.map((p) => p.ioc));

  return (
    <div className="probe">
      <div className="probe-row" style={{ color: "var(--vellum-mute)" }}>
        <span className="len">m</span>
        <span className="mono" style={{ fontSize: 9, letterSpacing: "0.22em", textTransform: "uppercase" }}>
          avg ioc across strips · english ≈ 0.0667
        </span>
        <span className="ioc">value</span>
      </div>
      {probes.map((p) => (
        <motion.div
          key={p.length}
          className={`probe-row ${p.length === winner.length ? "winner" : ""}`}
          initial={{ opacity: 0, x: -8 }}
          whileInView={{ opacity: 1, x: 0 }}
          viewport={{ once: true, amount: 0.6 }}
          transition={{ delay: p.length * 0.035 }}
        >
          <span className="len">{p.length}</span>
          <div className="track">
            <div className="fill" style={{ width: `${(p.ioc / maxIoc) * 100}%` }} />
            <div className="target" style={{ left: `${(0.0667 / maxIoc) * 100}%` }} />
          </div>
          <span className="ioc">{p.ioc.toFixed(4)}</span>
        </motion.div>
      ))}
    </div>
  );
}

/* ===========================================================
   STAGE 3 — Strip + chi-square reveal
   =========================================================== */
function StripChiViz({ ciphertext, keyLength }: { ciphertext: string; keyLength: number }) {
  const strips = useMemo(() => buildStrips(ciphertext, keyLength), [ciphertext, keyLength]);
  const visibleStrip = strips[0] ?? "";
  const profile = useMemo(() => chiSquareProfile(visibleStrip), [visibleStrip]);
  const best = profile.reduce((b, p) => (p.chi < b.chi ? p : b), profile[0]);
  const maxChi = Math.max(...profile.map((p) => p.chi));

  return (
    <div className="strip-viz">
      <div className="field-label" style={{ marginBottom: 4 }}>
        <span>Ciphertext folded into {keyLength} strips</span>
        <span className="hint">strip 1 highlighted</span>
      </div>
      <div className="strip-line">
        {cleanLetters(ciphertext)
          .slice(0, 60)
          .split("")
          .map((c, i) => {
            const stripIdx = i % keyLength;
            const cls = stripIdx === 0 ? "hl0" : stripIdx === 1 ? "hl1" : stripIdx === 2 ? "hl2" : "";
            return (
              <span key={i} className={`strip-cell ${cls}`}>
                {c}
              </span>
            );
          })}
      </div>
      <div className="field-label" style={{ marginTop: 12 }}>
        <span>χ² over 26 trial shifts for strip 1</span>
        <span className="hint">
          best = <b style={{ color: "var(--amber)" }}>{best.letter}</b>
        </span>
      </div>
      <div className="chi-bars">
        {profile.map((p) => (
          <div
            key={p.shift}
            className={`chi-bar ${p.shift === best.shift ? "best" : ""}`}
            style={{ height: `${100 - (p.chi / maxChi) * 90}%` }}
            title={`${p.letter}: χ² = ${p.chi.toFixed(1)}`}
          >
            {p.shift % 4 === 0 && <span className="lbl">{p.letter}</span>}
          </div>
        ))}
      </div>
    </div>
  );
}

/* ===========================================================
   STAGE 4 — Reveal
   =========================================================== */
function RevealViz() {
  const [progress, setProgress] = useState(0);
  useEffect(() => {
    const id = window.setInterval(
      () => setProgress((p) => (p >= 1 ? 0 : Math.min(1, p + 1 / 32))),
      120
    );
    return () => window.clearInterval(id);
  }, []);
  const target = "THE COURIER WILL CROSS THE EASTERN BRIDGE BEFORE DAWN";
  const scrambled = scrubText(target, progress);
  return (
    <div className="reveal-viz">
      <div className="field-label">
        <span>Candidate score S(P,K)</span>
        <span className="hint">{(progress * 100).toFixed(0)}%</span>
      </div>
      <div className="scrambled">cipher: BTXY DXLBANS YJRT XBNFF RVF VEFRGSI WJSJSV YOTNUS PVAS</div>
      <div className="clear">
        {scrambled
          .split(" ")
          .map((word, i) => (
            <React.Fragment key={i}>
              {progress > i / 12 ? <b>{word}</b> : <span>{word}</span>}{" "}
            </React.Fragment>
          ))}
      </div>
    </div>
  );
}

/* ===========================================================
   WALKTHROUGH SECTION
   =========================================================== */
function Walkthrough() {
  useMathJax();
  const cipher = DEMO_CIPHER;

  return (
    <section id="walkthrough">
      <div className="shell">
        <div className="section-head">
          <div className="marker">03 · method</div>
          <div>
            <h2>
              How the solver hears <em>a repeating key</em>.
            </h2>
            <p className="sub">
              The Vigenère cipher only looks random. A repeated key of length <span className="mono">m</span> imprints a
              statistical fingerprint every <span className="mono">m</span> characters — and that fingerprint is what
              the solver listens for. Four stages, each one visible below.
            </p>
          </div>
        </div>

        <div className="walkthrough">
          {/* Stage 1 */}
          <div className="stage">
            <div className="stage-num">01</div>
            <div className="stage-text">
              <h3>Normalize the stream.</h3>
              <p>
                Punctuation and casing are theater for humans, noise for the math. The solver
                folds everything to uppercase A–Z so each position is a clean integer 0–25.
                Spaces are remembered only to restore the result at the end.
              </p>
              <div className="formula">P, C ∈ {`{`}0,…,25{`}`}<sup>n</sup> &nbsp; with A=0, …, Z=25</div>
            </div>
            <div className="stage-viz">
              <NormalizeViz raw={SAMPLE_TEXT} />
            </div>
          </div>

          {/* Stage 2 */}
          <div className="stage">
            <div className="stage-num">02</div>
            <div className="stage-text">
              <h3>Probe the period.</h3>
              <p>
                For each candidate length <span className="mono">m</span>, the ciphertext is sliced
                into <span className="mono">m</span> interleaved strips. Each strip is a pure
                Caesar shift, so its <em>index of coincidence</em> should approach English's
                ≈ 0.0667 when the period is right and stay near 0.038 (uniform noise) when it
                isn't. The winning bar below is the recovered period.
              </p>
              <div className="formula">Ī(m) = (1/m) · Σ I(strip_r),&nbsp; argmax over m</div>
            </div>
            <div className="stage-viz">
              <KeyLengthProbe ciphertext={cipher} />
            </div>
          </div>

          {/* Stage 3 */}
          <div className="stage">
            <div className="stage-num">03</div>
            <div className="stage-text">
              <h3>Solve each strip as a Caesar.</h3>
              <p>
                With the period locked, each strip carries one letter of the key. The solver
                tries all 26 shifts and keeps the one whose decoded letter frequencies best
                match English — measured by chi-square distance from the reference histogram.
                Repeating across strips reconstructs the key in full.
              </p>
              <div className="formula">k_r = argmin_s χ²( decode(strip_r, s) )</div>
            </div>
            <div className="stage-viz">
              <StripChiViz ciphertext={cipher} keyLength={5} />
            </div>
          </div>

          {/* Stage 4 */}
          <div className="stage">
            <div className="stage-num">04</div>
            <div className="stage-text">
              <h3>Score, rank, reveal.</h3>
              <p>
                Candidates from the top key-lengths are decrypted in parallel and scored on
                three signals: closeness of IoC to English, presence of common digrams and
                short words, and the residual χ² fit. The leader becomes the recovered
                plaintext; the others stay in view as a confidence ladder.
              </p>
              <div className="formula">S = 150·(1−|I−0.0667|/0.0667) + W(P) − χ²/(N/25)</div>
            </div>
            <div className="stage-viz">
              <RevealViz />
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ===========================================================
   FREQUENCY LAB
   =========================================================== */
function FrequencyLab() {
  const [src, setSrc] = useState(DEMO_CIPHER);
  const stats = useMemo(() => letterStats(src), [src]);
  const max = Math.max(...stats.map((s) => s.count), 1);
  const total = stats.reduce((s, x) => s + x.count, 0) || 1;
  const maxPct = Math.max(...stats.map((s) => (s.count / total) * 100), 13);

  return (
    <section id="frequency">
      <div className="shell">
        <div className="section-head">
          <div className="marker">04 · evidence</div>
          <div>
            <h2>
              The alphabet leaves a <em>signature</em>.
            </h2>
            <p className="sub">
              Drop plaintext to see English's familiar profile — peaks at E, T, A, O, N. Drop
              ciphertext from a long key and the histogram flattens out toward uniform. That
              difference is the solver's first piece of evidence.
            </p>
          </div>
        </div>

        <div className="freq-grid">
          <div>
            <div className="field-label">
              <span>Source</span>
              <span className="hint">{cleanLetters(src).length} letters</span>
            </div>
            <textarea
              rows={8}
              value={src}
              onChange={(e) => setSrc(e.target.value)}
              spellCheck={false}
            />
            <div className="metric-row" style={{ marginTop: 16 }}>
              <div className="metric">
                <div className="lbl">Words</div>
                <div className="val">{estimateReadingStats(src).words}</div>
              </div>
              <div className="metric">
                <div className="lbl">Unique</div>
                <div className="val">{estimateReadingStats(src).uniqueLetters}</div>
              </div>
              <div className="metric">
                <div className="lbl">IoC</div>
                <div className="val">{estimateReadingStats(src).ioc.toFixed(4)}</div>
              </div>
            </div>
          </div>

          <div className="freq-panel">
            <div className="field-label">
              <span>Histogram</span>
              <span className="hint">tick = English reference</span>
            </div>
            <div className="stat-grid">
              {stats.map((s, i) => {
                const pct = (s.count / total) * 100;
                const expectedPct = ENGLISH_FREQUENCIES[i] * 100;
                return (
                  <div className="letter-bar" key={s.letter}>
                    <span className="letter">{s.letter}</span>
                    <div className="track">
                      <div className="fill" style={{ width: `${(s.count / max) * 100}%` }} />
                      <div className="expected" style={{ left: `${(expectedPct / maxPct) * 100}%` }} />
                    </div>
                    <span className="pct">{pct.toFixed(1)}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ===========================================================
   MATH SECTION
   =========================================================== */
function MathSection() {
  useMathJax();
  return (
    <section id="math">
      <div className="shell">
        <div className="section-head">
          <div className="marker">05 · score</div>
          <div>
            <h2>
              Four equations, <em>start to end.</em>
            </h2>
            <p className="sub">
              The arithmetic underneath every panel above. MathJax renders so the page reads
              like a notebook, not a screenshot.
            </p>
          </div>
        </div>

        <div className="math-grid">
          <div className="math-card feature">
            <h4>Encrypt &amp; decrypt</h4>
            <p>
              Letters become integers \(A=0,\ldots,Z=25\). A key \(K\) of length \(m\) repeats
              over the plaintext, producing the ciphertext.
            </p>
            <div className="math-line">{"\\[ C_i = (P_i + K_{i \\bmod m}) \\bmod 26 \\]"}</div>
            <div className="math-line">{"\\[ P_i = (C_i - K_{i \\bmod m}) \\bmod 26 \\]"}</div>
          </div>

          <div className="math-card">
            <h4>Index of coincidence</h4>
            <p>
              Probability that two random letters in the same strip match. English ≈ 0.0667,
              uniform noise ≈ 0.0385.
            </p>
            <div className="math-line">
              {"\\[ I = \\frac{\\sum_{j=0}^{25} n_j(n_j-1)}{N(N-1)} \\]"}
            </div>
          </div>

          <div className="math-card">
            <h4>Period evidence</h4>
            <p>
              For each guessed period \(m\), average IoC across all \(m\) strips. The right
              period peaks toward English.
            </p>
            <div className="math-line">
              {"\\[ \\bar I_m=\\frac{1}{m}\\sum_{r=0}^{m-1} I(\\text{strip}_r) \\]"}
            </div>
          </div>

          <div className="math-card">
            <h4>Chi-square fit</h4>
            <p>
              For each Caesar shift inside a strip, compare observed frequencies \(O\) with
              expected English frequencies \(E\).
            </p>
            <div className="math-line">
              {"\\[ \\chi^2(s)=\\sum_{j=0}^{25}\\frac{(O_{j,s}-E_j)^2}{E_j} \\]"}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ===========================================================
   APP
   =========================================================== */
function App() {
  return (
    <>
      <TopBar />
      <Hero />
      <About />
      <Tableau />

      <section id="workbench">
        <div className="shell">
          <div className="section-head">
            <div className="marker">02 · workbench</div>
            <div>
              <h2>
                Encrypt, decrypt, or<br />
                <em>solve</em> in one panel.
              </h2>
              <p className="sub">
                The same three primitives live behind one console — switch modes, paste your
                text, and the right pane shows the answer alongside the evidence: recovered
                key, candidate ranking, and live statistical metrics.
              </p>
            </div>
          </div>
          <Workbench />
        </div>
      </section>

      <Walkthrough />
      <FrequencyLab />
      <MathSection />

      <section style={{ borderTop: "1px solid var(--rule)" }}>
        <div className="shell">
          <div className="final">
            <div>
              <span className="eyebrow"><span className="dot" />exhibit</span>
              <h2 style={{ marginTop: 16 }}>
                Built to be read,<br />
                not just <em>run</em>.
              </h2>
              <p>
                Keyboard-friendly controls, local computation, and a narrative laid out for
                anyone who's curious how a 16th-century cipher loses to nothing more than
                histograms and chi-square.
              </p>
            </div>
            <a className="btn primary" href="#workbench">
              Try it now <ArrowUpRight size={14} />
            </a>
          </div>
          <footer>
            <span>Vigenère Solver Lab · v0.2</span>
            <span>runs locally · MIT</span>
          </footer>
        </div>
      </section>
    </>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
