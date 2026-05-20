#!/usr/bin/env python3
"""
auto_cover_letter_gpt.py

Generate evidence-grounded, job-specific cover letters using OpenAI's Responses API.

Inputs:
  1. candidate profile JSON
  2. one job JSON, a list of job JSON objects, or {"jobs": [...]} for batching

Outputs:
  - Markdown letter
  - plaintext letter
  - LaTeX letter
  - structured audit JSON with fit summary, keywords, claims, and warnings

Setup:
  python -m pip install --upgrade openai
  export OPENAI_API_KEY="sk-..."

Examples:
  python auto_cover_letter_gpt.py --write-examples

  python auto_cover_letter_gpt.py \
    --profile applicant_profile.example.json \
    --jobs jobs.example.json \
    --out-dir generated_letters

  python auto_cover_letter_gpt.py \
    --profile applicant_profile.example.json \
    --jobs jobs.example.json \
    --format tex --out-dir generated_letters

  python auto_cover_letter_gpt.py \
    --profile applicant_profile.example.json \
    --company "Resecurity" \
    --job-title "Dark Web Threat Analyst" \
    --responsibility "Collect, validate, and analyze underground activity" \
    --requirement "OSINT and Python automation" \
    --note "Keep tone investigative and direct"
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Iterable

DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-5.5")

SYSTEM_PROMPT = """
You are a senior technical career writer specializing in cybersecurity, AI security,
application security, offensive security, threat intelligence, and software engineering roles.

Generate a concise, credible cover letter that maps the candidate's strongest verified evidence
to the supplied company and job information.

Rules:
- Use only facts from candidate_profile, job_info, and explicit web-search results if web_search is enabled.
- Do not invent employers, certifications, degrees, awards, metrics, tools, clients, dates, or outcomes.
- Do not exaggerate seniority. If evidence is adjacent rather than exact, phrase it honestly.
- Avoid generic filler: passionate, excited to apply, perfect fit, fast-paced environment, team player.
- Prefer concrete proof: internships, projects, tools, systems, standards, CTFs, automation, reports.
- Keep the cover letter 3-5 paragraphs unless job_info asks otherwise.
- Keep personal narrative brief and professional. Do not include childhood stories unless explicitly requested.
- Return only JSON matching the provided schema.
""".strip()

LETTER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "subject": {
            "type": "string",
            "description": "Short subject line, e.g. Application for Security Engineer Intern.",
        },
        "salutation": {
            "type": "string",
            "description": "Professional greeting, e.g. Dear Security Hiring Team,",
        },
        "body_paragraphs": {
            "type": "array",
            "description": "Three to five concise body paragraphs. No salutation or signature.",
            "items": {"type": "string"},
        },
        "closing": {
            "type": "string",
            "description": "One short professional closing sentence before the signature.",
        },
        "signature": {
            "type": "string",
            "description": "Candidate name only unless otherwise requested.",
        },
        "fit_summary": {
            "type": "array",
            "description": "Brief bullets explaining the strongest candidate-role alignments.",
            "items": {"type": "string"},
        },
        "keywords_used": {
            "type": "array",
            "description": "ATS/recruiter-relevant keywords intentionally included.",
            "items": {"type": "string"},
        },
        "claims_used": {
            "type": "array",
            "description": "Concrete candidate claims used in the letter; each must be supported by input data.",
            "items": {"type": "string"},
        },
        "warnings": {
            "type": "array",
            "description": "Manual review warnings, weak evidence, missing context, or verification needs.",
            "items": {"type": "string"},
        },
    },
    "required": [
        "subject",
        "salutation",
        "body_paragraphs",
        "closing",
        "signature",
        "fit_summary",
        "keywords_used",
        "claims_used",
        "warnings",
    ],
}

EXAMPLE_PROFILE: dict[str, Any] = {
    "candidate": {
        "name": "Evan Pardon",
        "location": "Rochester, MI",
        "email": "evanpardon@pm.me",
        "phone": "248-860-2491",
        "github": "https://github.com/supasuge",
        "linkedin": "https://linkedin.com/in/evan-pardon",
        "portfolio": "https://supasuge.com",
    },
    "positioning_summary": "Cybersecurity researcher and AI/cybersecurity student with hands-on experience in AppSec, offensive tooling, CTF infrastructure, cryptanalysis, automotive security testing, and Python/Go automation.",
    "education": [
        "B.S. Artificial Intelligence, Cybersecurity Concentration, Oakland University, expected Dec 2028",
        "A.A.S. Cybersecurity, Oakland Community College, Aug 2025",
    ],
    "certifications": [
        "Certified AppSec Practitioner (CAP), The SecOps Group, 2024",
        "CompTIA Security+, 2024",
        "CompTIA Network+, 2023",
    ],
    "experience": [
        {
            "organization": "Dana Incorporated",
            "role": "Cybersecurity Engineer Intern",
            "dates": "May 2023 - Dec 2023",
            "evidence": [
                "Built Python/FastAPI key-rotation middleware integrating Azure Managed HSM for secure ECU key-management workflows.",
                "Performed CAN/UDS on-target security testing aligned with ISO/SAE 21434.",
                "Authored reusable test cases and onboarding documentation adopted by the team.",
            ],
        },
        {
            "organization": "Fortify Vector Labs LLC",
            "role": "Founder & Principal Consultant",
            "dates": "Mar 2026 - Present",
            "evidence": [
                "Independent security lab focused on AppSec research, red-team tooling, CTF infrastructure, and AI-security experimentation.",
                "Publishes tooling and write-ups through GitHub and portfolio.",
            ],
        },
        {
            "organization": "Handshake",
            "role": "AI Trainer / Data Annotator",
            "dates": "Dec 2025 - Present",
            "evidence": [
                "Evaluates and annotates multimodal datasets for model quality, safety, and instruction-following across structured workflows."
            ],
        },
    ],
    "projects": [
        {
            "name": "AutoRT",
            "evidence": [
                "Built a policy-driven multi-agent red-team assessment PoC using LangGraph/MCP concepts for recon, enumeration, vulnerability analysis, evidence collection, reporting, and remediation workflows."
            ],
        },
        {
            "name": "GrizzHacks8 CTF",
            "evidence": [
                "Built and managed self-hosted CTF infrastructure and authored challenges with public source, write-ups, and reproducible solver paths."
            ],
        },
        {
            "name": "VigenereSolver-ng",
            "evidence": [
                "Built a modular Python cryptanalysis toolkit using Kasiski/Friedman analysis, corpus scoring, and LLM-assisted key refinement."
            ],
        },
        {
            "name": "VeriVote",
            "evidence": [
                "Prototyped privacy-preserving voting flow combining homomorphic tallying, ECC signing, ring-signature concepts, and zero-knowledge authentication."
            ],
        },
    ],
    "skills": {
        "languages": ["Python", "Go", "Bash", "SQL", "C"],
        "security": [
            "Application security",
            "Threat intelligence",
            "OSINT",
            "Cryptanalysis",
            "CTF infrastructure",
            "Offensive security tooling",
            "Automotive cybersecurity",
            "Active Directory enumeration",
            "Security automation",
        ],
        "tools": [
            "Burp Suite",
            "Nmap",
            "Wireshark",
            "Ghidra",
            "GDB",
            "Metasploit",
            "Nessus/OpenVAS",
            "Hashcat/John",
            "impacket/NetExec",
            "Sliver",
            "Volatility",
            "AFL++",
        ],
        "standards_protocols": [
            "MITRE ATT&CK",
            "NIST CSF",
            "NIST SP 800-61",
            "OWASP Top 10",
            "ISO/SAE 21434",
            "TCP/IP",
            "TLS",
            "DNS",
            "HTTP(S)",
            "SMB",
            "Kerberos",
            "LDAP",
            "PKI",
            "CAN/UDS",
        ],
    },
    "achievements": [
        "Won 1st place in Hack The Box Data Dystopia at DEF CON 32 with Team L3ak.",
        "Top 1% on TryHackMe/Hack The Box.",
        "Founded OCC Cyber Club and grew weekly attendance from 8 to 15+.",
        "Authored CTF challenges/infrastructure for GrizzHacks, HackDearborn, L3akCTF, and PwnSecCTF, supporting 1,000+ cumulative participants.",
        "ISACA Detroit 2026 Student Scholarship recipient.",
    ],
    "writing_preferences": {
        "tone": "direct, technical, polished, confident, human",
        "length_words": "280-420",
        "avoid": [
            "oversharing personal childhood stories",
            "inflated claims",
            "generic passion language",
            "unverified company facts",
        ],
    },
}

EXAMPLE_JOBS: dict[str, Any] = {
    "jobs": [
        {
            "company_name": "Resecurity",
            "hiring_team": "Resecurity Hiring Team",
            "job_title": "Dark Web Threat Analyst",
            "job_location": "Remote",
            "company_context": [
                "Threat intelligence company focused on cybercrime monitoring, digital risk, and adversary activity."
            ],
            "responsibilities": [
                "Collect, validate, and analyze underground/dark web activity.",
                "Translate findings into actionable intelligence.",
                "Monitor cybercrime ecosystems, credential theft, ransomware, fraud, and access broker activity.",
                "Produce structured reporting for stakeholders.",
            ],
            "requirements": [
                "Cybersecurity research background",
                "OSINT and multi-source correlation",
                "Python automation",
                "Threat actor/TTP analysis",
                "Clear written communication",
            ],
            "keywords": [
                "OSINT",
                "dark web",
                "threat intelligence",
                "cybercrime",
                "MITRE ATT&CK",
                "Python",
                "ransomware",
                "credential theft",
            ],
            "notes": [
                "Keep the tone direct and credible.",
                "Do not include long childhood/Minecraft anecdotes.",
                "Mention cybercriminal ecosystem familiarity only as research interest, not operational participation.",
            ],
            "cover_letter_preferences": {
                "tone": "technical, investigative, restrained, sincere",
                "length_words": 375,
                "must_include": ["OSINT", "Python automation", "CTF/research background"],
                "avoid": ["overly personal narrative", "claims about illegal access", "unverified company details"],
            },
        }
    ]
}


@dataclass(frozen=True)
class Config:
    model: str
    max_output_tokens: int
    temperature: float | None
    web_search: bool
    store: bool


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SystemExit(f"File not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {path}: line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_text(path: Path, text: str, overwrite: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not overwrite:
        raise SystemExit(f"Refusing to overwrite existing file: {path}. Add --overwrite to replace it.")
    path.write_text(text, encoding="utf-8")


def normalize_jobs(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, dict) and isinstance(raw.get("jobs"), list):
        jobs = raw["jobs"]
    elif isinstance(raw, list):
        jobs = raw
    elif isinstance(raw, dict):
        jobs = [raw]
    else:
        raise SystemExit("Jobs input must be a JSON object, a JSON list, or {'jobs': [...]}. ")

    clean: list[dict[str, Any]] = []
    for index, job in enumerate(jobs, start=1):
        if not isinstance(job, dict):
            raise SystemExit(f"Job #{index} is not a JSON object.")
        if not job.get("company_name") or not job.get("job_title"):
            raise SystemExit(f"Job #{index} must include company_name and job_title.")
        clean.append(job)
    return clean


def job_from_cli(args: argparse.Namespace) -> dict[str, Any] | None:
    if not args.company and not args.job_title:
        return None
    if not args.company or not args.job_title:
        raise SystemExit("CLI mode requires both --company and --job-title.")

    job: dict[str, Any] = {
        "company_name": args.company,
        "job_title": args.job_title,
    }
    if args.hiring_team:
        job["hiring_team"] = args.hiring_team
    if args.job_location:
        job["job_location"] = args.job_location
    if args.company_context:
        job["company_context"] = args.company_context
    if args.responsibility:
        job["responsibilities"] = args.responsibility
    if args.requirement:
        job["requirements"] = args.requirement
    if args.keyword:
        job["keywords"] = args.keyword
    if args.note:
        job["notes"] = args.note
    return job


def validate_profile(profile: dict[str, Any]) -> None:
    candidate = profile.get("candidate")
    if not isinstance(candidate, dict):
        raise SystemExit("Profile must include a candidate object.")
    missing = [field for field in ["name", "email"] if not candidate.get(field)]
    if missing:
        raise SystemExit(f"Profile candidate is missing required field(s): {', '.join(missing)}")


def slugify(value: str) -> str:
    value = value.lower().strip()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    value = re.sub(r"-+", "-", value).strip("-")
    return value or "cover-letter"


def compact_payload(profile: dict[str, Any], job: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    return {
        "candidate_profile": profile,
        "job_info": job,
        "generation_options": {
            "requested_date": date.today().isoformat(),
            "tone_override": args.tone,
            "target_words": args.words,
            "format_requested": args.format,
            "web_search_enabled": args.web_search,
            "audit_requirement": "Populate claims_used only with facts explicitly supported by the provided inputs or web-search results.",
        },
    }


def call_openai(payload: dict[str, Any], config: Config) -> dict[str, Any]:
    try:
        from openai import OpenAI  # type: ignore
    except ImportError as exc:
        raise SystemExit("Missing dependency: openai. Install with: python -m pip install --upgrade openai") from exc

    client = OpenAI()
    request: dict[str, Any] = {
        "model": config.model,
        "input": [
            {"role": "developer", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": "Generate a targeted cover letter from this JSON payload:\n"
                + json.dumps(payload, indent=2, ensure_ascii=False),
            },
        ],
        "max_output_tokens": config.max_output_tokens,
        "text": {
            "format": {
                "type": "json_schema",
                "name": "cover_letter_generation",
                "strict": True,
                "schema": LETTER_SCHEMA,
            }
        },
    }

    if config.temperature is not None:
        request["temperature"] = config.temperature
    if config.store is not None:
        request["store"] = config.store
    if config.web_search:
        request["tools"] = [{"type": "web_search"}]

    try:
        response = client.responses.create(**request)
    except Exception as exc:
        raise SystemExit(f"OpenAI API request failed: {exc}") from exc

    raw = getattr(response, "output_text", None)
    if not raw:
        raise SystemExit("OpenAI response did not include output_text. Check model/tool compatibility.")

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Could not parse model output as JSON: {exc}\n\nRaw output:\n{raw}") from exc

    validate_letter(data)
    return data


def validate_letter(letter: dict[str, Any]) -> None:
    missing = [key for key in LETTER_SCHEMA["required"] if key not in letter]
    if missing:
        raise SystemExit(f"Model output missing required key(s): {', '.join(missing)}")
    if not isinstance(letter.get("body_paragraphs"), list) or not letter["body_paragraphs"]:
        raise SystemExit("Model output body_paragraphs must be a non-empty list.")


def latex_escape(value: Any) -> str:
    text = str(value)
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(char, char) for char in text)


def today_human() -> str:
    return date.today().strftime("%B %d, %Y").replace(" 0", " ")


def candidate_contact_lines(profile: dict[str, Any]) -> list[str]:
    candidate = profile.get("candidate", {})
    lines = []
    for key in ["name", "location", "email", "phone", "linkedin", "github", "portfolio", "website"]:
        value = candidate.get(key)
        if value:
            lines.append(str(value))
    return lines


def render_markdown(profile: dict[str, Any], job: dict[str, Any], letter: dict[str, Any], include_audit: bool) -> str:
    contact = candidate_contact_lines(profile)
    name = profile["candidate"].get("name", letter.get("signature", ""))
    hiring_team = job.get("hiring_team") or f"{job.get('company_name')} Hiring Team"
    body = "\n\n".join(str(p).strip() for p in letter["body_paragraphs"] if str(p).strip())

    output = (
        f"**{contact[0]}**\n"
        + "\n".join(contact[1:])
        + f"\n\n{today_human()}\n\n{hiring_team}\n\n"
        + f"**Subject: {letter['subject']}**\n\n"
        + f"{letter['salutation']}\n\n"
        + body
        + f"\n\n{letter['closing']}\n\nSincerely,\n\n{name}\n"
    )
    if include_audit:
        output += "\n" + render_audit(letter)
    return output


def render_text(profile: dict[str, Any], job: dict[str, Any], letter: dict[str, Any], include_audit: bool) -> str:
    md = render_markdown(profile, job, letter, include_audit)
    return re.sub(r"\*\*(.*?)\*\*", r"\1", md)


def render_latex(profile: dict[str, Any], job: dict[str, Any], letter: dict[str, Any]) -> str:
    contact = [latex_escape(line) for line in candidate_contact_lines(profile)]
    name = latex_escape(profile["candidate"].get("name", letter.get("signature", "")))
    hiring_team = latex_escape(job.get("hiring_team") or f"{job.get('company_name')} Hiring Team")
    paragraphs = "\n\n".join(latex_escape(p.strip()) for p in letter["body_paragraphs"] if str(p).strip())
    contact_block = r" \\".join(contact)

    return rf"""\documentclass[letterpaper,11pt]{{article}}
\usepackage[T1]{{fontenc}}
\usepackage[utf8]{{inputenc}}
\usepackage[margin=1in]{{geometry}}
\usepackage[hidelinks]{{hyperref}}
\usepackage{{parskip}}
\input{{glyphtounicode}}
\pdfgentounicode=1

\hypersetup{{
  pdftitle={{{name} Cover Letter - {latex_escape(job.get('company_name', 'Company'))}}},
  pdfauthor={{{name}}},
  pdfsubject={{{latex_escape(letter['subject'])}}}
}}

\begin{{document}}

\begin{{flushleft}}
{contact_block}
\end{{flushleft}}

\vspace{{0.35cm}}

{latex_escape(today_human())}

\vspace{{0.35cm}}

\begin{{flushleft}}
{hiring_team}
\end{{flushleft}}

\vspace{{0.35cm}}

\textbf{{Subject: {latex_escape(letter['subject'])}}}

\vspace{{0.35cm}}

{latex_escape(letter['salutation'])}

{paragraphs}

{latex_escape(letter['closing'])}

Sincerely,\\
{name}

\end{{document}}
"""


def render_audit(letter: dict[str, Any]) -> str:
    sections = []
    labels = [
        ("Fit summary", "fit_summary"),
        ("Keywords used", "keywords_used"),
        ("Claims used", "claims_used"),
        ("Warnings / review before sending", "warnings"),
    ]
    for title, key in labels:
        items = letter.get(key, [])
        if isinstance(items, list) and items:
            body = "\n".join(f"- {item}" for item in items if str(item).strip())
            if body:
                sections.append(f"### {title}\n{body}")
    return "\n\n".join(sections) + "\n"


def output_paths(out_dir: Path, job: dict[str, Any], fmt: str) -> dict[str, Path]:
    base = slugify(f"{job.get('company_name', 'company')}-{job.get('job_title', 'cover-letter')}")
    paths: dict[str, Path] = {"json": out_dir / f"{base}.audit.json"}
    if fmt in {"all", "md"}:
        paths["md"] = out_dir / f"{base}.md"
    if fmt in {"all", "txt"}:
        paths["txt"] = out_dir / f"{base}.txt"
    if fmt in {"all", "tex"}:
        paths["tex"] = out_dir / f"{base}.tex"
    return paths


def write_outputs(
    out_dir: Path,
    profile: dict[str, Any],
    job: dict[str, Any],
    letter: dict[str, Any],
    fmt: str,
    include_audit: bool,
    overwrite: bool,
) -> None:
    paths = output_paths(out_dir, job, fmt)
    write_json(paths["json"], letter)
    eprint(f"wrote {paths['json']}")
    if "md" in paths:
        write_text(paths["md"], render_markdown(profile, job, letter, include_audit), overwrite)
        eprint(f"wrote {paths['md']}")
    if "txt" in paths:
        write_text(paths["txt"], render_text(profile, job, letter, include_audit), overwrite)
        eprint(f"wrote {paths['txt']}")
    if "tex" in paths:
        write_text(paths["tex"], render_latex(profile, job, letter), overwrite)
        eprint(f"wrote {paths['tex']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate targeted cover letters with OpenAI Responses API.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--profile", type=Path, help="Candidate profile JSON file.")
    parser.add_argument("--jobs", type=Path, help="Job JSON file: object, list, or {'jobs': [...]}. Optional when using CLI job fields.")
    parser.add_argument("--out-dir", type=Path, default=Path("generated_cover_letters"), help="Output directory.")
    parser.add_argument("--format", choices=["all", "md", "txt", "tex"], default="all", help="Output format(s).")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="OpenAI model name.")
    parser.add_argument("--max-output-tokens", type=int, default=2200, help="Maximum model output tokens.")
    parser.add_argument("--temperature", type=float, default=None, help="Optional generation temperature. Leave unset for model default.")
    parser.add_argument("--web-search", action="store_true", help="Allow OpenAI web_search for current company context.")
    parser.add_argument("--store", action="store_true", help="Allow OpenAI to store the response. By default, store=false is sent.")
    parser.add_argument("--words", type=int, default=375, help="Target approximate word count.")
    parser.add_argument("--tone", default="technical, direct, polished, sincere", help="Tone/style guidance.")
    parser.add_argument("--include-audit", action="store_true", help="Append audit sections to Markdown/text outputs; do not include in final submission.")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing output files.")
    parser.add_argument("--dry-run-prompt", action="store_true", help="Print payload(s) without calling the API.")
    parser.add_argument("--write-examples", action="store_true", help="Write applicant_profile.example.json and jobs.example.json, then exit.")

    # Quick no-job-file mode.
    parser.add_argument("--company", help="Company name for one-off generation.")
    parser.add_argument("--hiring-team", help="Hiring team/contact line.")
    parser.add_argument("--job-title", help="Job title for one-off generation.")
    parser.add_argument("--job-location", help="Remote/hybrid/location text.")
    parser.add_argument("--company-context", action="append", help="Company context sentence. Can be repeated.")
    parser.add_argument("--responsibility", action="append", help="Job responsibility. Can be repeated.")
    parser.add_argument("--requirement", action="append", help="Job requirement. Can be repeated.")
    parser.add_argument("--keyword", action="append", help="Keyword to intentionally align to. Can be repeated.")
    parser.add_argument("--note", action="append", help="Extra generation note. Can be repeated.")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.write_examples:
        write_json(Path("applicant_profile.example.json"), EXAMPLE_PROFILE)
        write_json(Path("jobs.example.json"), EXAMPLE_JOBS)
        print("Wrote applicant_profile.example.json and jobs.example.json")
        return 0

    if not args.profile:
        raise SystemExit("Missing --profile. Use --write-examples to create starter JSON files.")

    profile = read_json(args.profile)
    if not isinstance(profile, dict):
        raise SystemExit("Profile JSON must be an object.")
    validate_profile(profile)

    cli_job = job_from_cli(args)
    if args.jobs and cli_job:
        raise SystemExit("Use either --jobs or CLI job fields, not both.")
    if args.jobs:
        jobs = normalize_jobs(read_json(args.jobs))
    elif cli_job:
        jobs = [cli_job]
    else:
        raise SystemExit("Missing job input. Provide --jobs or use --company and --job-title.")

    config = Config(
        model=args.model,
        max_output_tokens=args.max_output_tokens,
        temperature=args.temperature,
        web_search=args.web_search,
        store=args.store,
    )

    for job in jobs:
        payload = compact_payload(profile, job, args)
        if args.dry_run_prompt:
            print(json.dumps(payload, indent=2, ensure_ascii=False))
            continue

        eprint(f"generating {job['company_name']} / {job['job_title']} with {config.model}")
        letter = call_openai(payload, config)
        write_outputs(
            args.out_dir,
            profile,
            job,
            letter,
            args.format,
            args.include_audit,
            args.overwrite,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
