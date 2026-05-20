# Auto Cover Letter Generator

Generates evidence-grounded, job-specific cover letters through the OpenAI Responses API.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\\Scripts\\activate
python -m pip install -r requirements.txt
export OPENAI_API_KEY="sk-..." # Windows PowerShell: setx OPENAI_API_KEY "sk-..."
```

## Create starter files

```bash
python auto_cover_letter_gpt.py --write-examples
```

## Generate letters from a jobs file

```bash
python auto_cover_letter_gpt.py \
  --profile applicant_profile.example.json \
  --jobs jobs.example.json \
  --out-dir generated_cover_letters \
  --format all
```

## One-off generation without a jobs file

```bash
python auto_cover_letter_gpt.py \
  --profile applicant_profile.example.json \
  --company "Resecurity" \
  --hiring-team "Resecurity Hiring Team" \
  --job-title "Dark Web Threat Analyst" \
  --responsibility "Collect, validate, and analyze underground activity" \
  --requirement "OSINT and Python automation" \
  --keyword "threat intelligence" \
  --note "Keep tone investigative and direct"
```

Use `--web-search` only when you want the model to verify current public company context. Keep it off when you already supplied the relevant job/company facts.

Use `--include-audit` only for internal review; do not send audit sections with the final cover letter.
