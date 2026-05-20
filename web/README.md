# Vigenère Solver — Web Lab

An interactive, in-browser playground for the Vigenère cipher. Encrypt, decrypt, or hand it
only the ciphertext and watch the auto-solver recover the key by index of coincidence and
chi-square fit. Everything runs locally — no server, no API, no telemetry.

## What's in the page

| Section       | What it does                                                                       |
| ------------- | ---------------------------------------------------------------------------------- |
| **Hero**      | Animated cipher → key → plaintext plate over a film-grain editorial backdrop.      |
| **About**     | Four pillars (what / why / how / speed) plus a 6-stop "single letter" rail.        |
| **Tableau**   | Interactive 26×26 tabula recta. Hover to highlight row/column; auto-demo cycles.   |
| **Workbench** | Encrypt, decrypt, or **Analyze** a ciphertext. Real solver, live metrics, copy.    |
| **Method**    | 4-stage walkthrough — normalize → probe → strip + χ² → reveal — with live charts.  |
| **Frequency** | Live histogram with the English-reference tick on every letter bar.                |
| **Math**      | MathJax-rendered equations for encrypt, decrypt, IoC, period evidence, and χ².     |

## How the solver actually works

The "Analyze" button in the workbench runs the real algorithm in
[`src/vigenere.ts`](src/vigenere.ts). No precomputed answers.

1. **Normalize** — strip everything except `A–Z`, uppercase it. That's the working stream.
2. **Probe the period** with Friedman's test. For each candidate length `m ∈ [1, ⌊n/6⌋]`, split
   the ciphertext into `m` interleaved strips and average their indices of coincidence.
   English ≈ 0.0667; uniform noise ≈ 0.0385. Apply a small factor penalty so multiples of a
   strong shorter period (e.g. 6 vs. 3) don't win spuriously.
3. **Solve each strip as a Caesar.** For every strip and every shift `s ∈ [0, 25]`, compute
   χ² against the English reference frequencies. The minimum is one letter of the key.
4. **Score candidates.** For the top key-lengths, decrypt and rank with
   `S = 150·(1 − |I − 0.0667|/0.0667) + W(P) − χ²/(N/25)` where `W(P)` is a common-word bonus.
5. **Reveal.** The leader is the recovered plaintext; the next 3 stay as a confidence ladder.

Total work is `O(L · max_m · 26)` — a few tens of milliseconds for typical pastes.

## Run locally

```bash
cd web
npm install
npm run dev          # http://localhost:5173
```

## Build

```bash
npm run build              # base "/" — Vercel / Netlify / Cloudflare Pages
npm run build:gh-pages     # base "/Vigenere-Solver/" — GitHub Pages project site
npm run build:static       # base "./" — works opened directly from disk
npm run preview            # local preview of the built bundle on :4173
```

## Deployment plan

The site is a static SPA, ~111 kB gzipped. Pick the host that matches how you run things.

### 1. GitHub Pages (recommended, free, zero-config)

A workflow at `.github/workflows/deploy-web.yml` builds and publishes to Pages on every push
to `main` that touches `web/`.

**One-time setup** (in the GitHub UI):

1. Repo → **Settings** → **Pages**
2. **Source**: `GitHub Actions`
3. Push to `main`. The workflow builds with `VITE_BASE=/Vigenere-Solver/`, copies
   `index.html` to `404.html` for client-side routing, and deploys.

Public URL: `https://<user>.github.io/Vigenere-Solver/`

### 2. Vercel

```bash
npm i -g vercel
cd web
vercel              # first run links the project
vercel --prod
```

Or import the repo at <https://vercel.com/new>:
- **Root Directory**: `web`
- **Framework Preset**: Vite
- **Build Command**: `npm run build`
- **Output Directory**: `dist`

### 3. Netlify

```bash
npm i -g netlify-cli
cd web
npm run build
netlify deploy --dir=dist --prod
```

Or via the UI: connect repo, set **Base directory** = `web`, **Build command** =
`npm run build`, **Publish directory** = `web/dist`.

### 4. Cloudflare Pages

In the Pages dashboard:
- **Project root**: `web`
- **Build command**: `npm run build`
- **Build output directory**: `dist`
- **Node version**: `20`

### 5. Any plain static host (S3 / nginx / `python -m http.server`)

```bash
npm run build:static          # uses relative asset paths
# upload web/dist/** to your host's web root
```

For nginx, a single-file SPA needs a fallback so deep links still resolve:

```nginx
location / {
  try_files $uri $uri/ /index.html;
}
```

### 6. Docker (optional)

```Dockerfile
FROM node:20-alpine AS build
WORKDIR /app
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
```

## Project layout

```
web/
├── index.html              MathJax bootstrap + #root
├── src/
│   ├── main.tsx            React app: hero, about, tableau, workbench, walkthrough, math
│   ├── styles.css          Design system (8pt grid, Fraunces + DM Sans + JetBrains Mono)
│   └── vigenere.ts         Pure cipher + solver — exported helpers drive the visualizations
├── vite.config.ts          Configurable base path via VITE_BASE
└── package.json
```

## Browser support

Targets ES2020. Tested on current Firefox, Chromium, and Safari. No service worker, no
storage, no fetch — the page is genuinely just markup + JS + WebFonts + MathJax CDN.
