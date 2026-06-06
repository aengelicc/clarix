<p align="center">
  <img src="frontend/public/shield.svg" width="64" alt="Clarix logo" />
</p>

<h1 align="center">Clarix</h1>

<p align="center">
  Pre-deployment security analysis for your codebase.<br/>
  Static regex scanning + optional LLM-powered deep review — all in one tool.
</p>

<p align="center">
  <a href="#features">Features</a> ·
  <a href="#quick-start">Quick Start</a> ·
  <a href="#docker">Docker</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="#rules">Rules</a> ·
  <a href="#license">License</a>
</p>

---

## Features

- **Static analysis** — 146 built-in regex rules across Security, HIPAA, PCI-DSS, GDPR, SOC 2, OWASP Top 10 (2021), and CIS Critical Security Controls v8 frameworks. No API key required.
- **LLM deep review** — optional AI-powered code analysis via Anthropic Claude or OpenAI GPT-4o for richer findings.
- **GitHub + local** — analyze any public or private GitHub repo, or point it at a local folder.
- **Rules manager** — enable, disable, edit, or add custom rules. Bulk toggle all on/off to run only the checks you want.
- **Live streaming** — results stream in real time over SSE as each file is scanned.
- **Export** — download the full report as Markdown, JSON, or **SARIF 2.1.0** (compatible with GitHub Code Scanning).
- **Docker ready** — one `docker-compose up` for production.

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+

### 1. Clone

```bash
git clone https://github.com/aengelicc/clarix.git
cd clarix
```

### 2. Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` with your API keys (only needed for LLM analysis — static-only mode requires no keys):

```env
LLM_PROVIDER=anthropic          # or openai
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
GITHUB_PAT=ghp_...              # only needed for private repos
```

Start the backend:

```bash
uvicorn app.main:app --reload --port 8000
```

### 3. Frontend

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173** — API calls are proxied to the backend automatically.

---

## Docker

The fastest way to run Clarix in production:

```bash
cp backend/.env.example backend/.env
# Edit backend/.env with your keys
docker-compose up --build
```

| Service  | URL                    |
| -------- | ---------------------- |
| Frontend | http://localhost:3000  |
| Backend  | http://localhost:8000  |

---

## Configuration

All backend configuration lives in `backend/.env`:

| Variable             | Default                    | Description                              |
| -------------------- | -------------------------- | ---------------------------------------- |
| `LLM_PROVIDER`       | `anthropic`                | `anthropic` or `openai`                  |
| `ANTHROPIC_API_KEY`  | —                          | Required for LLM analysis with Claude    |
| `ANTHROPIC_MODEL`    | `claude-sonnet-4-6`        | Claude model ID                          |
| `OPENAI_API_KEY`     | —                          | Required for LLM analysis with GPT       |
| `OPENAI_MODEL`       | `gpt-4o`                   | OpenAI model ID                          |
| `GITHUB_PAT`         | —                          | Personal access token for private repos  |
| `MAX_FILES`          | `100`                      | Maximum files to scan per analysis       |
| `MAX_FILE_SIZE_KB`   | `500`                      | Skip files larger than this              |

---

## Usage

### Analyzing a repository

1. Paste a GitHub URL or click **Browse** to pick a local folder.
2. *(Optional)* Open **Analysis Settings** to choose your LLM provider or toggle **Static analysis only** to skip LLM calls entirely.
3. Click **Start Analysis**.

Results stream in across five tabs: **Overview**, **Issues**, **Files**, **Compliance**, and **AI Insights**. The Compliance tab includes separate views for HIPAA, PCI-DSS, GDPR, SOC 2, OWASP Top 10, and CIS Controls v8.

### Static-only mode

Enable **Static analysis only** in the settings panel to run purely regex-based scans with no API key required. Faster, and useful for CI/pre-commit hooks.

---

## Rules

Clarix ships with 146 built-in rules. Open **Manage security rules** from the home screen to:

- **Enable / disable** individual rules or bulk-toggle all on/off.
- **Edit** any rule's pattern, severity, or description.
- **Add** custom regex rules scoped to a specific scanner and language.
- **Delete** rules you don't need.

Rules are stored in `backend/app/data/rules.json` and persist across restarts.

---

## Project Structure

```
clarix/
├── backend/
│   ├── app/
│   │   ├── api/           # REST + SSE endpoints
│   │   ├── core/          # Pydantic models & config
│   │   ├── data/          # rules.json (seeded on first run)
│   │   └── services/      # Ingestion, LLM, scanners, rules store
│   ├── requirements.txt
│   └── .env.example
│
└── frontend/
    ├── src/
    │   ├── components/    # Dashboard, RulesManager, InputForm, …
    │   └── hooks/         # useAnalysis, useRules
    └── package.json
```

---

## License

[MIT](LICENSE)
