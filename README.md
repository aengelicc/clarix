# 🛡️ Clarix — Fullstack Edition

Pre-deployment code assessment platform with a **FastAPI backend** and **React + Tailwind frontend**.

## Architecture

```
codegate-fullstack/
├── backend/               # FastAPI + analysis engine
│   ├── app/
│   │   ├── main.py        # FastAPI app entry
│   │   ├── core/          # Config + Pydantic models
│   │   ├── api/           # REST endpoints
│   │   └── services/      # Ingestion, LLM, Security, Analyzer
│   ├── requirements.txt
│   └── .env.example
│
└── frontend/              # React + Vite + Tailwind
    ├── src/
    │   ├── components/    # Dashboard, IssueList, RiskScore, etc.
    │   ├── hooks/         # useAnalysis API hook
    │   └── App.jsx
    └── package.json
```

## Quick Start

### 1. Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your API keys
uvicorn app.main:app --reload --port 8000
```

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

The frontend will proxy API calls to `http://localhost:8000` automatically.

Open `http://localhost:5173` in your browser.

## Configuration

Backend `.env`:

```env
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-your-key
OPENAI_MODEL=gpt-4o
ANTHROPIC_API_KEY=sk-ant-your-key
ANTHROPIC_MODEL=claude-3-5-sonnet-20241022
GITHUB_PAT=ghp-your-pat
```

## Features

- 🔗 GitHub (public/private) + Local folder analysis
- 🤖 OpenAI GPT-4o or Anthropic Claude 3.5 Sonnet
- 🔒 Regex-based secret scanning + dangerous pattern detection
- 📊 Animated risk score gauge, language pie chart, issue explorer
- 📤 Export to Markdown and JSON
- 🎨 Clean, modern Tailwind UI with dark accents

## Deployment

### Docker (coming next)
Build a `docker-compose.yml` with:
- Backend container (Python)
- Frontend container (Nginx serving static build)
- Optional: Redis for job queuing large repos

### Production Build

```bash
cd frontend
npm run build
# Serve dist/ via Nginx or copy into backend static files
```

## License
MIT
