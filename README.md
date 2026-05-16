# REDCON OFFENCE — Platform

Penetration-Testing-as-a-Service platform. FastAPI backend + Next.js frontend, served behind nginx at https://platform.redconoffence.com.

## Architecture

| Component       | Path                    | Runtime              | Port (local) |
|-----------------|-------------------------|----------------------|--------------|
| API             | `fastapi_backend/`      | uvicorn (FastAPI)    | 8001         |
| Frontend        | `frontend/`             | Next.js 14           | 3001         |
| Templates       | `templates/`            | Jinja2 (legacy)      | —            |

The Flask app (`app.py`) is legacy / dead code; the live backend is `fastapi_backend/main.py`.

## Local development

```bash
# Backend
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in secrets
uvicorn fastapi_backend.main:app --reload --port 8001

# Frontend
cd frontend
npm install
npm run dev            # http://localhost:3000
```

## Deployment

Production runs on `89.47.113.185` under systemd:

- `redcon-api.service`  → uvicorn on `:8001`
- `redcon-next.service` → next start on `:3001`

Deploy via **GitHub Actions → "Deploy to production" → Run workflow** (manual trigger).

The deploy job SSHes in, `git reset --hard origin/main`, installs deps, runs `next build`, and restarts both services.
