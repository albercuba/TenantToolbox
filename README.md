# TenantToolbox

Self-hosted Microsoft 365 security and management platform for MSPs.

## Current status

Phase 0 foundation is scaffolded with:

- FastAPI backend with health and tenant endpoints
- React + TypeScript + Vite frontend
- Frontend visual system based on `Templates/PharmaPMS/ui-template`
- Docker Compose services for the API, frontend, PostgreSQL, Redis, and worker placeholder

The current dashboard uses sample tenant data until the database and Microsoft Graph consent flow are implemented.

## Local development

Backend:

```sh
cd backend
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Frontend:

```sh
cd frontend
npm install
npm run dev
```

Or start the full foundation stack:

```sh
docker compose up --build
```

- Frontend: http://localhost:5173
- API docs: http://localhost:8000/docs
- API health: http://localhost:8000/api/health

The Compose database credentials are development-only defaults. Use environment-backed secrets before any shared or production deployment.
