# TenantToolbox

Self-hosted Microsoft 365 security and management platform for MSPs.

## Current status

Phase 0 foundation is implemented with:

- FastAPI backend with local owner/tech authentication and JWT-protected APIs
- PostgreSQL models and versioned initial migration for organizations, staff, tenants, and encrypted credentials
- Microsoft Entra admin-consent URL and callback flow with Graph organization verification
- React + TypeScript + Vite frontend using the `Templates/PharmaPMS/ui-template` visual system
- Docker Compose services for the API, frontend, PostgreSQL, Redis, and worker placeholder

The SPA now includes local sign-in and loads the authenticated tenant list from the API. Tenant posture metrics remain placeholders until Phase 1 Graph polling is implemented. See [`docs/azure-ad-setup.md`](docs/azure-ad-setup.md) for Entra configuration.

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
cp .env.example .env
# Set JWT_SECRET and CREDENTIAL_ENCRYPTION_KEY in .env
docker compose up --build
```

- Frontend: http://localhost:5173
- API docs: http://localhost:8000/docs
- API health: http://localhost:8000/api/health

The Compose database credentials are development-only defaults. Use environment-backed secrets before any shared or production deployment.
