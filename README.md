# ThreatLens AI: Malware Classification & Threat Detection System

ThreatLens AI is a full-stack cybersecurity platform for static malware analysis, machine-learning-based classification, threat monitoring, alerting, and reporting.

## Architecture

This repository is organized as a modular monorepo:

- **frontend/**: React + Vite + TypeScript + Tailwind UI
- **backend/**: FastAPI service with domain-oriented modules
- **supabase/**: migration/seed assets for Supabase PostgreSQL
- **docs/**: additional project documentation

## Technology Stack

- **Frontend**: React, Vite, TypeScript, Tailwind CSS, React Router, Axios
- **Backend**: FastAPI, Pydantic, SQLAlchemy, JWT auth/RBAC scaffolding
- **Data/Storage**: Supabase PostgreSQL + Supabase Storage
- **ML**: scikit-learn, TensorFlow, Pandas, NumPy (scaffolded)
- **Malware Analysis**: static-analysis analyzer interfaces (hashing, metadata, PE, strings, imports, network IOCs, YARA)
- **Threat Intel**: VirusTotal API key configuration scaffold
- **DevOps**: Docker, Docker Compose, GitHub

## Repository Structure

```text
threatlens-ai/
├── frontend/
├── backend/
├── supabase/
├── docs/
├── docker-compose.yml
├── .env.example
└── README.md
```

## Backend Highlights

- API prefix: `/api/v1`
- Domain modules in `backend/app/modules/`:
  - auth
  - users
  - file_analysis
  - malware_classification
  - threat_monitoring
  - alerts
  - analytics
  - reports
- Core app concerns in `backend/app/core/`:
  - `config.py`, `security.py`, `dependencies.py`, `logging.py`
- Supabase integration layer in `backend/app/db/supabase.py`
- ML scaffolding in `backend/app/ml/`

> Security baseline: uploaded files are treated as untrusted input; only static-analysis scaffolding is included. No malware execution logic is implemented.

## Frontend Highlights

- Route scaffolding for:
  - Login
  - Dashboard
  - File Upload
  - File Analysis
  - Malware Report
  - Threat Monitoring
  - Alerts
  - Analytics
  - Profile
- Centralized API client at `frontend/src/services/apiClient.ts`

## Local Development

### Prerequisites

- Node.js 20+
- Python 3.11+

### Setup

1. Copy env template:

```bash
cp .env.example .env
```

2. Frontend:

```bash
cd frontend
npm install
npm run dev
```

3. Backend:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Environment Variables

Define these in `.env`:

- `SUPABASE_URL`
- `SUPABASE_SERVICE_KEY`
- `SUPABASE_DB_URL`
- `SUPABASE_STORAGE_BUCKET`
- `JWT_SECRET_KEY`
- `JWT_ALGORITHM`
- `JWT_ACCESS_TOKEN_EXPIRE_MINUTES`
- `VIRUSTOTAL_API_KEY`
- `VITE_API_BASE_URL`

## Supabase Configuration

- Use Supabase PostgreSQL for relational entities (users, metadata, analysis results, threats, alerts, reports).
- Use Supabase Storage for uploaded malware samples.
- Keep Supabase calls within the dedicated DB/integration layer.

## Docker

Run the frontend and backend containers:

```bash
docker compose up --build
```

- Frontend: `http://localhost:5173`
- Backend: `http://localhost:8000`

## Contribution Workflow

1. Create a branch
2. Make focused changes
3. Run relevant checks (build/tests)
4. Open/update PR with clear summary
