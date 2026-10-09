# ThreatLens AI: Malware Classification & Threat Detection System

ThreatLens AI is a full-stack cybersecurity platform for static malware analysis, machine-learning classification, behavioral analysis, threat monitoring, alerting, reporting and administration. Files are analysed, never executed.

## Milestone status

**Milestone 1 (Weeks 1-2): complete.** Authentication and RBAC, file upload, and the static-analysis pipeline: hashing, file-type ID, metadata, PE header and import/API analysis, string extraction, YARA, signature matching, IOC extraction, risk scoring.

**Milestone 2 (Weeks 3-4): complete.** Trained LightGBM detector and family classifier, a fusion engine that blends the ML score with the rule engine, detection logging, the live Threat Monitor, and alert generation.

**Milestone 3 (Weeks 5-6): complete.** MITRE ATT&CK behavioral analysis (static inference only), VirusTotal threat-intel lookups, threat-prediction reports, the analytics dashboard, in-app notifications, and the investigation / summary / monitoring PDF reports.

**Milestone 4 (Weeks 7-8): in progress.**
- Done: workflow validation (`docs/TEST_PLAN_AND_VALIDATION.md`), UI responsiveness and performance work, the full **Administrator console** (users and roles, settings and security policies, integrations, activity log, ML model management), API-gateway **rate limiting**, **SIEM/SOAR** webhook integration, an analyst **feedback loop** with model-drift detection, the **Researcher workspace** (datasets and malware families), incident tracking, persistent alerts/incidents, production start-up safety checks, API docs and a Postman collection, and an end-to-end demo driver.
- Remaining: production container images and the cloud deployment.

## Quick start (local, no database needed)

```bash
# terminal 1: API
cd backend && pip install -r requirements.txt
python -m uvicorn app.main:app --port 8000
# terminal 2: UI
npm --prefix frontend install && npm --prefix frontend run dev
```

Open http://localhost:5173 and sign in with any password as:

| Email | Role |
|---|---|
| `analyst@local` | Security Analyst |
| `soc@local` | SOC Team Member |
| `admin@local` | Administrator |
| `researcher@local` | Researcher |

With no Supabase variables set, the backend uses the local dev login, in-memory data and local file storage (`backend/var/uploads/`). Run the tests with `cd backend && python -m pytest`.

To see every feature populated, start both servers and run the demo driver:

```bash
python demo/m4_end_to_end_demo.py        # add --skip-real when offline
```

See `demo/DEMO_SCRIPT.md` for the screen-share walkthrough.

## Roles

| Role | Can |
|---|---|
| Security Analyst | Upload and scan files; classification, behavior and investigation reports; threat monitor; alerts and incidents; confirm or correct verdicts; research workspace |
| SOC Team Member | Monitor detections and active threats; alerts, history and incidents; operational reports; analytics |
| Administrator | Manage users and roles; configure settings and security policies; manage integrations and ML models; monitor platform activity; everything above |
| Researcher | Upload samples; malware datasets and family analysis; behavior analysis; export research reports and datasets; historical analytics |

Full matrix and enforcement points: `docs/RBAC.md`.

## Architecture

A modular monorepo:

- **frontend/**: React + Vite + TypeScript + Tailwind (lazy-loaded, role-guarded pages)
- **backend/**: FastAPI service, one module per domain (`backend/app/modules/`)
- **supabase/**: PostgreSQL migrations and seed data
- **demo/**: sample files and the demo driver
- **docs/**: architecture, RBAC, test plan, OpenAPI spec and Postman collection

How the architecture diagram maps to code: `docs/ARCHITECTURE.md`.

### Backend modules

| Module | Purpose |
|---|---|
| `auth`, `users` | JWT sign-in, profiles, role lookup |
| `file_analysis` | Upload, storage, hashing, metadata, PE, strings, imports, IOCs, YARA, signatures, risk |
| `behavioral_analysis` | ATT&CK behavior inference from static signals |
| `malware_classification`, `pipeline` | ML inference and the per-scan orchestration (verdict fusion) |
| `threat_monitoring` | Detection log, dashboards data, monitoring report |
| `alerts`, `notifications` | Alerts, incidents, email, in-app feed, SIEM forwarding |
| `reports`, `analytics` | PDF reports and history, analytics rollups |
| `threat_intel` | VirusTotal hash lookups |
| `model_management` | Analyst feedback, live accuracy, drift detection |
| `research` | Datasets and malware-family analysis |
| `admin`, `audit`, `integrations` | Administrator console, activity log, SIEM/SOAR webhook |

Core concerns in `backend/app/core/`: configuration, JWT security, rate limiting, request metrics, runtime-editable settings, start-up safety checks.

> Security baseline: uploaded files are untrusted and never executed. Behavioral analysis is inferred from static artifacts (imports, PE structure, YARA, strings); there is no sandbox or dynamic execution.

## Technology stack

- **Frontend:** React, Vite, TypeScript, Tailwind CSS, React Router, Axios
- **Backend:** Python, FastAPI, Pydantic, JWT (python-jose)
- **Data and storage:** Supabase (PostgreSQL + Storage), with an in-memory fallback for local development
- **ML:** LightGBM, scikit-learn, pandas, NumPy; features from `pefile` and our own extractor
- **Analysis:** YARA (`yara-python`), signature matching, MITRE ATT&CK mapping
- **Threat intel and integrations:** VirusTotal API, SMTP, SIEM/SOAR webhook
- **Reports:** ReportLab
- **DevOps:** Docker, Docker Compose, GitHub

## Configuration

Copy `.env.example` to `.env`. Every variable is documented there. The important ones:

| Variable | Purpose |
|---|---|
| `APP_ENV` | `production` refuses to start with unsafe configuration |
| `JWT_SECRET_KEY` | Signing key for tokens; generate a long random value |
| `SUPABASE_URL`, `SUPABASE_SERVICE_KEY` | Identity provider and database; unset means local dev mode |
| `CORS_ALLOW_ORIGINS` | Frontend origin(s) allowed to call the API |
| `RATE_LIMIT_PER_MINUTE`, `LOGIN_RATE_LIMIT_PER_MINUTE` | API gateway limits (also editable in the Admin Console) |
| `VIRUSTOTAL_API_KEY`, `SMTP_*`, `SIEM_WEBHOOK_*` | Optional integrations |

Database setup: apply `supabase/migrations/001` to `006` in order (`supabase/README.md`).

## API

- Interactive docs: http://localhost:8000/docs
- OpenAPI spec: `docs/openapi.json`; Postman collection: `docs/postman/ThreatLens.postman_collection.json`
- Regenerate both: `cd backend && PYTHONPATH=. python scripts/export_api_docs.py`

## Docker

```bash
cp .env.example .env
docker compose up --build
```

- Frontend: `http://localhost:5173`
- Backend: `http://localhost:8000`

## Contribution workflow

1. Create a branch
2. Make focused changes
3. Run the checks: `cd backend && python -m pytest` and `cd frontend && npm run build`
4. Open or update a PR with a clear summary
