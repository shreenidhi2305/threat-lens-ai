# Milestone 1 — Project Initialization, Design & Core Setup

Weeks 1–2. Status of each deliverable, plus the system/UI design.

## Deliverable status

| Spec item | Status | Where |
|---|---|---|
| Project objectives & cybersecurity workflows | ✅ | `README.md`, this doc |
| System architecture | ✅ | Architecture diagram; monorepo (`frontend/`, `backend/`, `supabase/`) |
| Database schema | ✅ | `docs/DATABASE.md`, `supabase/migrations/` |
| UI wireframes & workflow planning | ✅ | "UI screens" below; implemented in `frontend/src/pages/` |
| Frontend & backend environment setup | ✅ | Vite + FastAPI, `docker-compose.yml` |
| Authentication | ✅ | Supabase Auth + JWT; local dev login fallback |
| Role-based access system | ✅ | `require_roles()` on every protected route; RLS in SQL |
| File upload workflow | ✅ | `POST /api/v1/files/upload` (multipart) → storage → analysis |
| Static analysis: hashing | ✅ | `analyzers/hashing.py` — MD5 / SHA-1 / SHA-256 |
| Static analysis: metadata extraction | ✅ | `analyzers/metadata.py` — type ID, entropy, extension mismatch |
| Static analysis: signature matching | ✅ | `analyzers/signature_matching.py` — SHA-256 vs `data/signatures.json` |
| Static analysis: YARA-based detection | ✅ | `analyzers/yara.py` + `rules/threatlens.yar` |
| Suspicious-indicators report + risk score | ✅ | `analyzers/risk.py` (rule-based, 0–100) |
| Embedded URL / IP detection | ✅ | `analyzers/network_indicators.py` |

Deferred by design (later milestones): ML malware classifier (M2), detection
logging & threat dashboards (M2), alert generation (M2), behavioural analysis &
analytics dashboards (M3), Docker/cloud deploy (M4). PE-header / import-table
analyzers are stubbed for a later pass.

## Architecture

```
Users ─▶ React SPA ─▶  FastAPI (API Gateway: JWT auth, RBAC, validation)
                         │
                         ├─ File Service      : upload, storage, hashing
                         ├─ Analysis Service  : static analysis pipeline
                         ├─ (M2) Classification / Alert / Threat services
                         │
                         └─ Data layer: PostgreSQL (Supabase) + Supabase Storage
                                        (+ MongoDB / Redis planned for M2)
```

Backend is domain-modular: `backend/app/modules/<domain>/{router,service,schemas}.py`.

## RBAC matrix (enforced)

| Endpoint | Security Analyst | SOC Team Member | Administrator | Researcher |
|---|:-:|:-:|:-:|:-:|
| `POST /files/upload`, `/files/scan` | ✅ | — | ✅ | ✅ |
| `POST /malware/classify` | ✅ | — | ✅ | ✅ |
| `GET /threats/snapshot` | ✅ | ✅ | ✅ | — |
| `GET /alerts/` | ✅ | ✅ | ✅ | — |
| `GET /analytics/summary` | ✅ | ✅ | ✅ | ✅ |
| `GET /reports/{id}` | ✅ | ✅ | ✅ | ✅ |
| `GET /users/me` | any authenticated user | | | |

## Static analysis pipeline

`POST /files/upload` (multipart) → store bytes → `analyze_static_file()`:

1. **Hashing** — MD5, SHA-1, SHA-256
2. **Metadata** — magic-byte file type, MIME, size, Shannon entropy (packed
   heuristic), printable ratio, declared-extension-vs-content mismatch
3. **Signature matching** — SHA-256 against the local signature set
4. **YARA** — compiled rules from `rules/*.yar`
5. **Network IOCs** — embedded URLs, public IPs, domains
6. **Risk assessment** — rule-based aggregation of the above into a 0–100
   score, `low`/`medium`/`high` level, a classification, and a recommended
   action

Response = the "static analysis report" from the spec: file metadata report,
suspicious indicators report, signature matches, risk score, and the feature
inputs the M2 classifier will consume.

## UI screens (wireframe / workflow plan)

| Route | Screen | Milestone 1 scope |
|---|---|---|
| `/login` | Login | Email + password form → `POST /auth/login`, stores JWT. Shows the dev-login role hints locally. |
| `/dashboard` | Dashboard | Current user + role, quick links, "analyze a file" call-to-action. |
| `/upload` | Submit File | File picker / drag-drop → `POST /files/upload` → redirect to the report. |
| `/analysis` | Analysis Report | Full static-analysis result: risk gauge + classification, hashes, metadata, YARA matches, signature match, network IOCs, suspicious-indicator list, string sample. |
| `/profile` | Profile | `GET /users/me`. |
| `/malware-report`, `/threat-monitoring`, `/alerts`, `/analytics` | — | Placeholders labelled "Milestone 2". |

Nav items are filtered by the signed-in user's role. Unauthenticated access to
any protected route redirects to `/login`.
