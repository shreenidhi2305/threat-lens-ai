# ThreatLens AI — Milestone 1 Progress Report

**Project:** ThreatLens AI — Malware Classification & Threat Detection System
**Milestone:** 1 of 4 — Project Initialization, Design Process & Core Setup (Weeks 1–2)
**Status:** Complete
**Repository:** https://github.com/shreenidhi2305/threat-lens-ai
**Date:** _<fill in>_
**Team:** _<names / roles>_

---

## 1. Summary

Milestone 1 is complete. The team has a running full-stack platform: a React
analyst console backed by a FastAPI service, JWT authentication with
role-based access control, a file-upload workflow, and a working static
malware-analysis pipeline (hashing, metadata and file-type identification,
signature matching, YARA rule matching, embedded-indicator extraction, and a
rule-based risk score). The database schema is designed and captured as SQL
migrations, and the UI screens and workflows are planned and implemented.

Uploaded files are analyzed statically and are never executed.

---

## 2. Milestone 1 evaluation criteria — status

| Criterion (from the project spec) | Status | Evidence |
|---|---|---|
| Project initialization and architecture setup completed | Done | Modular monorepo (`frontend/`, `backend/`, `supabase/`, `docs/`); `docker-compose.yml`; architecture documented in `docs/MILESTONE_1.md` |
| Authentication and file analysis workflows implemented | Done | JWT auth (`/api/v1/auth/login`), `POST /api/v1/files/upload`, static-analysis service |
| Static analysis — hashing, metadata extraction, YARA-based detection functional | Done | `backend/app/modules/file_analysis/analyzers/` — `hashing.py`, `metadata.py`, `yara.py` (21 rules), `signature_matching.py`, `network_indicators.py`, `risk.py` |
| System design and UI planning completed | Done | DB schema in `supabase/migrations/`, `docs/DATABASE.md`; UI screens + workflow plan in `docs/MILESTONE_1.md`, implemented in `frontend/src/pages/` |

---

## 3. What was delivered

### 3.1 Authentication & RBAC
- JWT-based login. Locally a development login is used; the production path
  authenticates against Supabase Auth and reads the user's role from the
  `profiles` table.
- Four roles from the spec — Security Analyst, SOC Team Member, Administrator,
  Researcher — enforced server-side on every protected route via a
  `require_roles()` dependency, and mirrored in the database with row-level
  security policies.
- The UI filters navigation and actions by role (e.g. a SOC Team Member cannot
  submit files for analysis).

### 3.2 Database schema (Supabase / PostgreSQL)
- `001_rbac_schema.sql` — `roles`, `profiles`, a new-user trigger, RLS policies.
- `002_samples_and_analysis.sql` — `samples` (deduplicated by SHA-256) and
  `analysis_results` (hashes, metadata, YARA matches, IOCs, risk score and
  classification as JSONB), with RLS.
- Tables for detection logs, threats, and alerts are designed for Milestone 2.

### 3.3 File upload & static analysis pipeline
`POST /api/v1/files/upload` accepts a file (multipart, 32 MB limit), stores it
(Supabase Storage in production, local disk in development), and runs:

1. **Hashing** — MD5, SHA-1, SHA-256.
2. **Metadata & file-type identification** — magic-byte type detection, MIME
   type, size, Shannon entropy (with a packed/encrypted heuristic), and a
   declared-extension vs. real-content mismatch check.
3. **Signature matching** — SHA-256 against a local signature set.
4. **YARA matching** — 21 rules grouped by MITRE ATT&CK tactic (delivery,
   defense evasion, persistence, credential access, injection, C2, impact,
   obfuscation), each returning matched strings and technique IDs.
5. **Embedded indicator extraction** — URLs, public IP addresses, domains.
6. **Risk assessment** — a deterministic 0–100 score, a `low`/`medium`/`high`
   level, a classification, and a recommended action, aggregated from all of
   the above. (This is a rule-based "Static Analysis Output"; the ML classifier
   is Milestone 2.)

The response is the static-analysis report from the spec: file metadata report,
suspicious-indicators report, signature matches, risk score, and the feature
inputs the Milestone 2 classifier will consume.

### 3.4 Frontend — analyst console
React + Vite + TypeScript + Tailwind. Implemented screens:

- **Sign in** — email/password.
- **Overview** — analysis history, risk stats, quick actions.
- **Submit File** — drag-and-drop upload.
- **Analysis Report** — verdict header (score, risk meter, classification,
  recommended action, filename, SHA-256), then suspicious indicators, signature
  and YARA detections, file metadata and hashes, network indicators, and
  extracted strings.
- **Threat Monitor / Alerts / Analytics** — populated from analysis history.
- **Profile** — account and role permissions.

### 3.5 Testing
- 39 automated backend tests (`pytest`) covering hashing vectors, metadata and
  file-type detection, YARA matching, IOC extraction, risk scoring, RBAC
  enforcement, and the upload endpoint. All passing.
- Verified end-to-end in the browser across desktop and mobile widths.

---

## 4. My contribution — _<your name>_

- **Assigned scope:** file hashing and metadata extraction.
  - `hashing.py` — MD5 / SHA-1 / SHA-256, with a chunked-stream variant for
    large uploads.
  - `metadata.py` — self-contained magic-byte file-type identification (no
    external `libmagic` dependency), size, Shannon entropy with a packed-file
    heuristic, printable-byte ratio, and the extension-vs-content mismatch flag.
  - Unit tests with NIST/RFC known-answer vectors.
- _<add anything else you personally did: integration, frontend, demo, etc.>_

---

## 5. How to run and verify

No database or cloud account is required for local review.

```bash
# backend
python -m uvicorn app.main:app --app-dir backend --port 8000
# frontend
npm --prefix frontend install && npm --prefix frontend run dev
```

Open http://localhost:5173 and sign in as `analyst@local` (any password).
Backend tests: `cd backend && python -m pytest`.

A short demo walkthrough and a set of harmless test samples are in `demo/`
(`demo/DEMO_SCRIPT.md`).

---

## 6. Next — Milestone 2 (Weeks 3–4)

Train the malware classification model, implement detection-logging workflows,
build the threat-monitoring dashboard with live data, and add alert generation.
The static-analysis outputs from Milestone 1 are the feature inputs for the
classifier.
