# Architecture

How the system in the specification's architecture diagram maps onto this codebase.

```
Users (Analyst / SOC / Admin / Researcher)
        |
Web dashboard (React)  Dashboard · Reports · Alerts · Analytics · Research · Admin Console
        |  JWT
API gateway (FastAPI middleware)  auth · routing · rate limiting · validation · metrics
        |
Backend services
  File -> Analysis -> Behavioral -> ML Prediction -> Classification -> Alert
        |                                                    |
   ML engine (features · models · registry · feedback)   External integrations
        |                                                (VirusTotal · SMTP · SIEM/SOAR)
Data layer (Supabase PostgreSQL + Storage; in-memory fallback for local dev)
```

## Diagram component to code

| Diagram box | Implementation |
|---|---|
| Web dashboard | `frontend/src` (React, Vite, TypeScript, Tailwind); pages are lazy-loaded and role-guarded |
| Authentication (JWT) | `app/core/security.py`, `app/modules/auth`; Supabase Auth in production, dev login locally |
| Request routing | `app/api/v1/router.py` (one router per module) |
| **Rate limiting** | `app/core/rate_limit.py`: sliding window per user (or IP), stricter budget for sign-ins, `429` + `Retry-After` |
| Security and validation | `require_roles` on every route, upload size cap and chunked read, Pydantic request models, startup safety checks (`app/core/startup_checks.py`) |
| File Service | `app/modules/file_analysis/{router,storage}.py`: upload, hashing, validation, Supabase Storage or local disk |
| Analysis Service | `app/modules/file_analysis/analyzers/`: metadata, PE headers, strings, imports, IOCs, YARA, signatures, risk |
| Behavior parsing | `app/modules/behavioral_analysis`: MITRE ATT&CK inference from static signals only (nothing is executed) |
| ML Prediction Service | `app/ml/inference`, `app/ml/features` (407-feature vector), LightGBM detector + classifier |
| Classification Service | `app/modules/pipeline/fusion.py`: fuses ML and rules into one verdict with an `agreement` flag |
| Alert Service | `app/modules/alerts`: threat alerts, email, dashboard alerts, incident creation and tracking |
| **Notification flow** | `app/modules/notifications` (in-app feed), `alerts/notifications.py` (SMTP) |
| VirusTotal API / Threat-intel feeds | `app/modules/threat_intel` (hash lookups only; the file is never uploaded) |
| Email / SMTP | `app/modules/alerts/notifications.py` |
| **SIEM / SOAR integration** | `app/modules/integrations/siem.py`: alerts and incidents forwarded as HMAC-signed JSON webhooks |
| ML Engine: feature engineering, trained models, model manager | `app/ml/features`, `app/ml/models/{artifacts,registry}.py` |
| ML Engine: evaluation and validation | offline metrics in the model sidecars; **live accuracy** from analyst feedback (`app/modules/model_management`) |
| ML Engine: continuous learning and updates | analyst feedback loop, drift detection, labelled export, offline retrain, hot reload from the Admin Console |
| Data layer: PostgreSQL | Supabase migrations `supabase/migrations/001` to `006`; users, detections, alerts, incidents, reports, notifications, audit log, feedback |
| Data layer: file storage and model storage | Supabase Storage bucket (or `backend/var/uploads`), `app/ml/models/artifacts` |
| Platform monitoring | `app/core/metrics.py`, `app/modules/admin` |

## Scan pipeline

`app/modules/pipeline/service.py` runs the same stages for every upload, in order:
static analysis, behavioral analysis, ML inference, verdict fusion, threat-intel lookup,
persisted report, detection log, alert. Static rules and the ML model are both mandatory
(no fallback routing); the ML model only scores PE files and reports `applicable: false`
otherwise.

## Persistence

Every store follows one pattern: write through to Supabase when it is configured, keep an
in-memory copy as the local-dev store and as the fallback if the database is unreachable.
Alerts and incidents are reloaded from the database on first use after a restart.

| Data | Table |
|---|---|
| Users and roles | `profiles`, `roles` |
| Detection log | `detections` |
| Alerts, incidents | `alerts`, `incidents` |
| Notifications | `notifications` |
| Report history, per-scan reports | `reports`, `analysis_reports` |
| Audit log | `audit_log` |
| Analyst feedback | `analyst_feedback` |

Apply the migrations in order (`supabase/README.md`). `006` is needed for the admin
console features; the app degrades gracefully (in-memory) if a table is missing.

## Deliberate departures from the diagram

- **MongoDB and Redis are not used.** The spec's tech-stack list offers "PostgreSQL / MongoDB",
  and PostgreSQL covers it: full analysis results are stored as `jsonb`
  (`analysis_reports.analysis_data`). The diagram's Redis cache/session role is filled by
  stateless JWTs and an in-process rate limiter and cache. This keeps the deployment to one
  API process plus Supabase. To run several API workers, swap `SlidingWindowLimiter` and the
  in-memory alert/notification caches for Redis-backed ones; the interfaces are small.
- **Retraining is an offline step.** The platform measures live accuracy, flags drift and
  exports the labelled set; retraining itself is `python -m app.ml.training.train`, followed
  by a hot reload (no restart) from the Admin Console.
- **Static analysis only.** Files are never executed; behavior is inferred from static
  signals and mapped to ATT&CK.
