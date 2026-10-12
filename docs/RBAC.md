# Roles and permissions

ThreatLens enforces access **on the server** with `require_roles(...)` on every route
(`backend/app/core/dependencies.py`); the UI only mirrors it
(`frontend/src/lib/nav.ts`, which also guards the pages). Roles live in the Supabase
`roles` / `profiles` tables; locally the dev login picks a role from the email prefix
(`analyst@`, `soc@`, `admin@`, `researcher@`).

A user's role is read from their sign-in token, so a role change made by an administrator
applies the next time that person signs in.

## Matrix

| Capability (from the spec) | Analyst | SOC | Admin | Researcher | Where |
|---|:-:|:-:|:-:|:-:|---|
| Upload files / run static analysis | yes | - | yes | yes | `POST /files/upload`, `/files/scan`, Submit File |
| View classification and behavior reports | yes | yes (read-only) | yes | yes | Reports, Behavior Analysis |
| Threat monitoring dashboards | yes | yes | yes | - | `/threats/*`, Threat Monitor |
| Review alerts / alert history | yes | yes | yes | - | `/alerts/*`, Alerts |
| Track malware incidents | yes | yes | yes | - | `/alerts/incidents`, Alerts |
| In-app notifications | yes | yes | yes | - | `/notifications/*`, header bell |
| Confirm / correct verdicts (feedback) | yes | yes | yes | - | `POST /feedback`, Threat Monitor |
| Generate investigation reports | yes | yes* | yes | yes | `POST /reports/pdf` |
| Generate operational / monitoring reports | yes | yes | yes | - | `POST /reports/summary`, `/threats/report` |
| Threat summary report | yes | yes | yes | yes | `POST /reports/summary` |
| Analytics dashboards (historical threat analytics) | yes | yes | yes | yes | `/analytics/*` |
| Malware datasets and family analysis | yes | - | yes | yes | `/research/*`, Research |
| Export research reports / datasets | yes | - | yes | yes | CSV exports in Research |
| Export analyst-labelled training data | - | - | yes | yes | `GET /feedback/export.csv` |
| Manage users and roles | - | - | yes | - | `/admin/users`, Admin Console |
| Configure platform settings | - | - | yes | - | `/admin/settings` |
| Manage security policies | - | - | yes | - | rate limits, session lifetime, alert threshold, upload cap |
| Manage integrations and APIs | - | - | yes | - | `/admin/integrations` (VirusTotal, SMTP, SIEM/SOAR, Supabase) |
| Monitor platform activities | - | - | yes | - | `/admin/overview`, `/admin/audit` |
| Manage deployed ML models | - | - | yes | - | `/admin/models`, hot reload |
| Edit own profile | yes | yes | yes | yes | `PATCH /users/me` |

\* The endpoint renders a result the caller already holds; SOC members cannot scan files,
so in practice they report from the Threat Monitor and the Report Center.

## Administrator guard rails

- You cannot change **your own** role, and the **last administrator cannot be demoted**.
- Only an allow-list of settings is editable at runtime (alert threshold, API and login
  rate limits, session lifetime, upload cap). Secrets, credentials and infrastructure URLs
  stay in the server environment and are never exposed by the API.
- Every administrator action, sign-in (including failures), scan, report download, alert
  or incident change, role change, settings change and export is recorded in the audit log
  (`audit_log` table; in memory without Supabase).

## Verifying

`backend/tests/test_rbac.py`, `test_admin_console.py`, `test_feedback_and_research.py`
and `test_workflow_validation.py` assert the allow/deny behaviour above, including a
`403` for every non-admin on every `/admin` endpoint.
