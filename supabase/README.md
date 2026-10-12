# Supabase assets

- `migrations/`: SQL migrations for the Supabase PostgreSQL schema. Apply them **in order**.
- `seed/`: seed data (the four roles) for a fresh database.

| Migration | Adds |
|---|---|
| `001_rbac_schema.sql` | `roles`, `profiles`, sign-up trigger, admin policies |
| `002_samples_and_analysis.sql` | `samples` and static-analysis results |
| `003_detections_and_alerts.sql` | `detections`, `alerts`, `incidents`, `ml_models` |
| `004_notifications_and_reports.sql` | `notifications`, report history (`reports`) |
| `005_analysis_reports.sql` | `analysis_reports`: one persisted threat-prediction report per scan |
| `006_admin_audit_feedback.sql` | `audit_log`, `analyst_feedback`, `profiles.display_name`, `alerts.agreement`, `detections.ml_applicable` |

## Fresh database

1. Run `001` to `006` in the Supabase SQL editor.
2. Run `seed/001_seed_roles.sql`.
3. Create your first user in Supabase Auth, then make them an administrator:

```sql
update public.profiles
set role_id = (select id from public.roles where name = 'Administrator')
where email = 'you@example.com';
```

New users default to Security Analyst; after that, administrators manage roles from the
Admin Console.

## Backend settings

Set `SUPABASE_URL` and `SUPABASE_SERVICE_KEY` (the service key stays on the server only).
Without them the backend runs in local dev mode with in-memory data.
