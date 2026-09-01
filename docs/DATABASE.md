# Database Schema

PostgreSQL, managed via Supabase. Migrations live in `supabase/migrations/`
and are applied in filename order. Seed data in `supabase/seed/`.

## Milestone 1 (implemented)

### `001_rbac_schema.sql` — authentication & RBAC

| Table | Purpose | Key columns |
|---|---|---|
| `roles` | The 4 fixed roles from the spec | `id`, `name` (check-constrained), `description` |
| `profiles` | One row per Supabase Auth user, holds their role | `id` → `auth.users`, `email`, `role_id` → `roles` |

- Trigger `on_auth_user_created` auto-creates a `profiles` row (default role
  *Security Analyst*) on signup.
- RLS: users read their own profile; Administrators read/update all profiles.

### `002_samples_and_analysis.sql` — file upload & static analysis

| Table | Purpose | Key columns |
|---|---|---|
| `samples` | One row per uploaded file, deduped by `sha256` | `sha256` (unique), `filename`, `size_bytes`, `storage_path`, `uploaded_by` |
| `analysis_results` | One static-analysis run per sample | `sample_id`, `hashes`/`metadata`/`yara_matches`/… (`jsonb`), `risk_score`, `risk_level`, `classification` |

- Uploaded file bytes go to **Supabase Storage** (bucket `samples`); only the
  object path is stored in `samples.storage_path`.
- RLS: any authenticated user can read; Security Analyst / Administrator /
  Researcher can insert.

## Later milestones (planned, not yet created)

| Milestone | Tables |
|---|---|
| M2 – threat monitoring | `detections` (detection log), `threats`, `incidents`, `alerts` |
| M2 – classification | `classification_runs`, `malware_families` |
| M3 – analytics | materialised views / rollups over `detections` + `analysis_results` |

MongoDB (per the architecture diagram) is a candidate for high-volume
detection logs in M2; for M1 everything is PostgreSQL.

## Local development

No database is required for local dev or the demo. When Supabase env vars are
unset the backend uses a local dev login and stores uploads under
`backend/var/uploads/`. Set `SUPABASE_URL` + `SUPABASE_SERVICE_KEY` to switch
to the real backend.
