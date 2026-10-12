-- Milestone 4: administrator console, audit log, analyst feedback (continuous learning),
-- and the extra columns the alert service writes through.
-- Depends on 001 - 005.

-- Editable display name on the user profile.
alter table public.profiles add column if not exists display_name text;

-- The alert service persists which engines agreed on the verdict.
alter table public.alerts add column if not exists agreement text;

-- Whether the ML detector applied to the file (it only scores PE files); used to measure its accuracy fairly.
alter table public.detections add column if not exists ml_applicable boolean;

-- ---------------------------------------------------------------------------
-- audit_log: security-relevant platform activity (sign-ins, scans, role changes, ...)
-- ---------------------------------------------------------------------------
create table if not exists public.audit_log (
  id          uuid primary key default gen_random_uuid(),
  actor       text,
  role        text,
  action      text not null,
  target      text,
  detail      text,
  status      text not null default 'success' check (status in ('success', 'failure', 'denied')),
  ip          text,
  created_at  timestamptz not null default now()
);

create index if not exists audit_log_created_at_idx on public.audit_log(created_at desc);
create index if not exists audit_log_action_idx on public.audit_log(action);

alter table public.audit_log enable row level security;

create policy "administrators can read the audit log"
  on public.audit_log for select to authenticated
  using (
    exists (
      select 1 from public.profiles p join public.roles r on r.id = p.role_id
      where p.id = auth.uid() and r.name = 'Administrator'
    )
  );

-- ---------------------------------------------------------------------------
-- analyst_feedback: ground-truth corrections used to track model drift and retrain
-- ---------------------------------------------------------------------------
create table if not exists public.analyst_feedback (
  id              uuid primary key default gen_random_uuid(),
  sha256          text not null unique,
  filename        text,
  label           text not null check (label in ('malicious', 'benign')),
  model_verdict   text,
  model_score     int,
  ml_probability  double precision,
  ml_applicable   boolean,
  agrees          boolean not null default true,
  note            text,
  actor           text,
  created_at      timestamptz not null default now()
);

create index if not exists analyst_feedback_created_at_idx on public.analyst_feedback(created_at desc);

alter table public.analyst_feedback enable row level security;

create policy "feedback readable by authenticated users"
  on public.analyst_feedback for select to authenticated using (true);
