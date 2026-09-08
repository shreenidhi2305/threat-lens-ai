-- Milestone 2: ML classification results, detection log, alerts, incidents.
-- Depends on 001_rbac_schema.sql and 002_samples_and_analysis.sql.

-- ---------------------------------------------------------------------------
-- ml_models: registry of trained model versions
-- ---------------------------------------------------------------------------
create table if not exists public.ml_models (
  id           uuid primary key default gen_random_uuid(),
  kind         text not null check (kind in ('detector', 'classifier')),
  version      text not null,
  model_type   text,
  metrics      jsonb not null default '{}'::jsonb,
  feature_count int,
  is_active     boolean not null default false,
  trained_at   timestamptz,
  created_at   timestamptz not null default now(),
  unique (kind, version)
);

-- ---------------------------------------------------------------------------
-- detections: one row per analysed file (the detection log)
-- ---------------------------------------------------------------------------
create table if not exists public.detections (
  id              uuid primary key default gen_random_uuid(),
  sample_id       uuid references public.samples(id) on delete set null,
  sha256          text not null,
  filename        text,
  verdict_label   text not null check (verdict_label in ('malicious', 'suspicious', 'benign')),
  score           int not null check (score between 0 and 100),
  level           text not null check (level in ('low', 'medium', 'high')),
  family          text,
  ml_probability  double precision,
  ml_category     text,
  yara_rule_count int not null default 0,
  signature       text,
  model_version   text,
  agreement       text check (agreement in ('agree', 'ml-only', 'rules-only', 'conflict')),
  analyst_id      uuid references public.profiles(id) on delete set null,
  created_at      timestamptz not null default now()
);

create index if not exists detections_created_at_idx on public.detections(created_at desc);
create index if not exists detections_level_idx on public.detections(level);
create index if not exists detections_sha256_idx on public.detections(sha256);

-- ---------------------------------------------------------------------------
-- incidents: an investigation grouping one or more alerts
-- ---------------------------------------------------------------------------
create table if not exists public.incidents (
  id          uuid primary key default gen_random_uuid(),
  title       text not null,
  status      text not null default 'open' check (status in ('open', 'contained', 'closed')),
  severity    text not null check (severity in ('high', 'critical')),
  opened_by   uuid references public.profiles(id) on delete set null,
  created_at  timestamptz not null default now(),
  closed_at   timestamptz
);

-- ---------------------------------------------------------------------------
-- alerts: raised when a detection crosses the alerting threshold
-- ---------------------------------------------------------------------------
create table if not exists public.alerts (
  id             uuid primary key default gen_random_uuid(),
  detection_id   uuid references public.detections(id) on delete cascade,
  incident_id    uuid references public.incidents(id) on delete set null,
  severity       text not null check (severity in ('high', 'critical')),
  status         text not null default 'open' check (status in ('open', 'acknowledged', 'resolved')),
  title          text not null,
  sample_sha256  text not null,
  sample_name    text,
  verdict_label  text,
  verdict_score  int,
  category       text,
  notified       boolean not null default false,
  note           text,
  created_by     uuid references public.profiles(id) on delete set null,
  created_at     timestamptz not null default now(),
  resolved_at    timestamptz
);

create index if not exists alerts_status_idx on public.alerts(status);
create index if not exists alerts_created_at_idx on public.alerts(created_at desc);

-- ---------------------------------------------------------------------------
-- RLS
-- ---------------------------------------------------------------------------
alter table public.ml_models enable row level security;
alter table public.detections enable row level security;
alter table public.incidents enable row level security;
alter table public.alerts enable row level security;

create policy "detections readable by authenticated users"
  on public.detections for select to authenticated using (true);
create policy "alerts readable by authenticated users"
  on public.alerts for select to authenticated using (true);
create policy "incidents readable by authenticated users"
  on public.incidents for select to authenticated using (true);
create policy "ml_models readable by authenticated users"
  on public.ml_models for select to authenticated using (true);

create policy "soc and analysts manage alerts"
  on public.alerts for update to authenticated
  using (
    exists (
      select 1 from public.profiles p join public.roles r on r.id = p.role_id
      where p.id = auth.uid()
        and r.name in ('Security Analyst', 'SOC Team Member', 'Administrator')
    )
  );

create policy "soc and analysts manage incidents"
  on public.incidents for all to authenticated
  using (
    exists (
      select 1 from public.profiles p join public.roles r on r.id = p.role_id
      where p.id = auth.uid()
        and r.name in ('Security Analyst', 'SOC Team Member', 'Administrator')
    )
  );
