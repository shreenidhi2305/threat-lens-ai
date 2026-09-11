-- Milestone 1: file upload + static analysis persistence.
-- Depends on 001_rbac_schema.sql (profiles, roles).

-- ---------------------------------------------------------------------------
-- samples: one row per uploaded file (deduplicated by sha256)
-- ---------------------------------------------------------------------------
create table if not exists public.samples (
  id            uuid primary key default gen_random_uuid(),
  sha256        text not null unique,
  md5           text,
  sha1          text,
  filename      text not null,
  size_bytes    bigint not null,
  mime_type     text,
  file_type     text,
  storage_path  text not null,               -- object path in the samples bucket
  uploaded_by   uuid references public.profiles(id) on delete set null,
  created_at    timestamptz not null default now()
);

create index if not exists samples_uploaded_by_idx on public.samples(uploaded_by);
create index if not exists samples_created_at_idx on public.samples(created_at desc);

-- ---------------------------------------------------------------------------
-- analysis_results: one row per static-analysis run for a sample
-- ---------------------------------------------------------------------------
create table if not exists public.analysis_results (
  id                    uuid primary key default gen_random_uuid(),
  sample_id             uuid not null references public.samples(id) on delete cascade,
  hashes                jsonb not null default '{}'::jsonb,
  metadata              jsonb not null default '{}'::jsonb,
  signature_match       jsonb not null default '{}'::jsonb,
  yara_matches          jsonb not null default '[]'::jsonb,
  network_indicators    jsonb not null default '{}'::jsonb,
  suspicious_indicators jsonb not null default '[]'::jsonb,
  risk_score            int not null default 0 check (risk_score between 0 and 100),
  risk_level            text not null default 'low' check (risk_level in ('low', 'medium', 'high')),
  classification        text,
  analyzed_by           uuid references public.profiles(id) on delete set null,
  created_at            timestamptz not null default now()
);

create index if not exists analysis_results_sample_id_idx on public.analysis_results(sample_id);
create index if not exists analysis_results_risk_level_idx on public.analysis_results(risk_level);
create index if not exists analysis_results_created_at_idx on public.analysis_results(created_at desc);

-- ---------------------------------------------------------------------------
-- RLS: authenticated users can read; Researchers/Analysts/Admins can insert.
-- (Detection-log / alert tables come in Milestone 2.)
-- ---------------------------------------------------------------------------
alter table public.samples enable row level security;
alter table public.analysis_results enable row level security;

create policy "samples readable by authenticated users"
  on public.samples for select to authenticated using (true);

create policy "analysis readable by authenticated users"
  on public.analysis_results for select to authenticated using (true);

create policy "scanners can insert samples"
  on public.samples for insert to authenticated
  with check (
    exists (
      select 1 from public.profiles p
      join public.roles r on r.id = p.role_id
      where p.id = auth.uid()
        and r.name in ('Security Analyst', 'Administrator', 'Researcher')
    )
  );

create policy "scanners can insert analysis results"
  on public.analysis_results for insert to authenticated
  with check (
    exists (
      select 1 from public.profiles p
      join public.roles r on r.id = p.role_id
      where p.id = auth.uid()
        and r.name in ('Security Analyst', 'Administrator', 'Researcher')
    )
  );
