-- Milestone 3: persistent threat prediction reports

create table if not exists public.reports (
  id                uuid primary key default gen_random_uuid(),
  sample_id         uuid,
  filename          text,
  status            text not null default 'completed',
  file_hash         text,
  predicted_class   text,
  confidence        double precision,
  is_malicious      boolean,
  risk_score        int check (risk_score between 0 and 100),
  severity          text,
  static_indicators jsonb not null default '[]'::jsonb,
  recommendation    text,
  analysis_data     jsonb,
  created_at        timestamptz not null default now()
);

create index if not exists reports_created_at_idx
  on public.reports(created_at desc);

create index if not exists reports_file_hash_idx
  on public.reports(file_hash);