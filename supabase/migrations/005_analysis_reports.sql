-- Milestone 3: persisted per-scan threat-prediction reports.
-- Distinct from `public.reports` (004_notifications_and_reports.sql), which is
-- the audit trail of explicitly-downloaded investigation/summary PDFs. This
-- table stores one row per pipeline scan, with the full analysis payload, so
-- any past scan's report can be revisited and re-rendered without the client
-- holding state.

create table if not exists public.analysis_reports (
  id                uuid primary key default gen_random_uuid(),
  sample_id         text,
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

create index if not exists analysis_reports_created_at_idx on public.analysis_reports(created_at desc);
create index if not exists analysis_reports_file_hash_idx on public.analysis_reports(file_hash);

alter table public.analysis_reports enable row level security;

create policy "analysis reports readable by authenticated users"
  on public.analysis_reports for select to authenticated using (true);

create policy "authenticated users can log analysis reports"
  on public.analysis_reports for insert to authenticated with check (true);
