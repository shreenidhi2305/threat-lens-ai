-- Milestone 3: in-app notification feed + generated-report history.
-- Depends on 001_rbac_schema.sql, 002_samples_and_analysis.sql, 003_detections_and_alerts.sql.

-- ---------------------------------------------------------------------------
-- notifications: mirrors alerts / status changes / incidents / reports as a
-- readable, dismissible feed for the console's notification bell.
-- ---------------------------------------------------------------------------
create table if not exists public.notifications (
  id            uuid primary key default gen_random_uuid(),
  category      text not null check (category in ('alert', 'status', 'incident', 'report')),
  severity      text not null check (severity in ('info', 'low', 'medium', 'high', 'critical')),
  title         text not null,
  message       text not null,
  alert_id      uuid references public.alerts(id) on delete set null,
  incident_id   uuid references public.incidents(id) on delete set null,
  report_id     uuid,
  read          boolean not null default false,
  email_sent    boolean not null default false,
  created_at    timestamptz not null default now()
);

create index if not exists notifications_created_at_idx on public.notifications(created_at desc);
create index if not exists notifications_read_idx on public.notifications(read);

alter table public.notifications enable row level security;

create policy "notifications readable by authenticated users"
  on public.notifications for select to authenticated using (true);

create policy "soc and analysts manage notifications"
  on public.notifications for update to authenticated
  using (
    exists (
      select 1 from public.profiles p join public.roles r on r.id = p.role_id
      where p.id = auth.uid()
        and r.name in ('Security Analyst', 'SOC Team Member', 'Administrator')
    )
  );

-- ---------------------------------------------------------------------------
-- reports: history of generated report documents (per-sample investigation
-- reports and aggregate threat-summary / operational reports).
-- ---------------------------------------------------------------------------
create table if not exists public.reports (
  id             uuid primary key default gen_random_uuid(),
  report_type    text not null check (report_type in ('investigation', 'summary')),
  format         text not null default 'pdf',
  title          text not null,
  created_by     uuid references public.profiles(id) on delete set null,
  sha256         text,
  filename       text,
  verdict_label  text,
  risk_score     int,
  window         text,
  created_at     timestamptz not null default now()
);

create index if not exists reports_created_at_idx on public.reports(created_at desc);
create index if not exists reports_report_type_idx on public.reports(report_type);

alter table public.reports enable row level security;

create policy "reports readable by authenticated users"
  on public.reports for select to authenticated using (true);

create policy "authenticated users can log generated reports"
  on public.reports for insert to authenticated with check (true);
