-- Roles table
create table if not exists public.roles (
  id serial primary key,
  name text unique not null check (
    name in ('Security Analyst', 'SOC Team Member', 'Administrator', 'Researcher')
  ),
  description text
);

-- Profiles: one row per Supabase Auth user, holding their role
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  role_id int not null references public.roles(id),
  created_at timestamptz not null default now()
);

-- Keep profiles.email in sync automatically on signup
create or replace function public.handle_new_user()
returns trigger as $$
begin
  insert into public.profiles (id, email, role_id)
  values (new.id, new.email, (select id from public.roles where name = 'Security Analyst'));
  return new;
end;
$$ language plpgsql security definer;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- RLS
alter table public.roles enable row level security;
alter table public.profiles enable row level security;

create policy "roles are readable by authenticated users"
  on public.roles for select
  to authenticated
  using (true);

create policy "users can read their own profile"
  on public.profiles for select
  to authenticated
  using (auth.uid() = id);

create policy "admins can read all profiles"
  on public.profiles for select
  to authenticated
  using (
    exists (
      select 1 from public.profiles p
      join public.roles r on r.id = p.role_id
      where p.id = auth.uid() and r.name = 'Administrator'
    )
  );

create policy "admins can update roles"
  on public.profiles for update
  to authenticated
  using (
    exists (
      select 1 from public.profiles p
      join public.roles r on r.id = p.role_id
      where p.id = auth.uid() and r.name = 'Administrator'
    )
  );