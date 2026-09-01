insert into public.roles (name, description) values
  ('Security Analyst', 'Upload/scan files, review classifications, manage alerts'),
  ('SOC Team Member', 'Monitor detection logs and active threats'),
  ('Administrator', 'Full platform and user management access'),
  ('Researcher', 'Upload samples, analyze malware families, export research')
on conflict (name) do nothing;