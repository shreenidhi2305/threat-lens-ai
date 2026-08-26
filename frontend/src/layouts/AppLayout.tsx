import { Link, Outlet } from 'react-router-dom';

const navItems = [
  { to: '/dashboard', label: 'Dashboard' },
  { to: '/upload', label: 'File Upload' },
  { to: '/analysis', label: 'File Analysis' },
  { to: '/malware-report', label: 'Malware Report' },
  { to: '/threat-monitoring', label: 'Threat Monitoring' },
  { to: '/alerts', label: 'Alerts' },
  { to: '/analytics', label: 'Analytics' },
  { to: '/profile', label: 'Profile' },
];

export function AppLayout() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-200">
      <header className="border-b border-slate-800 p-4">
        <h1 className="text-xl font-semibold">ThreatLens AI</h1>
      </header>
      <div className="flex">
        <aside className="hidden w-64 border-r border-slate-800 p-4 md:block">
          <nav className="space-y-2">
            {navItems.map((item) => (
              <Link key={item.to} to={item.to} className="block rounded px-3 py-2 hover:bg-slate-800">
                {item.label}
              </Link>
            ))}
          </nav>
        </aside>
        <main className="flex-1 p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
