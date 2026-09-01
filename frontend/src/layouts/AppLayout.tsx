import { NavLink, Outlet, useNavigate } from 'react-router-dom';

import { useAuth } from '../auth/AuthContext';
import { visibleNav } from '../lib/nav';

export function AppLayout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login', { replace: true });
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200">
      <header className="flex items-center justify-between border-b border-slate-800 px-6 py-3">
        <div className="flex items-center gap-2">
          <span className="text-lg font-semibold text-cyan-400">ThreatLens AI</span>
          <span className="text-xs text-slate-500">Malware Classification &amp; Threat Detection</span>
        </div>
        <div className="flex items-center gap-4 text-sm">
          <div className="text-right">
            <div className="text-slate-300">{user?.email}</div>
            <div className="text-xs text-cyan-400">{user?.role}</div>
          </div>
          <button
            onClick={handleLogout}
            className="rounded border border-slate-700 px-3 py-1 text-slate-300 hover:bg-slate-800"
          >
            Sign out
          </button>
        </div>
      </header>
      <div className="flex">
        <aside className="hidden w-56 shrink-0 border-r border-slate-800 p-4 md:block">
          <nav className="space-y-1">
            {visibleNav(user?.role).map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  `block rounded px-3 py-2 text-sm ${
                    isActive ? 'bg-cyan-500/10 text-cyan-300' : 'text-slate-300 hover:bg-slate-800'
                  }`
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
        </aside>
        <main className="min-w-0 flex-1 p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
