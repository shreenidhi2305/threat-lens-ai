import { useEffect, useRef, useState } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';

import { useAuth } from '../auth/AuthContext';
import { visibleSections } from '../lib/nav';
import { ChevronDownIcon, LogoutIcon, ShieldIcon } from '../ui/icons';

const TITLES: Record<string, string> = {
  '/dashboard': 'Overview',
  '/submit': 'Submit File',
  '/reports': 'Analysis Report',
  '/threats': 'Threat Monitor',
  '/alerts': 'Alerts',
  '/analytics': 'Analytics',
  '/profile': 'Profile',
};

function initials(email: string): string {
  return email.slice(0, 2).toUpperCase();
}

function UserMenu() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onClick = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onClick);
    return () => document.removeEventListener('mousedown', onClick);
  }, [open]);

  if (!user) return null;

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 rounded-md py-1 pl-1 pr-2 transition-colors duration-150 ease-out hover:bg-surface-raised"
      >
        <span className="grid size-7 place-items-center rounded-md bg-accent-quiet text-2xs font-semibold text-accent">
          {initials(user.email)}
        </span>
        <span className="hidden text-left sm:block">
          <span className="block text-xs font-medium leading-tight text-text">{user.email}</span>
          <span className="block text-2xs leading-tight text-muted">{user.role}</span>
        </span>
        <ChevronDownIcon className="text-muted" />
      </button>
      {open && (
        <div className="tl-rise absolute right-0 z-20 mt-2 w-56 overflow-hidden rounded-lg border border-line bg-surface shadow-xl shadow-black/40">
          <div className="border-b border-line-soft px-3 py-2.5">
            <div className="truncate text-sm text-text">{user.email}</div>
            <div className="mt-0.5 text-2xs text-muted">{user.role}</div>
          </div>
          <button
            onClick={() => {
              logout();
              navigate('/login', { replace: true });
            }}
            className="flex w-full items-center gap-2 px-3 py-2.5 text-left text-sm text-secondary transition-colors duration-150 ease-out hover:bg-surface-raised hover:text-text"
          >
            <LogoutIcon /> Sign out
          </button>
        </div>
      )}
    </div>
  );
}

export function AppLayout() {
  const { user } = useAuth();
  const { pathname } = useLocation();
  const sections = visibleSections(user?.role);
  const title = TITLES[pathname] ?? 'ThreatLens';

  return (
    <div className="flex min-h-screen bg-bg">
      <aside className="fixed inset-y-0 left-0 hidden w-60 flex-col border-r border-line bg-surface md:flex">
        <div className="flex h-14 items-center gap-2 px-5">
          <ShieldIcon className="text-lg text-accent" />
          <span className="text-sm font-semibold tracking-[-0.01em]">ThreatLens</span>
        </div>
        <nav className="flex-1 space-y-6 overflow-y-auto px-3 py-4">
          {sections.map((section) => (
            <div key={section.heading}>
              <div className="px-3 pb-1.5 text-[0.6875rem] font-semibold uppercase tracking-[0.08em] text-muted">
                {section.heading}
              </div>
              <div className="space-y-0.5">
                {section.items.map(({ to, label, icon: Icon }) => (
                  <NavLink
                    key={to}
                    to={to}
                    className={({ isActive }) =>
                      `flex items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors duration-150 ease-out ${
                        isActive
                          ? 'bg-accent-quiet font-medium text-accent'
                          : 'text-secondary hover:bg-surface-raised hover:text-text'
                      }`
                    }
                  >
                    <Icon className="text-base" />
                    {label}
                  </NavLink>
                ))}
              </div>
            </div>
          ))}
        </nav>
        <div className="border-t border-line-soft px-5 py-3 text-2xs text-muted">
          Static analysis only. Files are never executed.
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col md:pl-60">
        <header className="sticky top-0 z-10 flex h-14 items-center justify-between border-b border-line bg-bg/80 px-5 backdrop-blur">
          <div className="flex items-center gap-2 md:hidden">
            <ShieldIcon className="text-accent" />
          </div>
          <h1 className="text-sm font-medium text-text">{title}</h1>
          <UserMenu />
        </header>

        {/* mobile nav */}
        <nav className="flex gap-1 overflow-x-auto border-b border-line bg-surface px-3 py-2 md:hidden">
          {sections.flatMap((s) =>
            s.items.map(({ to, label, icon: Icon }) => (
              <NavLink
                key={to}
                to={to}
                className={({ isActive }) =>
                  `flex shrink-0 items-center gap-1.5 rounded-md px-2.5 py-1.5 text-xs transition-colors ${
                    isActive ? 'bg-accent-quiet text-accent' : 'text-secondary'
                  }`
                }
              >
                <Icon className="text-sm" />
                {label}
              </NavLink>
            )),
          )}
        </nav>

        <main className="mx-auto w-full max-w-[1180px] flex-1 px-5 py-7 sm:px-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
