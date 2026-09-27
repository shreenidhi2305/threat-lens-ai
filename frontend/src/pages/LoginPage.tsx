import { useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';

import { useAuth } from '../auth/AuthContext';
import { Button } from '../ui/Button';
import { Field } from '../ui/Field';
import { ShieldIcon } from '../ui/icons';

const DEMO_LOGINS = [
  ['analyst@local', 'Security Analyst'],
  ['soc@local', 'SOC Team Member'],
  ['admin@local', 'Administrator'],
  ['researcher@local', 'Researcher'],
];

export function LoginPage() {
  const { user, login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('analyst@local');
  const [password, setPassword] = useState('demo');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (user) return <Navigate to="/dashboard" replace />;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await login(email, password);
      navigate('/dashboard', { replace: true });
    } catch {
      setError('Sign in failed. Check the address and that the API is reachable.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid min-h-screen bg-bg lg:grid-cols-[1.05fr_1fr]">
      <div className="relative hidden flex-col justify-between overflow-hidden border-r border-line bg-surface p-12 lg:flex">
        <div className="flex items-center gap-2">
          <ShieldIcon className="text-xl text-accent" />
          <span className="text-base font-semibold tracking-[-0.01em]">ThreatLens</span>
        </div>
        <div className="max-w-md">
          <h1 className="text-3xl font-semibold leading-tight tracking-[-0.02em]">
            Static malware analysis, one verdict at a time.
          </h1>
          <p className="mt-4 text-sm leading-relaxed text-secondary">
            Upload a suspicious file. ThreatLens hashes it, identifies its type, matches it against
            signatures and YARA rules, extracts embedded indicators, and returns a single risk score
            with the evidence behind it. Files are analyzed, never executed.
          </p>
        </div>
        <dl className="grid grid-cols-3 gap-6 text-sm">
          {[
            ['3', 'hash algorithms'],
            ['YARA', 'rule matching'],
            ['0-100', 'risk scoring'],
          ].map(([k, v]) => (
            <div key={v}>
              <dt className="font-mono text-lg text-text">{k}</dt>
              <dd className="mt-0.5 text-2xs uppercase tracking-[0.06em] text-muted">{v}</dd>
            </div>
          ))}
        </dl>
        <div
          className="pointer-events-none absolute -right-32 -top-32 size-96 rounded-full opacity-[0.12] blur-3xl"
          style={{ background: 'var(--accent)' }}
        />
      </div>

      <div className="flex items-center justify-center px-6 py-12">
        <div className="w-full max-w-sm">
          <div className="mb-8 flex items-center gap-2 lg:hidden">
            <ShieldIcon className="text-xl text-accent" />
            <span className="text-base font-semibold">ThreatLens</span>
          </div>
          <h2 className="text-xl font-semibold tracking-[-0.01em]">Sign in</h2>
          <p className="mt-1 text-sm text-secondary">Access the analyst console.</p>

          <form onSubmit={submit} className="mt-6 space-y-4">
            <Field
              label="Work email"
              type="email"
              autoComplete="username"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
            <Field
              label="Password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              error={error ?? undefined}
            />
            <Button type="submit" loading={busy} className="w-full">
              Sign in
            </Button>
          </form>

          <div className="mt-6 rounded-md border border-line-soft bg-surface p-3">
            <p className="mb-2 text-2xs font-medium uppercase tracking-[0.06em] text-muted">
              Demo accounts · any password
            </p>
            <ul className="space-y-1 text-xs">
              {DEMO_LOGINS.map(([addr, role]) => (
                <li key={addr} className="flex items-center justify-between">
                  <button
                    type="button"
                    onClick={() => setEmail(addr)}
                    className="font-mono text-accent hover:underline"
                  >
                    {addr}
                  </button>
                  <span className="text-muted">{role}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
