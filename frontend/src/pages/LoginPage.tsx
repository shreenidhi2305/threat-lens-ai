import { useState } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';

import { useAuth } from '../auth/AuthContext';

const DEV_LOGINS = [
  { email: 'analyst@local', role: 'Security Analyst' },
  { email: 'soc@local', role: 'SOC Team Member' },
  { email: 'admin@local', role: 'Administrator' },
  { email: 'researcher@local', role: 'Researcher' },
];

export function LoginPage() {
  const { user, login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('analyst@local');
  const [password, setPassword] = useState('demo');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (user) {
    return <Navigate to="/dashboard" replace />;
  }

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await login(email, password);
      navigate('/dashboard', { replace: true });
    } catch {
      setError('Login failed. Check your credentials and that the API is running.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 px-4">
      <div className="w-full max-w-sm">
        <div className="mb-6 text-center">
          <h1 className="text-2xl font-semibold text-cyan-400">ThreatLens AI</h1>
          <p className="text-sm text-slate-500">Sign in to the analyst console</p>
        </div>
        <form onSubmit={handleSubmit} className="space-y-4 rounded-lg border border-slate-800 bg-slate-900 p-6">
          <label className="block text-sm">
            <span className="text-slate-400">Email</span>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 outline-none focus:border-cyan-500"
            />
          </label>
          <label className="block text-sm">
            <span className="text-slate-400">Password</span>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 outline-none focus:border-cyan-500"
            />
          </label>
          {error && <p className="text-sm text-rose-400">{error}</p>}
          <button
            type="submit"
            disabled={busy}
            className="w-full rounded bg-cyan-600 py-2 font-medium text-white hover:bg-cyan-500 disabled:opacity-50"
          >
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
        <div className="mt-4 rounded border border-slate-800 bg-slate-900/50 p-3 text-xs text-slate-500">
          <p className="mb-1 font-medium text-slate-400">Local demo logins (any password):</p>
          <ul className="space-y-0.5">
            {DEV_LOGINS.map((d) => (
              <li key={d.email}>
                <button
                  type="button"
                  className="text-cyan-500 hover:underline"
                  onClick={() => setEmail(d.email)}
                >
                  {d.email}
                </button>{' '}
                → {d.role}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
