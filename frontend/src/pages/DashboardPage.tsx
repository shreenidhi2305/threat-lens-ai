import { Link } from 'react-router-dom';

import { useAnalysis } from '../analysis/AnalysisStore';
import { useAuth } from '../auth/AuthContext';

export function DashboardPage() {
  const { user } = useAuth();
  const { result } = useAnalysis();
  const canScan =
    user?.role === 'Security Analyst' ||
    user?.role === 'Administrator' ||
    user?.role === 'Researcher';

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-semibold">Welcome, {user?.email}</h2>
        <p className="text-sm text-slate-500">Signed in as {user?.role}</p>
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
          <div className="text-xs uppercase text-slate-500">Last scan</div>
          <div className="mt-1 text-2xl font-semibold">
            {result ? `${result.risk.score}/100` : '—'}
          </div>
          <div className="text-sm text-slate-400">
            {result ? result.risk.classification : 'No file analysed this session'}
          </div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
          <div className="text-xs uppercase text-slate-500">Milestone</div>
          <div className="mt-1 text-2xl font-semibold">1 / 4</div>
          <div className="text-sm text-slate-400">Auth, RBAC &amp; static analysis</div>
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
          <div className="text-xs uppercase text-slate-500">Your access</div>
          <div className="mt-1 text-2xl font-semibold">{canScan ? 'Scan' : 'Read'}</div>
          <div className="text-sm text-slate-400">
            {canScan ? 'Can submit files for analysis' : 'Monitoring & dashboards only'}
          </div>
        </div>
      </div>

      {canScan && (
        <Link
          to="/upload"
          className="inline-block rounded bg-cyan-600 px-4 py-2 font-medium text-white hover:bg-cyan-500"
        >
          Analyse a file
        </Link>
      )}
    </div>
  );
}
