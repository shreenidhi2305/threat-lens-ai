import { Link } from 'react-router-dom';

import { ScanList } from '../components/ScanList';
import { useAuth } from '../auth/AuthContext';
import { getHistory } from '../lib/history';
import { Button } from '../ui/Button';
import { UploadIcon } from '../ui/icons';
import { EmptyState, Stat } from '../ui/primitives';

export function DashboardPage() {
  const { user } = useAuth();
  const history = getHistory();
  const canScan =
    user?.role === 'Security Analyst' || user?.role === 'Administrator' || user?.role === 'Researcher';

  const high = history.filter((h) => h.level === 'high').length;
  const medium = history.filter((h) => h.level === 'medium').length;
  const avg = history.length
    ? Math.round(history.reduce((s, h) => s + h.score, 0) / history.length)
    : 0;

  return (
    <div className="space-y-7">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold tracking-[-0.01em]">
            {history.length ? 'Recent activity' : `Welcome, ${user?.email.split('@')[0]}`}
          </h2>
          <p className="mt-1 text-sm text-secondary">
            {canScan
              ? 'Submit a suspicious file to run the static-analysis pipeline.'
              : 'Monitoring view. File submission is limited to analysts and researchers.'}
          </p>
        </div>
        {canScan && (
          <Link to="/submit">
            <Button>
              <UploadIcon /> Submit file
            </Button>
          </Link>
        )}
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <Stat label="Files analyzed" value={history.length} hint="this browser session" />
        <Stat
          label="High risk"
          value={<span className={high ? 'text-risk-high' : undefined}>{high}</span>}
          hint={`${medium} medium`}
        />
        <Stat label="Average score" value={history.length ? `${avg}/100` : '—'} />
      </div>

      {history.length === 0 ? (
        <EmptyState
          icon={<UploadIcon />}
          title="No analyses yet"
          description={
            canScan
              ? 'Your analyzed files and their verdicts will appear here.'
              : 'Analyzed files will appear here once analysts start submitting them.'
          }
          action={
            canScan ? (
              <Link to="/submit">
                <Button>Submit your first file</Button>
              </Link>
            ) : undefined
          }
        />
      ) : (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-2xs font-semibold uppercase tracking-[0.08em] text-muted">
              Analysis history
            </h3>
            <Link to="/reports" className="text-xs text-accent hover:underline">
              Open latest report
            </Link>
          </div>
          <ScanList entries={history.slice(0, 12)} />
        </div>
      )}
    </div>
  );
}
