import { useAuth } from '../auth/AuthContext';
import { clearHistory, getHistory } from '../lib/history';
import { Button } from '../ui/Button';
import { InfoRow, Panel } from '../ui/primitives';

const PERMISSIONS: Record<string, string[]> = {
  'Security Analyst': [
    'Submit files for static analysis',
    'View analysis reports and threat monitor',
    'Review alerts',
  ],
  'SOC Team Member': ['View threat monitor and alerts', 'Access analytics'],
  Administrator: ['Everything analysts can do', 'Manage users, roles, and platform settings'],
  Researcher: ['Submit and bulk-analyze samples', 'Review classifications and export findings'],
};

export function ProfilePage() {
  const { user } = useAuth();
  const scanCount = getHistory().length;
  const perms = user ? (PERMISSIONS[user.role] ?? []) : [];

  return (
    <div className="max-w-2xl space-y-6">
      <h2 className="text-lg font-semibold tracking-[-0.01em]">Profile</h2>

      <Panel title="Account">
        <InfoRow label="Email" value={user?.email ?? '—'} />
        <InfoRow label="Role" value={user?.role ?? '—'} />
        <InfoRow label="User ID" value={user?.id ?? '—'} mono copy />
        <InfoRow label="Files analyzed (session)" value={scanCount} />
      </Panel>

      <Panel title={`${user?.role ?? 'Role'} permissions`}>
        <ul className="space-y-1.5 text-sm text-secondary">
          {perms.map((p) => (
            <li key={p} className="flex gap-2">
              <span className="mt-1.5 size-1 shrink-0 rounded-full bg-accent" />
              {p}
            </li>
          ))}
        </ul>
      </Panel>

      <Panel title="Session data">
        <div className="flex items-center justify-between gap-4">
          <p className="text-sm text-secondary">
            Analysis history is stored in this browser only.
          </p>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => {
              clearHistory();
              location.reload();
            }}
          >
            Clear history
          </Button>
        </div>
      </Panel>
    </div>
  );
}
