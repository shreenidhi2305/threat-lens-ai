import { useAuth } from '../auth/AuthContext';
import { fetchModelInfo } from '../lib/api';
import { useAsync } from '../lib/useAsync';
import { InfoRow, Panel } from '../ui/primitives';

const PERMISSIONS: Record<string, string[]> = {
  'Security Analyst': [
    'Submit files for analysis',
    'View analysis reports and the threat monitor',
    'Review and triage alerts',
  ],
  'SOC Team Member': ['View the threat monitor and alerts', 'Access analytics'],
  Administrator: ['Everything analysts can do', 'Manage users, roles, and platform settings'],
  Researcher: ['Submit and bulk-analyse samples', 'Review classifications and export findings'],
};

export function ProfilePage() {
  const { user } = useAuth();
  const model = useAsync(fetchModelInfo);
  const perms = user ? (PERMISSIONS[user.role] ?? []) : [];
  const det = model.data?.detector;
  const clf = model.data?.classifier;

  return (
    <div className="max-w-2xl space-y-6">
      <h2 className="text-lg font-semibold tracking-[-0.01em]">Profile</h2>

      <Panel title="Account">
        <InfoRow label="Email" value={user?.email ?? '—'} />
        <InfoRow label="Role" value={user?.role ?? '—'} />
        <InfoRow label="User ID" value={user?.id ?? '—'} mono copy />
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

      <Panel title="Detection models">
        {det ? (
          <>
            <InfoRow label="Detector" value={det.version} />
            <InfoRow
              label="ROC-AUC"
              value={String((det.metrics as Record<string, number>).roc_auc ?? '—')}
            />
            <InfoRow label="Classifier" value={clf ? clf.version : 'not loaded'} />
            <InfoRow label="Categories" value={clf ? clf.classes.join(', ') : '—'} />
            <InfoRow label="Feature vector" value={`${model.data?.feature_count ?? '—'} features`} />
          </>
        ) : (
          <p className="text-sm text-secondary">Model registry not loaded.</p>
        )}
      </Panel>
    </div>
  );
}
