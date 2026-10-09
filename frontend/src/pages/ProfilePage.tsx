import { useState } from 'react';

import { useAuth } from '../auth/AuthContext';
import { fetchModelInfo } from '../lib/api';
import { errorMessage } from '../lib/download';
import { useAsync } from '../lib/useAsync';
import { Button } from '../ui/Button';
import { InfoRow, Panel } from '../ui/primitives';

// Mirrors the role matrix in docs/RBAC.md (and what the API enforces).
const PERMISSIONS: Record<string, string[]> = {
  'Security Analyst': [
    'Upload suspicious files and run static analysis scans',
    'View malware classification and behavior-analysis reports',
    'Access the threat monitor and analytics dashboards',
    'Review alerts, create incidents, and confirm or correct verdicts',
    'Generate investigation reports',
    'Research workspace: datasets and malware families',
  ],
  'SOC Team Member': [
    'Monitor detection logs and view active threats',
    'Access security dashboards and analytics',
    'Track malware incidents and review alert history',
    'Confirm or correct verdicts',
    'Generate operational reports',
  ],
  Administrator: [
    'Manage users and roles',
    'Configure platform settings and security policies',
    'Manage integrations (VirusTotal, email, SIEM/SOAR) and ML models',
    'Access all dashboards and reports',
    'Monitor platform activity through the audit log',
  ],
  Researcher: [
    'Upload malware samples for research',
    'Access malware datasets and analyze malware families',
    'Review classification results and behavior analysis',
    'Export research reports and datasets',
    'Access historical threat analytics',
  ],
};

export function ProfilePage() {
  const { user, saveDisplayName } = useAuth();
  const model = useAsync(fetchModelInfo);
  const perms = user ? (PERMISSIONS[user.role] ?? []) : [];
  const det = model.data?.detector;
  const clf = model.data?.classifier;

  const [name, setName] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const draft = name ?? user?.display_name ?? '';
  const dirty = draft.trim() !== (user?.display_name ?? '') && draft.trim().length > 0;

  const save = async () => {
    setBusy(true);
    setMessage(null);
    try {
      await saveDisplayName(draft.trim());
      setName(null);
      setMessage({ ok: true, text: 'Profile updated.' });
    } catch (err) {
      setMessage({ ok: false, text: errorMessage(err, 'Could not update your profile') });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="max-w-2xl space-y-6">
      <h2 className="text-lg font-semibold tracking-[-0.01em]">Profile</h2>

      <Panel title="Account">
        <InfoRow label="Email" value={user?.email ?? '—'} />
        <InfoRow label="Role" value={user?.role ?? '—'} />
        <InfoRow label="User ID" value={user?.id ?? '—'} mono copy />
        <form
          className="mt-3 flex flex-col gap-2 border-t border-line-soft pt-3 sm:flex-row sm:items-end"
          onSubmit={(e) => {
            e.preventDefault();
            if (dirty) void save();
          }}
        >
          <label className="flex-1 text-xs text-secondary">
            Display name
            <input
              value={draft}
              onChange={(e) => setName(e.target.value)}
              maxLength={60}
              placeholder="How your name appears in the console"
              className="mt-1 w-full rounded-md border border-line bg-surface px-2.5 py-2 text-sm text-text outline-none placeholder:text-muted focus:border-accent"
            />
          </label>
          <Button type="submit" disabled={!dirty} loading={busy}>
            Save
          </Button>
        </form>
        {message && (
          <p className={`mt-2 text-xs ${message.ok ? 'text-risk-low' : 'text-risk-high'}`}>
            {message.text}
          </p>
        )}
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
