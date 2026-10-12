import { useEffect, useMemo, useState } from 'react';

import { useAuth } from '../auth/AuthContext';
import {
  changeUserRole,
  downloadCsv,
  fetchAdminModels,
  fetchAdminOverview,
  fetchAdminSettings,
  fetchAdminUsers,
  fetchAuditLog,
  fetchIntegrations,
  reloadModels,
  resetAdminSettings,
  saveAdminSettings,
  testIntegration,
} from '../lib/api';
import type { SettingField } from '../lib/adminTypes';
import { ago, duration, errorMessage, saveBlob } from '../lib/download';
import type { UserRole } from '../lib/types';
import { useAsync } from '../lib/useAsync';
import { usePolling } from '../lib/usePolling';
import { Button } from '../ui/Button';
import { Badge, Panel, Spinner, Stat } from '../ui/primitives';

const ROLES: UserRole[] = ['Security Analyst', 'SOC Team Member', 'Administrator', 'Researcher'];

const TABS = [
  { id: 'overview', label: 'Platform monitor' },
  { id: 'users', label: 'Users & roles' },
  { id: 'settings', label: 'Settings & policies' },
  { id: 'integrations', label: 'Integrations' },
  { id: 'audit', label: 'Activity log' },
  { id: 'models', label: 'ML models' },
] as const;

type TabId = (typeof TABS)[number]['id'];

const selectCls =
  'rounded-md border border-line bg-surface px-2 py-1.5 text-xs text-text outline-none focus:border-accent';
const inputCls =
  'rounded-md border border-line bg-surface px-2.5 py-1.5 text-xs text-text placeholder:text-muted outline-none focus:border-accent';

function Loading() {
  return (
    <div className="flex justify-center py-16">
      <Spinner />
    </div>
  );
}

function Notice({ tone, children }: { tone: 'ok' | 'error' | 'warn'; children: React.ReactNode }) {
  const cls =
    tone === 'ok'
      ? 'border-risk-low/40 bg-risk-low-wash text-risk-low'
      : tone === 'warn'
        ? 'border-risk-medium/40 bg-risk-medium-wash text-risk-medium'
        : 'border-risk-high/40 bg-risk-high-wash text-risk-high';
  return <div className={`rounded-md border px-3 py-2 text-sm ${cls}`}>{children}</div>;
}

/* -------------------------------------------------------------------------- */

function OverviewTab() {
  const overview = useAsync((signal) => fetchAdminOverview(signal));
  usePolling(overview.reload, 10_000);
  const o = overview.data;
  if (!o) return overview.error ? <Notice tone="error">{overview.error}</Notice> : <Loading />;

  const classes = o.requests.by_status_class;
  return (
    <div className="space-y-5">
      {o.warnings.length > 0 && (
        <Notice tone="warn">
          <div className="font-medium">Configuration warnings</div>
          <ul className="mt-1 list-disc space-y-0.5 pl-5 text-xs">
            {o.warnings.map((w) => (
              <li key={w}>{w}</li>
            ))}
          </ul>
        </Notice>
      )}

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Stat label="Uptime" value={duration(o.uptime_seconds)} hint={`v${o.version} · ${o.environment}`} />
        <Stat
          label="Requests"
          value={o.requests.total_requests}
          hint={`${o.requests.rate_limited} rate-limited`}
        />
        <Stat
          label="Avg latency"
          value={`${o.requests.avg_latency_ms} ms`}
          hint={`p95 ${o.requests.p95_latency_ms} ms · ${o.requests.slow_requests} slow`}
        />
        <Stat
          label="Errors (5xx)"
          value={classes['5xx'] ?? 0}
          hint={`${classes['4xx'] ?? 0} client errors`}
        />
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <Panel title="Platform data">
          <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
            {Object.entries(o.totals).map(([key, value]) => (
              <div key={key} className="flex justify-between border-b border-line-soft py-1.5">
                <dt className="capitalize text-secondary">{key.replace(/_/g, ' ')}</dt>
                <dd className="font-mono text-text">{value}</dd>
              </div>
            ))}
          </dl>
        </Panel>

        <Panel title="Runtime">
          <dl className="space-y-2 text-sm">
            <div className="flex justify-between">
              <dt className="text-secondary">Data store</dt>
              <dd>
                <Badge tone={o.persistence === 'supabase' ? 'low' : 'medium'}>{o.persistence}</Badge>
              </dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-secondary">Authentication</dt>
              <dd>
                <Badge tone={o.auth_mode === 'supabase' ? 'low' : 'medium'}>{o.auth_mode}</Badge>
              </dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-secondary">Detector model</dt>
              <dd className="font-mono text-xs text-text">{o.models.detector?.version ?? 'not loaded'}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-secondary">Classifier model</dt>
              <dd className="font-mono text-xs text-text">{o.models.classifier?.version ?? 'not loaded'}</dd>
            </div>
          </dl>
        </Panel>
      </div>

      <Panel title="Activity by action">
        {Object.keys(o.audit_actions).length === 0 ? (
          <p className="text-sm text-secondary">No activity recorded yet.</p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {Object.entries(o.audit_actions)
              .sort((a, b) => b[1] - a[1])
              .map(([action, count]) => (
                <span
                  key={action}
                  className="rounded-md border border-line-soft bg-surface-raised px-2 py-1 text-xs text-secondary"
                >
                  {action} <span className="font-mono text-text">{count}</span>
                </span>
              ))}
          </div>
        )}
      </Panel>
    </div>
  );
}

/* -------------------------------------------------------------------------- */

function UsersTab() {
  const { user: me } = useAuth();
  const users = useAsync((signal) => fetchAdminUsers(signal));
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<{ tone: 'ok' | 'error'; text: string } | null>(null);

  const change = async (id: string, email: string, role: string) => {
    setBusy(id);
    setMessage(null);
    try {
      await changeUserRole(id, role);
      setMessage({ tone: 'ok', text: `${email} is now ${role}. It applies at their next sign-in.` });
      users.reload();
    } catch (err) {
      setMessage({ tone: 'error', text: errorMessage(err, 'Could not change the role') });
    } finally {
      setBusy(null);
    }
  };

  if (!users.data) return users.error ? <Notice tone="error">{users.error}</Notice> : <Loading />;

  return (
    <div className="space-y-4">
      {message && <Notice tone={message.tone}>{message.text}</Notice>}
      <Panel title={`${users.data.length} users`}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-2xs uppercase tracking-[0.06em] text-muted">
                <th className="pb-2 pr-4 font-medium">User</th>
                <th className="pb-2 pr-4 font-medium">Role</th>
                <th className="hidden pb-2 pr-4 font-medium sm:table-cell">Last sign-in</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line-soft">
              {users.data.map((u) => {
                const self = u.id.toLowerCase() === me?.id.toLowerCase();
                return (
                  <tr key={u.id}>
                    <td className="py-2.5 pr-4">
                      <div className="text-text">{u.display_name || u.email}</div>
                      {u.display_name && <div className="text-2xs text-muted">{u.email}</div>}
                    </td>
                    <td className="py-2.5 pr-4">
                      <select
                        aria-label={`Role for ${u.email}`}
                        className={selectCls}
                        value={u.role}
                        disabled={self || busy === u.id}
                        onChange={(e) => change(u.id, u.email, e.target.value)}
                      >
                        {ROLES.map((r) => (
                          <option key={r} value={r}>
                            {r}
                          </option>
                        ))}
                      </select>
                      {self && <span className="ml-2 text-2xs text-muted">you</span>}
                    </td>
                    <td className="hidden py-2.5 pr-4 text-xs text-muted sm:table-cell">
                      {u.last_login ? ago(u.last_login) : '—'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-2xs text-muted">
          Roles are read from the sign-in token, so a change applies the next time that person signs
          in. You can&apos;t change your own role, and the last administrator can&apos;t be demoted.
        </p>
      </Panel>
    </div>
  );
}

/* -------------------------------------------------------------------------- */

function SettingsTab() {
  const settings = useAsync((signal) => fetchAdminSettings(signal));
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ tone: 'ok' | 'error'; text: string } | null>(null);

  const fields = settings.data;
  const groups = useMemo(() => {
    const map = new Map<string, SettingField[]>();
    for (const f of fields ?? []) map.set(f.group, [...(map.get(f.group) ?? []), f]);
    return [...map.entries()];
  }, [fields]);

  if (!fields) return settings.error ? <Notice tone="error">{settings.error}</Notice> : <Loading />;

  const current = (f: SettingField) => draft[f.key] ?? String(f.value);
  const changed = fields.filter((f) => draft[f.key] !== undefined && draft[f.key] !== String(f.value));

  const save = async () => {
    setBusy(true);
    setMessage(null);
    try {
      const values: Record<string, string | number> = {};
      for (const f of changed) values[f.key] = f.type === 'int' ? Number(draft[f.key]) : draft[f.key];
      await saveAdminSettings(values);
      setDraft({});
      settings.reload();
      setMessage({ tone: 'ok', text: 'Settings saved. They apply immediately.' });
    } catch (err) {
      setMessage({ tone: 'error', text: errorMessage(err, 'Could not save settings') });
    } finally {
      setBusy(false);
    }
  };

  const reset = async () => {
    setBusy(true);
    setMessage(null);
    try {
      await resetAdminSettings();
      setDraft({});
      settings.reload();
      setMessage({ tone: 'ok', text: 'Settings restored to their defaults.' });
    } catch (err) {
      setMessage({ tone: 'error', text: errorMessage(err, 'Could not reset settings') });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-4">
      {message && <Notice tone={message.tone}>{message.text}</Notice>}
      {groups.map(([group, items]) => (
        <Panel key={group} title={group}>
          <div className="divide-y divide-line-soft">
            {items.map((f) => (
              <div key={f.key} className="flex flex-col gap-2 py-3 sm:flex-row sm:items-center sm:justify-between">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 text-sm text-text">
                    {f.label}
                    {f.overridden && <Badge tone="accent">changed</Badge>}
                  </div>
                  <div className="text-xs text-secondary">{f.description}</div>
                  <div className="text-2xs text-muted">
                    Default {String(f.default)}
                    {f.type === 'int' ? ` · allowed ${f.min}–${f.max}` : ''}
                  </div>
                </div>
                {f.type === 'choice' ? (
                  <select
                    aria-label={f.label}
                    className={selectCls}
                    value={current(f)}
                    onChange={(e) => setDraft({ ...draft, [f.key]: e.target.value })}
                  >
                    {f.choices?.map((c) => (
                      <option key={c} value={c}>
                        {c}
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    aria-label={f.label}
                    type="number"
                    min={f.min}
                    max={f.max}
                    className={`${inputCls} w-28`}
                    value={current(f)}
                    onChange={(e) => setDraft({ ...draft, [f.key]: e.target.value })}
                  />
                )}
              </div>
            ))}
          </div>
        </Panel>
      ))}
      <div className="flex items-center gap-3">
        <Button onClick={save} disabled={changed.length === 0} loading={busy}>
          Save changes{changed.length > 0 ? ` (${changed.length})` : ''}
        </Button>
        <Button variant="secondary" onClick={reset} disabled={busy}>
          Restore defaults
        </Button>
        {changed.length > 0 && (
          <button onClick={() => setDraft({})} className="text-xs text-muted hover:text-secondary">
            Discard
          </button>
        )}
      </div>
      <p className="text-2xs text-muted">
        Secrets, credentials and infrastructure URLs are never editable here — they stay in the
        server environment. Every change is recorded in the activity log.
      </p>
    </div>
  );
}

/* -------------------------------------------------------------------------- */

function IntegrationsTab() {
  const integrations = useAsync((signal) => fetchIntegrations(signal));
  const [testing, setTesting] = useState<string | null>(null);
  const [results, setResults] = useState<Record<string, { ok: boolean; text: string }>>({});

  const test = async (id: string) => {
    setTesting(id);
    try {
      const out = await testIntegration(id);
      setResults((r) => ({ ...r, [id]: { ok: out.ok, text: out.ok ? 'Test event delivered.' : (out.error ?? 'Failed') } }));
      integrations.reload();
    } catch (err) {
      setResults((r) => ({ ...r, [id]: { ok: false, text: errorMessage(err) } }));
    } finally {
      setTesting(null);
    }
  };

  if (!integrations.data)
    return integrations.error ? <Notice tone="error">{integrations.error}</Notice> : <Loading />;

  return (
    <div className="grid gap-4 md:grid-cols-2">
      {integrations.data.map((i) => (
        <Panel
          key={i.id}
          title={i.name}
          aside={
            <Badge tone={!i.configured ? 'neutral' : i.healthy === false ? 'high' : 'low'}>
              {!i.configured ? 'not configured' : i.healthy === false ? 'failing' : 'connected'}
            </Badge>
          }
        >
          <p className="text-sm text-secondary">{i.description}</p>
          {i.destination && <p className="mt-2 font-mono text-xs text-muted">{i.destination}</p>}
          {i.detail && <p className="mt-2 text-xs text-muted">{i.detail}</p>}
          {Object.keys(i.stats).length > 0 && i.configured && (
            <p className="mt-2 text-xs text-secondary">
              sent <span className="font-mono text-text">{String(i.stats.sent ?? 0)}</span> · failed{' '}
              <span className="font-mono text-text">{String(i.stats.failed ?? 0)}</span>
              {i.stats.signed ? ' · signed' : ' · unsigned'}
            </p>
          )}
          {i.testable && (
            <div className="mt-3 flex items-center gap-3">
              <Button size="sm" variant="secondary" loading={testing === i.id} onClick={() => test(i.id)}>
                Send test
              </Button>
              {results[i.id] && (
                <span className={`text-xs ${results[i.id].ok ? 'text-risk-low' : 'text-risk-high'}`}>
                  {results[i.id].text}
                </span>
              )}
            </div>
          )}
        </Panel>
      ))}
    </div>
  );
}

/* -------------------------------------------------------------------------- */

const ACTION_GROUPS = [
  'auth', 'scan', 'report', 'alert', 'incident', 'user', 'settings', 'integration', 'model',
  'feedback', 'research', 'audit',
];

function AuditTab() {
  const [q, setQ] = useState('');
  const [debouncedQ, setDebouncedQ] = useState('');
  const [action, setAction] = useState('');
  const log = useAsync(
    (signal) => fetchAuditLog({ q: debouncedQ, action }, 200, signal),
    [debouncedQ, action],
  );
  usePolling(log.reload, 15_000);

  useEffect(() => {
    const t = setTimeout(() => setDebouncedQ(q.trim()), 300);
    return () => clearTimeout(t);
  }, [q]);

  const exportCsv = async () => saveBlob(await downloadCsv('/admin/audit/export.csv'), 'audit-log.csv');

  return (
    <Panel
      title="Activity log"
      aside={
        <button onClick={exportCsv} className="text-xs text-accent hover:underline">
          Export CSV
        </button>
      }
    >
      <div className="mb-3 flex flex-col gap-2 sm:flex-row">
        <input
          className={`${inputCls} sm:w-64`}
          placeholder="Search user, action, target…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          aria-label="Search activity"
        />
        <select
          aria-label="Action"
          className={selectCls}
          value={action}
          onChange={(e) => setAction(e.target.value)}
        >
          <option value="">All actions</option>
          {ACTION_GROUPS.map((a) => (
            <option key={a} value={a}>
              {a}
            </option>
          ))}
        </select>
      </div>
      {!log.data ? (
        <Loading />
      ) : log.data.length === 0 ? (
        <p className="py-8 text-center text-sm text-secondary">No matching activity.</p>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-line-soft" aria-busy={log.refreshing}>
          <table className="w-full text-sm">
            <thead className="bg-surface-raised/60 text-left text-2xs uppercase tracking-[0.06em] text-muted">
              <tr>
                <th className="px-3 py-2 font-medium">When</th>
                <th className="px-3 py-2 font-medium">Who</th>
                <th className="px-3 py-2 font-medium">Action</th>
                <th className="hidden px-3 py-2 font-medium md:table-cell">Detail</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line-soft">
              {log.data.map((e) => (
                <tr key={e.id}>
                  <td className="whitespace-nowrap px-3 py-2 text-xs text-muted" title={e.at}>
                    {ago(e.at)}
                  </td>
                  <td className="px-3 py-2">
                    <div className="text-xs text-text">{e.actor ?? '—'}</div>
                    <div className="text-2xs text-muted">{e.role ?? ''}</div>
                  </td>
                  <td className="px-3 py-2">
                    <span className="font-mono text-xs text-text">{e.action}</span>
                    {e.status !== 'success' && (
                      <Badge tone="high" className="ml-2">
                        {e.status}
                      </Badge>
                    )}
                  </td>
                  <td className="hidden max-w-xs truncate px-3 py-2 text-xs text-secondary md:table-cell" title={e.detail ?? ''}>
                    {e.detail ?? e.target ?? ''}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

/* -------------------------------------------------------------------------- */

function pct(value: number | null): string {
  return value == null ? '—' : `${(value * 100).toFixed(1)}%`;
}

function ModelsTab() {
  const models = useAsync((signal) => fetchAdminModels(signal));
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ tone: 'ok' | 'error'; text: string } | null>(null);

  const reload = async () => {
    setBusy(true);
    setMessage(null);
    try {
      await reloadModels();
      models.reload();
      setMessage({ tone: 'ok', text: 'Model artifacts reloaded from disk — no restart needed.' });
    } catch (err) {
      setMessage({ tone: 'error', text: errorMessage(err, 'Reload failed') });
    } finally {
      setBusy(false);
    }
  };

  const exportLabels = async () =>
    saveBlob(await downloadCsv('/feedback/export.csv'), 'analyst-feedback.csv');

  if (!models.data) return models.error ? <Notice tone="error">{models.error}</Notice> : <Loading />;
  const { registry, feedback: fb } = models.data;
  const det = registry.detector;
  const clf = registry.classifier;

  return (
    <div className="space-y-5">
      {message && <Notice tone={message.tone}>{message.text}</Notice>}
      <Notice tone={fb.retrain_recommended ? 'warn' : 'ok'}>
        <div className="font-medium">
          {fb.retrain_recommended ? 'Retraining recommended' : 'Model health'}
        </div>
        <div className="mt-0.5 text-xs">{fb.retrain_reason}</div>
      </Notice>

      <div className="grid gap-5 lg:grid-cols-2">
        <Panel
          title="Deployed models"
          aside={
            <Button size="sm" variant="secondary" loading={busy} onClick={reload}>
              Reload models
            </Button>
          }
        >
          <dl className="space-y-2 text-sm">
            <div className="flex justify-between">
              <dt className="text-secondary">Detector</dt>
              <dd className="font-mono text-xs text-text">{det?.version ?? 'not loaded'}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-secondary">ROC-AUC (offline test)</dt>
              <dd className="font-mono text-xs text-text">{String(det?.metrics.roc_auc ?? '—')}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-secondary">False-positive rate (offline)</dt>
              <dd className="font-mono text-xs text-text">
                {String(det?.metrics.false_positive_rate ?? '—')}
              </dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-secondary">Classifier</dt>
              <dd className="font-mono text-xs text-text">{clf?.version ?? 'not loaded'}</dd>
            </div>
            <div className="flex justify-between">
              <dt className="text-secondary">Categories</dt>
              <dd className="text-xs text-text">{clf?.classes.join(', ') ?? '—'}</dd>
            </div>
          </dl>
          <p className="mt-3 text-2xs text-muted">
            To retrain, run <code className="font-mono">python -m app.ml.training.train</code>{' '}
            offline, drop the new artifacts into <code className="font-mono">ml/models/artifacts</code>{' '}
            and press Reload models.
          </p>
        </Panel>

        <Panel
          title="Live accuracy from analyst feedback"
          aside={
            <button onClick={exportLabels} className="text-xs text-accent hover:underline">
              Export labelled data
            </button>
          }
        >
          {fb.total === 0 ? (
            <p className="text-sm text-secondary">
              No corrections yet. Analysts confirm or correct verdicts from the Threat Monitor; that
              ground truth measures real-world accuracy and feeds retraining.
            </p>
          ) : (
            <dl className="space-y-2 text-sm">
              <div className="flex justify-between">
                <dt className="text-secondary">Reviewed samples</dt>
                <dd className="font-mono text-text">
                  {fb.total} ({fb.confirmed_malicious} malicious · {fb.confirmed_benign} benign)
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-secondary">Verdicts matching analysts</dt>
                <dd className="font-mono text-text">{pct(fb.agreement_rate)}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-secondary">Fused verdict precision / recall</dt>
                <dd className="font-mono text-text">
                  {pct(fb.fused_verdict.precision)} / {pct(fb.fused_verdict.recall)}
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-secondary">ML detector precision / recall</dt>
                <dd className="font-mono text-text">
                  {pct(fb.ml_detector.precision)} / {pct(fb.ml_detector.recall)}
                </dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-secondary">False positives / negatives</dt>
                <dd className="font-mono text-text">
                  {fb.fused_verdict.fp} / {fb.fused_verdict.fn}
                </dd>
              </div>
            </dl>
          )}
        </Panel>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */

export function AdminPage() {
  const [tab, setTab] = useState<TabId>('overview');

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-lg font-semibold tracking-[-0.01em]">Admin Console</h2>
        <p className="mt-1 text-sm text-secondary">
          Manage users and roles, platform settings and security policies, integrations, and the
          deployed models. Monitor platform activity.
        </p>
      </div>

      <div role="tablist" aria-label="Admin sections" className="flex gap-1 overflow-x-auto border-b border-line">
        {TABS.map((t) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={tab === t.id}
            onClick={() => setTab(t.id)}
            className={`shrink-0 border-b-2 px-3 py-2 text-sm transition-colors ${
              tab === t.id
                ? 'border-accent font-medium text-accent'
                : 'border-transparent text-secondary hover:text-text'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'overview' && <OverviewTab />}
      {tab === 'users' && <UsersTab />}
      {tab === 'settings' && <SettingsTab />}
      {tab === 'integrations' && <IntegrationsTab />}
      {tab === 'audit' && <AuditTab />}
      {tab === 'models' && <ModelsTab />}
    </div>
  );
}
