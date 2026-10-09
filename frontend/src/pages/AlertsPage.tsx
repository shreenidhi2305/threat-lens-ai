import { useState } from 'react';

import {
  acknowledgeAlert,
  createIncident,
  fetchAlertStats,
  fetchAlerts,
  fetchIncidents,
  resolveAlert,
  updateIncidentStatus,
} from '../lib/api';
import type { Alert, Incident } from '../lib/types';
import { useAsync } from '../lib/useAsync';
import { Button } from '../ui/Button';
import { BellIcon } from '../ui/icons';
import { Badge, EmptyState, Panel, Spinner } from '../ui/primitives';

function ago(iso: string): string {
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

const STATUS_TONE = {
  open: 'high',
  acknowledged: 'medium',
  resolved: 'low',
} as const;

const INCIDENT_TONE = { open: 'high', contained: 'medium', closed: 'low' } as const;
const INCIDENT_STATES: Incident['status'][] = ['open', 'contained', 'closed'];

export function AlertsPage() {
  const alerts = useAsync((signal) => fetchAlerts(undefined, signal));
  const stats = useAsync(fetchAlertStats);
  const incidents = useAsync(fetchIncidents);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);

  const refresh = () => {
    alerts.reload();
    stats.reload();
    incidents.reload();
  };

  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    try {
      await fn();
      setSelected(new Set());
      refresh();
    } finally {
      setBusy(false);
    }
  };

  const toggle = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const list = alerts.data ?? [];
  const st = stats.data;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold tracking-[-0.01em]">Alerts</h2>
          <p className="mt-1 text-sm text-secondary">
            Raised automatically when the fused verdict is {`≥`} high risk.
            {st && !st.notifications_enabled && (
              <span className="text-muted"> Email notifications are not configured.</span>
            )}
          </p>
        </div>
        {selected.size > 0 && (
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="secondary"
              loading={busy}
              onClick={() =>
                act(() => createIncident([...selected], `Incident: ${selected.size} alerts`))
              }
            >
              Create incident ({selected.size})
            </Button>
          </div>
        )}
      </div>

      {st && (
        <div className="flex flex-wrap gap-x-6 gap-y-1 text-sm text-secondary">
          <span>
            <span className="font-mono text-risk-high">{st.open}</span> open
          </span>
          <span>
            <span className="font-mono text-risk-medium">{st.acknowledged}</span> acknowledged
          </span>
          <span>
            <span className="font-mono text-muted">{st.resolved}</span> resolved
          </span>
          {incidents.data && incidents.data.length > 0 && (
            <span>
              <span className="font-mono text-text">{incidents.data.length}</span> incident(s)
            </span>
          )}
        </div>
      )}

      {incidents.data && incidents.data.length > 0 && (
        <Panel title={`Incidents · ${incidents.data.length}`}>
          <ul className="divide-y divide-line-soft">
            {incidents.data.map((inc: Incident) => (
              <li
                key={inc.id}
                className="flex flex-col gap-2 py-2.5 sm:flex-row sm:items-center sm:justify-between"
              >
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-medium text-text">{inc.title}</span>
                    <Badge tone={inc.severity === 'critical' ? 'high' : 'medium'}>{inc.severity}</Badge>
                    <Badge tone={INCIDENT_TONE[inc.status]}>{inc.status}</Badge>
                  </div>
                  <div className="mt-0.5 text-2xs text-muted">
                    {inc.alert_ids.length} alert(s) ·{' '}
                    {list
                      .filter((a) => a.incident_id === inc.id)
                      .map((a) => a.sample_name)
                      .join(', ') || 'linked alerts'}{' '}
                    · opened {ago(inc.created_at)}
                    {inc.closed_at && ` · closed ${ago(inc.closed_at)}`}
                  </div>
                </div>
                <select
                  aria-label={`Status of ${inc.title}`}
                  value={inc.status}
                  disabled={busy}
                  onChange={(e) =>
                    act(() => updateIncidentStatus(inc.id, e.target.value as Incident['status']))
                  }
                  className="rounded-md border border-line bg-surface px-2 py-1 text-xs text-text outline-none focus:border-accent disabled:opacity-50"
                >
                  {INCIDENT_STATES.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </select>
              </li>
            ))}
          </ul>
        </Panel>
      )}

      {alerts.loading ? (
        <div className="flex justify-center py-16">
          <Spinner />
        </div>
      ) : list.length === 0 ? (
        <EmptyState
          icon={<BellIcon />}
          title="No open alerts"
          description="High-risk verdicts generate an alert here for triage."
        />
      ) : (
        <ul className="space-y-2.5">
          {list.map((a: Alert) => (
            <li
              key={a.id}
              className={`rounded-lg border px-4 py-3 ${
                a.status === 'resolved'
                  ? 'border-line bg-surface opacity-60'
                  : 'border-risk-high/30 bg-risk-high-wash'
              }`}
            >
              <div className="flex items-start gap-3">
                <input
                  type="checkbox"
                  checked={selected.has(a.id)}
                  onChange={() => toggle(a.id)}
                  className="mt-1 accent-[var(--accent)]"
                  aria-label={`Select alert ${a.title}`}
                />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-medium text-text">{a.title}</span>
                    <Badge tone={a.severity === 'critical' ? 'high' : 'medium'}>{a.severity}</Badge>
                    <Badge tone={STATUS_TONE[a.status]}>{a.status}</Badge>
                    {a.incident_id && <Badge tone="accent">incident</Badge>}
                  </div>
                  <div className="mt-0.5 flex flex-wrap items-center gap-x-3 text-xs text-secondary">
                    <span className="truncate font-mono">{a.sample_name}</span>
                    <span>score {a.verdict_score}</span>
                    {a.category && <span>{a.category}</span>}
                    {a.notified && <span className="text-muted">emailed</span>}
                  </div>
                </div>
                <div className="flex shrink-0 flex-col items-end gap-1.5">
                  <span className="text-2xs text-muted">{ago(a.created_at)}</span>
                  {a.status !== 'resolved' && (
                    <div className="flex gap-1.5">
                      {a.status === 'open' && (
                        <button
                          disabled={busy}
                          onClick={() => act(() => acknowledgeAlert(a.id))}
                          className="rounded border border-line px-2 py-0.5 text-2xs text-secondary hover:text-text disabled:opacity-50"
                        >
                          Acknowledge
                        </button>
                      )}
                      <button
                        disabled={busy}
                        onClick={() => act(() => resolveAlert(a.id))}
                        className="rounded border border-line px-2 py-0.5 text-2xs text-secondary hover:text-text disabled:opacity-50"
                      >
                        Resolve
                      </button>
                    </div>
                  )}
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
