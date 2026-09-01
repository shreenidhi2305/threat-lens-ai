import { getHistory } from '../lib/history';
import { BellIcon } from '../ui/icons';
import { Badge, EmptyState } from '../ui/primitives';

function ago(ts: number): string {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function AlertsPage() {
  const alerts = getHistory().filter((h) => h.level === 'high');

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-lg font-semibold tracking-[-0.01em]">Alerts</h2>
        <p className="mt-1 text-sm text-secondary">
          Raised automatically when a file is classified high risk.
        </p>
      </div>

      {alerts.length === 0 ? (
        <EmptyState
          icon={<BellIcon />}
          title="No open alerts"
          description="High-risk classifications generate an alert here for review."
        />
      ) : (
        <ul className="space-y-2.5">
          {alerts.map((a) => (
            <li
              key={a.id}
              className="flex items-start gap-3 rounded-lg border border-risk-high/30 bg-risk-high-wash px-4 py-3"
            >
              <BellIcon className="mt-0.5 shrink-0 text-risk-high" />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-medium text-text">{a.classification}</span>
                  <Badge tone="high">score {a.score}</Badge>
                </div>
                <div className="mt-0.5 truncate font-mono text-xs text-secondary">{a.filename}</div>
              </div>
              <span className="shrink-0 text-2xs text-muted">{ago(a.at)}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
