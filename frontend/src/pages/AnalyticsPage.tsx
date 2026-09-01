import { getHistory } from '../lib/history';
import type { RiskLevel } from '../lib/types';
import { ChartIcon } from '../ui/icons';
import { EmptyState, Panel, Stat } from '../ui/primitives';

const LEVELS: { key: RiskLevel; label: string; color: string }[] = [
  { key: 'high', label: 'High', color: 'var(--risk-high)' },
  { key: 'medium', label: 'Medium', color: 'var(--risk-medium)' },
  { key: 'low', label: 'Low', color: 'var(--risk-low)' },
];

export function AnalyticsPage() {
  const history = getHistory();

  if (history.length === 0) {
    return (
      <div className="space-y-5">
        <h2 className="text-lg font-semibold tracking-[-0.01em]">Analytics</h2>
        <EmptyState
          icon={<ChartIcon />}
          title="Nothing to chart yet"
          description="Analyze a few files and this page will summarize risk distribution and detection rates."
        />
      </div>
    );
  }

  const total = history.length;
  const counts = Object.fromEntries(
    LEVELS.map((l) => [l.key, history.filter((h) => h.level === l.key).length]),
  ) as Record<RiskLevel, number>;
  const detections = history.filter((h) => h.level !== 'low').length;
  const avg = Math.round(history.reduce((s, h) => s + h.score, 0) / total);

  const classCounts = history.reduce<Record<string, number>>((acc, h) => {
    acc[h.classification] = (acc[h.classification] ?? 0) + 1;
    return acc;
  }, {});
  const topClasses = Object.entries(classCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);

  return (
    <div className="space-y-7">
      <div>
        <h2 className="text-lg font-semibold tracking-[-0.01em]">Analytics</h2>
        <p className="mt-1 text-sm text-secondary">
          Summary across {total} analyzed {total === 1 ? 'file' : 'files'} this session.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <Stat label="Total analyzed" value={total} />
        <Stat
          label="Detection rate"
          value={`${Math.round((detections / total) * 100)}%`}
          hint={`${detections} flagged medium or high`}
        />
        <Stat label="Average risk score" value={`${avg}/100`} />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Risk distribution">
          <div className="space-y-3">
            {LEVELS.map((l) => {
              const n = counts[l.key];
              const pct = Math.round((n / total) * 100);
              return (
                <div key={l.key}>
                  <div className="mb-1 flex items-center justify-between text-xs">
                    <span className="text-secondary">{l.label}</span>
                    <span className="font-mono text-muted">
                      {n} · {pct}%
                    </span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-surface-raised">
                    <div
                      className="h-full rounded-full transition-[width] duration-500 ease-out"
                      style={{ width: `${Math.max(pct, n ? 3 : 0)}%`, backgroundColor: l.color }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </Panel>

        <Panel title="Top classifications">
          {topClasses.length === 0 ? (
            <p className="text-sm text-secondary">No classifications recorded.</p>
          ) : (
            <ul className="space-y-2">
              {topClasses.map(([name, n]) => (
                <li key={name} className="flex items-center justify-between gap-4 text-sm">
                  <span className="truncate text-text">{name}</span>
                  <span className="shrink-0 font-mono text-xs text-muted">{n}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
    </div>
  );
}
