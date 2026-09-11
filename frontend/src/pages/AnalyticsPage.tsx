import { fetchDetections, fetchModelInfo, fetchThreatSnapshot } from '../lib/api';
import type { RiskLevel } from '../lib/types';
import { useAsync } from '../lib/useAsync';
import { ChartIcon } from '../ui/icons';
import { EmptyState, Panel, Spinner, Stat } from '../ui/primitives';

const LEVELS: { key: RiskLevel; label: string; color: string }[] = [
  { key: 'high', label: 'High', color: 'var(--risk-high)' },
  { key: 'medium', label: 'Medium', color: 'var(--risk-medium)' },
  { key: 'low', label: 'Low', color: 'var(--risk-low)' },
];

function pct(n: number): string {
  return `${(n * 100).toFixed(1)}%`;
}

export function AnalyticsPage() {
  const detections = useAsync(() => fetchDetections(500));
  const snapshot = useAsync(fetchThreatSnapshot);
  const model = useAsync(fetchModelInfo);

  if (detections.loading || snapshot.loading) {
    return (
      <div className="flex justify-center py-20">
        <Spinner />
      </div>
    );
  }

  const items = detections.data ?? [];
  const s = snapshot.data;

  if (!s || s.total_detections === 0) {
    return (
      <div className="space-y-5">
        <h2 className="text-lg font-semibold tracking-[-0.01em]">Analytics</h2>
        <EmptyState
          icon={<ChartIcon />}
          title="Nothing to chart yet"
          description="Analyse a few files and this page summarises risk distribution, engine agreement and model performance."
        />
      </div>
    );
  }

  const total = s.total_detections;
  const detectionRate = (s.malicious + s.suspicious) / total;
  const byLevel = Object.fromEntries(
    LEVELS.map((l) => [l.key, items.filter((d) => d.level === l.key).length]),
  ) as Record<RiskLevel, number>;
  const agreementCounts = items.reduce<Record<string, number>>((acc, d) => {
    const k = d.agreement ?? 'unknown';
    acc[k] = (acc[k] ?? 0) + 1;
    return acc;
  }, {});
  const mlCaught = items.filter((d) => d.agreement === 'ml-only').length;

  const det = model.data?.detector;
  const m = (det?.metrics ?? {}) as Record<string, number>;

  return (
    <div className="space-y-7">
      <div>
        <h2 className="text-lg font-semibold tracking-[-0.01em]">Analytics</h2>
        <p className="mt-1 text-sm text-secondary">
          Across {total} analysed {total === 1 ? 'file' : 'files'}.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-4">
        <Stat label="Total analysed" value={total} />
        <Stat label="Detection rate" value={pct(detectionRate)} hint={`${s.malicious + s.suspicious} flagged`} />
        <Stat label="ML-only catches" value={mlCaught} hint="missed by the rule engine" />
        <Stat label="Last 24h" value={s.last_24h} />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Risk distribution">
          <div className="space-y-3">
            {LEVELS.map((l) => {
              const n = byLevel[l.key];
              const p = Math.round((n / total) * 100);
              return (
                <div key={l.key}>
                  <div className="mb-1 flex items-center justify-between text-xs">
                    <span className="text-secondary">{l.label}</span>
                    <span className="font-mono text-muted">
                      {n} · {p}%
                    </span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-surface-raised">
                    <div
                      className="h-full rounded-full transition-[width] duration-500 ease-out"
                      style={{ width: `${Math.max(p, n ? 3 : 0)}%`, backgroundColor: l.color }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </Panel>

        <Panel title="Engine agreement">
          <ul className="space-y-2 text-sm">
            {(['agree', 'ml-only', 'rules-only', 'conflict'] as const).map((k) => (
              <li key={k} className="flex items-center justify-between gap-4">
                <span className="text-secondary">{k}</span>
                <span className="font-mono text-xs text-muted">{agreementCounts[k] ?? 0}</span>
              </li>
            ))}
          </ul>
        </Panel>

        <Panel title="Top malware families">
          {s.top_families.length === 0 ? (
            <p className="text-sm text-secondary">No malicious detections yet.</p>
          ) : (
            <ul className="space-y-2">
              {s.top_families.map((f) => (
                <li key={f.family} className="flex items-center justify-between gap-4 text-sm">
                  <span className="truncate text-text">{f.family}</span>
                  <span className="shrink-0 font-mono text-xs text-muted">{f.count}</span>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Detection model">
          {det ? (
            <div className="space-y-1.5 text-sm">
              <div className="flex justify-between">
                <span className="text-secondary">Version</span>
                <span className="font-mono text-xs text-text">{det.version}</span>
              </div>
              {['roc_auc', 'precision', 'recall', 'false_positive_rate'].map((k) =>
                m[k] == null ? null : (
                  <div key={k} className="flex justify-between">
                    <span className="text-secondary">{k.replace(/_/g, ' ')}</span>
                    <span className="font-mono text-xs text-text">{m[k].toFixed(4)}</span>
                  </div>
                ),
              )}
              {model.data?.classifier && (
                <div className="flex justify-between pt-1">
                  <span className="text-secondary">Categories</span>
                  <span className="text-xs text-text">
                    {model.data.classifier.classes.join(', ')}
                  </span>
                </div>
              )}
            </div>
          ) : (
            <p className="text-sm text-secondary">Model registry not loaded.</p>
          )}
        </Panel>
      </div>
    </div>
  );
}
