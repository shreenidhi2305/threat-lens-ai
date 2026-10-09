import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import {
  fetchAnalyticsSummary,
  fetchAnalyticsTimeline,
  fetchDetections,
  fetchModelInfo,
} from '../lib/api';
import type { Detection } from '../lib/types';
import { useAsync } from '../lib/useAsync';
import { ChartIcon } from '../ui/icons';
import { EmptyState, Panel, Spinner, Stat } from '../ui/primitives';

const LEVELS: { key: string; label: string; color: string }[] = [
  { key: 'high', label: 'High', color: 'var(--risk-high)' },
  { key: 'medium', label: 'Medium', color: 'var(--risk-medium)' },
  { key: 'low', label: 'Low', color: 'var(--risk-low)' },
];

const VERDICTS: { key: string; label: string; color: string }[] = [
  { key: 'malicious', label: 'Malicious', color: 'var(--risk-high)' },
  { key: 'suspicious', label: 'Suspicious', color: 'var(--risk-medium)' },
  { key: 'benign', label: 'Benign', color: 'var(--risk-low)' },
];

type WindowKey = '24h' | '7d' | '30d';

function pct(n: number): string {
  return `${(n * 100).toFixed(1)}%`;
}

function toCsv(rows: Detection[]): string {
  const head = [
    'id', 'at', 'filename', 'sha256', 'verdict', 'level', 'score', 'family',
    'ml_probability', 'ml_category', 'yara_rules', 'signature', 'agreement', 'analyst',
  ];
  const esc = (v: unknown): string => {
    const s = v == null ? '' : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = rows.map((d) =>
    [
      d.id, d.at, d.filename, d.sha256, d.verdict_label, d.level, d.score, d.family ?? '',
      d.ml_probability ?? '', d.ml_category ?? '', d.yara_rule_count, d.signature ?? '',
      d.agreement ?? '', d.analyst ?? '',
    ]
      .map(esc)
      .join(','),
  );
  return [head.join(','), ...lines].join('\n');
}

const selectCls =
  'rounded-md border border-line bg-surface px-2 py-1.5 text-xs text-text outline-none focus:border-accent';

export function AnalyticsPage() {
  const [window_, setWindow] = useState<WindowKey>('7d');
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  const summary = useAsync(fetchAnalyticsSummary);
  const timeline = useAsync(() => fetchAnalyticsTimeline(window_), [window_]);
  const model = useAsync(fetchModelInfo);

  // Keep the dashboard current without a manual reload.
  useEffect(() => {
    const id = setInterval(() => {
      summary.reload();
      timeline.reload();
    }, 20000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (summary.loading) {
    return (
      <div className="flex justify-center py-20">
        <Spinner />
      </div>
    );
  }

  const s = summary.data;

  if (!s || s.total_samples === 0) {
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

  const total = s.total_samples;
  const buckets = timeline.data ?? [];
  const maxBucket = Math.max(...buckets.map((b) => b.total), 1);

  const det = model.data?.detector;
  const m = (det?.metrics ?? {}) as Record<string, number>;

  const exportCsv = async (): Promise<void> => {
    setExporting(true);
    setExportError(null);
    try {
      const rows = await fetchDetections(1000);
      const blob = new Blob([toCsv(rows)], { type: 'text/csv;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `analytics-detections-${new Date().toISOString().slice(0, 10)}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      setExportError('Could not export detections right now.');
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="space-y-7">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold tracking-[-0.01em]">Analytics</h2>
          <p className="mt-1 text-sm text-secondary">
            Across {total} analysed {total === 1 ? 'file' : 'files'}.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {exportError && <span className="text-xs text-risk-high">{exportError}</span>}
          <button
            type="button"
            onClick={exportCsv}
            disabled={exporting}
            className="rounded-md border border-line px-2.5 py-1.5 text-xs text-secondary hover:text-text disabled:opacity-50"
          >
            {exporting ? 'Exporting…' : 'Export CSV'}
          </button>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-4">
        <Stat label="Total analysed" value={total} />
        <Stat
          label="Detection rate"
          value={pct(s.detection_rate)}
          hint={`${s.malicious + s.suspicious} flagged`}
        />
        <Stat label="ML-only catches" value={s.ml_only_catches} hint="missed by the rule engine" />
        <Stat label="Last 24h" value={s.last_24h} />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel
          title={`Activity · ${window_}`}
          aside={
            <select
              aria-label="Timeline window"
              className={selectCls}
              value={window_}
              onChange={(e) => setWindow(e.target.value as WindowKey)}
            >
              <option value="24h">24h</option>
              <option value="7d">7d</option>
              <option value="30d">30d</option>
            </select>
          }
        >
          {timeline.loading ? (
            <div className="flex justify-center py-6">
              <Spinner />
            </div>
          ) : buckets.length === 0 ? (
            <p className="text-sm text-secondary">No activity in this window.</p>
          ) : (
            <div>
              <div className="flex h-24 items-end gap-1">
                {buckets.map((b) => (
                  <div
                    key={b.label + b.bucket}
                    title={`${b.label}: ${b.total} (${b.malicious} mal / ${b.suspicious} susp)`}
                    className={`min-w-0 flex-1 rounded-sm ${
                      b.malicious > 0
                        ? 'bg-risk-high/80'
                        : b.suspicious > 0
                          ? 'bg-risk-medium/80'
                          : b.total > 0
                            ? 'bg-risk-low/70'
                            : 'bg-surface-raised'
                    }`}
                    style={{ height: `${Math.max((b.total / maxBucket) * 100, b.total ? 6 : 4)}%` }}
                  />
                ))}
              </div>
              <div className="mt-1.5 flex justify-between text-2xs text-muted">
                <span>{buckets[0]?.label}</span>
                <span>{buckets[buckets.length - 1]?.label}</span>
              </div>
            </div>
          )}
        </Panel>

        <Panel title="Verdict breakdown">
          <div className="space-y-3">
            {VERDICTS.map((v) => {
              const n = s.by_verdict[v.key] ?? 0;
              const p = total ? Math.round((n / total) * 100) : 0;
              return (
                <div key={v.key}>
                  <div className="mb-1 flex items-center justify-between text-xs">
                    <span className="text-secondary">{v.label}</span>
                    <span className="font-mono text-muted">
                      {n} · {p}%
                    </span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-surface-raised">
                    <div
                      className="h-full rounded-full transition-[width] duration-500 ease-out"
                      style={{ width: `${Math.max(p, n ? 3 : 0)}%`, backgroundColor: v.color }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </Panel>

        <Panel title="Risk distribution">
          <div className="space-y-3">
            {LEVELS.map((l) => {
              const n = s.by_level[l.key] ?? 0;
              const p = total ? Math.round((n / total) * 100) : 0;
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
                <span className="font-mono text-xs text-muted">{s.by_agreement[k] ?? 0}</span>
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
                <li key={String(f.family)} className="flex items-center justify-between gap-4 text-sm">
                  <span className="truncate text-text">{String(f.family)}</span>
                  <span className="shrink-0 font-mono text-xs text-muted">{String(f.count)}</span>
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

        <Panel
          title="Operations snapshot"
          aside={
            <Link to="/reports" className="text-2xs text-accent hover:underline">
              Report Center
            </Link>
          }
        >
          <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-secondary">Open alerts</span>
              <span className={`font-mono text-xs ${s.open_alerts ? 'text-risk-high' : 'text-text'}`}>
                {s.open_alerts}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-secondary">Critical alerts</span>
              <span className={`font-mono text-xs ${s.critical_alerts ? 'text-risk-high' : 'text-text'}`}>
                {s.critical_alerts}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-secondary">Reports generated</span>
              <span className="font-mono text-xs text-text">{s.reports_generated}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-secondary">Avg. risk score</span>
              <span className="font-mono text-xs text-text">{s.avg_risk_score}</span>
            </div>
          </div>
        </Panel>
      </div>
    </div>
  );
}