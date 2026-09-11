import { Fragment, useEffect, useMemo, useState } from 'react';

import {
  fetchDetections,
  fetchThreatFamilies,
  fetchThreatStats,
  fetchThreatTimeline,
} from '../lib/api';
import type { Detection, RiskLevel } from '../lib/types';
import { useAsync } from '../lib/useAsync';
import { RadarIcon } from '../ui/icons';
import { Badge, EmptyState, Panel, Spinner, Stat } from '../ui/primitives';

const DOT: Record<RiskLevel, string> = {
  low: 'bg-risk-low',
  medium: 'bg-risk-medium',
  high: 'bg-risk-high',
};

type WindowKey = '24h' | '7d' | '30d';

function ago(iso: string): string {
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
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
const inputCls =
  'w-full rounded-md border border-line bg-surface px-2.5 py-1.5 text-xs text-text placeholder:text-muted outline-none focus:border-accent sm:w-56';

export function ThreatsPage() {
  const [q, setQ] = useState('');
  const [debouncedQ, setDebouncedQ] = useState('');
  const [level, setLevel] = useState('');
  const [verdict, setVerdict] = useState('');
  const [family, setFamily] = useState('');
  const [window, setWindow] = useState<WindowKey>('24h');
  const [threatsOnly, setThreatsOnly] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);

  useEffect(() => {
    const t = setTimeout(() => setDebouncedQ(q.trim()), 350);
    return () => clearTimeout(t);
  }, [q]);

  const stats = useAsync(fetchThreatStats);
  const timeline = useAsync(() => fetchThreatTimeline(window), [window]);
  const families = useAsync(fetchThreatFamilies);
  const detections = useAsync(
    () =>
      fetchDetections(500, {
        level: level || undefined,
        verdict: verdict || undefined,
        family: family || undefined,
        q: debouncedQ || undefined,
      }),
    [level, verdict, family, debouncedQ],
  );

  // Auto-refresh every 15s for real-time monitoring.
  useEffect(() => {
    const id = setInterval(() => {
      stats.reload();
      timeline.reload();
      detections.reload();
    }, 15000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const reloadAll = (): void => {
    stats.reload();
    timeline.reload();
    detections.reload();
    families.reload();
  };

  const rows = useMemo(() => {
    const all = detections.data ?? [];
    if (!threatsOnly) return all;
    return all.filter((d) => d.verdict_label !== 'benign');
  }, [detections.data, threatsOnly]);

  const s = stats.data;
  const buckets = timeline.data ?? [];
  const maxBucket = Math.max(...buckets.map((b) => b.total), 1);
  const familyOptions = families.data ?? [];
  const loading = stats.loading && detections.loading && timeline.loading;
  const error = stats.error ?? detections.error ?? timeline.error;

  const exportCsv = (): void => {
    const blob = new Blob([toCsv(rows)], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threats-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const byLevel = s?.by_level ?? {};

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-lg font-semibold tracking-[-0.01em]">
            Threat Monitor
            <span className="flex items-center gap-1.5 rounded-full border border-line px-2 py-0.5 text-2xs font-normal text-secondary">
              <span className="size-1.5 animate-pulse rounded-full bg-risk-low" /> Live
            </span>
          </h2>
          <p className="mt-1 text-sm text-secondary">
            Real-time tracking of flagged files, families, and detection activity.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-2xs text-muted">Auto-refresh 15s</span>
          <button
            type="button"
            onClick={reloadAll}
            className="rounded-md border border-line px-2.5 py-1.5 text-xs text-secondary hover:text-text"
          >
            Refresh
          </button>
          <button
            type="button"
            onClick={exportCsv}
            disabled={rows.length === 0}
            className="rounded-md border border-line px-2.5 py-1.5 text-xs text-secondary hover:text-text disabled:opacity-50"
          >
            Export CSV
          </button>
        </div>
      </div>

      {loading ? (
        <div className="flex justify-center py-16">
          <Spinner />
        </div>
      ) : error && rows.length === 0 && !s ? (
        <EmptyState
          icon={<RadarIcon />}
          title="Could not load threat data"
          description={error}
          action={
            <button
              type="button"
              onClick={reloadAll}
              className="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-white"
            >
              Retry
            </button>
          }
        />
      ) : (
        <>
          <div className="grid gap-4 sm:grid-cols-3 lg:grid-cols-6">
            <Stat label="Total" value={s?.total_detections ?? '—'} />
            <Stat
              label="Malicious"
              value={
                <span className={s?.malicious ? 'text-risk-high' : undefined}>
                  {s?.malicious ?? '—'}
                </span>
              }
            />
            <Stat
              label="Suspicious"
              value={
                <span className={s?.suspicious ? 'text-risk-medium' : undefined}>
                  {s?.suspicious ?? '—'}
                </span>
              }
            />
            <Stat label="Benign" value={s?.benign ?? '—'} />
            <Stat
              label="Open alerts"
              value={
                <span className={s?.open_alerts ? 'text-risk-high' : undefined}>
                  {s?.open_alerts ?? '—'}
                </span>
              }
            />
            <Stat
              label="Last 24h"
              value={s?.last_24h ?? '—'}
              hint={
                s ? `detection rate ${(s.detection_rate * 100).toFixed(1)}%` : undefined
              }
            />
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <Panel
              title={`Activity · ${window}`}
              aside={
                <select
                  aria-label="Timeline window"
                  className={selectCls}
                  value={window}
                  onChange={(e) => setWindow(e.target.value as WindowKey)}
                >
                  <option value="24h">24h</option>
                  <option value="7d">7d</option>
                  <option value="30d">30d</option>
                </select>
              }
            >
              {buckets.length === 0 ? (
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

            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-1 xl:grid-cols-2">
              <Panel title="Risk distribution">
                {(['high', 'medium', 'low'] as const).map((lv) => {
                  const n = byLevel[lv] ?? 0;
                  const total = s?.total_detections ?? 0;
                  const p = total ? Math.round((n / total) * 100) : 0;
                  return (
                    <div key={lv} className="mb-2.5 last:mb-0">
                      <div className="mb-1 flex justify-between text-xs">
                        <span className="capitalize text-secondary">{lv}</span>
                        <span className="font-mono text-muted">
                          {n} · {p}%
                        </span>
                      </div>
                      <div className="h-1.5 overflow-hidden rounded-full bg-surface-raised">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${Math.max(p, n ? 3 : 0)}%`,
                            backgroundColor: `var(--risk-${lv})`,
                          }}
                        />
                      </div>
                    </div>
                  );
                })}
              </Panel>
              <Panel title="Top families">
                {!s || s.by_family.length === 0 ? (
                  <p className="text-sm text-secondary">No families yet.</p>
                ) : (
                  <ul className="space-y-1.5">
                    {s.by_family.slice(0, 6).map((f) => (
                      <li key={f.family} className="flex justify-between gap-3 text-sm">
                        <button
                          type="button"
                          onClick={() => setFamily(f.family === family ? '' : String(f.family))}
                          className="truncate text-text hover:underline"
                          title="Filter by family"
                        >
                          {String(f.family)}
                        </button>
                        <span className="font-mono text-xs text-muted">{String(f.count)}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </Panel>
            </div>
          </div>

          <Panel
            title="Threat feed"
            aside={
              <span className="text-2xs text-muted">
                {rows.length} shown · ML-only {s?.ml_only_catches ?? 0}
              </span>
            }
          >
            <div className="mb-3 flex flex-col gap-2 lg:flex-row lg:items-center">
              <input
                className={inputCls}
                placeholder="Search filename, sha256, family…"
                value={q}
                onChange={(e) => setQ(e.target.value)}
                aria-label="Search threats"
              />
              <div className="flex flex-wrap items-center gap-2">
                <select
                  aria-label="Risk level"
                  className={selectCls}
                  value={level}
                  onChange={(e) => setLevel(e.target.value)}
                >
                  <option value="">All levels</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
                <select
                  aria-label="Verdict"
                  className={selectCls}
                  value={verdict}
                  onChange={(e) => setVerdict(e.target.value)}
                >
                  <option value="">All verdicts</option>
                  <option value="malicious">Malicious</option>
                  <option value="suspicious">Suspicious</option>
                  <option value="benign">Benign</option>
                </select>
                <select
                  aria-label="Family"
                  className={selectCls}
                  value={family}
                  onChange={(e) => setFamily(e.target.value)}
                >
                  <option value="">All families</option>
                  {familyOptions.map((f) => (
                    <option key={f} value={f}>
                      {f}
                    </option>
                  ))}
                </select>
                <label className="flex items-center gap-1.5 text-xs text-secondary">
                  <input
                    type="checkbox"
                    checked={threatsOnly}
                    onChange={(e) => setThreatsOnly(e.target.checked)}
                    className="accent-[var(--accent)]"
                  />
                  Threats only
                </label>
                {(q || level || verdict || family) && (
                  <button
                    type="button"
                    onClick={() => {
                      setQ('');
                      setLevel('');
                      setVerdict('');
                      setFamily('');
                    }}
                    className="text-xs text-accent hover:underline"
                  >
                    Clear
                  </button>
                )}
              </div>
            </div>

            {detections.loading ? (
              <div className="flex justify-center py-10">
                <Spinner />
              </div>
            ) : rows.length === 0 ? (
              <EmptyState
                icon={<RadarIcon />}
                title="No threats match"
                description="Adjust filters or submit a file — flagged verdicts surface here."
              />
            ) : (
              <div className="overflow-x-auto rounded-lg border border-line-soft">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-line-soft text-left text-2xs uppercase tracking-[0.06em] text-muted">
                      <th className="px-4 py-2.5 font-medium">File</th>
                      <th className="hidden px-4 py-2.5 font-medium sm:table-cell">Family</th>
                      <th className="px-4 py-2.5 font-medium">Score</th>
                      <th className="hidden px-4 py-2.5 font-medium md:table-cell">Engines</th>
                      <th className="px-4 py-2.5 text-right font-medium">Analysed</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line-soft">
                    {rows.map((d) => (
                      <Fragment key={d.id}>
                        <tr
                          onClick={() => setExpanded(expanded === d.id ? null : d.id)}
                          className="cursor-pointer transition-colors hover:bg-surface-raised"
                        >
                          <td className="px-4 py-2.5">
                            <div className="flex items-center gap-2">
                              <span className={`size-1.5 shrink-0 rounded-full ${DOT[d.level]}`} />
                              <span className="truncate font-mono text-xs text-text">
                                {d.filename}
                              </span>
                            </div>
                            {d.ml_probability != null && (
                              <div className="mt-0.5 pl-3.5 text-2xs text-muted">
                                ML {(d.ml_probability * 100).toFixed(0)}%
                                {d.ml_category ? ` · ${d.ml_category}` : ''}
                              </div>
                            )}
                          </td>
                          <td className="hidden px-4 py-2.5 text-secondary sm:table-cell">
                            {d.family ?? '—'}
                          </td>
                          <td className="px-4 py-2.5">
                            <Badge tone={d.level}>{d.score}</Badge>
                          </td>
                          <td className="hidden px-4 py-2.5 text-xs text-muted md:table-cell">
                            {d.agreement ?? '—'}
                          </td>
                          <td className="px-4 py-2.5 text-right text-xs text-muted">
                            {ago(d.at)}
                          </td>
                        </tr>
                        {expanded === d.id && (
                          <tr className="bg-surface-raised/40">
                            <td colSpan={5} className="px-4 py-3">
                              <div className="grid gap-x-6 gap-y-1.5 text-xs sm:grid-cols-2">
                                <span className="break-all font-mono text-muted">
                                  sha256 {d.sha256}
                                </span>
                                <span className="text-secondary">
                                  verdict {d.verdict_label} · level {d.level}
                                </span>
                                <span className="text-secondary">
                                  yara {d.yara_rule_count} · signature {d.signature ?? '—'}
                                </span>
                                <span className="text-secondary">
                                  model {d.model_version ?? '—'} · analyst {d.analyst ?? '—'}
                                </span>
                              </div>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>
        </>
      )}
    </div>
  );
}
