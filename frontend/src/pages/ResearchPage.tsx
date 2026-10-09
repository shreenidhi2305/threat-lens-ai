import { useState } from 'react';

import { downloadCsv, fetchDatasets, fetchFamilies, fetchFamilyDetail } from '../lib/api';
import type { DatasetInfo } from '../lib/adminTypes';
import { ago, errorMessage, saveBlob } from '../lib/download';
import { useAsync } from '../lib/useAsync';
import { FlaskIcon } from '../ui/icons';
import { Badge, EmptyState, Panel, Spinner } from '../ui/primitives';

const ISO = /^\d{4}-\d{2}-\d{2}T/;

function stat(value: unknown): string {
  if (value == null) return '—';
  if (typeof value === 'number') return value.toLocaleString();
  if (typeof value === 'string' && ISO.test(value)) {
    return new Date(value).toLocaleDateString(undefined, {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
    });
  }
  return String(value);
}

function DatasetCard({ d, onError }: { d: DatasetInfo; onError: (m: string) => void }) {
  const [busy, setBusy] = useState(false);

  const exportIt = async () => {
    if (!d.export_path) return;
    setBusy(true);
    try {
      saveBlob(await downloadCsv(d.export_path), `${d.id}.csv`);
    } catch (err) {
      onError(errorMessage(err, 'Export failed'));
    } finally {
      setBusy(false);
    }
  };

  const entries = Object.entries(d.stats).filter(
    ([, v]) => v != null && typeof v !== 'object' && v !== '',
  );
  const classes = d.stats.classes as string[] | undefined;

  return (
    <Panel
      title={d.name}
      aside={
        d.exportable ? (
          <button
            onClick={exportIt}
            disabled={busy}
            className="text-xs text-accent hover:underline disabled:opacity-50"
          >
            {busy ? 'Exporting…' : 'Export CSV'}
          </button>
        ) : (
          <Badge tone="neutral">reference only</Badge>
        )
      }
    >
      <p className="text-sm text-secondary">{d.description}</p>
      <div className="mt-3 flex flex-wrap items-baseline gap-x-6 gap-y-1 text-sm">
        <span>
          <span className="font-mono text-lg text-text">{d.records.toLocaleString()}</span>{' '}
          <span className="text-secondary">records</span>
        </span>
        {d.license && <Badge tone="accent">{d.license} licence</Badge>}
      </div>
      <dl className="mt-3 text-xs">
        {entries.map(([k, v]) => (
          <div key={k} className="flex justify-between gap-3 border-b border-line-soft py-1.5">
            <dt className="shrink-0 capitalize text-secondary">{k.replace(/_/g, ' ')}</dt>
            <dd className="break-all text-right font-mono text-text">{stat(v)}</dd>
          </div>
        ))}
      </dl>
      {classes && classes.length > 0 && (
        <p className="mt-2 text-xs text-secondary">Classes: {classes.join(', ')}</p>
      )}
      {d.source && <p className="mt-2 break-all font-mono text-2xs text-muted">{d.source}</p>}
      {d.note && <p className="mt-2 text-2xs text-muted">{d.note}</p>}
    </Panel>
  );
}

function FamilyDetailPanel({ name, onClose }: { name: string; onClose: () => void }) {
  const detail = useAsync((signal) => fetchFamilyDetail(name, signal), [name]);
  const d = detail.data;

  return (
    <Panel
      title={`Family · ${name}`}
      aside={
        <button onClick={onClose} className="text-xs text-muted hover:text-secondary">
          Close
        </button>
      }
    >
      {!d ? (
        <div className="flex justify-center py-6">
          <Spinner />
        </div>
      ) : (
        <div className="space-y-4">
          <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-sm sm:grid-cols-4">
            <div>
              <dt className="text-2xs uppercase tracking-[0.06em] text-muted">Samples</dt>
              <dd className="font-mono text-text">{d.samples}</dd>
            </div>
            <div>
              <dt className="text-2xs uppercase tracking-[0.06em] text-muted">Avg score</dt>
              <dd className="font-mono text-text">{d.avg_score}</dd>
            </div>
            <div>
              <dt className="text-2xs uppercase tracking-[0.06em] text-muted">Avg ML probability</dt>
              <dd className="font-mono text-text">
                {d.avg_ml_probability == null ? '—' : `${(d.avg_ml_probability * 100).toFixed(0)}%`}
              </dd>
            </div>
            <div>
              <dt className="text-2xs uppercase tracking-[0.06em] text-muted">Avg YARA rules</dt>
              <dd className="font-mono text-text">{d.avg_yara_rules}</dd>
            </div>
          </dl>

          <div className="flex flex-wrap gap-2 text-xs">
            {Object.entries(d.agreement).map(([k, v]) => (
              <span key={k} className="rounded-md border border-line-soft bg-surface-raised px-2 py-1 text-secondary">
                {k} <span className="font-mono text-text">{v}</span>
              </span>
            ))}
            {Object.entries(d.ml_categories).map(([k, v]) => (
              <span key={k} className="rounded-md border border-line-soft bg-surface-raised px-2 py-1 text-secondary">
                ML {k} <span className="font-mono text-text">{v}</span>
              </span>
            ))}
            {d.signatures.map((s) => (
              <Badge key={s} tone="high">
                {s}
              </Badge>
            ))}
          </div>

          <div className="overflow-x-auto rounded-lg border border-line-soft">
            <table className="w-full text-sm">
              <thead className="bg-surface-raised/60 text-left text-2xs uppercase tracking-[0.06em] text-muted">
                <tr>
                  <th className="px-3 py-2 font-medium">Sample</th>
                  <th className="px-3 py-2 font-medium">Verdict</th>
                  <th className="px-3 py-2 font-medium">Score</th>
                  <th className="hidden px-3 py-2 font-medium sm:table-cell">SHA-256</th>
                  <th className="px-3 py-2 text-right font-medium">Seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line-soft">
                {d.recent_samples.map((s) => (
                  <tr key={s.sha256 + s.at}>
                    <td className="px-3 py-2 font-mono text-xs text-text">{s.filename}</td>
                    <td className="px-3 py-2 text-xs text-secondary">{s.verdict}</td>
                    <td className="px-3 py-2 font-mono text-xs text-text">{s.score}</td>
                    <td className="hidden max-w-[14rem] truncate px-3 py-2 font-mono text-2xs text-muted sm:table-cell" title={s.sha256}>
                      {s.sha256}
                    </td>
                    <td className="px-3 py-2 text-right text-xs text-muted">{ago(s.at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </Panel>
  );
}

export function ResearchPage() {
  const datasets = useAsync((signal) => fetchDatasets(signal));
  const families = useAsync((signal) => fetchFamilies(signal));
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);

  const exportFamilies = async () => {
    setExporting(true);
    try {
      saveBlob(await downloadCsv('/research/families/export.csv'), 'malware-families.csv');
    } catch (err) {
      setError(errorMessage(err, 'Export failed'));
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-semibold tracking-[-0.01em]">Research workspace</h2>
        <p className="mt-1 text-sm text-secondary">
          Malware datasets and family analysis built from everything analysed on this platform.
          Exports are CSV for use in notebooks and external tools.
        </p>
      </div>

      {error && (
        <div className="rounded-md border border-risk-high/40 bg-risk-high-wash px-3 py-2 text-sm text-risk-high">
          {error}
        </div>
      )}

      <section className="space-y-3">
        <h3 className="text-2xs font-semibold uppercase tracking-[0.08em] text-muted">Datasets</h3>
        {!datasets.data ? (
          <div className="flex justify-center py-10">
            <Spinner />
          </div>
        ) : (
          <div className="grid gap-4 md:grid-cols-2 2xl:grid-cols-3">
            {datasets.data.map((d) => (
              <DatasetCard key={d.id} d={d} onError={setError} />
            ))}
          </div>
        )}
      </section>

      <section className="space-y-3">
        <h3 className="text-2xs font-semibold uppercase tracking-[0.08em] text-muted">
          Malware families
        </h3>
        <Panel
          title="Families seen"
          aside={
            <button
              onClick={exportFamilies}
              disabled={exporting}
              className="text-xs text-accent hover:underline disabled:opacity-50"
            >
              {exporting ? 'Exporting…' : 'Export CSV'}
            </button>
          }
        >
          {!families.data ? (
            <div className="flex justify-center py-8">
              <Spinner />
            </div>
          ) : families.data.length === 0 ? (
            <EmptyState
              icon={<FlaskIcon />}
              title="No families yet"
              description="Analyse malicious samples and their families are profiled here."
            />
          ) : (
            <div className="overflow-x-auto rounded-lg border border-line-soft">
              <table className="w-full text-sm">
                <thead className="bg-surface-raised/60 text-left text-2xs uppercase tracking-[0.06em] text-muted">
                  <tr>
                    <th className="px-3 py-2 font-medium">Family</th>
                    <th className="px-3 py-2 font-medium">Samples</th>
                    <th className="hidden px-3 py-2 font-medium sm:table-cell">Malicious</th>
                    <th className="px-3 py-2 font-medium">Avg score</th>
                    <th className="hidden px-3 py-2 font-medium md:table-cell">ML categories</th>
                    <th className="px-3 py-2 text-right font-medium">Last seen</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line-soft">
                  {families.data.map((f) => (
                    <tr
                      key={f.family}
                      onClick={() => setSelected(selected === f.family ? null : f.family)}
                      className={`cursor-pointer transition-colors hover:bg-surface-raised ${
                        selected === f.family ? 'bg-surface-raised/60' : ''
                      }`}
                    >
                      <td className="px-3 py-2.5 text-text">{f.family}</td>
                      <td className="px-3 py-2.5 font-mono text-xs text-text">{f.samples}</td>
                      <td className="hidden px-3 py-2.5 font-mono text-xs text-secondary sm:table-cell">
                        {f.malicious}
                      </td>
                      <td className="px-3 py-2.5 font-mono text-xs text-text">{f.avg_score}</td>
                      <td className="hidden px-3 py-2.5 text-xs text-secondary md:table-cell">
                        {Object.keys(f.ml_categories).join(', ') || '—'}
                      </td>
                      <td className="px-3 py-2.5 text-right text-xs text-muted">{ago(f.last_seen)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
        {selected && <FamilyDetailPanel name={selected} onClose={() => setSelected(null)} />}
      </section>
    </div>
  );
}
