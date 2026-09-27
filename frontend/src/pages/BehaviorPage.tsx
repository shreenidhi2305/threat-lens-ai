import { useRef, useState } from 'react';
import { AxiosError } from 'axios';

import { analyzeBehaviorDirect, fetchBehaviorCatalog } from '../lib/api';
import type { BehavioralAnalysisResult } from '../lib/types';
import { useAsync } from '../lib/useAsync';
import { ActivityIcon, DownloadIcon, LayersIcon, TargetIcon, UploadIcon } from '../ui/icons';
import { Badge, Panel, Spinner, SectionLabel } from '../ui/primitives';
import { BehaviorAnalysisPanel } from '../components/BehaviorAnalysisPanel';
import { Button } from '../ui/Button';

function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

export function BehaviorPage() {
  const catalog = useAsync(fetchBehaviorCatalog);
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<BehavioralAnalysisResult | null>(null);

  const run = async () => {
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      const r = await analyzeBehaviorDirect(file);
      setResult(r);
    } catch (err) {
      setError(err instanceof AxiosError ? String(err.response?.data?.detail ?? err.message) : 'Behavioral analysis failed');
    } finally {
      setBusy(false);
    }
  };

  if (catalog.loading) {
    return (
      <div className="flex justify-center py-20">
        <Spinner />
      </div>
    );
  }

  const total = catalog.data?.total ?? 0;
  const order = catalog.data?.tactic_order ?? [];
  type CatalogBehavior = { tactic: string; tactic_id: string; id: string; technique: string; technique_id: string; name: string; description: string; severity: string; mitre_url: string };
  const grouped = new Map<string, CatalogBehavior[]>();
  for (const b of (catalog.data?.behaviors ?? []) as CatalogBehavior[]) {
    const arr = grouped.get(b.tactic) || [];
    arr.push(b as CatalogBehavior);
    grouped.set(b.tactic, arr);
  }

  return (
    <div className="space-y-7">
      <div>
        <div className="flex items-center gap-2">
          <ActivityIcon className="text-lg text-accent" />
          <h2 className="text-lg font-semibold tracking-[-0.01em]">Behavioral Analysis System</h2>
        </div>
        <p className="mt-1 max-w-3xl text-sm text-secondary">
          Static behavioral inference without execution. The engine maps static signals (strings, imports, YARA techniques,
          network IOCs, packer heuristics, extension masquerading) to <span className="font-medium text-text">MITRE ATT&amp;CK</span> tactics and
          techniques. Every finding lists its evidence and confidence; results are blended with the ML verdict for the final risk.
        </p>
        <p className="mt-1 text-2xs text-muted">Files are never executed. All inferences are made from static content.</p>
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <Panel title="Catalog" aside={<LayersIcon className="text-muted" />}>
          <div className="text-2xl font-semibold tracking-[-0.01em] text-text">{total}</div>
          <div className="text-xs text-secondary">behaviors across {order.length} tactics</div>
          <div className="mt-2 text-2xs text-muted">Each maps to a MITRE technique with severity and evidence rules.</div>
        </Panel>
        <Panel title="Tactics covered" aside={<TargetIcon className="text-muted" />}>
          <div className="text-sm text-text">{order.join(' · ')}</div>
          <div className="mt-1 text-2xs text-muted">Kill-chain order used for the attack-chain visualization.</div>
        </Panel>
        <Panel title="Evidence sources" aside={<DownloadIcon className="text-muted" />}>
          <div className="flex flex-wrap gap-1.5 text-2xs">
            {['YARA rule + MITRE', 'suspicious string', 'API / import', 'network IOC', 'metadata / entropy', 'signature'].map((s) => (
              <span key={s} className="rounded bg-surface-raised px-1.5 py-0.5 text-secondary">{s}</span>
            ))}
          </div>
          <div className="mt-2 text-2xs text-muted">Corroboration raises confidence and risk contribution.</div>
        </Panel>
      </div>

      {/* Direct behavioral scan */}
      <div>
        <SectionLabel>Run Direct Behavioral Scan</SectionLabel>
        <Panel>
          <p className="text-sm text-secondary">Upload a file to run only the behavioral engine (no ML fusion, no verdict). Useful for ATT&CK enrichment triage.</p>
          <div
            onClick={() => inputRef.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => { e.preventDefault(); setDragging(false); setFile(e.dataTransfer.files[0] ?? null); }}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => e.key === 'Enter' && inputRef.current?.click()}
            className={`mt-4 flex cursor-pointer flex-col items-center justify-center rounded-lg border border-dashed px-6 py-10 text-center transition-colors ${dragging ? 'border-accent bg-accent-quiet' : 'border-line bg-surface hover:border-secondary'}`}
          >
            <input ref={inputRef} type="file" className="hidden" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
            <UploadIcon className="mb-3 text-2xl text-muted" />
            {file ? (
              <>
                <div className="font-mono text-sm text-text">{file.name}</div>
                <div className="mt-0.5 text-xs text-muted">{bytes(file.size)}</div>
              </>
            ) : (
              <>
                <div className="text-sm text-text">Drop a file for behavioral scan</div>
                <div className="mt-0.5 text-xs text-muted">Up to 32 MB · static only</div>
              </>
            )}
          </div>
          {error && <div className="mt-3 rounded-md border border-risk-high/40 bg-risk-high-wash px-3 py-2 text-sm text-risk-high">{error}</div>}
          <div className="mt-4 flex items-center gap-3">
            <Button onClick={run} disabled={!file} loading={busy}>
              {busy ? 'Analyzing' : 'Run behavioral analysis'}
            </Button>
            {file && !busy && <button onClick={() => { setFile(null); setResult(null); }} className="text-xs text-muted hover:text-secondary">Clear</button>}
          </div>
          {result && (
            <div className="mt-6">
              <BehaviorAnalysisPanel behavioral={result} />
            </div>
          )}
        </Panel>
      </div>

      {/* Catalog */}
      <div>
        <SectionLabel>Behavior Catalog · {total} MITRE-mapped behaviors</SectionLabel>
        <div className="space-y-6">
          {order
            .filter((t) => grouped.has(t))
            .map((tactic) => {
              const items = grouped.get(tactic)!;
              return (
                <div key={tactic}>
                  <div className="mb-2 flex items-center gap-2">
                    <h3 className="text-2xs font-semibold uppercase tracking-[0.08em] text-muted">{tactic}</h3>
                    <Badge tone="neutral">{items.length}</Badge>
                  </div>
                  <div className="grid gap-3 lg:grid-cols-2">
                    {items.map((b: any) => (
                      <div key={b.id} className="rounded-lg border border-line bg-surface p-3">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-mono text-2xs text-muted">{b.id}</span>
                          <Badge tone={b.severity === 'critical' || b.severity === 'high' ? 'high' : b.severity === 'medium' ? 'medium' : 'low'}>{b.severity}</Badge>
                          <span className="font-mono text-2xs text-secondary">{b.technique_id}</span>
                          <a href={b.mitre_url} target="_blank" rel="noreferrer" className="ml-auto text-2xs text-accent hover:underline">MITRE</a>
                        </div>
                        <div className="mt-1.5 text-sm font-medium text-text">{b.name}</div>
                        <div className="text-xs text-secondary">{b.technique}</div>
                        <p className="mt-2 text-xs leading-relaxed text-muted">{b.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
        </div>
      </div>
    </div>
  );
}
