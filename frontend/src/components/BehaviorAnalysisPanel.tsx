import type { BehavioralAnalysisResult, BehaviorSeverity, RiskLevel } from '../lib/types';
import { GlobeIcon, ShieldIcon } from '../ui/icons';
import { Badge, Panel, RiskMeter, SectionLabel } from '../ui/primitives';

const LEVEL_WASH: Record<RiskLevel, string> = {
  low: 'border-risk-low/30 bg-risk-low-wash',
  medium: 'border-risk-medium/30 bg-risk-medium-wash',
  high: 'border-risk-high/30 bg-risk-high-wash',
};
const LEVEL_TEXT: Record<RiskLevel, string> = {
  low: 'text-risk-low',
  medium: 'text-risk-medium',
  high: 'text-risk-high',
};

const SEV_TONE: Record<BehaviorSeverity, 'high' | 'medium' | 'low' | 'neutral'> = {
  critical: 'high',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'neutral',
};

const SEV_LABEL: Record<BehaviorSeverity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
};

function confidenceColor(c: number): string {
  if (c >= 0.85) return 'text-risk-high';
  if (c >= 0.65) return 'text-risk-medium';
  return 'text-risk-low';
}

const TACTIC_ORDER = [
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
  'Initial Access',
];

export function BehaviorAnalysisPanel({ behavioral }: { behavioral: BehavioralAnalysisResult | null | undefined }) {
  if (!behavioral) {
    return (
      <Panel title="Behavioral Analysis">
        <p className="text-sm text-secondary">Behavioral analysis is not available for this result.</p>
        <p className="mt-1 text-2xs text-muted">Re-scan the file via the pipeline to generate behavioral insights. Files are never executed.</p>
      </Panel>
    );
  }

  const lvl = behavioral.risk_level as RiskLevel;
  const observed = behavioral.behaviors.filter((b) => b.observed);
  const grouped = new Map<string, typeof observed>();
  for (const b of observed) {
    const arr = grouped.get(b.tactic) || [];
    arr.push(b);
    grouped.set(b.tactic, arr);
  }
  // sort tactics by defined order
  const orderedTactics = Array.from(grouped.entries()).sort((a, b) => {
    const ai = TACTIC_ORDER.indexOf(a[0]);
    const bi = TACTIC_ORDER.indexOf(b[0]);
    return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
  });

  const hasBehaviors = observed.length > 0;

  return (
    <div className="space-y-6">
      {/* Header risk card */}
      <div className={`overflow-hidden rounded-lg border ${LEVEL_WASH[lvl]}`}>
        <div className="grid gap-6 p-5 sm:grid-cols-[auto_1fr] sm:items-start sm:p-6">
          <div className="sm:w-48">
            <div className="flex items-end gap-1">
              <span className={`font-mono text-5xl font-semibold leading-none ${LEVEL_TEXT[lvl]}`}>{behavioral.risk_score}</span>
              <span className="pb-1 text-sm text-muted">/100</span>
            </div>
            <div className="mt-3">
              <RiskMeter score={behavioral.risk_score} level={lvl} />
            </div>
            <div className={`mt-2 text-2xs font-semibold uppercase tracking-[0.1em] ${LEVEL_TEXT[lvl]}`}>
              {lvl} behavioral risk · {(behavioral.confidence * 100).toFixed(0)}% conf
            </div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              <Badge tone={lvl}>{behavioral.behaviors_detected} / {behavioral.behaviors_total} behaviors</Badge>
              {behavioral.kill_chain_stage && <Badge tone="neutral">{behavioral.kill_chain_stage}</Badge>}
            </div>
          </div>
          <div className="min-w-0 border-t border-line-soft pt-4 sm:border-l sm:border-t-0 sm:pl-6 sm:pt-0">
            <div className="flex items-center gap-2 text-sm font-semibold text-text">
              <ShieldIcon className={LEVEL_TEXT[lvl]} />
              Behavioral Profile
            </div>
            <p className="mt-2 text-sm leading-relaxed text-secondary">{behavioral.summary}</p>
            <div className="mt-3 flex flex-wrap items-center gap-2 text-2xs text-muted">
              <span>Techniques: {behavioral.technique_coverage.length ? behavioral.technique_coverage.join(', ') : 'none'}</span>
              {behavioral.file_hash && <span>· {behavioral.file_hash.slice(0, 12)}…</span>}
              <span>· {new Date(behavioral.generated_at).toLocaleString()}</span>
            </div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {behavioral.technique_coverage.slice(0, 6).map((tid) => (
                <a
                  key={tid}
                  href={`https://attack.mitre.org/techniques/${tid.split('.')[0]}/`}
                  target="_blank"
                  rel="noreferrer"
                  className="rounded bg-surface-raised px-1.5 py-0.5 font-mono text-2xs text-accent hover:underline"
                >
                  {tid}
                </a>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Attack chain */}
      <div>
        <SectionLabel>Attack Chain (Kill-Chain Order)</SectionLabel>
        <Panel>
          {behavioral.attack_chain.length === 0 ? (
            <p className="text-sm text-secondary">No tactics were hit. The file shows no discernible kill-chain progression.</p>
          ) : (
            <div className="flex flex-wrap items-center gap-1.5">
              {TACTIC_ORDER.filter((t) => behavioral.tactics_summary.some((s) => s.tactic === t)).map((tactic) => {
                const summary = behavioral.tactics_summary.find((s) => s.tactic === tactic);
                const active = behavioral.attack_chain.includes(tactic);
                const detected = summary?.detected ?? 0;
                return (
                  <div key={tactic} className="flex items-center gap-1.5">
                    <span
                      className={`rounded-md px-2.5 py-1.5 text-2xs font-semibold uppercase tracking-[0.06em] ring-1 ${
                        active
                          ? detected > 0
                            ? 'bg-risk-high-wash text-risk-high ring-risk-high/20'
                            : 'bg-surface-raised text-secondary ring-line'
                          : 'bg-surface text-muted ring-line-soft opacity-60'
                      }`}
                    >
                      {tactic}
                      {summary && detected > 0 && <span className="ml-1 font-mono normal-case tracking-normal">· {detected}/{summary.total}</span>}
                    </span>
                    <span className="text-muted last:hidden">→</span>
                  </div>
                );
              })}
            </div>
          )}
          <p className="mt-3 text-2xs text-muted">Highlighted tactics contain at least one observed behavior. Chain is ordered by MITRE kill-chain priority, not temporal order. Static analysis never executes the file.</p>
        </Panel>
      </div>

      {/* Tactics summary */}
      <div>
        <SectionLabel>Tactic Coverage</SectionLabel>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {behavioral.tactics_summary.map((t) => {
            const pct = t.total ? Math.round((t.detected / t.total) * 100) : 0;
            const tone: RiskLevel = t.max_severity === 'critical' || t.max_severity === 'high' ? 'high' : t.max_severity === 'medium' ? 'medium' : 'low';
            return (
              <div key={t.tactic} className="rounded-lg border border-line bg-surface p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-2xs font-semibold uppercase tracking-[0.06em] text-muted">{t.tactic}</span>
                  {t.detected > 0 ? <Badge tone={SEV_TONE[t.max_severity as BehaviorSeverity] ?? 'neutral'}>{SEV_LABEL[t.max_severity as BehaviorSeverity] ?? t.max_severity}</Badge> : <Badge tone="neutral">clear</Badge>}
                </div>
                <div className="mt-2 flex items-baseline gap-2">
                  <span className={`font-mono text-lg font-semibold ${t.detected ? (tone === 'high' ? 'text-risk-high' : tone === 'medium' ? 'text-risk-medium' : 'text-risk-low') : 'text-muted'}`}>
                    {t.detected}/{t.total}
                  </span>
                  <span className="text-2xs text-muted">{pct}% of tactic</span>
                </div>
                <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-surface-raised">
                  <div
                    className="h-full rounded-full transition-[width] duration-500"
                    style={{
                      width: `${t.detected ? Math.max(pct, 8) : 0}%`,
                      backgroundColor: t.detected ? (tone === 'high' ? 'var(--risk-high)' : tone === 'medium' ? 'var(--risk-medium)' : 'var(--risk-low)') : 'transparent',
                    }}
                  />
                </div>
                <div className="mt-1 text-2xs font-mono text-muted">{t.tactic_id}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Detailed behaviors */}
      <div>
        <SectionLabel>Observed Behaviors ({observed.length})</SectionLabel>
        {!hasBehaviors ? (
          <Panel>
            <div className="flex items-center gap-2 text-sm text-secondary">
              <GlobeIcon className="text-muted" />
              No MITRE behaviors were inferred. The file lacks static indicators that map to attack techniques.
            </div>
          </Panel>
        ) : (
          <div className="space-y-6">
            {orderedTactics.map(([tactic, items]) => (
              <div key={tactic}>
                <div className="mb-2 flex items-center gap-2">
                  <h3 className="text-2xs font-semibold uppercase tracking-[0.08em] text-muted">{tactic}</h3>
                  <span className="text-2xs font-mono text-muted">· {items.length} behavior{items.length !== 1 ? 's' : ''}</span>
                </div>
                <div className="grid gap-3">
                  {items
                    .slice()
                    .sort((a, b) => {
                      const order: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
                      return (order[b.severity] ?? 0) - (order[a.severity] ?? 0);
                    })
                    .map((b) => (
                      <div key={b.id} className="overflow-hidden rounded-lg border border-line bg-surface">
                        <div className="flex flex-wrap items-start justify-between gap-3 border-b border-line-soft bg-surface-raised/40 px-4 py-3">
                          <div className="min-w-0">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className="font-mono text-2xs text-muted">{b.id}</span>
                              <Badge tone={SEV_TONE[b.severity]}>{SEV_LABEL[b.severity]}</Badge>
                              <span className={`text-2xs font-medium ${confidenceColor(b.confidence)}`}>{(b.confidence * 100).toFixed(0)}% conf</span>
                              <span className="rounded bg-surface px-1.5 py-0.5 font-mono text-2xs text-secondary">{b.technique_id}</span>
                            </div>
                            <div className="mt-1 text-sm font-semibold text-text">{b.name}</div>
                            <div className="text-xs text-secondary">{b.technique}</div>
                          </div>
                          <div className="flex items-center gap-2 shrink-0">
                            <span className="hidden sm:inline text-2xs text-muted">+{b.risk_contribution} pts</span>
                            {b.mitre_url && (
                              <a
                                href={b.mitre_url}
                                target="_blank"
                                rel="noreferrer"
                                className="rounded bg-accent-quiet px-2 py-1 text-2xs font-medium text-accent hover:underline"
                              >
                                MITRE
                              </a>
                            )}
                          </div>
                        </div>
                        <div className="px-4 py-3">
                          <p className="text-sm text-secondary">{b.description}</p>
                          <div className="mt-3">
                            <div className="mb-1 text-2xs font-semibold uppercase tracking-[0.06em] text-muted">Evidence ({b.evidence.length})</div>
                            <ul className="space-y-1.5">
                              {b.evidence.map((e, i) => (
                                <li key={i} className="flex gap-2.5 text-sm">
                                  <span className={`mt-1.5 size-1.5 shrink-0 rounded-full ${b.severity === 'critical' || b.severity === 'high' ? 'bg-risk-high' : b.severity === 'medium' ? 'bg-risk-medium' : 'bg-risk-low'}`} />
                                  <span className="min-w-0">
                                    <span className="rounded bg-surface-raised px-1 py-0.5 font-mono text-2xs text-muted">{e.type}</span>{' '}
                                    <span className="break-all text-text">{e.value}</span>
                                    <span className="ml-1 text-2xs text-muted">· {(e.confidence * 100).toFixed(0)}%</span>
                                  </span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {!hasBehaviors ? null : (
        <div className="rounded-lg border border-line-soft bg-surface-raised/30 px-4 py-3 text-2xs leading-relaxed text-muted">
          <span className="font-semibold text-secondary">Interpretation note:</span> Behaviors are inferred statically from strings, imports, YARA, network IOCs and metadata. No code is executed. Confidence reflects corroboration count; a single indicator yields ~60-72% confidence, multiple independent signals push toward 90%+. Use the fused verdict (static + ML) as the primary decision, and treat behavioral findings as ATT&CK enrichment for triage and reporting.
        </div>
      )}
    </div>
  );
}
