import type { AnalysisResult, Agreement, MLPrediction, RiskLevel } from '../lib/types';
import { AlertTriangleIcon, FingerprintIcon, GlobeIcon, RadarIcon } from '../ui/icons';
import { Badge, CopyButton, InfoRow, Panel, RiskMeter, SectionLabel } from '../ui/primitives';

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

const AGREEMENT_COPY: Record<Agreement, string> = {
  agree: 'Rule engine and ML model agree',
  'ml-only': 'Flagged by the ML model; rule engine quiet',
  'rules-only': 'Flagged by the rule engine; ML model quiet',
  conflict: 'Engines disagree — analyst review advised',
};

function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

const yaraSeverity = (m: AnalysisResult['yara_matches'][number]): RiskLevel => {
  const s = String(m.meta.severity ?? '').toLowerCase();
  if (s === 'high') return 'high';
  if (s === 'medium') return 'medium';
  return 'low';
};

function EngineDot({ on, tone }: { on: boolean; tone: 'high' | 'muted' }) {
  return (
    <span
      className={`size-1.5 rounded-full ${on ? (tone === 'high' ? 'bg-risk-high' : 'bg-risk-medium') : 'bg-muted/40'}`}
    />
  );
}

function MLPanel({ ml }: { ml: MLPrediction | null }) {
  if (!ml || !ml.available) {
    return (
      <Panel title="ML Detection" aside={<RadarIcon className="text-muted" />}>
        <p className="text-sm text-secondary">
          {ml?.reason ? `Model unavailable: ${ml.reason}.` : 'ML model not loaded.'}
        </p>
      </Panel>
    );
  }
  const prob = ml.malware_probability ?? 0;
  const tone: RiskLevel = prob >= 0.7 ? 'high' : prob >= 0.4 ? 'medium' : 'low';
  return (
    <Panel
      title="ML Detection"
      aside={<span className="text-2xs text-muted">{ml.model_versions.detector ?? 'model'}</span>}
    >
      <div className="space-y-3">
        <div className="flex items-end justify-between">
          <div>
            <div className="text-2xs uppercase tracking-[0.06em] text-muted">malware probability</div>
            <div className={`font-mono text-2xl font-semibold ${LEVEL_TEXT[tone]}`}>
              {(prob * 100).toFixed(1)}%
            </div>
          </div>
          <Badge tone={ml.applicable && ml.malicious ? 'high' : 'low'}>
            {!ml.applicable ? 'informational' : ml.malicious ? 'malicious' : 'benign'}
          </Badge>
        </div>
        <RiskMeter score={Math.round(prob * 100)} level={tone} />
        {!ml.applicable && (
          <p className="text-2xs text-muted">
            Model is trained on Windows PE files; for this file type the rule engine is authoritative.
          </p>
        )}
        {ml.applicable && ml.malicious ? (
          <div>
            <div className="mb-1 text-2xs uppercase tracking-[0.06em] text-muted">ML classification</div>
            {ml.top_categories.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {ml.top_categories.slice(0, 3).map((c) => (
                  <span
                    key={c.category}
                    className="rounded bg-surface-raised px-1.5 py-0.5 text-2xs text-secondary"
                  >
                    {c.category} {(c.probability * 100).toFixed(0)}%
                  </span>
                ))}
              </div>
            ) : <p className="text-sm text-secondary">ML malware detected; no category probabilities available.</p>}
          </div>
        ) : ml.applicable ? (
          <div>
            <div className="mb-1 text-2xs uppercase tracking-[0.06em] text-muted">ML classification</div>
            <div className="text-lg font-semibold text-text">Benign</div>
            <p className="text-xs text-secondary">The ML detector did not classify this sample as malware.</p>
          </div>
        ) : null}
      </div>
    </Panel>
  );
}

export function AnalysisReport({ result }: { result: AnalysisResult }) {
  const { risk, metadata, hashes, signature_match: sig, yara_matches, network_indicators: net, ml } = result;
  const v = result.verdict;
  const level: RiskLevel = v?.level ?? risk.level;
  const score = v?.score ?? risk.score;
  const classification = v?.classification ?? risk.classification;
  const action = v?.recommended_action ?? risk.recommended_action;
  const filename = result.object_path.split('/').pop() || result.object_path;
  const iocCount = net.urls.length + net.ips.length + net.domains.length;
  const yaraFamilies = Array.from(new Set(yara_matches
    .map((match) => match.meta.family)
    .filter((family): family is string => typeof family === 'string' && family.length > 0)));
  const ruleFamilies = Array.from(new Set([
    ...(sig.matched && sig.type ? [sig.type] : []),
    ...yaraFamilies,
  ]));
  const ruleEvidence = risk.level !== 'low' || sig.matched || yara_matches.length > 0 || result.suspicious_indicators.length > 0;
  const mlBenign = Boolean(ml?.available && ml?.applicable && ml.malicious === false);
  const elevatedByRules = Boolean(mlBenign && ruleEvidence && v && v.label !== 'benign');

  return (
    <div className="space-y-6">
      {/* verdict */}
      <div className={`overflow-hidden rounded-lg border ${LEVEL_WASH[level]}`}>
        <div className="grid gap-6 p-5 sm:grid-cols-[auto_1fr] sm:items-start sm:p-6">
          <div className="sm:w-44">
            <div className="flex items-end gap-1">
              <span className={`font-mono text-5xl font-semibold leading-none ${LEVEL_TEXT[level]}`}>
                {score}
              </span>
              <span className="pb-1 text-sm text-muted">/100</span>
            </div>
            <div className="mt-3">
              <RiskMeter score={score} level={level} />
            </div>
            <div className={`mt-2 text-2xs font-semibold uppercase tracking-[0.1em] ${LEVEL_TEXT[level]}`}>
              {level} risk{v ? ` · ${(v.confidence * 100).toFixed(0)}% conf` : ''}
            </div>
          </div>
          <div className="min-w-0 border-t border-line-soft pt-4 sm:border-l sm:border-t-0 sm:pl-6 sm:pt-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-lg font-semibold tracking-[-0.01em] text-text">{classification}</span>
              {v?.family && <Badge tone={level}>{v.family}</Badge>}
            </div>
            <div className="mt-1 flex items-center gap-1.5 text-sm text-secondary">
              <AlertTriangleIcon className={LEVEL_TEXT[level]} />
              {action}
            </div>
            {v && (
              <div className="mt-3 flex items-center gap-2 text-xs text-secondary">
                <span className="flex items-center gap-1">
                  <EngineDot on={risk.level !== 'low'} tone="high" /> Rules
                </span>
                <span className="flex items-center gap-1">
                  <EngineDot on={Boolean(ml?.applicable && ml?.malicious)} tone="high" /> ML
                </span>
                <span className="text-muted">— {AGREEMENT_COPY[v.agreement]}</span>
              </div>
            )}
            {elevatedByRules && (
              <p className="mt-3 rounded border border-risk-medium/30 bg-risk-medium-wash px-3 py-2 text-xs text-secondary">
                ML classified the sample as benign; the final verdict was elevated due to rule/YARA evidence.
              </p>
            )}
            <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted">
              <span className="font-mono text-secondary">{filename}</span>
              <span>·</span>
              <span>{bytes(metadata.size_bytes)}</span>
              <span>·</span>
              <span>{metadata.file_type}</span>
            </div>
            <div className="group mt-1 flex items-center gap-1.5">
              <span className="truncate font-mono text-2xs text-muted">{hashes.sha256}</span>
              <CopyButton value={hashes.sha256} label="SHA-256" />
            </div>
          </div>
        </div>
      </div>

      {/* indicators */}
      <div>
        <SectionLabel>Suspicious Indicators</SectionLabel>
        {result.suspicious_indicators.length === 0 ? (
          <p className="rounded-lg border border-line bg-surface px-4 py-3 text-sm text-secondary">
            No suspicious indicators were raised by the static analysis.
          </p>
        ) : (
          <ul className="divide-y divide-line-soft overflow-hidden rounded-lg border border-line bg-surface">
            {result.suspicious_indicators.map((ind, i) => (
              <li key={i} className="flex gap-3 px-4 py-2.5 text-sm">
                <span
                  className={`mt-1.5 size-1.5 shrink-0 rounded-full ${level === 'high' ? 'bg-risk-high' : level === 'medium' ? 'bg-risk-medium' : 'bg-risk-low'
                    }`}
                />
                <span className="text-text">{ind}</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* detection */}
      <div>
        <SectionLabel>Detection Engines</SectionLabel>
        <div className="grid gap-4 lg:grid-cols-3">
          <MLPanel ml={ml} />

          <Panel title="Signature Match" aside={<FingerprintIcon className="text-muted" />}>
            {sig.matched ? (
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm text-risk-high">{sig.name}</span>
                  {sig.severity && <Badge tone="high">{sig.severity}</Badge>}
                </div>
                <p className="text-xs text-secondary">
                  SHA-256 matched a known {sig.type ?? 'malware'} signature.
                </p>
              </div>
            ) : (
              <p className="text-sm text-secondary">No known-hash signature match.</p>
            )}
          </Panel>

          <Panel
            title={`YARA${result.yara_available ? '' : ' · unavailable'}`}
            aside={<span className="text-2xs text-muted">{yara_matches.length} matched</span>}
          >
            {yara_matches.length === 0 ? (
              <p className="text-sm text-secondary">No YARA rules matched.</p>
            ) : (
              <ul className="space-y-3">
                {yara_matches.map((m) => (
                  <li key={m.rule} className="min-w-0">
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                      <span className="break-all font-mono text-xs text-text">{m.rule}</span>
                      <Badge tone={yaraSeverity(m)}>{String(m.meta.severity ?? 'n/a')}</Badge>
                    </div>
                    <div className="mt-1 space-y-0.5 text-xs text-secondary">
                      {m.tags.length > 0 && <p>Tags: {m.tags.join(', ')}</p>}
                      {typeof m.meta.family === 'string' && <p>Family: {m.meta.family}</p>}
                      {typeof m.meta.mitre === 'string' && <p>MITRE: {m.meta.mitre}</p>}
                      {typeof m.meta.description === 'string' && <p>{m.meta.description}</p>}
                    </div>
                    {m.matched_strings.length > 0 && (
                      <p className="mt-1 line-clamp-2 break-all font-mono text-2xs text-muted">
                        {m.matched_strings.join('  ·  ')}
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>
      </div>

      {/* classification */}
      <div>
        <SectionLabel>Classification Sources</SectionLabel>
        <div className="grid gap-4 md:grid-cols-2">
          <Panel title="ML classification" aside={<RadarIcon className="text-muted" />}>
            {ml?.available && ml.category ? (
              <div className="space-y-2">
                <div className="text-lg font-semibold text-text">{ml.category}</div>
                <p className="text-xs text-secondary">
                  Category inferred by the pretrained ML classifier.
                </p>
                {ml.category_confidence != null && (
                  <InfoRow label="Category confidence" value={`${(ml.category_confidence * 100).toFixed(1)}%`} />
                )}
              </div>
            ) : (
              <p className="text-sm text-secondary">No ML category is available for this result.</p>
            )}
          </Panel>
          <Panel title="Rule/YARA family" aside={<FingerprintIcon className="text-muted" />}>
            <div className="space-y-2">
              <div className="text-lg font-semibold text-text">
                {ruleFamilies.length > 0 ? ruleFamilies.join(', ') : 'No family identified'}
              </div>
              <p className="text-xs text-secondary">
                Derived from hash signatures and YARA metadata, independent of ML classification.
              </p>
              {sig.matched && <InfoRow label="Signature evidence" value={sig.name ?? 'Known signature'} mono />}
              {yara_matches.length > 0 && <InfoRow label="YARA evidence" value={`${yara_matches.length} matched rule${yara_matches.length === 1 ? '' : 's'}`} />}
            </div>
          </Panel>
        </div>
      </div>

      {/* file details */}
      <div>
        <SectionLabel>File Details</SectionLabel>
        <div className="grid gap-4 md:grid-cols-2">
          <Panel title="Metadata">
            <InfoRow label="Detected type" value={metadata.file_type} />
            <InfoRow label="MIME" value={metadata.mime_type} mono />
            <InfoRow label="Size" value={bytes(metadata.size_bytes)} />
            <InfoRow
              label="Extension check"
              value={
                metadata.extension_matches_content === false ? (
                  <span className="text-risk-high">mismatch ({metadata.extension})</span>
                ) : metadata.extension_matches_content === true ? (
                  'consistent'
                ) : (
                  'n/a'
                )
              }
            />
            <InfoRow
              label="Entropy"
              value={
                <>
                  {metadata.shannon_entropy.toFixed(2)}
                  {metadata.likely_packed && <span className="ml-1.5 text-risk-medium">packed?</span>}
                </>
              }
            />
            <InfoRow label="Magic bytes" value={metadata.magic_hex} mono copy />
          </Panel>
          <Panel title="Hashes">
            <InfoRow label="MD5" value={hashes.md5} mono copy />
            <InfoRow label="SHA-1" value={hashes.sha1} mono copy />
            <InfoRow label="SHA-256" value={hashes.sha256} mono copy />
          </Panel>
        </div>
      </div>

      {/* network */}
      <div>
        <SectionLabel>Network Indicators</SectionLabel>
        <Panel>
          {iocCount === 0 ? (
            <div className="flex items-center gap-2 text-sm text-secondary">
              <GlobeIcon className="text-muted" />
              No embedded URLs, IP addresses, or domains.
            </div>
          ) : (
            <div className="space-y-4">
              {(['urls', 'ips', 'domains'] as const).map((key) =>
                net[key].length === 0 ? null : (
                  <div key={key}>
                    <div className="mb-1.5 text-2xs font-medium uppercase tracking-[0.06em] text-muted">
                      {key === 'ips' ? 'IP addresses' : key}
                    </div>
                    <ul className="space-y-1">
                      {net[key].map((val) => (
                        <li key={val} className="group flex items-center gap-1.5">
                          <span className="break-all font-mono text-xs text-risk-medium">{val}</span>
                          <CopyButton value={val} label={key} />
                        </li>
                      ))}
                    </ul>
                  </div>
                ),
              )}
            </div>
          )}
        </Panel>
      </div>

      <p className="text-2xs text-muted">{result.notes.join(' ')}</p>
    </div>
  );
}
