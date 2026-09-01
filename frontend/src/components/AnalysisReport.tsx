import type { AnalysisResult, RiskLevel } from '../lib/types';
import { AlertTriangleIcon, CodeIcon, FingerprintIcon, GlobeIcon } from '../ui/icons';
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

export function AnalysisReport({ result }: { result: AnalysisResult }) {
  const { risk, metadata, hashes, signature_match: sig, yara_matches, network_indicators: net } = result;
  const filename = result.object_path.split('/').pop() || result.object_path;
  const iocCount = net.urls.length + net.ips.length + net.domains.length;

  return (
    <div className="space-y-6">
      {/* verdict */}
      <div className={`overflow-hidden rounded-lg border ${LEVEL_WASH[risk.level]}`}>
        <div className="grid gap-6 p-5 sm:grid-cols-[auto_1fr] sm:items-center sm:p-6">
          <div className="sm:w-44">
            <div className="flex items-end gap-1">
              <span className={`font-mono text-5xl font-semibold leading-none ${LEVEL_TEXT[risk.level]}`}>
                {risk.score}
              </span>
              <span className="pb-1 text-sm text-muted">/100</span>
            </div>
            <div className="mt-3">
              <RiskMeter score={risk.score} level={risk.level} />
            </div>
            <div className={`mt-2 text-2xs font-semibold uppercase tracking-[0.1em] ${LEVEL_TEXT[risk.level]}`}>
              {risk.level} risk
            </div>
          </div>
          <div className="min-w-0 border-t border-line-soft pt-4 sm:border-l sm:border-t-0 sm:pl-6 sm:pt-0">
            <div className="text-lg font-semibold tracking-[-0.01em] text-text">{risk.classification}</div>
            <div className="mt-1 flex items-center gap-1.5 text-sm text-secondary">
              <AlertTriangleIcon className={LEVEL_TEXT[risk.level]} />
              {risk.recommended_action}
            </div>
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
                <span className={`mt-1.5 size-1.5 shrink-0 rounded-full ${
                  risk.level === 'high' ? 'bg-risk-high' : risk.level === 'medium' ? 'bg-risk-medium' : 'bg-risk-low'
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
        <SectionLabel>Detection</SectionLabel>
        <div className="grid gap-4 md:grid-cols-2">
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
            title={`YARA${result.yara_available ? '' : ' · engine unavailable'}`}
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
                    {typeof m.meta.description === 'string' && (
                      <p className="mt-1 text-xs text-secondary">{m.meta.description}</p>
                    )}
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
                      {net[key].map((v) => (
                        <li key={v} className="group flex items-center gap-1.5">
                          <span className="break-all font-mono text-xs text-risk-medium">{v}</span>
                          <CopyButton value={v} label={key} />
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

      {/* strings */}
      {result.strings_sample.length > 0 && (
        <details className="group rounded-lg border border-line bg-surface">
          <summary className="flex cursor-pointer items-center gap-2 px-4 py-3 text-2xs font-semibold uppercase tracking-[0.08em] text-muted marker:content-['']">
            <CodeIcon />
            Extracted strings
            <span className="font-normal normal-case tracking-normal text-muted">
              ({result.strings_sample.length} shown)
            </span>
          </summary>
          <pre className="max-h-72 overflow-auto border-t border-line-soft px-4 py-3 font-mono text-2xs leading-relaxed text-secondary">
            {result.strings_sample.join('\n')}
          </pre>
        </details>
      )}

      <p className="text-2xs text-muted">{result.notes.join(' ')}</p>
    </div>
  );
}
