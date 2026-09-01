import type { AnalysisResult, RiskLevel } from '../lib/types';

const RISK_STYLES: Record<RiskLevel, string> = {
  low: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300',
  medium: 'border-amber-500/40 bg-amber-500/10 text-amber-300',
  high: 'border-rose-500/40 bg-rose-500/10 text-rose-300',
};

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900 p-4">
      <h3 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">{title}</h3>
      {children}
    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex justify-between gap-4 border-b border-slate-800 py-1.5 text-sm last:border-0">
      <span className="text-slate-500">{label}</span>
      <span className={`text-right text-slate-200 ${mono ? 'break-all font-mono text-xs' : ''}`}>
        {value}
      </span>
    </div>
  );
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

export function AnalysisReport({ result }: { result: AnalysisResult }) {
  const { risk, metadata, hashes, signature_match, yara_matches, network_indicators } = result;

  return (
    <div className="space-y-4">
      {/* verdict */}
      <div className={`flex flex-wrap items-center justify-between gap-4 rounded-lg border p-5 ${RISK_STYLES[risk.level]}`}>
        <div>
          <div className="text-xs uppercase tracking-wide opacity-80">Risk score</div>
          <div className="text-4xl font-bold">{risk.score}<span className="text-xl opacity-60">/100</span></div>
        </div>
        <div className="text-right">
          <div className="text-lg font-semibold">{risk.classification}</div>
          <div className="text-sm opacity-80">{risk.recommended_action}</div>
          <div className="mt-1 text-xs uppercase tracking-widest opacity-70">{risk.level} risk</div>
        </div>
      </div>

      <div className="grid items-start gap-4 md:grid-cols-2">
        <Section title="Suspicious Indicators">
          {result.suspicious_indicators.length === 0 ? (
            <p className="text-sm text-slate-500">No suspicious indicators found.</p>
          ) : (
            <ul className="space-y-1.5 text-sm text-slate-200">
              {result.suspicious_indicators.map((ind, i) => (
                <li key={i} className="flex gap-2">
                  <span className="text-rose-400">▸</span>
                  <span>{ind}</span>
                </li>
              ))}
            </ul>
          )}
        </Section>

        <Section title="File Metadata">
          <Row label="Object path" value={result.object_path} mono />
          <Row label="Size" value={formatBytes(metadata.size_bytes)} />
          <Row label="Detected type" value={metadata.file_type} />
          <Row label="MIME" value={metadata.mime_type} />
          <Row
            label="Extension match"
            value={
              metadata.extension_matches_content === false
                ? `NO (declared ${metadata.extension})`
                : metadata.extension_matches_content === true
                  ? 'yes'
                  : 'n/a'
            }
          />
          <Row label="Entropy" value={`${metadata.shannon_entropy} ${metadata.likely_packed ? '(packed?)' : ''}`} />
        </Section>

        <Section title="Hashes">
          <Row label="MD5" value={hashes.md5} mono />
          <Row label="SHA-1" value={hashes.sha1} mono />
          <Row label="SHA-256" value={hashes.sha256} mono />
        </Section>

        <Section title="Signature Match">
          {signature_match.matched ? (
            <div className="text-sm">
              <div className="font-semibold text-rose-300">{signature_match.name}</div>
              <div className="text-slate-400">
                type: {signature_match.type} · severity: {signature_match.severity}
              </div>
            </div>
          ) : (
            <p className="text-sm text-slate-500">No known-hash signature match.</p>
          )}
        </Section>

        <Section title={`YARA Matches${result.yara_available ? '' : ' (engine unavailable)'}`}>
          {yara_matches.length === 0 ? (
            <p className="text-sm text-slate-500">No YARA rules matched.</p>
          ) : (
            <ul className="space-y-2 text-sm">
              {yara_matches.map((m) => (
                <li key={m.rule} className="rounded border border-slate-800 p-2">
                  <div className="font-mono text-cyan-300">{m.rule}</div>
                  {typeof m.meta.description === 'string' && (
                    <div className="text-slate-400">{m.meta.description}</div>
                  )}
                  {m.matched_strings.length > 0 && (
                    <div className="mt-1 truncate font-mono text-xs text-slate-500">
                      {m.matched_strings.join(' · ')}
                    </div>
                  )}
                </li>
              ))}
            </ul>
          )}
        </Section>

        <Section title="Network Indicators">
          {network_indicators.urls.length + network_indicators.ips.length + network_indicators.domains.length === 0 ? (
            <p className="text-sm text-slate-500">No embedded URLs, IPs or domains.</p>
          ) : (
            <div className="space-y-2 text-sm">
              {network_indicators.urls.length > 0 && (
                <div>
                  <div className="text-slate-500">URLs</div>
                  <ul className="font-mono text-xs text-amber-300">
                    {network_indicators.urls.map((u) => <li key={u} className="break-all">{u}</li>)}
                  </ul>
                </div>
              )}
              {network_indicators.ips.length > 0 && (
                <div>
                  <div className="text-slate-500">IPs</div>
                  <div className="font-mono text-xs text-amber-300">{network_indicators.ips.join(', ')}</div>
                </div>
              )}
              {network_indicators.domains.length > 0 && (
                <div>
                  <div className="text-slate-500">Domains</div>
                  <div className="font-mono text-xs text-amber-300">{network_indicators.domains.join(', ')}</div>
                </div>
              )}
            </div>
          )}
        </Section>
      </div>

      {result.strings_sample.length > 0 && (
        <Section title="Extracted Strings (sample)">
          <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all font-mono text-xs text-slate-400">
            {result.strings_sample.join('\n')}
          </pre>
        </Section>
      )}

      <p className="text-xs text-slate-600">{result.notes.join(' ')}</p>
    </div>
  );
}
