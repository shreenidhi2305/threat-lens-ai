import type { Agreement, Detection, RiskLevel } from '../lib/types';
import { Badge } from '../ui/primitives';

const DOT: Record<RiskLevel, string> = {
  low: 'bg-risk-low',
  medium: 'bg-risk-medium',
  high: 'bg-risk-high',
};

const AGREEMENT_LABEL: Record<Agreement, string> = {
  agree: 'rules + ML',
  'ml-only': 'ML only',
  'rules-only': 'rules only',
  conflict: 'conflict',
};

function ago(iso: string): string {
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function ScanList({ detections }: { detections: Detection[] }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-line bg-surface">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-line-soft text-left text-2xs uppercase tracking-[0.06em] text-muted">
            <th className="px-4 py-2.5 font-medium">File</th>
            <th className="hidden px-4 py-2.5 font-medium sm:table-cell">Family</th>
            <th className="hidden px-4 py-2.5 font-medium md:table-cell">Engines</th>
            <th className="px-4 py-2.5 font-medium">Score</th>
            <th className="px-4 py-2.5 text-right font-medium">Analysed</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line-soft">
          {detections.map((d) => (
            <tr key={d.id} className="transition-colors hover:bg-surface-raised">
              <td className="px-4 py-2.5">
                <div className="flex items-center gap-2">
                  <span className={`size-1.5 shrink-0 rounded-full ${DOT[d.level]}`} />
                  <span className="truncate font-mono text-xs text-text">{d.filename}</span>
                </div>
                {d.ml_probability != null && (
                  <div className="mt-0.5 pl-3.5 text-2xs text-muted">
                    ML {(d.ml_probability * 100).toFixed(0)}%
                  </div>
                )}
              </td>
              <td className="hidden px-4 py-2.5 text-secondary sm:table-cell">{d.family ?? '—'}</td>
              <td className="hidden px-4 py-2.5 text-xs text-muted md:table-cell">
                {d.agreement ? AGREEMENT_LABEL[d.agreement] : '—'}
              </td>
              <td className="px-4 py-2.5">
                <Badge tone={d.level}>{d.score}</Badge>
              </td>
              <td className="px-4 py-2.5 text-right text-xs text-muted">{ago(d.at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
