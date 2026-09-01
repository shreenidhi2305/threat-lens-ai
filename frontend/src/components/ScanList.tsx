import type { HistoryEntry } from '../lib/history';
import type { RiskLevel } from '../lib/types';
import { Badge } from '../ui/primitives';

const DOT: Record<RiskLevel, string> = {
  low: 'bg-risk-low',
  medium: 'bg-risk-medium',
  high: 'bg-risk-high',
};

function ago(ts: number): string {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function kb(n: number): string {
  return n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} KB`;
}

export function ScanList({ entries }: { entries: HistoryEntry[] }) {
  return (
    <div className="overflow-hidden rounded-lg border border-line bg-surface">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-line-soft text-left text-2xs uppercase tracking-[0.06em] text-muted">
            <th className="px-4 py-2.5 font-medium">File</th>
            <th className="hidden px-4 py-2.5 font-medium sm:table-cell">Classification</th>
            <th className="px-4 py-2.5 font-medium">Risk</th>
            <th className="px-4 py-2.5 text-right font-medium">Analyzed</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line-soft">
          {entries.map((e) => (
            <tr key={e.id} className="transition-colors hover:bg-surface-raised">
              <td className="px-4 py-2.5">
                <div className="flex items-center gap-2">
                  <span className={`size-1.5 shrink-0 rounded-full ${DOT[e.level]}`} />
                  <span className="truncate font-mono text-xs text-text">{e.filename}</span>
                </div>
                <div className="mt-0.5 pl-3.5 text-2xs text-muted">{kb(e.size_bytes)}</div>
              </td>
              <td className="hidden px-4 py-2.5 text-secondary sm:table-cell">{e.classification}</td>
              <td className="px-4 py-2.5">
                <Badge tone={e.level}>{e.score}</Badge>
              </td>
              <td className="px-4 py-2.5 text-right text-xs text-muted">{ago(e.at)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
