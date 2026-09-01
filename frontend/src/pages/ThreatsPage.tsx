import { Link } from 'react-router-dom';

import { ScanList } from '../components/ScanList';
import { getHistory } from '../lib/history';
import { RadarIcon } from '../ui/icons';
import { EmptyState } from '../ui/primitives';

export function ThreatsPage() {
  const threats = getHistory().filter((h) => h.level === 'high' || h.level === 'medium');

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-lg font-semibold tracking-[-0.01em]">Threat Monitor</h2>
        <p className="mt-1 text-sm text-secondary">
          Files that scored medium or high risk in static analysis.
        </p>
      </div>

      {threats.length === 0 ? (
        <EmptyState
          icon={<RadarIcon />}
          title="No threats detected"
          description="Files that raise indicators or match a signature or YARA rule will surface here."
        />
      ) : (
        <>
          <div className="flex gap-6 text-sm">
            <span className="text-secondary">
              <span className="font-mono text-risk-high">
                {threats.filter((t) => t.level === 'high').length}
              </span>{' '}
              high
            </span>
            <span className="text-secondary">
              <span className="font-mono text-risk-medium">
                {threats.filter((t) => t.level === 'medium').length}
              </span>{' '}
              medium
            </span>
          </div>
          <ScanList entries={threats} />
          <p className="text-xs text-muted">
            <Link to="/reports" className="text-accent hover:underline">
              Open the latest report
            </Link>{' '}
            for full detail.
          </p>
        </>
      )}
    </div>
  );
}
