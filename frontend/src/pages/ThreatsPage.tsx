import { ScanList } from '../components/ScanList';
import { fetchDetections, fetchThreatSnapshot } from '../lib/api';
import { useAsync } from '../lib/useAsync';
import { RadarIcon } from '../ui/icons';
import { EmptyState, Spinner } from '../ui/primitives';

export function ThreatsPage() {
  const detections = useAsync(() => fetchDetections(200));
  const snapshot = useAsync(fetchThreatSnapshot);

  const threats = (detections.data ?? []).filter((d) => d.verdict_label !== 'benign');
  const s = snapshot.data;

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-lg font-semibold tracking-[-0.01em]">Threat Monitor</h2>
        <p className="mt-1 text-sm text-secondary">
          Files the detection pipeline flagged as malicious or suspicious.
        </p>
      </div>

      {detections.loading ? (
        <div className="flex justify-center py-16">
          <Spinner />
        </div>
      ) : threats.length === 0 ? (
        <EmptyState
          icon={<RadarIcon />}
          title="No threats detected"
          description="Files flagged by the ML model, a signature, or a YARA rule surface here."
        />
      ) : (
        <>
          <div className="flex flex-wrap gap-6 text-sm">
            <span className="text-secondary">
              <span className="font-mono text-risk-high">{s?.malicious ?? 0}</span> malicious
            </span>
            <span className="text-secondary">
              <span className="font-mono text-risk-medium">{s?.suspicious ?? 0}</span> suspicious
            </span>
            {s && s.top_families.length > 0 && (
              <span className="text-secondary">
                top family:{' '}
                <span className="text-text">{s.top_families[0].family}</span> ({s.top_families[0].count})
              </span>
            )}
          </div>
          <ScanList detections={threats} />
        </>
      )}
    </div>
  );
}
