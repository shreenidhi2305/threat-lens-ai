import { Link } from 'react-router-dom';

import { useAuth } from '../auth/AuthContext';
import { ScanList } from '../components/ScanList';
import {
  downloadPreviousReport,
  fetchDetections,
  fetchReports,
  fetchThreatSnapshot,
} from '../lib/api';
import { useAsync } from '../lib/useAsync';
import { Button } from '../ui/Button';
import { UploadIcon } from '../ui/icons';
import { EmptyState, Spinner, Stat } from '../ui/primitives';

export function DashboardPage() {
  const { user } = useAuth();
  const canScan =
    user?.role === 'Security Analyst' || user?.role === 'Administrator' || user?.role === 'Researcher';

  const snapshot = useAsync(fetchThreatSnapshot);
  const detections = useAsync(() => fetchDetections(12));
  const reports = useAsync(fetchReports);

  const s = snapshot.data;

  return (
    <div className="space-y-7">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold tracking-[-0.01em]">
            {s?.total_detections ? 'Recent activity' : `Welcome, ${user?.email.split('@')[0]}`}
          </h2>
          <p className="mt-1 text-sm text-secondary">
            {canScan
              ? 'Submit a file to run the static + ML detection pipeline.'
              : 'Monitoring view. File submission is limited to analysts and researchers.'}
          </p>
        </div>
        {canScan && (
          <Link to="/submit">
            <Button>
              <UploadIcon /> Submit file
            </Button>
          </Link>
        )}
      </div>

      <div className="grid gap-4 sm:grid-cols-4">
        <Stat label="Files analysed" value={s?.total_detections ?? '—'} />
        <Stat
          label="Malicious"
          value={<span className={s?.malicious ? 'text-risk-high' : undefined}>{s?.malicious ?? '—'}</span>}
          hint={`${s?.suspicious ?? 0} suspicious`}
        />
        <Stat
          label="Open alerts"
          value={<span className={s?.open_alerts ? 'text-risk-high' : undefined}>{s?.open_alerts ?? '—'}</span>}
        />
        <Stat label="Last 24h" value={s?.last_24h ?? '—'} />
      </div>

      {detections.loading ? (
        <div className="flex justify-center py-16">
          <Spinner />
        </div>
      ) : detections.data && detections.data.length > 0 ? (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-2xs font-semibold uppercase tracking-[0.08em] text-muted">
              Detection log
            </h3>
            <Link to="/threats" className="text-xs text-accent hover:underline">
              Threat monitor
            </Link>
          </div>
          <ScanList detections={detections.data} />
        </div>
      ) : (
        <EmptyState
          icon={<UploadIcon />}
          title="No detections yet"
          description={
            canScan
              ? 'Analysed files and their verdicts will appear here.'
              : 'Detections will appear here once analysts start submitting files.'
          }
          action={
            canScan ? (
              <Link to="/submit">
                <Button>Submit your first file</Button>
              </Link>
            ) : undefined
          }
        />
      )}
            {reports.data && reports.data.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-2xs font-semibold uppercase tracking-[0.08em] text-muted">
              Previous Threat Reports
            </h3>
          </div>

          <div className="overflow-x-auto rounded-lg border border-line bg-surface">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line-soft text-left text-2xs uppercase tracking-[0.06em] text-muted">
                  <th className="px-4 py-2.5 font-medium">Filename</th>
                  <th className="px-4 py-2.5 font-medium">Verdict</th>
                  <th className="px-4 py-2.5 font-medium">Risk</th>
                  <th className="px-4 py-2.5 text-right font-medium">Download</th>
                </tr>
              </thead>

              <tbody className="divide-y divide-line-soft">
                {reports.data.map((report) => (
                  <tr
                    key={report.report_id}
                    className="transition-colors hover:bg-surface-raised"
                  >
                    <td className="px-4 py-2.5">
                      <span className="truncate font-mono text-xs text-text">
                        {report.filename ?? 'Unknown file'}
                      </span>
                    </td>

                    <td className="px-4 py-2.5 text-secondary">
                      {report.predicted_class ?? 'Unknown'}
                    </td>

                    <td className="px-4 py-2.5">
                      <span className="text-sm font-medium">
                        {report.risk_score ?? '—'}
                      </span>
                    </td>

                    <td className="px-4 py-2.5 text-right">
                      <button
                        type="button"
                        className="text-xs text-accent hover:underline"
                        onClick={async () => {
                          const blob = await downloadPreviousReport(report.report_id);
                          const url = URL.createObjectURL(blob);
                          const link = document.createElement('a');
                          link.href = url;
                          link.download = `${report.filename ?? 'analysis'}-report.pdf`;
                          link.click();
                          URL.revokeObjectURL(url);
                        }}
                      >
                        Download PDF
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
