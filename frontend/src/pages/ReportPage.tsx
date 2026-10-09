import { useState } from 'react';
import { Link } from 'react-router-dom';

import { useAnalysis } from '../analysis/AnalysisStore';
import { AnalysisReport } from '../components/AnalysisReport';
import { downloadAnalysisPdf, downloadSummaryReport, fetchReportHistory } from '../lib/api';
import type { ReportRecord } from '../lib/types';
import { useAsync } from '../lib/useAsync';
import { Button } from '../ui/Button';
import { DownloadIcon, FileScanIcon } from '../ui/icons';
import { Badge, EmptyState, Panel, Spinner } from '../ui/primitives';

const WINDOWS = ['24h', '7d', '30d'] as const;

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.style.display = 'none';
  document.body.appendChild(link);
  link.click();
  window.setTimeout(() => {
    URL.revokeObjectURL(url);
    link.remove();
  }, 1000);
}

function when(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function ReportCenter() {
  const history = useAsync(() => fetchReportHistory(20));
  const [window_, setWindow] = useState<(typeof WINDOWS)[number]>('7d');
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const generateSummary = async () => {
    setGenerating(true);
    setError(null);
    try {
      const blob = await downloadSummaryReport(window_);
      triggerDownload(blob, `threat-summary-${window_}.pdf`);
      history.reload();
    } catch {
      setError('The summary report could not be generated. Please try again.');
    } finally {
      setGenerating(false);
    }
  };

  const items: ReportRecord[] = history.data ?? [];

  return (
    <Panel
      title="Report Center"
      aside={
        <div className="flex items-center gap-1.5">
          <select
            value={window_}
            onChange={(e) => setWindow(e.target.value as (typeof WINDOWS)[number])}
            className="h-8 rounded-md border border-line bg-surface px-2 text-2xs text-text"
          >
            {WINDOWS.map((w) => (
              <option key={w} value={w}>
                {w}
              </option>
            ))}
          </select>
          <Button variant="secondary" size="sm" onClick={generateSummary} loading={generating}>
            <DownloadIcon />
            Threat summary
          </Button>
        </div>
      }
    >
      {error && <p className="mb-3 text-sm text-risk-high">{error}</p>}
      {history.loading ? (
        <div className="flex justify-center py-6">
          <Spinner />
        </div>
      ) : items.length === 0 ? (
        <p className="text-sm text-secondary">
          No reports generated yet. Download an analysis report or a threat summary and it will
          appear here.
        </p>
      ) : (
        <ul className="divide-y divide-line-soft">
          {items.map((r) => (
            <li key={r.id} className="flex items-center justify-between gap-3 py-2.5 text-sm">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <Badge tone={r.report_type === 'summary' ? 'accent' : 'neutral'}>
                    {r.report_type}
                  </Badge>
                  <span className="truncate text-text">{r.title}</span>
                </div>
                <div className="mt-0.5 text-2xs text-muted">
                  {when(r.created_at)}
                  {r.verdict_label && <> · verdict {r.verdict_label}</>}
                  {r.window && <> · window {r.window}</>}
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

export function ReportPage() {
  const { result } = useAnalysis();
  const [downloading, setDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  const downloadReport = async () => {
    if (!result) return;
    setDownloading(true);
    setDownloadError(null);
    try {
      const blob = await downloadAnalysisPdf(result);
      triggerDownload(blob, `${result.object_path.split('/').pop() || 'analysis'}-report.pdf`);
    } catch {
      setDownloadError('The PDF report could not be generated. Please try again.');
    } finally {
      setDownloading(false);
    }
  };

  return (
    <div className="space-y-5">
      <ReportCenter />

      {!result ? (
        <EmptyState
          icon={<FileScanIcon />}
          title="No report to show"
          description="Submit a file for static analysis and its report will open here."
          action={
            <Link to="/submit">
              <Button>Submit a file</Button>
            </Link>
          }
        />
      ) : (
        <div className="space-y-5">
          <div className="flex items-center justify-between">
            <p className="text-sm text-secondary">
              Analysis of{' '}
              <span className="font-mono text-text">
                {result.object_path.split('/').pop() || result.object_path}
              </span>
            </p>
            <div className="flex items-center gap-2">
              <Button variant="secondary" size="sm" onClick={downloadReport} loading={downloading}>
                <DownloadIcon />
                Download PDF Report
              </Button>
              <Link to="/submit">
                <Button variant="secondary" size="sm">
                  New scan
                </Button>
              </Link>
            </div>
          </div>
          {downloadError && <p className="text-sm text-risk-high">{downloadError}</p>}
          <AnalysisReport result={result} />
        </div>
      )}
    </div>
  );
}
