import { Link } from 'react-router-dom';

import { useAnalysis } from '../analysis/AnalysisStore';
import { AnalysisReport } from '../components/AnalysisReport';
import { downloadAnalysisPdf } from '../lib/api';
import { Button } from '../ui/Button';
import { DownloadIcon, FileScanIcon } from '../ui/icons';
import { EmptyState } from '../ui/primitives';
import { useState } from 'react';

export function ReportPage() {
  const { result } = useAnalysis();
  const [downloading, setDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  if (!result) {
    return (
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
    );
  }

  const downloadReport = async () => {
    setDownloading(true);
    setDownloadError(null);
    try {
      const blob = await downloadAnalysisPdf(result);
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `${result.object_path.split('/').pop() || 'analysis'}-report.pdf`;
      link.style.display = 'none';
      document.body.appendChild(link);
      link.click();
      window.setTimeout(() => {
        URL.revokeObjectURL(url);
        link.remove();
      }, 1000);
    } catch {
      setDownloadError('The PDF report could not be generated. Please try again.');
    } finally {
      setDownloading(false);
    }
  };

  return (
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
  );
}
