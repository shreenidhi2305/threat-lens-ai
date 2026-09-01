import { Link } from 'react-router-dom';

import { useAnalysis } from '../analysis/AnalysisStore';
import { AnalysisReport } from '../components/AnalysisReport';
import { Button } from '../ui/Button';
import { FileScanIcon } from '../ui/icons';
import { EmptyState } from '../ui/primitives';

export function ReportPage() {
  const { result } = useAnalysis();

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

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <p className="text-sm text-secondary">
          Static analysis of{' '}
          <span className="font-mono text-text">
            {result.object_path.split('/').pop() || result.object_path}
          </span>
        </p>
        <Link to="/submit">
          <Button variant="secondary" size="sm">
            New scan
          </Button>
        </Link>
      </div>
      <AnalysisReport result={result} />
    </div>
  );
}
