import { Link } from 'react-router-dom';

import { useAnalysis } from '../analysis/AnalysisStore';
import { AnalysisReport } from '../components/AnalysisReport';

export function FileAnalysisPage() {
  const { result } = useAnalysis();

  if (!result) {
    return (
      <div className="max-w-lg rounded-lg border border-slate-800 bg-slate-900 p-8 text-center">
        <h2 className="text-xl font-semibold">No analysis yet</h2>
        <p className="mt-2 text-sm text-slate-500">
          Upload a file to see its static-analysis report here.
        </p>
        <Link
          to="/upload"
          className="mt-4 inline-block rounded bg-cyan-600 px-4 py-2 text-sm font-medium text-white hover:bg-cyan-500"
        >
          Submit a file
        </Link>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-semibold">Analysis Report</h2>
        <Link to="/upload" className="text-sm text-cyan-400 hover:underline">
          Analyse another file →
        </Link>
      </div>
      <AnalysisReport result={result} />
    </div>
  );
}
