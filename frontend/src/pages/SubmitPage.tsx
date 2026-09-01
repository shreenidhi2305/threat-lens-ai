import { useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AxiosError } from 'axios';

import { useAnalysis } from '../analysis/AnalysisStore';
import { uploadSample } from '../lib/api';
import { Button } from '../ui/Button';
import { UploadIcon } from '../ui/icons';

function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

export function SubmitPage() {
  const { commit } = useAnalysis();
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const run = async () => {
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      const result = await uploadSample(file);
      commit(result);
      navigate('/reports');
    } catch (err) {
      setError(
        err instanceof AxiosError
          ? String(err.response?.data?.detail ?? err.message)
          : 'Upload failed',
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto max-w-2xl space-y-5">
      <div>
        <h2 className="text-lg font-semibold tracking-[-0.01em]">Submit a file for analysis</h2>
        <p className="mt-1 text-sm text-secondary">
          The file is stored and analyzed statically: hashing, type identification, signature and
          YARA matching, and indicator extraction. It is never executed.
        </p>
      </div>

      <div
        onClick={() => inputRef.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          setFile(e.dataTransfer.files[0] ?? null);
        }}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => e.key === 'Enter' && inputRef.current?.click()}
        className={`flex cursor-pointer flex-col items-center justify-center rounded-lg border border-dashed px-6 py-14 text-center transition-colors duration-150 ease-out ${
          dragging ? 'border-accent bg-accent-quiet' : 'border-line bg-surface hover:border-secondary'
        }`}
      >
        <input
          ref={inputRef}
          type="file"
          className="hidden"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
        />
        <UploadIcon className="mb-3 text-2xl text-muted" />
        {file ? (
          <>
            <div className="font-mono text-sm text-text">{file.name}</div>
            <div className="mt-0.5 text-xs text-muted">{bytes(file.size)}</div>
          </>
        ) : (
          <>
            <div className="text-sm text-text">Drop a file here, or click to browse</div>
            <div className="mt-0.5 text-xs text-muted">Up to 32 MB</div>
          </>
        )}
      </div>

      {error && (
        <div className="rounded-md border border-risk-high/40 bg-risk-high-wash px-3 py-2 text-sm text-risk-high">
          {error}
        </div>
      )}

      <div className="flex items-center gap-3">
        <Button onClick={run} disabled={!file} loading={busy}>
          {busy ? 'Analyzing' : 'Run analysis'}
        </Button>
        {file && !busy && (
          <button
            onClick={() => setFile(null)}
            className="text-xs text-muted transition-colors hover:text-secondary"
          >
            Clear
          </button>
        )}
      </div>
    </div>
  );
}
