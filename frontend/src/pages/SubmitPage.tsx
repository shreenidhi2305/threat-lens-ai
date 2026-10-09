import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AxiosError, CanceledError } from 'axios';

import { useAnalysis } from '../analysis/AnalysisStore';
import { MAX_UPLOAD_BYTES, fetchUploadLimit, uploadSample } from '../lib/api';
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
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  // The cap is an administrator-set policy, so ask the API instead of hard-coding it.
  const [limit, setLimit] = useState(MAX_UPLOAD_BYTES);

  useEffect(() => {
    const controller = new AbortController();
    fetchUploadLimit(controller.signal)
      .then(setLimit)
      .catch(() => undefined);
    return () => controller.abort();
  }, []);

  // Validate before sending so an oversized file fails instantly instead of after a long upload.
  const choose = (next: File | null) => {
    if (next && next.size > limit) {
      setFile(null);
      setError(`${next.name} is ${bytes(next.size)}. The limit is ${bytes(limit)}.`);
      return;
    }
    setError(null);
    setFile(next);
  };

  const run = async () => {
    if (!file) return;
    const controller = new AbortController();
    abortRef.current = controller;
    setBusy(true);
    setProgress(0);
    setError(null);
    try {
      const result = await uploadSample(file, {
        onProgress: setProgress,
        signal: controller.signal,
      });
      commit(result);
      navigate('/reports');
    } catch (err) {
      if (err instanceof CanceledError) {
        setError('Analysis cancelled.');
      } else {
        setError(
          err instanceof AxiosError
            ? String(err.response?.data?.detail ?? err.message)
            : 'Upload failed',
        );
      }
    } finally {
      abortRef.current = null;
      setBusy(false);
    }
  };

  const cancel = () => abortRef.current?.abort();
  const sent = busy && progress >= 100;

  return (
    <div className="mx-auto max-w-2xl space-y-5">
      <div>
        <h2 className="text-lg font-semibold tracking-[-0.01em]">Submit a file for analysis</h2>
        <p className="mt-1 text-sm text-secondary">
          The file runs through the full pipeline: static analysis (hashing, type ID, signatures,
          YARA, indicators) and the ML detection model, fused into one verdict. It is never executed.
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
          choose(e.dataTransfer.files[0] ?? null);
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
          onChange={(e) => choose(e.target.files?.[0] ?? null)}
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
            <div className="mt-0.5 text-xs text-muted">Up to {Math.round(limit / 1024 / 1024)} MB</div>
          </>
        )}
      </div>

      {error && (
        <div className="rounded-md border border-risk-high/40 bg-risk-high-wash px-3 py-2 text-sm text-risk-high">
          {error}
        </div>
      )}

      {busy && (
        <div className="space-y-1.5" role="status" aria-live="polite">
          <div className="h-1.5 overflow-hidden rounded-full bg-surface-raised">
            <div
              className={`h-full rounded-full bg-accent transition-[width] duration-150 ease-out ${
                sent ? 'animate-pulse' : ''
              }`}
              style={{ width: `${sent ? 100 : progress}%` }}
            />
          </div>
          <div className="text-xs text-muted">
            {sent ? 'Uploaded. Analyzing the file…' : `Uploading… ${progress}%`}
          </div>
        </div>
      )}

      <div className="flex items-center gap-3">
        <Button onClick={run} disabled={!file} loading={busy}>
          {busy ? (sent ? 'Analyzing' : 'Uploading') : 'Run analysis'}
        </Button>
        {busy && (
          <button
            onClick={cancel}
            className="text-xs text-muted transition-colors hover:text-secondary"
          >
            Cancel
          </button>
        )}
        {file && !busy && (
          <button
            onClick={() => choose(null)}
            className="text-xs text-muted transition-colors hover:text-secondary"
          >
            Clear
          </button>
        )}
      </div>
    </div>
  );
}
