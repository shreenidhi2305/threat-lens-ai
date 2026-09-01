import { useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AxiosError } from 'axios';

import { useAnalysis } from '../analysis/AnalysisStore';
import { uploadSample } from '../lib/api';

export function FileUploadPage() {
  const { setResult } = useAnalysis();
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      const result = await uploadSample(file);
      setResult(result);
      navigate('/analysis');
    } catch (err) {
      const detail =
        err instanceof AxiosError
          ? (err.response?.data?.detail ?? err.message)
          : 'Upload failed';
      setError(String(detail));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="max-w-2xl space-y-4">
      <div>
        <h2 className="text-2xl font-semibold">Submit a suspicious file</h2>
        <p className="text-sm text-slate-500">
          The file is stored and analysed statically. It is never executed.
        </p>
      </div>

      <div
        onClick={() => inputRef.current?.click()}
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => {
          e.preventDefault();
          setFile(e.dataTransfer.files[0] ?? null);
        }}
        className="cursor-pointer rounded-lg border-2 border-dashed border-slate-700 bg-slate-900 p-10 text-center hover:border-cyan-600"
      >
        <input
          ref={inputRef}
          type="file"
          className="hidden"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
        />
        {file ? (
          <div>
            <div className="font-medium text-slate-200">{file.name}</div>
            <div className="text-xs text-slate-500">{file.size.toLocaleString()} bytes</div>
          </div>
        ) : (
          <div className="text-slate-500">Click to choose a file, or drag it here</div>
        )}
      </div>

      {error && <p className="text-sm text-rose-400">{error}</p>}

      <button
        onClick={submit}
        disabled={!file || busy}
        className="rounded bg-cyan-600 px-4 py-2 font-medium text-white hover:bg-cyan-500 disabled:opacity-50"
      >
        {busy ? 'Analysing…' : 'Upload & analyse'}
      </button>
    </div>
  );
}
