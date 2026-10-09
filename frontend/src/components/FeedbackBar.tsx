import { useState } from 'react';

import { submitFeedback } from '../lib/api';
import { errorMessage } from '../lib/download';
import type { Detection } from '../lib/types';

/**
 * Lets an analyst confirm or correct a verdict. The label is ground truth that feeds the
 * live accuracy figures on the admin ML page and the retraining export.
 */
export function FeedbackBar({ detection }: { detection: Detection }) {
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const send = async (label: 'malicious' | 'benign') => {
    setBusy(true);
    setError(null);
    try {
      const record = await submitFeedback(detection.sha256, label);
      setDone(
        record.agrees
          ? `Recorded: ${label} (matches the verdict).`
          : `Recorded: ${label}. The model said ${record.model_verdict}; this correction is used to track accuracy.`,
      );
    } catch (err) {
      setError(errorMessage(err, 'Could not record feedback'));
    } finally {
      setBusy(false);
    }
  };

  const btn =
    'rounded border border-line px-2 py-0.5 text-2xs text-secondary hover:text-text disabled:opacity-50';

  return (
    <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-line-soft pt-2.5 text-xs">
      <span className="text-muted">Is this verdict right?</span>
      <button className={btn} disabled={busy} onClick={() => send('malicious')}>
        Confirm malicious
      </button>
      <button className={btn} disabled={busy} onClick={() => send('benign')}>
        Mark benign (false positive)
      </button>
      {done && <span className="text-risk-low">{done}</span>}
      {error && <span className="text-risk-high">{error}</span>}
    </div>
  );
}
