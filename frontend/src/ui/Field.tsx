import type { InputHTMLAttributes, ReactNode } from 'react';

interface Props extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  hint?: ReactNode;
  error?: string;
}

export function Field({ label, hint, error, className = '', id, ...props }: Props) {
  const fieldId = id ?? `f-${label.toLowerCase().replace(/\s+/g, '-')}`;
  return (
    <div className={className}>
      <label htmlFor={fieldId} className="mb-1.5 block text-xs font-medium text-secondary">
        {label}
      </label>
      <input
        id={fieldId}
        className={`h-10 w-full rounded-md border bg-surface-raised px-3 text-sm text-text transition-colors duration-150 ease-out placeholder:text-muted focus:outline-none focus-visible:border-accent ${
          error ? 'border-risk-high' : 'border-line'
        }`}
        {...props}
      />
      {error ? (
        <p className="mt-1.5 text-xs text-risk-high">{error}</p>
      ) : hint ? (
        <p className="mt-1.5 text-xs text-muted">{hint}</p>
      ) : null}
    </div>
  );
}
