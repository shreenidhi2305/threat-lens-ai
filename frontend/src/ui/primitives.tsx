import { useState } from 'react';
import type { ReactNode } from 'react';

import { CheckIcon, CopyIcon } from './icons';
import type { RiskLevel } from '../lib/types';

/* -------------------------------------------------------------------------- */

export function Panel({
  title,
  aside,
  children,
  className = '',
}: {
  title?: ReactNode;
  aside?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`min-w-0 overflow-hidden rounded-lg border border-line bg-surface ${className}`}>
      {title && (
        <header className="flex items-center justify-between gap-3 border-b border-line-soft px-4 py-3">
          <h2 className="text-2xs font-semibold uppercase tracking-[0.08em] text-muted">{title}</h2>
          {aside && <div className="shrink-0">{aside}</div>}
        </header>
      )}
      <div className="min-w-0 p-4">{children}</div>
    </section>
  );
}

/* -------------------------------------------------------------------------- */

export function CopyButton({ value, label }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        void navigator.clipboard.writeText(value);
        setCopied(true);
        setTimeout(() => setCopied(false), 1200);
      }}
      aria-label={`Copy ${label ?? 'value'}`}
      className="shrink-0 rounded p-1 text-muted opacity-0 transition-opacity duration-150 ease-out hover:text-text group-hover:opacity-100 focus-visible:opacity-100"
    >
      {copied ? <CheckIcon className="text-risk-low" /> : <CopyIcon />}
    </button>
  );
}

export function InfoRow({
  label,
  value,
  mono = false,
  copy = false,
}: {
  label: string;
  value: ReactNode;
  mono?: boolean;
  copy?: boolean;
}) {
  return (
    <div className="group flex items-start justify-between gap-6 border-b border-line-soft py-2 text-sm last:border-0">
      <span className="shrink-0 pt-px text-secondary">{label}</span>
      <span className="flex min-w-0 items-center gap-1.5">
        <span className={`text-right ${mono ? 'break-all font-mono text-xs text-text' : 'text-text'}`}>
          {value}
        </span>
        {copy && typeof value === 'string' && <CopyButton value={value} label={label} />}
      </span>
    </div>
  );
}

/* -------------------------------------------------------------------------- */

type BadgeTone = RiskLevel | 'neutral' | 'accent';

const BADGE: Record<BadgeTone, string> = {
  low: 'bg-risk-low-wash text-risk-low',
  medium: 'bg-risk-medium-wash text-risk-medium',
  high: 'bg-risk-high-wash text-risk-high',
  neutral: 'bg-surface-raised text-secondary',
  accent: 'bg-accent-quiet text-accent',
};

export function Badge({
  tone = 'neutral',
  children,
  className = '',
}: {
  tone?: BadgeTone;
  children: ReactNode;
  className?: string;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-2xs font-medium ${BADGE[tone]} ${className}`}
    >
      {children}
    </span>
  );
}

/* -------------------------------------------------------------------------- */

export function RiskMeter({ score, level }: { score: number; level: RiskLevel }) {
  const color =
    level === 'high' ? 'var(--risk-high)' : level === 'medium' ? 'var(--risk-medium)' : 'var(--risk-low)';
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-raised">
      <div
        className="h-full rounded-full transition-[width] duration-500 ease-out"
        style={{ width: `${Math.max(score, 2)}%`, backgroundColor: color }}
      />
    </div>
  );
}

/* -------------------------------------------------------------------------- */

export function Stat({ label, value, hint }: { label: string; value: ReactNode; hint?: ReactNode }) {
  return (
    <div className="rounded-lg border border-line bg-surface px-4 py-3.5">
      <div className="text-2xs font-medium uppercase tracking-[0.06em] text-muted">{label}</div>
      <div className="mt-1.5 text-2xl font-semibold tracking-[-0.01em] text-text">{value}</div>
      {hint && <div className="mt-0.5 text-xs text-secondary">{hint}</div>}
    </div>
  );
}

/* -------------------------------------------------------------------------- */

export function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon?: ReactNode;
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-line bg-surface/40 px-6 py-16 text-center">
      {icon && <div className="mb-3 text-2xl text-muted">{icon}</div>}
      <h3 className="text-base font-medium text-text">{title}</h3>
      {description && <p className="mt-1 max-w-sm text-sm text-secondary">{description}</p>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

/* -------------------------------------------------------------------------- */

export function Spinner({ className = '' }: { className?: string }) {
  return (
    <span
      className={`inline-block size-4 animate-spin rounded-full border-2 border-secondary border-r-transparent ${className}`}
    />
  );
}

export function SectionLabel({ children }: { children: ReactNode }) {
  return (
    <h2 className="mb-3 text-2xs font-semibold uppercase tracking-[0.08em] text-muted">{children}</h2>
  );
}
