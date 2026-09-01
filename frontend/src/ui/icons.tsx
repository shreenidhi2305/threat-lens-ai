import type { SVGProps } from 'react';

type IconProps = SVGProps<SVGSVGElement>;

function Base({ children, ...props }: IconProps & { children: React.ReactNode }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      width="1em"
      height="1em"
      aria-hidden="true"
      {...props}
    >
      {children}
    </svg>
  );
}

export const ShieldIcon = (p: IconProps) => (
  <Base {...p}>
    <path d="M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6l7-3z" />
    <path d="M9 12l2 2 4-4" />
  </Base>
);

export const GridIcon = (p: IconProps) => (
  <Base {...p}>
    <rect x="3" y="3" width="7" height="7" rx="1.5" />
    <rect x="14" y="3" width="7" height="7" rx="1.5" />
    <rect x="3" y="14" width="7" height="7" rx="1.5" />
    <rect x="14" y="14" width="7" height="7" rx="1.5" />
  </Base>
);

export const UploadIcon = (p: IconProps) => (
  <Base {...p}>
    <path d="M12 15V4m0 0L8 8m4-4l4 4" />
    <path d="M5 15v3a2 2 0 002 2h10a2 2 0 002-2v-3" />
  </Base>
);

export const FileScanIcon = (p: IconProps) => (
  <Base {...p}>
    <path d="M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8l-5-5z" />
    <path d="M14 3v5h5" />
    <circle cx="11" cy="13" r="2.4" />
    <path d="M14.5 16.5L17 19" />
  </Base>
);

export const RadarIcon = (p: IconProps) => (
  <Base {...p}>
    <path d="M12 12L20 6" />
    <path d="M20 12a8 8 0 11-4.6-7.2" />
    <path d="M16.5 12a4.5 4.5 0 11-2.6-4.1" />
  </Base>
);

export const BellIcon = (p: IconProps) => (
  <Base {...p}>
    <path d="M18 8a6 6 0 10-12 0c0 6-2.5 7-2.5 7h17S18 14 18 8z" />
    <path d="M10.5 19a2 2 0 003 0" />
  </Base>
);

export const ChartIcon = (p: IconProps) => (
  <Base {...p}>
    <path d="M4 20V10M10 20V4M16 20v-7M22 20H2" />
  </Base>
);

export const UserIcon = (p: IconProps) => (
  <Base {...p}>
    <circle cx="12" cy="8" r="3.5" />
    <path d="M5 20c0-3.3 3.1-6 7-6s7 2.7 7 6" />
  </Base>
);

export const LogoutIcon = (p: IconProps) => (
  <Base {...p}>
    <path d="M15 4h3a2 2 0 012 2v12a2 2 0 01-2 2h-3" />
    <path d="M10 12h10m0 0l-3-3m3 3l-3 3" />
  </Base>
);

export const CopyIcon = (p: IconProps) => (
  <Base {...p}>
    <rect x="9" y="9" width="12" height="12" rx="2" />
    <path d="M5 15V5a2 2 0 012-2h8" />
  </Base>
);

export const CheckIcon = (p: IconProps) => (
  <Base {...p}>
    <path d="M4 12.5l5 5 11-11" />
  </Base>
);

export const AlertTriangleIcon = (p: IconProps) => (
  <Base {...p}>
    <path d="M12 4l9 15.5H3L12 4z" />
    <path d="M12 10v4m0 3v.5" />
  </Base>
);

export const ArrowRightIcon = (p: IconProps) => (
  <Base {...p}>
    <path d="M5 12h14m0 0l-6-6m6 6l-6 6" />
  </Base>
);

export const ChevronDownIcon = (p: IconProps) => (
  <Base {...p}>
    <path d="M6 9l6 6 6-6" />
  </Base>
);

export const GlobeIcon = (p: IconProps) => (
  <Base {...p}>
    <circle cx="12" cy="12" r="9" />
    <path d="M3 12h18M12 3c2.5 2.7 3.8 6 3.8 9S14.5 18.3 12 21c-2.5-2.7-3.8-6-3.8-9S9.5 5.7 12 3z" />
  </Base>
);

export const FingerprintIcon = (p: IconProps) => (
  <Base {...p}>
    <path d="M12 4a8 8 0 018 8v1" />
    <path d="M4 13v-1a8 8 0 013.5-6.6" />
    <path d="M8 12a4 4 0 018 0v2c0 1.5.3 3 1 4.5" />
    <path d="M12 12v3c0 2 .5 3.8 1.5 5.3" />
    <path d="M8.2 16c.5 1.8.6 3.4.3 5" />
  </Base>
);

export const CodeIcon = (p: IconProps) => (
  <Base {...p}>
    <path d="M9 8l-4 4 4 4M15 8l4 4-4 4" />
  </Base>
);
