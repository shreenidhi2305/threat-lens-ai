/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: 'var(--bg)',
        surface: 'var(--surface)',
        'surface-raised': 'var(--surface-raised)',
        line: 'var(--line)',
        'line-soft': 'var(--line-soft)',
        text: 'var(--text)',
        secondary: 'var(--text-secondary)',
        muted: 'var(--text-muted)',
        accent: 'var(--accent)',
        'accent-quiet': 'var(--accent-quiet)',
        risk: {
          low: 'var(--risk-low)',
          medium: 'var(--risk-medium)',
          high: 'var(--risk-high)',
          'low-wash': 'var(--risk-low-wash)',
          'medium-wash': 'var(--risk-medium-wash)',
          'high-wash': 'var(--risk-high-wash)',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', '"SF Mono"', 'Menlo', 'monospace'],
      },
      fontSize: {
        '2xs': ['0.75rem', { lineHeight: '1rem' }],
        xs: ['0.8125rem', { lineHeight: '1.15rem' }],
        sm: ['0.875rem', { lineHeight: '1.4rem' }],
        base: ['0.9375rem', { lineHeight: '1.55rem' }],
        lg: ['1.125rem', { lineHeight: '1.6rem' }],
        xl: ['1.4375rem', { lineHeight: '1.75rem' }],
        '2xl': ['1.75rem', { lineHeight: '2rem' }],
        '3xl': ['2.25rem', { lineHeight: '2.4rem' }],
        '5xl': ['3.25rem', { lineHeight: '1' }],
      },
      borderRadius: {
        DEFAULT: 'var(--radius)',
        md: '8px',
        lg: '12px',
      },
      transitionTimingFunction: {
        out: 'var(--ease)',
      },
    },
  },
  plugins: [],
};
