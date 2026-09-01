# DESIGN.md — ThreatLens AI

Dark, near-monochrome analyst console. Color is severity. Implemented as CSS
custom properties in `frontend/src/index.css`, surfaced to Tailwind through
`tailwind.config.js` (`bg-surface`, `text-muted`, `border-line`, `text-risk-high`…).

## Color (OKLCH)

### Neutrals — cool, faintly blue-tinted (hue 265, chroma ~0.006)

| Token | OKLCH | Role |
|---|---|---|
| `--bg` | `oklch(0.15 0.006 265)` | app background (deepest) |
| `--surface` | `oklch(0.185 0.006 265)` | panels, cards, sidebar |
| `--surface-raised` | `oklch(0.225 0.007 265)` | inputs, hover, nested rows |
| `--line` | `oklch(0.29 0.008 265)` | borders |
| `--line-soft` | `oklch(0.24 0.007 265)` | hairline dividers |
| `--text` | `oklch(0.96 0.004 265)` | primary text |
| `--text-secondary` | `oklch(0.74 0.006 265)` | labels, secondary |
| `--text-muted` | `oklch(0.56 0.006 265)` | captions, disabled |

### Accent — one restrained indigo, interactive affordance only (≤10% of surface)

| Token | OKLCH | Role |
|---|---|---|
| `--accent` | `oklch(0.70 0.13 265)` | links, focus ring, active nav, selection |
| `--accent-quiet` | `oklch(0.70 0.13 265 / 0.12)` | active nav background wash |

### Severity — the only loud color, carries risk level + semantic state

| Token | OKLCH | Role |
|---|---|---|
| `--risk-low` / success | `oklch(0.74 0.14 158)` | low risk, benign, success |
| `--risk-medium` / warning | `oklch(0.80 0.13 82)` | medium risk, suspicious, warning |
| `--risk-high` / danger | `oklch(0.64 0.20 25)` | high risk, malicious, error |
| each `-wash` | same hue `/ 0.12–0.15` | panel background tint |

Never `#000` / `#fff`. Primary buttons: `--text` fill, `--bg` label (near-white
on near-black), no hue.

## Typography

- **UI:** `Inter, system-ui, -apple-system, "Segoe UI", sans-serif` (Inter loaded
  from Google Fonts in `index.html`, system fallback is fine).
- **Mono:** `"JetBrains Mono", ui-monospace, "SF Mono", Menlo, monospace` for
  hashes, paths, IOCs, rule names, byte previews.
- Fixed rem scale, ratio ~1.2: `12 · 13 · 14(base) · 16 · 20 · 25 · 32`.
- Weights: 400 body, 500 labels/buttons, 600 headings. Tracking `-0.01em` on
  headings, `0.06em` uppercase on small section eyebrows.

## Layout

- **App shell:** fixed 240px left sidebar (`--surface`), top bar 56px with page
  context + user menu, content max-width 1200px with generous gutters.
- Sidebar collapses under 900px to an icon rail; content single-column under 720px.
- Spacing scale: `4 · 8 · 12 · 16 · 24 · 32 · 48`. Vary it; section gaps 24–32,
  in-panel 12–16.
- Panels: 1px `--line` border, 10px radius, `--surface` fill. No nested panels.
  Not everything is a panel: info rows and tables sit directly on the background.

## Components

Button, Badge (severity + neutral), Panel, SectionLabel, InfoRow (label / mono
value / copy), CopyButton, Stat, RiskMeter (horizontal bar, severity-filled),
EmptyState, Spinner, Field. Every interactive element defines default / hover /
focus-visible / active / disabled; inputs add error.

## Motion

150–200ms, `ease-out` (`cubic-bezier(0.22,1,0.36,1)`). Used for: hover feedback,
focus ring, panel/skeleton reveal, upload progress, nav transitions. No page-load
choreography.

## Report screen (the crown)

Sticky verdict header (score numeral, level badge, classification, recommended
action, filename + SHA-256). Body sections in order: Suspicious Indicators →
Detection (signature + YARA) → File Details (metadata + hashes) → Network IOCs →
Strings. Technical values monospaced with hover-reveal copy buttons.
