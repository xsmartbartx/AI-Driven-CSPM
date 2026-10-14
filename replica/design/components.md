# Components (built in `lib/ui-tokens/tokens.css`, used by site + app)

Own brand, system font stack, no third-party icons/fonts/logos. Icons: inline SVG drawn for this project. Accent is a placeholder teal; `/replica-brand` changes values, not names.

Button: variants primary, secondary (default), ghost, danger; sizes sm 28, md 36, lg 48; states hover, focus-visible (2px accent ring), disabled, loading (label kept, aria-busy). Real `<button>`/`<a>`. Used S01 S04 S06 S09 S19.
Input/Select/Textarea: 36px, border-input 3.9:1 vs bg, error text below + aria-invalid, mono for JSON. S04 S09 S18 S21.
Card: surface for tiles, 1px border + card shadow, 20px padding. S06 S12 S19.
KPI tile: label (xs muted), value (xl 28/700), delta chip. S06.
Score ring: SVG, role=img with aria-label "Posture score 78 of 100". S06.
Severity chip: critical/high/medium/low, colour AND text (never colour alone). S06-S08.
Status badge: open/fixed/accepted/false positive. S07 S08.
Data table: sortable header buttons, row link, empty + loading skeleton, keyboard reachable rows. S07 S10 S11 S18 S20.
Tabs/segmented: range 30d/3m/6m. S06.
Trend chart: SVG line/area, table fallback for screen readers. S06.
Banner: info, error, quota. Toast: aria-live polite. Dialog: focus trap, Esc closes (accepted-risk reason). Drawer: finding quick view (later).
Shell: header 56px, sidebar 248px collapsing under 900px, content max 1280. Dark mode via prefers-color-scheme + `data-theme` override.
Motion: 120/200ms, reduced-motion respected.
Contrast report: replica/design/tokens*.json, 17 pairs each, 0 AA failures (light and dark).
