# Frontend conventions

Server-side rendered with `templ` + htmx (ADR-03), interactive islands as Web Components
(ADR-04), fixed global CSS classes (ADR-12), three user-selectable layouts (ADR-13).
Everything is embedded in the binary via `embed.FS`. No Node.js in the build.

## Structure

```
internal/web/
├─ layout/        shells: compact.templ (A), standard.templ (B), focus.templ (C)
├─ components/    shared building blocks: table, badge, stat, form, chart box, empty state …
└─ pages/         one package/file per area: certificates, cas, domains, agents, audit, settings, design
web/styles/       tokens.css, base.css, components.css, layouts.css
web/islands/      TypeScript Web Components (<pki-chart>, <pki-agent-status>, <pki-dashboard>)
```

- **Pages never know which layout they're in.** A page renders its content; the shell is chosen from
  the user's preference (fallback: role default; mobile: C). A new page must work in all three shells.
- Shells differ in navigation and chrome only (A: tree nav + toolbar + task bar; B: top nav + title/filter
  bar + info column; C: slim text nav + KPIs + "needs attention").

## CSS

- Only classes defined in `web/styles/`. **No `style=""` attributes, no `<style>` blocks in templates** – CI checks this.
- Need something new? Add a class to `components.css` and show it in the `/design` gallery.
- Class names are short and stable: `.card .btn .btn-primary .tb .bd-ok .bd-wa .bd-cr .st .stat .form-row .chart-box .mono …`
- Sizes, colours, radii, fonts only via tokens (`var(--…)`) defined in `tokens.css`.
- Two token groups:
  - **Brand tokens** (themeable): `--brand`, `--accent`, `--logo`, fonts, radius, density.
  - **Status tokens** (fixed): `--status-ok`, `--status-warn`, `--status-crit`, `--status-info`. Never themeable.
- Light/dark via token overrides (`prefers-color-scheme` + explicit user choice).
- Density (compact/comfortable) via spacing tokens.

## Themes (three levels)

Global (instance) → tenant → user. Each level is a set of token overrides stored in the database and
emitted as a small CSS block. Higher levels decide which tokens lower levels may override.
- Themes are data, not code: no JavaScript, no templates, no arbitrary CSS selectors.
- Validate colours server-side and enforce WCAG contrast (auto-adjust foreground or reject).

## Look and feel

An early mockup was rejected as "too AI-looking". Aim for a calm, professional admin tool:
- Prefer **tables over cards** for lists; cards only for KPIs and dashboard widgets.
- **Icons sparingly** – navigation and a few actions; not in every row or heading. One icon set
  (an SVG sprite embedded in the binary), outline style.
- Serial numbers, fingerprints, OIDs, PEM in monospace (`.mono`) – admins compare them character by character.
- Dates absolute (`2027-01-04`) with relative hint ("in 12 days") where useful; times in UTC with local hint.
- Status always as colour **plus** text/icon (accessibility).

## htmx

- Progressive enhancement: forms work without JS where practical; htmx swaps fragments.
- CSRF token from `<meta name="csrf-token">`, sent via `hx-headers` set once on `<body>`.
- Server returns HTML fragments for htmx requests (`HX-Request` header), full pages otherwise.
- Live updates via Server-Sent Events (htmx SSE extension) – agent status, issuance feed.
- No `hx-on` inline handlers (CSP forbids inline script).

## Islands and charts

- Web Components in TypeScript, bundled by esbuild **as a Go library** during `go generate`; output embedded.
- Islands fetch JSON from the REST API (same session) or receive it via a `<script type="application/json">` data block.
- Charts: Apache ECharts; the ECharts theme is generated from the CSS tokens so charts follow themes and dark mode.
  Status series always use status tokens.
- Dashboard grid: gridstack.js; layout persisted per user.
- Vendor third-party JS as pinned files in the repo (with license), served from the binary – no CDNs (CSP `script-src 'self'`).

## Accessibility and testing

- Semantic HTML, labels for every input, keyboard navigation, visible focus.
- Screenshot tests per layout (A/B/C) and theme (light/dark) for key pages.
