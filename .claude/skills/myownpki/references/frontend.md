# Frontend conventions

Server-side rendered with `templ` + htmx (ADR-03), interactive islands as Web Components
(ADR-04), fixed global CSS classes (ADR-12), three user-selectable layouts (ADR-13).
Everything is embedded in the binary via `embed.FS`. No Node.js in the build.

## Structure

```
internal/web/
├─ view/          shared view types: page metadata, appearance prefs (cookie), status, date formats
├─ components/    shared building blocks: status text, message bar, breadcrumb, page head, tabs,
│                 key/value list, number row, form row, choice row, wizard steps, certificate table …
├─ layout/        app.templ – the application shell (header, sidebar, variants A/B/C)
├─ pages/         one package per area: overview, certificates, authorities, admin, design …
└─ fixture/       sample data for the dev-mode prototype only (replaced by the store in phase 1)
web/styles/       tokens.css, base.css, components.css, layouts.css
web/islands/      TypeScript Web Components (later: <pki-chart> …)
```

- **Pages never know which layout they're in.** A page renders its content into `layout.App`;
  the variant comes from the user's appearance preference (`data-layout` on `<html>`).
- Pages receive plain view models (`view.*`, page-specific `Data` structs). They never query services.
- Shell: dark header (product, tenant switch, search, user menu as `<details>`), text-only sidebar
  grouped by area (Overview, Certificates, Authorities, ACME, Agents, Administration), breadcrumb,
  page title left with commands right, content at full width.
- Variants (prototype, final split decided later – PLAN §14): A narrow sidebar, B standard sidebar
  (default), C no sidebar (main entries as one line). Small screens use the C navigation.
- Appearance (layout, light/dark/system, density) is stored server-side in a cookie whose values are
  checked against an allow-list – no JavaScript.

## CSS

- Only classes defined in `web/styles/`. **No `style=""` attributes, no `<style>` blocks in templates** – CI checks this.
- Need something new? Add a class to `components.css` and show it in the `/design` gallery.
- Class names are short and stable: `.btn .btn-primary .cmdbar .cmd .st .st-ok .msg .msg-warn .table .numbers .tabs .kv .form-row .steps .mono …`
- Sizes, colors, radii, fonts only via tokens (`var(--…)`) defined in `tokens.css`.
- Two token groups:
  - **Brand tokens** (themeable): `--brand`, `--accent`, `--logo`, fonts, radius, density.
  - **Status tokens** (fixed): `--status-ok`, `--status-warn`, `--status-crit`, `--status-info`. Never themeable.
- **Light is the default**; dark via `data-theme="dark"`, or `data-theme="system"` to follow the OS.
- Density (compact/comfortable) via spacing tokens.

## Themes (three levels)

Global (instance) → tenant → user. Each level is a set of token overrides stored in the database and
emitted as a small CSS block. Higher levels decide which tokens lower levels may override.
- Themes are data, not code: no JavaScript, no templates, no arbitrary CSS selectors.
- Validate colors server-side and enforce WCAG contrast (auto-adjust foreground or reject).

## Look and feel

Direction: **classic enterprise admin tool** (Windows Admin Center, vCenter). An early mockup was
rejected as "too AI-looking", and the first gallery still read as such – so:
- **Tables for everything that is a list**; dense rows, horizontal scroll instead of wrapping serials.
- **No cards and no boxes around sections.** Sections are separated by spacing and headings.
  Overview figures are a plain number row (`.numbers`), never tiles with colored edges.
- **Small radii only** (2 px, `--radius`); few borders – row separators, not frames.
- **No icons** in status, messages, buttons or navigation. Status is text, optionally with a small dot
  (`.st .st-dot`); color supports the text, never replaces it.
- **The logo is the only image**: `<img>` from `/static/brand/` (embedded from `assets/brand`, see its
  README) with an `alt` attribute – the small on-dark variant in the 48 px header. Brand gold `#C27F12` is
  for the logo only: never an accent, link or status color (it is close to the fixed warning color),
  and it is deliberately not a CSS token.
- **Messages** are a plain line with a text label – "Note:", "Warning:", "Error:", "Done:" – and a
  colored left rule; no tinted (pastel) backgrounds.
- **Commands** sit in a flat command bar (`.cmdbar`) above the table or right of the page title.
- **Fonts:** system UI fonts – Segoe UI on Windows (like Windows Admin Center), the platform font
  elsewhere; Consolas/Cascadia Mono for serials, fingerprints, OIDs and PEM (`.mono`).
- Dates absolute (`2027-01-04`) with a relative hint ("in 12 days"); times in UTC.

## Real UI and prototype (phase 1 step 14)

- `internal/web/app*.go` serve the real UI on the services (auth, CA engine, keyring) – the same
  ones the REST API calls, with the same permission checks. The prototype (`prototype*.go`, fixture
  data) runs only with `serve --dev`. Pages are shared: real-only parts hang on a `Real` field.
- **Post/Redirect/Get:** every POST form ends with **303 See Other** on a GET page, so a reload never
  repeats an action. Exceptions: the private key download (answers with the file) and wizard steps
  that only move between steps (no side effect).
- **Messages to the next page** travel in the short-lived cookie `__Host-myownpki_flash`, never in
  the URL – no text from a link reaches a page.
- **`next=`** is a local path only (`safeNext`): exactly one leading `/`, no `//`, `\`, dot segments,
  control characters – also percent-encoded; anything else goes to the dashboard.
- **Sign-in pages** use `layout.Plain` and show nothing about the instance (no version, seal state,
  demo mark). One message for a wrong name, a wrong password and a lockout.
- State-changing commands (sign out, seal, key download) are POST forms with the CSRF token
  (`csrf_token` field), never links. Navigation shows only built pages (`view.Page.BuiltOnly`).
- The access log names the route pattern, not the path (no IDs), and no client address.

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
- Tests render every page and fail on inline styles/scripts, event handlers, inline `<svg>`, images other
  than brand files with `alt`,
  undefined CSS classes, unknown tokens and hard-coded colors outside `tokens.css`.

## Screenshots

- `task screenshots` renders the dev prototype (fixture data, DEV MODE banner stays visible) with a
  headless Edge/Chrome/Chromium into `docs/screenshots/` and optimizes the PNGs losslessly (target
  < 150 KB each). Browser: auto-detected, or `task screenshots -- -browser PATH` / `MYOWNPKI_BROWSER`.
- **Regenerate only at milestones**, not on every UI change: every committed image stays in the Git
  history for good.
