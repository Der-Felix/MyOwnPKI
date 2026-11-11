---
name: ai-ui-design-master
description: Principles against generic "AI slop" UI – anti-default theming, established behavior instead of from-scratch primitives, one standout moment per page, and purposeful micro-interactions – applied to MyOwnPKI within the project's constraints (templ + htmx + Web Component islands, strict CSP, calm and plain admin look). Use it when designing or reviewing UI, components, themes or animations.
---

# AI UI Design Master (MyOwnPKI edition)

## MyOwnPKI constraints – these override everything below

Everything after this section is a general reference. Where it conflicts with this section, `docs/PLAN.md`
(ADRs) or `.claude/skills/myownpki/references/frontend.md`, those win. Read `frontend.md` first.

- **Stack.** templ + htmx for pages and interaction, Web Components ("islands") written in TypeScript where
  JavaScript is unavoidable, bundled with esbuild as a Go library (ADR-03, ADR-04). **No** React, Next.js,
  Tailwind, shadcn/ui, Radix, Base UI, Sonner, Vaul, cmdk, NumberFlow or similar; **no** `npm`/`npx`, no
  Node/Bun in the product or the build (supply-chain reasons, ADR-04). The library names and install
  commands below describe *what good behavior looks like*; never install or run them.
- **CSP is strict.** No inline styles (`style=""`, `<style>`), no inline scripts, no `hx-on` handlers, no CDN,
  no web fonts from a third party. Only the global classes and tokens in `web/styles/` (ADR-12). Need
  something new? Add a class to `components.css` and show it in the `/design` gallery. Status colors
  (`--status-ok/warn/crit/info`) are fixed; themes change brand tokens only.
- **Third-party JavaScript is a new dependency**, even when vendored (like the planned ECharts for
  charts). It needs a license check (permissive only: MIT, BSD, Apache-2.0, ISC, MPL-2.0 file-level) and the
  maintainer's explicit go first. Ask, don't add.
- **Mapping of the ideas below to this stack:**
  - Use native platform behavior first: `<dialog>` for modals, the `popover` attribute, `<details>`,
    `inert`, `:focus-visible`, `prefers-reduced-motion`. These give focus handling, Escape and screen reader
    semantics without a library.
  - htmx for interaction (fragment swaps, SSE for live data); small islands only where JS is really needed
    (toast stack, command palette). A number tick-up animation is a hand-written island, and only if the
    maintainer asks for it.
  - The anti-default theming ("three pillars": radius, tinted greys, type pairing) is applied through the
    design tokens in `web/styles/tokens.css` and the direction in `references/frontend.md` – not through a
    Tailwind config. The direction there is fixed: small radii (2 px), system UI fonts with a monospace for
    serials and fingerprints, no cards, no icons, brand gold `#C27F12` for the logo only.
  - The one-standout rule means in this admin tool: **no decorative effects on operational pages**. Calm and
    plain is the goal; an early mockup was rejected as "too AI-looking".
  - Layer 3 (marketing and hero effects) does **not** apply to the product UI. It may only inform the static
    demo/landing page on GitHub Pages, with at most one standout moment.
- **Accessibility and keyboard navigation are mandatory** for every interactive element: semantic HTML,
  labels for every input, visible focus, full keyboard operation. `prefers-reduced-motion` must be respected;
  motion never carries information that is not also available as text.
- **Stop and ask the maintainer** before anything that would change an ADR or add a dependency.

---

The following text is a general reference and is subordinate to the constraints above.

# Master Skill: High-Craft UI Design with AI (Claude Code & Coding Agents)

## 1. Core Philosophy & Prime Directive

When an AI is asked to build a UI element (such as a toast, a command menu, a drawer or complex dialogs) "just like that", it generates components from scratch every time, with generic default styling.

**The problem with that:**
1. **Missing physics and micro-interactions:** Out of the box, an AI does not know how a mobile drawer must feel when dragged (rubber-banding, flick-to-close), how toasts stack neatly on top of each other and expand on hover, or how numbers count up smoothly.
2. **Poor accessibility (a11y):** Hand-built dropdowns, modals and command menus almost always fail at focus traps, screen readers and complex keyboard navigation (arrow keys, Escape handling).
3. **The generic "AI look":** Default components without targeted design-token customization instantly look like a soulless SaaS template.

**The fundamental law of this skill:**
> **Never build complex UI primitives or interactive special components from scratch yourself.** Use established component libraries to give the model the "taste" and the attention to detail of experienced design engineers. Control the selection strictly through the following **3-layer architecture**.

---

## 2. The 3-Layer Component Architecture

Every UI component in a project falls into exactly one of three categories. As an AI agent you always pick the right tool from the matching layer.

### Layer 1: Foundations (the base – about 80% of the app)

Foundations provide the invisible behavior of a component: keyboard navigation, focus management, ARIA attributes and accessibility. The visual styling is entirely in your hands.

* **Primary libraries:**
  * **[shadcn/ui](https://ui.shadcn.com):** Standard foundation for React/Next.js. Copies the source code directly into the project, so the AI can read it and rebuild it completely.
  * **[Radix UI](https://www.radix-ui.com):** Unstyled primitives (the base under many `shadcn` components), ideal for complex dialogs, popovers, tabs and dropdowns.
  * **[Base UI](https://base-ui.com):** Excellent, clean headless alternative (from the makers of Material UI / Floating UI) for maximum control over your own design system.
* **Use for:** Buttons, inputs, select fields, dialogs/modals, dropdown menus, tabs, accordions, forms, tables.

#### CRITICAL RULE: The Anti-Default-shadcn Protocol
Unmodified `shadcn/ui` has become the new "AI sameness" (always the same `0.5rem` border radius, the same neutral slate/zinc gray, the same system or Inter font). Anyone familiar with tools like Claude Code or Lovable recognizes this look immediately.

**Mandatory customization at the start of every project (the 3 pillars of personality):**
Before you build the first page, you must break up the default theme in `globals.css` or `tailwind.config` using three levers:

| Design lever | Default AI look (AVOID) | Measure for a high-craft UI (ENFORCE) |
| :--- | :--- | :--- |
| **1. Border radius** | `rounded-md` / `rounded-lg` (`0.5rem`) everywhere, often nested inappropriately. | Commit to a clear extreme that fits the brand:<br>• **Editorial / fintech / dev tool:** Sharp and precise (`0px` to `4px` / `rounded-none` to `rounded-sm`).<br>• **Consumer / friendly app:** Soft and organic (`12px` up to pill shape `rounded-full` on buttons).<br>• *Important:* For nested elements always compute concentric radii (outer radius = inner radius + padding). |
| **2. Color palette & grays** | Pure black/white or lifeless default Tailwind `slate`/`gray`. | • **Tinted grays:** Use warm grays (`stone`, warm paper off-white such as `#FAF8F5`) for editorial products, or a deep, slightly blue/violet-tinted charcoal (`#0B0C10`) for dark-mode apps.<br>• **Brand colors:** Ask for the brand colors up front, or define a distinctive primary accent instead of default blue. |
| **3. Typography** | `Inter` or `system-ui` everywhere in the same weight. | Create contrast through deliberate font pairings:<br>• **Editorial / luxury SaaS:** A characterful serif for headings (e.g. *Instrument Serif*, *Playfair Display*, *Newsreader*) + a clean sans-serif for body text (*Geist*, *Plus Jakarta Sans*).<br>• **Technical / AI / dev tool:** A distinctive grotesque + `JetBrains Mono` or `Geist Mono` for all numbers, badges, timestamps and metrics (`tabular-nums`). |

---

### Layer 2: Specialists (the experts for micro-interactions)

Specialists are focused libraries that master **exactly one single component** perfectly. They solve exactly those subtle physics, animation and UX details that an AI skips when coding from scratch.

**STRICT PROHIBITION:** Never build your own toast system, your own mobile bottom-sheet drawer, your own Cmd+K menu or your own number tickers with plain `useState` and default CSS.

#### Binding selection matrix (after Emil Kowalski's `pick-ui-library`):

1. **[Sonner](https://sonner.emilkowal.ski) → for all toasts & notifications**
   * *Why not build it yourself?* AI-built toasts overlap incorrectly, disappear abruptly or cannot be paused cleanly.
   * *What Sonner delivers:* Automatic 3D stacking, smooth expansion on hover, fluid enter/exit animations, promise states (loading → success/error) and swipe-to-dismiss.

2. **[Vaul](https://vaul.emilkowal.ski) → for all drawers & mobile bottom sheets**
   * *Why not build it yourself?* A hand-built drawer only opens and closes rigidly on click; it lacks any touch feel.
   * *What Vaul delivers:* Real physics when dragging (drag-to-dismiss), "flick" detection (a quick swipe down closes immediately), snap points and optional background scaling as in native iOS.

3. **[cmdk](https://cmdk.paco.me) → for all command menus (Cmd+K / Ctrl+K) & complex search palettes**
   * *Why not build it yourself?* Home-grown search menus fall apart as soon as you try to move quickly through filtered lists, groups and submenus with the arrow keys.
   * *What cmdk delivers:* Lightning-fast, accessible filtering and sorting, flawless keyboard navigation, groupings and seamless integration with `shadcn/ui`.

4. **[NumberFlow](https://number-flow.barvian.me) → for all dynamic numbers, prices, counters & live metrics**
   * *Why not build it yourself?* When a price changes in a pricing toggle (monthly/yearly) or a live counter updates, the text jumps abruptly with standard code.
   * *What NumberFlow delivers:* Every digit rotates smoothly and independently into its new place like a mechanical departure board (including correct currency and percentage formatting).

---

### Layer 3: Designed Components & Marketplaces (bespoke & high-craft UI)

These are ready-designed, highly polished components with elaborate animations, shaders or special layouts, whose code is copied directly into your own project.

#### When to use which library:

* **[Beautiful UI](https://beautifului.dev) (by Turbo) → first choice for AI products & agent interfaces**
  * *Background:* Classic component libraries predate the AI boom and know no agent-specific states.
  * *Use for:* Streaming text views, **approval cards** (when an AI agent needs the user's permission for an action), **diff views** (code or text comparisons), tool-call indicators, reasoning/thinking states and agent screens.
* **[Magic UI](https://magicui.design) → animated extensions based on `shadcn/ui`**
  * *Background:* Over 150 free, animated components that build exactly on the `shadcn/ui` architecture and fit seamlessly into the existing setup.
  * *Use for:* Bento grids, marquees (scrolling customer logos/testimonials), animated connecting beams (animated beams for integrations), shimmer buttons, text reveals.
* **[RareUI](https://rareui.in) → eye-catching micro-moments & interactive surfaces**
  * *Background:* Can be installed into your own project code with a one-line command and customized freely.
  * *Use for:* Highly polished, animated buttons, special text effects, interactive backgrounds and attention-grabbing UI details.
* **[Aceternity UI](https://ui.aceternity.com) → dramatic landing-page & hero effects**
  * *Background:* Installable via the `shadcn` CLI (also directly by the coding agent).
  * *Use for:* 3D card effects (card hover perspective), background beams, spotlights, aurora backgrounds, complex scroll animations.
* **[21st.dev](https://21st.dev) → the curated component marketplace**
  * *Background:* A gathering place where various top design engineers publish their best individual components.
  * *Use for:* Perfect when you are looking for **one very specific component** (e.g. a special pricing slider, an original timeline or a special file uploader) without committing to a complete design library.

---

## 3. The "One-Standout Rule" (visual discipline)

When using components from **Layer 3 (Designed Components)**, one iron design rule applies:

> **At most ONE large, visually spectacular highlight moment per page (or per viewport).**

* **Right (designed look):** A calm, typographically precise page (Layer 1 + Layer 2) with **one** impressive interactive hero element, **one** animated architecture diagram (Magic UI beams) or **one** 3D showcase card. That draws the eye magnetically and makes the product look high-end.
* **Wrong (the new "over-engineered AI look"):** 10 effects from Aceternity and Magic UI on the same page – glowing borders, flying particles, wobbling 3D cards, glittering text and rotating gradients all at once. When everything glows and moves, nothing stands out any more and the page looks cheap.

---

## 4. Technical Workflow for Coding Agents (Claude Code / Cursor)

So that the AI agent uses these libraries without errors and adapts them to the product design, the following technical execution workflow applies:

### 1. Code ownership through CLI and registry installation
Install components – whenever possible – via the official CLI or the `shadcn` registry directly into the project directory (e.g. `src/components/ui/`) instead of using closed black-box NPM packages:
```bash
# Add base components & specialists via the shadcn CLI
npx shadcn@latest add button dialog tabs sonner drawer command

# Install special packages directly
npm install vaul cmdk sonner @number-flow/react
```
*Advantage:* Because the code physically lives in the project, the coding agent can read the file, understand it and adapt the Tailwind classes (radii, colors, shadows, fonts) directly to the brand design.

### 2. Automated decision check before coding (`pick-ui-library` logic)
Before the agent creates a new component, it internally runs through this checklist:

| If the requirement contains... | ...then you MUST choose this library | Rationale (1 sentence) |
| :--- | :--- | :--- |
| Standard UI (button, input, modal, select, tabs, dropdown) | **`shadcn/ui`** / **`Radix`** / **`Base UI`** (with a custom theme!) | Delivers flawless accessibility, keyboard focus and solid behavior as a customizable base. |
| Notification, feedback message, alert toast, status popup | **`Sonner`** | Handles toast stacking, hover expansion and fluid fade-in/out animations automatically. |
| Mobile menu from the bottom, bottom sheet, draggable side panel | **`Vaul`** | Offers real touch dragging with physics, flick-to-close and a native mobile feel. |
| Global search, Cmd+K palette, action launcher, quick filter | **`cmdk`** | Guarantees instant filtering and unbroken keyboard navigation with the arrow keys. |
| Price change, dashboard KPIs, live counter, percentage values | **`NumberFlow`** | Animates number changes by smoothly ticking through individual digits instead of hard jumps. |
| AI chat, agent confirmation (approval), streaming output, code diff | **`Beautiful UI`** | Offers interfaces developed specifically for modern AI workflows and agent states. |
| Hero animation, bento grid, 3D card, marketing eye-catcher | **`Magic UI`** / **`RareUI`** / **`Aceternity`** / **`21st.dev`** | Delivers ready-to-use high-craft effects (always in compliance with the *One-Standout Rule*). |

---

## 5. Pre-flight Checklist for Every New UI Project

When the user requests a new UI or feature without giving design details, the agent automatically applies the following steps:

1. **Define the brand identity (anti-default shadcn):**
   * Which **3 personality parameters** (border radius, gray/background tint, heading/body/mono font combination) do we use so that it does *not* look like default shadcn?
2. **Specialist scan:**
   * Is there feedback to the user? → plan for `Sonner`.
   * How does the view behave on mobile for detail views/filters? → use a `Vaul` drawer instead of cramped modals.
   * Is there power-user navigation or search? → build in `cmdk`.
   * Are prices, statistics or metrics updated dynamically? → wrap the numbers in `NumberFlow`.
3. **Define the standout moment:**
   * Which **one** element on the page gets special visual attention (e.g. a `Beautiful UI` component in the agent workflow or a `Magic UI` / `RareUI` effect in the hero area), while the rest stays calm and functional?

---

## 6. Copy-and-Paste Templates for Your Everyday Prompts

If you have not stored the skill globally, you can put Claude Code or other agents on track immediately with these compact prompt building blocks:

### Prompt block A: For SaaS dashboards & web apps
> "Do not build UI primitives from scratch. Use **shadcn/ui** as the foundation, but break up the default look: use a precise border radius of `4px`, a warm stone gray instead of default slate, a serif font (*Instrument Serif*) for large headings and *JetBrains Mono* for all data. Use **Sonner** for toasts, **Vaul** for mobile drawers, **cmdk** for the command menu and **NumberFlow** for all changing numbers and KPIs – these are mandatory."

### Prompt block B: For AI products & agentic interfaces
> "We are building an AI product. Use **shadcn/ui** (with a custom color and typography theme) for the base structure and follow the patterns of **Beautiful UI** for all AI-specific views (streaming text, tool calls, agent approval cards and diff views). Use **Sonner** for status toasts and **cmdk** for quick model/command switching."

### Prompt block C: For landing pages & marketing sites
> "Build the landing page on top of individually styled **shadcn/ui**. Use **NumberFlow** for the pricing toggle (monthly/yearly). Stick strictly to the **One-Standout Rule**: use exactly *one* large animated highlight effect in the hero area (in the style of **RareUI**, **Magic UI** or **Aceternity UI**) and keep the rest of the page calm, high-contrast and typographically refined, so that no overloaded AI look emerges."
