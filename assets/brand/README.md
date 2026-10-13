# MyOwnPKI brand assets

The logo shows a shield (protection), a certificate (the document) and a seal with a
keyhole (signature and private key). The SVG files are the source of truth; PNG and ICO
files are rendered from them.

## Colors

| Name | Hex | Use |
|---|---|---|
| Navy | `#1B2B45` | shield and document on light backgrounds |
| Light | `#E6ECF5` | shield and document on dark backgrounds |
| Gold | `#C27F12` | seal – logo only |

Gold is reserved for the logo. It is close to the UI's fixed warning color, so it must
never be used as an accent or status color in the interface.

## Variants

| File | Use |
|---|---|
| `logo.svg` | default, light backgrounds, 64 px and larger |
| `logo-on-dark.svg` | dark backgrounds (e.g. the app header), 64 px and larger |
| `logo-small.svg` / `logo-small-on-dark.svg` | 16–48 px: no document lines, larger seal |
| `logo-mono.svg` | single color via `currentColor` (print, embossing, monochrome contexts) |
| `favicon.svg` | browser tab; switches between navy and light with `prefers-color-scheme` |
| `favicon.ico` | legacy favicon, 16/32/48 px |
| `app.ico` | Windows executables and shortcuts, 16–256 px |
| `png/logo-*.png` | raster sizes 16–512 px (≤ 48 px use the small variant) |
| `png/apple-touch-icon.png` | iOS home screen, 180 px, white background |
| `png/icon-192.png`, `png/icon-512.png` | web app manifest |
| `png/icon-maskable-512.png` | web app manifest, `purpose: maskable` (logo inside the 80 % safe zone) |

## Rules

- Keep clear space around the logo of at least the shield's stroke width.
- Don't recolor the seal, add effects or stretch the logo.
- Below 64 px use the small variants; the document lines turn into noise at small sizes.
