/**
 * The palette has three sources that must agree, and nothing used to make them.
 *
 * 1. `themeManager.ts` — built-in theme hex values, applied at runtime over IPC.
 * 2. `globals.css` — `--rgb-*` fallbacks, painted on the very first frame before
 *    the theme IPC round-trip lands.
 * 3. `index.ts` — `backgroundColor` on the BrowserWindow, painted before the
 *    renderer exists at all.
 *
 * When they drifted, the UI lost its depth in a way that was invisible in any one
 * file. `globals.css` described a four-level surface ladder on a very dark canvas
 * (bg 13/13/17) with shadows tuned for it; the dark theme actually shipped
 * bg #1c1c1e with the sidebar set to the *same* value, so the nav rail had no
 * edge; and `ThemeProvider` overwrote only 7 of the ~13 tokens, leaving
 * cardElevated / borderStrong / textMuted / state colours from a stylesheet
 * calibrated for a different background. Meanwhile the window painted #1e1e2e —
 * a colour belonging to neither theme — so startup flashed a third shade.
 *
 * These tests pin the agreement, not the specific colours: change the palette
 * freely, but change it in all three places.
 */

import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const read = (rel: string): string =>
  readFileSync(join(process.cwd(), rel), 'utf8').replace(/\r\n/g, '\n')

const themeManagerSource = read('src/main/themeManager.ts')
const globalsSource = read('src/renderer/styles/globals.css')
const providerSource = read('src/renderer/providers/ThemeProvider.tsx')
const mainIndexSource = read('src/main/index.ts')

/** Pull one built-in theme's `colors` object out of themeManager. */
function themeColors(constName: string): Record<string, string> {
  const block = new RegExp(`const ${constName}[\\s\\S]*?colors: \\{([\\s\\S]*?)\\n  \\}`).exec(themeManagerSource)
  if (!block) throw new Error(`could not find ${constName} colors in themeManager.ts`)
  const out: Record<string, string> = {}
  for (const [, key, hex] of block[1].matchAll(/(\w+):\s*'(#[0-9a-fA-F]{6})'/g)) out[key] = hex.toLowerCase()
  return out
}

/** Pull the `--rgb-*` declarations out of one globals.css selector block. */
function cssChannels(selector: string): Record<string, string> {
  const block = new RegExp(`${selector.replace(/[[\]]/g, '\\$&')} \\{([\\s\\S]*?)\\n\\}`).exec(globalsSource)
  if (!block) throw new Error(`could not find ${selector} block in globals.css`)
  const out: Record<string, string> = {}
  for (const [, name, value] of block[1].matchAll(/--rgb-([a-z-]+):\s*([\d\s]+);/g)) {
    out[name] = value.trim().replace(/\s+/g, ' ')
  }
  return out
}

const hexToChannels = (hex: string): string => {
  const n = hex.replace('#', '')
  return [0, 2, 4].map((i) => parseInt(n.slice(i, i + 2), 16)).join(' ')
}

/** WCAG relative luminance. */
const luminance = (hex: string): number => {
  const n = hex.replace('#', '')
  const channels = [0, 2, 4]
    .map((i) => parseInt(n.slice(i, i + 2), 16) / 255)
    .map((v) => (v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4)))
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]
}

/**
 * WCAG contrast ratio, 1..21. Used for two different jobs below: readability
 * thresholds (4.5 body, 3 large/UI) and surface-separation floors — a card that
 * is a *different* colour from the canvas can still read as the same surface,
 * which is exactly the trap the previous palette fell into.
 */
const contrast = (a: string, b: string): number => {
  const [x, y] = [luminance(a), luminance(b)]
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05)
}

/** themeManager key → globals.css `--rgb-*` name. */
const TOKEN_NAMES: Record<string, string> = {
  background: 'bg',
  sidebar: 'sidebar',
  cardBackground: 'card',
  cardElevated: 'card-elevated',
  accent: 'accent',
  text: 'text',
  textSecondary: 'text-secondary',
  textMuted: 'text-muted',
  border: 'border',
  borderStrong: 'border-strong',
  success: 'success',
  warning: 'warning',
  danger: 'danger'
}

describe('palette agreement across themeManager, globals.css and the window', () => {
  it.each([
    ['DARK_THEME', '[data-theme="dark"]'],
    ['LIGHT_THEME', ':root']
  ])('%s matches the %s fallbacks in globals.css', (constName, selector) => {
    const theme = themeColors(constName)
    const css = cssChannels(selector)

    for (const [key, cssName] of Object.entries(TOKEN_NAMES)) {
      expect(theme[key], `${constName}.${key} missing`).toBeTruthy()
      expect(css[cssName], `--rgb-${cssName} missing from ${selector}`).toBeTruthy()
      expect(css[cssName], `--rgb-${cssName} must equal ${constName}.${key} (${theme[key]})`)
        .toBe(hexToChannels(theme[key]))
    }
  })

  it.each(['DARK_THEME', 'LIGHT_THEME'])('%s gives the sidebar its own level', (constName) => {
    // The shipped dark theme had sidebar === background byte for byte, which is
    // why the nav rail had no edge against the content area.
    const theme = themeColors(constName)
    expect(theme.sidebar).not.toBe(theme.background)
    expect(theme.cardBackground).not.toBe(theme.background)
    expect(theme.cardElevated).not.toBe(theme.cardBackground)
  })

  it.each(['DARK_THEME', 'LIGHT_THEME'])('%s keeps every surface step visible, not merely distinct', (constName) => {
    // Distinctness is not enough — Dark Modern's own card colour (#262626 on a
    // #1f1f1f canvas) is a different value that reads as the same surface, at
    // 1.09:1. These floors are what make a card look like a card; they are the
    // reason four values in DARK_THEME deviate from the upstream theme.
    const theme = themeColors(constName)
    const step = (a: string, b: string) => contrast(theme[a], theme[b])

    expect(step('cardBackground', 'background'), 'card vs canvas').toBeGreaterThanOrEqual(1.15)
    expect(step('border', 'cardBackground'), 'border vs card').toBeGreaterThanOrEqual(1.15)
    expect(step('borderStrong', 'cardBackground'), 'strong border vs card').toBeGreaterThanOrEqual(1.3)
    // The rail may be darker (dark theme) or lighter (light theme) than the
    // canvas; either way it must be separable.
    expect(step('sidebar', 'background'), 'rail vs canvas').toBeGreaterThanOrEqual(1.05)

    // The elevated step is asymmetric between the themes, and that is physics,
    // not an oversight. A light theme's card is already near-white, so elevated
    // has a hard ceiling at #ffffff and cannot climb far above it — there, the
    // separation is carried by the border instead. A dark theme has room to
    // spare, so it must actually use it.
    const elevatedFloor = constName === 'DARK_THEME' ? 1.12 : 1.02
    expect(step('cardElevated', 'cardBackground'), 'elevated vs card').toBeGreaterThanOrEqual(elevatedFloor)
  })

  it.each(['DARK_THEME', 'LIGHT_THEME'])('%s text clears WCAG AA on every surface it lands on', (constName) => {
    const theme = themeColors(constName)
    const on = (fg: string, bg: string) => contrast(theme[fg], theme[bg])

    for (const surface of ['background', 'sidebar', 'cardBackground', 'cardElevated']) {
      expect(on('text', surface), `text on ${surface}`).toBeGreaterThanOrEqual(4.5)
      // Secondary text appears inside inputs and inner panels too, so it has to
      // hold on the elevated surface — not just on the canvas.
      expect(on('textSecondary', surface), `textSecondary on ${surface}`).toBeGreaterThanOrEqual(4.5)
    }
    // Muted is hint/placeholder text: AA-large / non-text UI threshold.
    expect(on('textMuted', 'cardBackground'), 'textMuted on card').toBeGreaterThanOrEqual(3)
    // Accent is used for icons, rails and focus rings — UI contrast, not body.
    expect(on('accent', 'cardBackground'), 'accent on card').toBeGreaterThanOrEqual(3)
    expect(on('accent', 'background'), 'accent on canvas').toBeGreaterThanOrEqual(3)
    // State colours must be legible where they are actually drawn.
    for (const state of ['success', 'warning', 'danger']) {
      expect(on(state, 'cardBackground'), `${state} on card`).toBeGreaterThanOrEqual(3)
    }
  })

  it('white label on the accent fill is readable in both themes', () => {
    // MacButton's primary variant hardcodes white text, so a light accent would
    // silently produce an unreadable button.
    for (const constName of ['DARK_THEME', 'LIGHT_THEME']) {
      const accent = themeColors(constName).accent
      expect(contrast('#ffffff', accent), `white on ${constName} accent ${accent}`).toBeGreaterThanOrEqual(4.5)
    }
  })

  it('ThemeProvider writes every colour the contract declares', () => {
    // Half-applied palettes are the failure this whole file exists for: any key
    // ThemeProvider skips silently keeps the previous theme's value.
    for (const [key, cssName] of Object.entries(TOKEN_NAMES)) {
      expect(providerSource, `ThemeProvider must write --rgb-${cssName}`).toContain(`'--rgb-${cssName}'`)
      expect(providerSource, `ThemeProvider must read colors.${key}`).toContain(`theme.colors.${key}`)
    }
  })

  it('the window background matches the dark theme canvas', () => {
    // Painted before the renderer's first frame. Any other value is a visible
    // colour flash at startup.
    const dark = themeColors('DARK_THEME')
    expect(mainIndexSource).toContain(`backgroundColor: '${dark.background}'`)
  })

  it('fills in missing levels for themes stored before the palette widened', () => {
    expect(themeManagerSource).toContain('function withFullPalette')
    expect(themeManagerSource).toContain('.map(withFullPalette)')
  })
})
