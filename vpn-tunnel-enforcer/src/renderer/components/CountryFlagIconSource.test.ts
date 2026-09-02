/**
 * Flag sizing must stay inline — this is a cascade trap, not a style preference.
 *
 * flag-icons ships `.fi.fis { width: 1em }`. That is a two-class selector, so it
 * outranks every single-class Tailwind width utility regardless of stylesheet
 * order. Passing `className="h-5 w-5"` therefore applied the height and silently
 * dropped the width, leaving it at `1em` — the inherited font-size. A `text-sm`
 * row rendered a 14x20 box and the profile chip's `text-lg` wrapper an 18x24 one,
 * and `bg-cover` then cropped and stretched the square flag to fill it.
 *
 * The failure mode is what makes this worth a test: nothing errors, nothing warns,
 * and the class that does nothing looks exactly like the class that works. Anyone
 * "tidying" the inline style back into utilities reintroduces it invisibly.
 */

import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const read = (rel: string): string =>
  readFileSync(join(process.cwd(), rel), 'utf8').replace(/\r\n/g, '\n')

/**
 * Scan code, not prose. The component's own doc comment necessarily quotes the
 * strings these tests forbid (`w-5`, `bg-cover`, `.fi.fis { width: 1em }`) in
 * order to explain the trap, so a whole-file match would flag the explanation
 * and force the comment to be watered down. Same helper as
 * serverPickerGeoTransport.test.ts.
 */
const stripComments = (source: string): string =>
  source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^[ \t]*\/\/.*$/gm, '')

const component = read('src/renderer/components/CountryFlagIcon.tsx')
const componentCode = stripComments(component)
const callSites = [
  'src/renderer/components/DashboardSide.tsx',
  'src/renderer/components/ProfileSelectorInline.tsx',
  'src/renderer/components/ServerDetailModal.tsx',
  'src/renderer/pages/Dashboard.tsx',
  'src/renderer/pages/Servers.tsx'
]

describe('CountryFlagIcon sizing', () => {
  it('sets width, height and font-size inline so class specificity cannot win', () => {
    expect(component).toContain('const box = { width: size, height: size, fontSize: size }')
    expect(component).toContain('style={box}')
    // Both branches — flag and globe fallback — must be boxed.
    expect(component.match(/style=\{box\}/g)?.length).toBe(2)
  })

  it('takes a numeric size prop rather than sizing utilities', () => {
    expect(component).toContain('size?: number')
    expect(component).toContain('size = DEFAULT_SIZE')
  })

  it('does not reintroduce Tailwind width or height utilities on the flag', () => {
    // `w-5`/`h-5` here would be the exact regression: one silently ignored, the
    // other applied, producing a non-square box.
    expect(componentCode).not.toMatch(/'[^']*\bw-\d/)
    expect(componentCode).not.toMatch(/'[^']*\bh-\d/)
  })

  it('requests the square 1x1 asset and does not force background-size', () => {
    // The 1x1 asset is flag-icons' own square redrawing of each flag; it fills a
    // circle with nothing cropped. The 4x3 asset would need a `cover` crop that
    // shoves crosses and cantons off-centre.
    expect(componentCode).toContain('fi fis inline-block')
    // flag-icons' own `contain` cannot crop; `cover` on an off-square viewBox can.
    expect(componentCode).not.toContain('bg-cover')
    expect(componentCode).not.toContain("backgroundSize")
  })

  it.each(callSites)('%s passes size, never a width class', (rel) => {
    const source = read(rel)
    for (const [, props] of source.matchAll(/<CountryFlagIcon([^/>]*)\/>/g)) {
      expect(props, `dead width utility in ${rel}: ${props.trim()}`).not.toMatch(/\bw-\d/)
      expect(props, `dead height utility in ${rel}: ${props.trim()}`).not.toMatch(/\bh-\d/)
    }
  })
})
