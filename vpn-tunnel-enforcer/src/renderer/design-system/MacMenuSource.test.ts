import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

/**
 * Regression guard for "the row-action menu falls behind the next row".
 *
 * The server row, its group card and the collapse wrapper all clip
 * `overflow: hidden`, so an `absolute`-positioned dropdown inside the row gets
 * sheared off. The menu must be portalled to `document.body` and positioned
 * `fixed` against the trigger rect, and the outside-click watcher must treat
 * the portalled panel as "inside" so a click on an item still fires.
 */
const readSource = (rel: string): string =>
  readFileSync(join(process.cwd(), rel), 'utf8').replace(/\r\n/g, '\n')

const menuSource = readSource('src/renderer/design-system/MacMenu.tsx')

describe('MacMenu overflow-safe positioning', () => {
  it('portals the dropdown out of the clipping row', () => {
    expect(menuSource).toContain("import { createPortal } from 'react-dom'")
    expect(menuSource).toContain('document.body')
    expect(menuSource).toContain("position: 'fixed'")
  })

  it('does not position the panel absolutely inside the row anymore', () => {
    expect(menuSource).not.toContain("'absolute z-[130] mt-1")
  })

  it('keeps the portalled panel inside the outside-click boundary', () => {
    expect(menuSource).toContain('menuRef.current?.contains(target)')
    expect(menuSource).toContain('triggerRef.current?.contains(target)')
  })

  it('reflows on scroll and resize while open', () => {
    expect(menuSource).toContain("window.addEventListener('scroll', onReflow, true)")
    expect(menuSource).toContain("window.addEventListener('resize', onReflow)")
  })

  it('can flip above the trigger when there is no room below', () => {
    expect(menuSource).toContain("placement: 'above' | 'below'")
    expect(menuSource).toContain("translateY(-100%)")
  })
})
