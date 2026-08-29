import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

/**
 * Normalize line endings before matching. `core.autocrlf=true` (the Windows
 * default) checks these files out with CRLF, so the multi-line needle below —
 * written with a bare `\n` — silently stops matching the moment a file is
 * rewritten with CRLF, even though the code is exactly right. Same fix as
 * serverPickerResolvedIpSource.test.ts.
 */
const readSource = (rel: string): string =>
  readFileSync(join(process.cwd(), rel), 'utf8').replace(/\r\n/g, '\n')

const cardSource = readSource('src/renderer/design-system/MacCard.tsx')
const serversSource = readSource('src/renderer/pages/Servers.tsx')

describe('dense server card rendering', () => {
  it('supports solid cards without backdrop blur', () => {
    expect(cardSource).toContain('flat?: boolean')
    expect(cardSource).toContain("bg-[var(--color-card)] border border-[var(--color-border)]")
    expect(serversSource).toContain('<MacCard\n      flat')
  })
})
