import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const cardSource = readFileSync(join(process.cwd(), 'src/renderer/design-system/MacCard.tsx'), 'utf8')
const serversSource = readFileSync(join(process.cwd(), 'src/renderer/pages/Servers.tsx'), 'utf8')

describe('dense server card rendering', () => {
  it('supports solid cards without backdrop blur', () => {
    expect(cardSource).toContain('flat?: boolean')
    expect(cardSource).toContain("bg-[var(--color-card)] border border-[var(--color-border)]")
    expect(serversSource).toContain('<MacCard\n      flat')
  })
})
