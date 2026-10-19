import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const source = readFileSync(join(process.cwd(), 'src/renderer/components/ServerDetailModal.tsx'), 'utf8')

describe('server detail modal regressions', () => {
  it('keeps the device picker above following detail cards', () => {
    expect(source).toContain('<MacCard className="!p-3 relative z-20">')
  })
})
