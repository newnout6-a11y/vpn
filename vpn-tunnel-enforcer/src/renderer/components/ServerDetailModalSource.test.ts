import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

const source = readFileSync(join(process.cwd(), 'src/renderer/components/ServerDetailModal.tsx'), 'utf8')

describe('server detail modal regressions', () => {
  it('has a client-side deadline for a lost diagnostic IPC call', () => {
    expect(source).toContain('const PROBE_UI_TIMEOUT_MS = 10_000')
    expect(source).toContain('const probeTimeout = window.setTimeout')
    expect(source).toContain('window.clearTimeout(probeTimeout)')
  })

  it('keeps the device picker above following detail cards', () => {
    expect(source).toContain('<MacCard className="!p-3 relative z-20">')
  })
})
