import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'

describe('tray menu source regressions', () => {
  it('treats an active firewall kill-switch as active protection', () => {
    const source = readFileSync(join(process.cwd(), 'src', 'main', 'tray.ts'), 'utf8')
    const buildMenuStart = source.indexOf('function buildMenu()')
    const canStartIndex = source.indexOf('const canStart', buildMenuStart)
    const activeBlock = source.slice(buildMenuStart, canStartIndex)

    expect(activeBlock).toContain('trayState.firewallKillSwitchActive')
    expect(activeBlock).toContain("trayState.status === 'killswitch'")
  })
})
