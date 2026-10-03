import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'

const serverPickerSource = () => readFileSync(join(process.cwd(), 'src', 'main', 'serverPicker.ts'), 'utf8')

describe('serverPicker source regressions', () => {
  it('refreshes the IP monitor baseline after a direct VPN profile switch', () => {
    const source = serverPickerSource()
    const restartStart = source.indexOf('async function restartDirectVpnForSelectedProfile')
    const restartCall = source.indexOf("tunController.restartProtected('server switch'", restartStart)
    const barrierCall = source.indexOf('withProtectedIpTransition({', restartStart)
    const helper = readFileSync(join(process.cwd(), 'src/main/protectedIpTransition.ts'), 'utf8')

    expect(restartStart).toBeGreaterThanOrEqual(0)
    expect(restartCall).toBeGreaterThan(restartStart)
    expect(barrierCall).toBeGreaterThan(restartStart)
    expect(barrierCall).toBeLessThan(restartCall)
    expect(helper).toContain('ipMonitor.recheck(true, options.isCurrent)')
    expect(helper).toContain('ipMonitor.releaseDeferredResume()')
  })

  it('keeps the kill-switch applied across a server switch', () => {
    // Regression: this used to call tunController.stop() with no options, which
    // rolls back the firewall, baseline and adapter lockdown, then rebuilt them
    // in start() — seconds of unprotected egress on every server switch.
    const source = serverPickerSource()
    const restartStart = source.indexOf('async function restartDirectVpnForSelectedProfile')
    const restartEnd = source.indexOf('let profileSwitchGeneration', restartStart)
    const body = source.slice(restartStart, restartEnd)

    expect(restartEnd).toBeGreaterThan(restartStart)
    expect(body).toContain("tunController.restartProtected('server switch'")
    expect(body).not.toContain('tunController.stop()')
    expect(body).not.toContain('tunController.start(')
  })

  it('uses getFastPhysicalIpv4Sources via networkInterfaces to avoid PowerShell contention', () => {
    const source = serverPickerSource()
    expect(source).toContain('export function getFastPhysicalIpv4Sources()')
    expect(source).toContain('const fast = getFastPhysicalIpv4Sources()')
    expect(source).toContain('const PHYSICAL_SOURCE_FAILURE_CACHE_MS = 3_000')
  })
})
