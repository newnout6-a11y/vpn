import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'

const mainIndexSource = () => readFileSync(join(process.cwd(), 'src', 'main', 'index.ts'), 'utf8')

describe('main IPC regressions', () => {
  it('bounds inspect-vpn-input before resolving or persisting input', () => {
    const source = mainIndexSource()
    const handlerStart = source.indexOf("handleLogged('inspect-vpn-input'")
    const resolverCall = source.indexOf('resolveVpnProfiles(input', handlerStart)
    const sizeCheck = source.indexOf('MAX_INSPECT_VPN_INPUT_CHARS', handlerStart)

    expect(handlerStart).toBeGreaterThanOrEqual(0)
    expect(sizeCheck).toBeGreaterThan(handlerStart)
    expect(sizeCheck).toBeLessThan(resolverCall)
  })

  it('uses top-level execFile for stale runtime cleanup instead of dynamic child_process import', () => {
    const source = mainIndexSource()
    const handlerStart = source.indexOf("handleLogged('tun:kill-stale-singbox'")
    const handlerEnd = source.indexOf("handleLogged('diagnostics:run-leak-check'", handlerStart)
    const handler = source.slice(handlerStart, handlerEnd)

    expect(handler).toContain("execFile('taskkill'")
    expect(handler).not.toContain("await import('child_process')")
  })

  it('validates save-settings payload before persisting', () => {
    const source = mainIndexSource()
    const handlerStart = source.indexOf("handleLogged('save-settings'")
    const saveCall = source.indexOf('settingsStore.save(settings)', handlerStart)
    const validation = source.indexOf("requirePlainObject(settings, 'settings')", handlerStart)

    expect(handlerStart).toBeGreaterThanOrEqual(0)
    expect(validation).toBeGreaterThan(handlerStart)
    expect(validation).toBeLessThan(saveCall)
  })
})
