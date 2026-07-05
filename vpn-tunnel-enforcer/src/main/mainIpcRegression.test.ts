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

  it('uses owned runtime cleanup for stale runtime repair instead of dynamic child_process import', () => {
    const source = mainIndexSource()
    const handlerStart = source.indexOf("handleLogged('tun:kill-stale-singbox'")
    const handlerEnd = source.indexOf("handleLogged('diagnostics:run-leak-check'", handlerStart)
    const handler = source.slice(handlerStart, handlerEnd)

    expect(handler).toContain('killOwnedTunRuntimeProcesses()')
    expect(source).toContain('killOwnedTunRuntimeProcesses')
    expect(handler).not.toContain("await import('child_process')")
    expect(handler).not.toContain("taskkill', ['/F', '/IM'")
  })

  it('exposes targeted firewall repair separately from full firewall reset', () => {
    const source = mainIndexSource()
    const healthStart = source.indexOf("handleLogged('firewall:repair-health'")
    const repairStart = source.indexOf("handleLogged('firewall:repair-vpnte-rules'")
    const resetStart = source.indexOf("handleLogged('firewall:nuclear-reset'")

    expect(healthStart).toBeGreaterThanOrEqual(0)
    expect(repairStart).toBeGreaterThanOrEqual(0)
    expect(resetStart).toBeGreaterThanOrEqual(0)
    expect(source.slice(repairStart, resetStart > repairStart ? resetStart : undefined)).toContain('repairVpnteFirewallRules()')
    expect(source).toContain('getFirewallRepairHealth()')
  })

  it('keeps destructive maintenance IPC behind narrow entry points', () => {
    const source = mainIndexSource()
    const resetStart = source.indexOf("handleLogged('firewall:nuclear-reset'")
    const resetEnd = source.indexOf("handleLogged('firewall:repair-health'", resetStart)
    const resetHandler = source.slice(resetStart, resetEnd)

    expect(source).not.toContain("handleLogged('apply-tun-network-baseline'")
    expect(resetHandler).toContain('RESET_WINDOWS_FIREWALL_CONFIRMED')
    expect(resetHandler).toContain('nuclearFirewallReset()')
  })

  it('does not expose legacy Store repair as a standalone renderer IPC action', () => {
    const source = mainIndexSource()

    expect(source).not.toContain("handleLogged('run-store-repair'")
    expect(source).not.toContain("handleLogged('run-store-diagnostics'")
    expect(source).not.toContain("from './storeRepair'")
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
