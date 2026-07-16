import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'

const mainIndexSource = () => readFileSync(join(process.cwd(), 'src', 'main', 'index.ts'), 'utf8')
const serverProbeSource = () => readFileSync(join(process.cwd(), 'src', 'main', 'serverProbe.ts'), 'utf8')
const urlAvailabilitySource = () => readFileSync(join(process.cwd(), 'src', 'main', 'urlAvailability.ts'), 'utf8')
const serverPickerSource = () => readFileSync(join(process.cwd(), 'src', 'main', 'serverPicker.ts'), 'utf8')
const ipMonitorSource = () => readFileSync(join(process.cwd(), 'src', 'main', 'ipMonitor.ts'), 'utf8')
const leakDiagnosticsSource = () => readFileSync(join(process.cwd(), 'src', 'main', 'leakDiagnostics.ts'), 'utf8')

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

    expect(handler).toContain('if (tunController.getStatus().running)')
    expect(handler.indexOf('if (tunController.getStatus().running)')).toBeLessThan(
      handler.indexOf('killOwnedTunRuntimeProcesses()')
    )
    expect(handler).toContain('blocked: true')
    expect(handler).toContain('Отключите VPN перед завершением зависших процессов')
    expect(handler).toContain('killOwnedTunRuntimeProcesses()')
    expect(source).toContain('killOwnedTunRuntimeProcesses')
    expect(handler).not.toContain("await import('child_process')")
    expect(handler).not.toContain("taskkill', ['/F', '/IM'")
  })

  it('does not run targeted firewall repair while TUN is active', () => {
    const source = mainIndexSource()
    const handlerStart = source.indexOf("handleLogged('firewall:repair-vpnte-rules'")
    const handlerEnd = source.indexOf("handleLogged('get-location-privacy'", handlerStart)
    const handler = source.slice(handlerStart, handlerEnd)

    expect(handlerStart).toBeGreaterThanOrEqual(0)
    expect(handler).toContain('if (tunController.getStatus().running)')
    expect(handler).toContain('blocked: true')
    expect(handler).toContain('getFirewallRepairHealth({ protectedTunnelActive: true })')
    expect(handler).toContain('return repairVpnteFirewallRules()')
    expect(handler.indexOf('if (tunController.getStatus().running)')).toBeLessThan(
      handler.indexOf('return repairVpnteFirewallRules()')
    )
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
    expect(source).toContain('getFirewallRepairHealth({ protectedTunnelActive: tunController.getStatus().running })')
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

  it('restarts a running tunnel when safety settings affect live runtime config', () => {
    const source = mainIndexSource()
    const handlerStart = source.indexOf("handleLogged('save-settings'")
    const handlerEnd = source.indexOf("handleLogged('inspect-vpn-input'", handlerStart)
    const handler = source.slice(handlerStart, handlerEnd)

    expect(handler).toContain('previous.strictAdapterLockdown !== saved.strictAdapterLockdown')
    expect(handler).toContain('previous.publicWifiCompatibility !== saved.publicWifiCompatibility')
    expect(handler).toContain('previous.stealthMode !== saved.stealthMode')
    expect(handler).toContain('tunController.getStatus().running')
    expect(handler).toContain('tunController.restartWithLastOptions(`settings changed: ${changed}`)')
  })

  it('kicks Smart-RU managed rule-set auto-refresh on startup and relevant settings changes', () => {
    const source = mainIndexSource()
    const readyStart = source.indexOf('app.whenReady().then')
    const appReadyRefresh = source.indexOf("maybeRefreshSmartRouteRuleSets('app-ready')", readyStart)
    const handlerStart = source.indexOf("handleLogged('save-settings'")
    const handlerEnd = source.indexOf("handleLogged('inspect-vpn-input'", handlerStart)
    const handler = source.slice(handlerStart, handlerEnd)

    expect(source).toContain('maybeRefreshSmartRouteRuleSets')
    expect(appReadyRefresh).toBeGreaterThan(readyStart)
    expect(handler).toContain('previous.smartRuSplit !== saved.smartRuSplit')
    expect(handler).toContain('previous.smartRuRuleSetMode !== saved.smartRuRuleSetMode')
    expect(handler).toContain('previous.smartRuRuleSetAutoUpdate !== saved.smartRuRuleSetAutoUpdate')
    expect(handler).toContain("maybeRefreshSmartRouteRuleSets('settings-save')")
  })

  it('runs startup crash recovery before opening the renderer window', () => {
    const source = mainIndexSource()
    const readyStart = source.indexOf('app.whenReady().then')
    const recoveryCall = source.indexOf('await performCrashRecovery()', readyStart)
    const windowCall = source.indexOf('createWindow()', readyStart)

    expect(readyStart).toBeGreaterThanOrEqual(0)
    expect(recoveryCall).toBeGreaterThan(readyStart)
    expect(recoveryCall).toBeLessThan(windowCall)
    expect(source).toContain('recoverStaleKillSwitch(isOwnedTunRuntimeRunning)')
  })

  it('keeps proxy-list export as a separate server picker IPC path', () => {
    const source = readFileSync(join(process.cwd(), 'src', 'main', 'serverPicker.ts'), 'utf8')

    expect(source).toContain("handleLogged('servers:export-all-proxies-file'")
    expect(source).toContain('exportOutboundToProxyLine')
    expect(source).toContain('proxy-list-')
    expect(source).toContain("reason: 'unsupported-all'")
  })

  it('stops all external proxies before the main VPN disconnect', () => {
    const source = mainIndexSource()
    const stopStart = source.indexOf('async function stopProtection()')
    const tunStop = source.indexOf('const result = await tunController.stop()', stopStart)
    const proxyStop = source.indexOf("await externalProxy.stopAll('vpn-stop')", stopStart)

    expect(stopStart).toBeGreaterThanOrEqual(0)
    expect(proxyStop).toBeGreaterThan(stopStart)
    expect(proxyStop).toBeLessThan(tunStop)
  })

  it('stops all external proxies during application shutdown', () => {
    const source = mainIndexSource()
    const shutdownStart = source.indexOf('async function performShutdownCleanup')
    const proxyStop = source.indexOf('await externalProxy.stopAll(`shutdown: ${reason}`)', shutdownStart)

    expect(shutdownStart).toBeGreaterThanOrEqual(0)
    expect(proxyStop).toBeGreaterThan(shutdownStart)
  })

  it('respects disableGeoLookup in server probe enrichment', () => {
    const source = serverProbeSource()
    const handlerStart = source.indexOf("ipcMain.handle('server:probe'")
    const handlerEnd = source.indexOf('\n  })\n}', handlerStart)
    const handler = source.slice(handlerStart, handlerEnd)

    expect(source).toContain("import { settingsStore } from './settings'")
    expect(source).toContain('export interface ProbeServerOptions')
    expect(source).toContain('const disableGeoLookup = options.disableGeoLookup === true')
    expect(source).toContain('disableGeoLookup ? Promise.resolve(null) : getAsnInfo(primaryIp)')
    expect(handler).toContain('disableGeoLookup: settingsStore.get().disableGeoLookup === true')
  })

  it('respects disableGeoLookup in URL availability ASN enrichment', () => {
    const source = urlAvailabilitySource()
    const handlerStart = source.indexOf("ipcMain.handle('url-availability:check'")
    const handlerEnd = source.indexOf('\n  })', handlerStart)
    const handler = source.slice(handlerStart, handlerEnd)

    expect(source).toContain("import { settingsStore } from './settings'")
    expect(source).toContain('interface UrlAvailabilityOptions')
    expect(source).toContain('if (options.disableGeoLookup === true) return null')
    expect(source).toContain('const asn = await fetchAsn(firstIp, options).catch(() => null)')
    expect(source).toContain('probeNative(parsed, options)')
    expect(handler).toContain('disableGeoLookup: settingsStore.get().disableGeoLookup === true')
  })

  it('respects disableGeoLookup in server picker country verification', () => {
    const source = serverPickerSource()
    const activeStart = source.indexOf("handleLogged('servers:verify-active-country'")
    const activeEnd = source.indexOf("handleLogged('servers:verify-country'", activeStart)
    const activeHandler = source.slice(activeStart, activeEnd)
    const verifyStart = activeEnd
    const verifyEnd = source.indexOf("handleLogged('servers:add'", verifyStart)
    const verifyHandler = source.slice(verifyStart, verifyEnd)

    expect(source).toContain('function geoLookupDisabled(): boolean')
    expect(source).toContain('return settingsStore.get().disableGeoLookup === true')
    expect(source).toContain('if (geoLookupDisabled() || unique.length === 0) return out')
    expect(source).toContain('if (geoLookupDisabled()) return null')
    expect(activeHandler).toContain("reason: 'geo-lookup-disabled'")
    expect(activeHandler.indexOf("reason: 'geo-lookup-disabled'")).toBeLessThan(
      activeHandler.indexOf('geolocateIp(cleanIp)')
    )
    expect(verifyHandler).toContain("reason: 'geo-lookup-disabled'")
    expect(verifyHandler.indexOf("reason: 'geo-lookup-disabled'")).toBeLessThan(
      verifyHandler.indexOf('verifyProfileCountry(cleanId)')
    )
  })

  it('keeps routine public-IP checks off geo-profile providers', () => {
    expect(ipMonitorSource()).not.toContain('https://ipinfo.io/json')
    expect(leakDiagnosticsSource()).not.toContain('https://ipinfo.io/json')
  })
})
