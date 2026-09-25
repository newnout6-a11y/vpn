import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
import { filterEntries, exportJson, exportCsv } from './connectionHistory'
import { parseVpnProfiles } from './vpnProfiles'
import type { ConnectionLogEntry } from '../shared/ipc-types'

const readNormalized = (relPath: string) =>
  readFileSync(join(process.cwd(), relPath), 'utf8').replace(/\r\n/g, '\n')

const tunControllerSource = readNormalized('src/main/tunController.ts')
const indexSource = readNormalized('src/main/index.ts')
const appSource = readNormalized('src/renderer/App.tsx')
const serversSource = readNormalized('src/renderer/pages/Servers.tsx')
const firewallSource = readNormalized('src/main/firewallKillSwitch.ts')
const appLoggerSource = readNormalized('src/main/appLogger.ts')
const serverPickerSource = readNormalized('src/main/serverPicker.ts')
const profileRotationSource = readNormalized('src/main/profileRotation.ts')
const vpnProfilesSource = readNormalized('src/main/vpnProfiles.ts')
const logsSource = readNormalized('src/renderer/pages/Logs.tsx')

describe('Audit Fixes Regression: tunController', () => {
  it('guarantees rollback and reports failure if Wintun interface fails to reach Status=Up', () => {
    expect(tunControllerSource).toContain("const tunReady = await timeAsync('wait-tun-interface', () => waitForTunInterface(5000))")
    expect(tunControllerSource).toContain('if (!tunReady) {')
    expect(tunControllerSource).toContain('await killOwnedRuntimeProcesses()')
    expect(tunControllerSource).toContain("await rollbackEarlyAdapterLockdown('tun interface failed to reach Status=Up')")
    expect(tunControllerSource).toContain("await disableKillSwitchIfActive('tun interface failed to reach Status=Up')")
    expect(tunControllerSource).toContain('finish({\n              success: false,')
  })

  it('guarantees rollback and reports failure if firewall kill-switch fails to engage', () => {
    expect(tunControllerSource).toContain("logEvent('error', 'tun', 'firewall kill-switch failed to engage — aborting start and rolling back'")
    expect(tunControllerSource).toContain("await rollbackEarlyAdapterLockdown('kill-switch failed to engage')")
    expect(tunControllerSource).toContain("await disableKillSwitchIfActive('kill-switch failed to engage')")
    expect(tunControllerSource).toContain('finish({\n                success: false,')
  })

  it('prevents stop/start race via stopRequested flag at multiple critical checkpoints', () => {
    expect(tunControllerSource).toContain('let stopRequested = false')
    expect(tunControllerSource).toContain('stopRequested = true')
    expect(tunControllerSource).toContain('if (stopRequested) {')
    expect(tunControllerSource).toContain('start aborted by stop request before launch')
    expect(tunControllerSource).toContain('start polling aborted by stop request')
    expect(tunControllerSource).toContain('start aborted by stop request before TUN wait')
    expect(tunControllerSource).toContain('start aborted by stop request after TUN wait')
    expect(tunControllerSource).toContain('start aborted by stop request before marking running')
  })

  it('saves proxyEngine in lastStartOptions and preserves it on restart, server switch and rotation', () => {
    expect(tunControllerSource).toContain('proxyEngine: startOptions.proxyEngine')
    expect(tunControllerSource).toContain('proxyEngine: snapshot.proxyEngine ?? (settings as any).proxyEngine')
    expect(tunControllerSource).toContain('getLastStartOptions(): StartOptions | null')
    expect(serverPickerSource).toContain('proxyEngine: tunController.getLastStartOptions?.()?.proxyEngine ?? settings.proxyEngine')
    expect(profileRotationSource).toContain('proxyEngine: tunController.getLastStartOptions?.()?.proxyEngine ?? settings.proxyEngine')
  })

  it('preserves multiplex for VLESS/Reality to mitigate TSPU Signal 3', () => {
    expect(tunControllerSource).toContain('isVlessRealityOutbound')
    expect(tunControllerSource).toContain('if (!isVlessRealityOutbound) {')
    expect(tunControllerSource).toContain('if (result.multiplex !== undefined) delete result.multiplex')
    expect(tunControllerSource).toContain('TSPU Signal 3')
  })
})

describe('Audit Fixes Regression: vpnProfiles multiplex & padding', () => {
  it('preserves padding property when normalising mux into multiplex', () => {
    expect(vpnProfilesSource).toContain('...(mux.padding !== undefined ? { padding: mux.padding } : {})')
  })

  it('parses mux and padding query parameters in vless share links', () => {
    const uri = 'vless://uuid-123@1.2.3.4:443?security=reality&pbk=RuInAfvwciF_P8AIkIEX6T45hr2t1X15a3kpX0Cx2XY&sid=d34db33f&fp=chrome&sni=example.com&mux=1&padding=1#RealityMux'
    const profiles = parseVpnProfiles(uri)
    expect(profiles).toHaveLength(1)
    expect(profiles[0].outbound.multiplex).toEqual({
      enabled: true,
      padding: true
    })
  })
})

describe('Audit Fixes Regression: Servers.tsx error toast', () => {
  it('displays user-facing error toast when server selection fails', () => {
    expect(serversSource).toContain('addGlobalToast = useAppStore((s) => s.addGlobalToast)')
    expect(serversSource).toContain('addGlobalToast(')
    expect(serversSource).toContain("'Не удалось выбрать сервер'")
  })
})

describe('Audit Fixes Regression: leak detector self-blinding prevention', () => {
  it('checks areTunRoutesActive before calling ipMonitor.recheck(true) on probe timeout', () => {
    expect(indexSource).toContain('const routesActive = await areTunRoutesActive().catch(() => false)')
    expect(indexSource).toContain('skipping ipMonitor.recheck(true) to avoid self-blinding leak detector')
  })

  it('guards IPC recheck-public-ip from rebaselining when tunnel is not running', () => {
    expect(indexSource).toContain('recheck-public-ip requested rebaseline while tunnel is not running')
  })

  it('checks areTunRoutesActive in serverPicker fallback before calling recheck(true)', () => {
    expect(serverPickerSource).toContain('TUN routes are not active after profile switch; skipping ipMonitor.recheck(true)')
  })
})

describe('Audit Fixes Regression: Soft routing lifecycle', () => {
  it('keeps Soft mode out of Hard AutoPilot and restores env autoconfig on startup', () => {
    expect(appSource).toContain("settings.autoPilotEnabled && settings.routingMode !== 'soft'")
    expect(appSource).toContain("settings.routingMode === 'soft' && settings.connectionMode !== 'directVpn'")
    expect(appSource).toContain("window.electronAPI.applyAutoconfig(['env']")
  })

  it('uses a dedicated Soft start path for tray and schedules', () => {
    expect(indexSource).toContain('async function startSoftProtection(')
    expect(indexSource).toContain("schedule.mode === 'soft' ? startSoftProtection : startProtection")
    expect(indexSource).toContain("sendToMainWindow('soft-status-changed', true)")
  })

  it('does not discard persisted Soft env autoconfig during crash recovery', () => {
    expect(indexSource).toContain('preserving env autoconfig during Soft-mode crash recovery')
    expect(indexSource).toContain("rollbackSoftAutoconfigIfApplied('protection stop')")
  })
})

describe('Audit Fixes Regression: appLogger optimization & topology', () => {
  it('does not redact numeric fields to <redacted-topology>', () => {
    expect(appLoggerSource).toContain("if (typeof value === 'number') {\n    return value\n  }")
  })

  it('uses ensureLogDir to avoid disk mkdir on every log event', () => {
    expect(appLoggerSource).toContain('let logDirEnsured = false')
    expect(appLoggerSource).toContain('async function ensureLogDir()')
    expect(appLoggerSource).toContain('await ensureLogDir()')
    const logEventFn = appLoggerSource.slice(appLoggerSource.indexOf('export function logEvent('))
    const logEventBody = logEventFn.slice(0, logEventFn.indexOf('\n}'))
    expect(logEventBody).not.toContain('mkdir(getLogDir()')
  })
})

describe('Audit Fixes Regression: NTP UDP 123 kill-switch allow', () => {
  it('allows UDP port 123 for clock sync against Reality server desync', () => {
    expect(firewallSource).toContain('RULE_PREFIX}-allow-ntp')
    expect(firewallSource).toContain('-Protocol UDP -RemotePort 123')
    expect(firewallSource).toContain('${psSingleQuote(ntpAllow)}')
  })
})

describe('Audit Fixes Regression: Connection History error logging & display', () => {
  it('records failed connection attempts with a structured outcome across all failure paths', () => {
    // Every "never came up" path funnels through recordStartFailure(), which
    // writes disconnectReason:'error' + a start-failed outcome carrying the hint.
    expect(indexSource).toContain('function recordStartFailure(')
    expect(indexSource).toContain("disconnectReason: 'error'")
    expect(indexSource).toContain("makeOutcome('start-failed'")
    expect(indexSource).toContain('recordStartFailure({ id: ')
    expect(indexSource).toContain('Не удалось снять старую блокировку перед перезапуском')
    expect(indexSource).toContain('clearStaleKillSwitchBeforeStart')
  })

  it('supports errorMessage in ConnectionLogEntry filtering, JSON export and CSV export', () => {
    const failedEntry: ConnectionLogEntry = {
      id: 'failed-1',
      startedAt: 1700000000000,
      endedAt: 1700000000000,
      profileName: 'Broken Server',
      profileId: 'srv-broken',
      mode: 'direct',
      bytesDown: 0,
      bytesUp: 0,
      disconnectReason: 'error',
      errorMessage: 'Handshake timeout on Reality SNI'
    }

    const filtered = filterEntries([failedEntry], { text: 'Reality SNI' })
    expect(filtered).toHaveLength(1)
    expect(filtered[0].errorMessage).toBe('Handshake timeout on Reality SNI')

    const json = exportJson([failedEntry])
    expect(json).toContain('Handshake timeout on Reality SNI')

    const csv = exportCsv([failedEntry])
    expect(csv).toContain('errorMessage')
    expect(csv).toContain('Handshake timeout on Reality SNI')
  })

  it('surfaces a legacy errorMessage in the Logs.tsx outcome view', () => {
    // Legacy rows (no structured outcome) fall back to errorMessage as the
    // headline, and OutcomeDetail also shows it verbatim as legacyMessage.
    expect(logsSource).toContain('entry.errorMessage || t(`logs.outcome.${kind}`)')
    expect(logsSource).toContain('legacyMessage')
    expect(logsSource).toContain('entry.outcome?.headline || entry.errorMessage')
  })
})
