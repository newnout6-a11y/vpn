import { describe, it, expect, vi, beforeEach } from 'vitest'
import { readFileSync } from 'node:fs'
import ts from 'typescript'

const h = vi.hoisted(() => ({
  trafficStats: { running: false, downloadBps: 0, uploadBps: 0 },
  lastPublicIpSuccessAt: 0
}))

vi.mock('electron', () => ({
  app: {
    getPath: () => '/tmp/vpnte-test',
    getAppPath: () => '/tmp/vpnte-test/app',
    isPackaged: false
  }
}))

vi.mock('electron-store', () => ({
  default: class MockStore {
    private data: Record<string, any> = {}
    get(key?: string) {
      if (!key) return { settings: {} }
      return this.data[key]
    }
    set(key: string, value: any) {
      this.data[key] = value
    }
  }
}))

vi.mock('sudo-prompt', () => ({ default: { exec: vi.fn() }, exec: vi.fn() }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./notifications', () => ({ notify: vi.fn().mockResolvedValue(undefined) }))
vi.mock('./admin', () => ({
  execElevated: vi.fn().mockResolvedValue({ stdout: '', stderr: '' }),
  isProcessElevated: vi.fn().mockResolvedValue(false)
}))
vi.mock('./firewallKillSwitch', () => ({
  enableKillSwitch: vi.fn(),
  disableKillSwitch: vi.fn(),
  disableKillSwitchIfActive: vi.fn(),
  isKillSwitchActive: vi.fn().mockResolvedValue(false)
}))
vi.mock('./physicalAdapterLockdown', () => ({
  applyPhysicalAdapterLockdown: vi.fn(),
  isPhysicalAdapterLockdownApplied: vi.fn().mockResolvedValue(false),
  repairOrphanedPhysicalAdapterDns: vi.fn(),
  rollbackPhysicalAdapterLockdownIfApplied: vi.fn()
}))
vi.mock('./systemNetwork', () => ({
  rollbackTunNetworkBaselineIfApplied: vi.fn().mockResolvedValue({ success: true })
}))
vi.mock('./ipMonitor', () => ({
  ipMonitor: {
    suspend: vi.fn(),
    resume: vi.fn(),
    getStatus: vi.fn(),
    getLastSuccessAt: () => h.lastPublicIpSuccessAt
  }
}))
vi.mock('./trafficMonitor', () => ({
  trafficMonitor: {
    getCurrentStats: () => h.trafficStats,
    start: vi.fn(),
    stop: vi.fn(),
    onStatsChange: vi.fn()
  }
}))
vi.mock('./leakSelfTest', () => ({ cancelLeakSelfTest: vi.fn() }))
vi.mock('./competingTunDetector', () => ({
  startCompetingTunWatch: vi.fn(),
  stopCompetingTunWatch: vi.fn()
}))

import {
  hasRecentWatchdogConfirmation,
  setWatchdogProbeConfirmationChecker,
  tunController
} from './tunController'

describe('watchdog traffic recovery (hasRecentWatchdogConfirmation)', () => {
  beforeEach(() => {
    h.trafficStats = { running: false, downloadBps: 0, uploadBps: 0 }
    h.lastPublicIpSuccessAt = 0
    setWatchdogProbeConfirmationChecker(null)
  })

  it('returns false when no traffic, no public IP confirmation, and no probe confirmation', () => {
    expect(hasRecentWatchdogConfirmation(45000)).toBe(false)
  })

  it('returns true when public IP was confirmed within maxAgeMs', () => {
    h.lastPublicIpSuccessAt = Date.now() - 5000 // 5s ago
    expect(hasRecentWatchdogConfirmation(45000)).toBe(true)
  })

  it('returns false when public IP confirmation has expired', () => {
    h.lastPublicIpSuccessAt = Date.now() - 50000 // 50s ago, window is 45s
    expect(hasRecentWatchdogConfirmation(45000)).toBe(false)
  })

  it('returns true when traffic is actively flowing (downloadBps > 1024)', () => {
    h.trafficStats = { running: true, downloadBps: 4500, uploadBps: 200 }
    expect(hasRecentWatchdogConfirmation(45000)).toBe(true)
  })

  it('returns true when traffic is actively flowing (uploadBps > 1024)', () => {
    h.trafficStats = { running: true, downloadBps: 100, uploadBps: 2048 }
    expect(hasRecentWatchdogConfirmation(45000)).toBe(true)
  })

  it('returns false when traffic monitor is running but throughput is under threshold', () => {
    h.trafficStats = { running: true, downloadBps: 512, uploadBps: 128 }
    expect(hasRecentWatchdogConfirmation(45000)).toBe(false)
  })

  it('returns false when traffic throughput is high but traffic monitor is not running', () => {
    h.trafficStats = { running: false, downloadBps: 50000, uploadBps: 50000 }
    expect(hasRecentWatchdogConfirmation(45000)).toBe(false)
  })

  it('returns true when external probe checker confirms alive', () => {
    setWatchdogProbeConfirmationChecker((maxAgeMs) => maxAgeMs >= 1000)
    expect(hasRecentWatchdogConfirmation(45000)).toBe(true)
  })

  it('returns false when external probe checker reports negative', () => {
    setWatchdogProbeConfirmationChecker(() => false)
    expect(hasRecentWatchdogConfirmation(45000)).toBe(false)
  })
})

describe('tunController.recoverProxyIfAlive', () => {
  it('exposes recoverProxyIfAlive and markProxyRecovered on tunController', () => {
    expect(typeof tunController.recoverProxyIfAlive).toBe('function')
    expect(typeof tunController.markProxyRecovered).toBe('function')
    expect(typeof tunController.hasRecentWatchdogConfirmation).toBe('function')
  })
})

describe('retained-TUN watchdog profile name (AT-00-005 / AT-02-011)', () => {
  it.each(['Switched server', null])('reports the current profile name %j with the original label as fallback', async name => {
    const source = ts.createSourceFile('tunController.ts', readFileSync('src/main/tunController.ts', 'utf8'), ts.ScriptTarget.Latest, true)
    const method = source.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'startServerWatchdog')!
    const status = { running: true, vpnProfileName: 'Original server' as string | null }
    let tick!: () => Promise<void>
    const deps = { currentStatus: status, stopProxyWatchdog: vi.fn(), markProxyRecovered: vi.fn(),
      markProxyUnreachable: vi.fn(), hasRecentPublicIpConfirmation: () => false, hasRecentWatchdogConfirmation: () => false,
      DIRECT_VPN_WATCHDOG_SUPPRESS_MS: 45000, DIRECT_VPN_WATCHDOG_INTERVAL_MS: 5000,
      setInterval: (callback: () => Promise<void>) => { tick = callback; return 1 } }
    const code = ts.transpileModule(`let watchdogTimer=null,watchdogFailures=0; ${method.getText(source)}; return startServerWatchdog;`,
      { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
    const start = new Function(...Object.keys(deps), code)(...Object.values(deps))
    start('fixture.example', 443, 'Original server')
    await tick()
    // A retained switch keeps this watchdog callback and changes the active status.
    status.vpnProfileName = name
    await tick(); await tick()
    expect(deps.markProxyUnreachable).toHaveBeenCalledExactlyOnceWith(expect.stringContaining(`«${name || 'Original server'}»`))
  })
})
