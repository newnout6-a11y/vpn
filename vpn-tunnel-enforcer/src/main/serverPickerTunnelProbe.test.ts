/**
 * Regression: `tunnelHttpProbe` must prove that traffic actually egressed
 * through `proxy-out` — not merely that *some* host answered.
 *
 * The bug: the probe list led with `yandex.ru/favicon.ico` and
 * `gosuslugi.ru/favicon.ico`. Smart-RU split routing sends those exact
 * domains to `direct-out`, so `Promise.any` resolved over the PHYSICAL link
 * and `verifyAdaptiveConnection` reported "tunnel verification succeeded"
 * while proxy-out was 100% dead (rejected REALITY key). The kill-switch
 * then held with no working tunnel behind it — a total outage the app
 * labelled "protected".
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { readFileSync } from 'fs'
import { join } from 'path'

let tunnelRunning = true
let tunnelStartedAt = 1000

const axiosGet = vi.fn()

vi.mock('electron', () => ({
  app: { getPath: () => '/tmp/vpnte-test', getAppPath: () => '/tmp/vpnte-test' },
  dialog: {},
  ipcMain: { handle: vi.fn() }
}))
vi.mock('electron-store', () => ({
  default: class MockStore {
    get() { return [] }
    set() { /* noop */ }
  }
}))
vi.mock('axios', () => ({ default: { get: (...args: any[]) => axiosGet(...args) } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({}) } }))
vi.mock('./vpnProfiles', () => ({ resolveVpnProfiles: vi.fn(), exportOutboundToUri: vi.fn() }))
vi.mock('./tunController', () => ({
  tunController: {
    getStatus: () => ({
      running: tunnelRunning,
      startedAt: tunnelRunning ? tunnelStartedAt : null,
      pid: tunnelRunning ? 1234 : null,
      mode: 'directVpn',
      proxyAddr: null,
      proxyType: null,
      vpnProfileName: 'Test'
    })
  },
  getDirectProxyPort: () => null
}))
vi.mock('./serverGroups', () => ({
  serverGroups: { getGroups: () => [], createGroup: vi.fn(), deleteGroup: vi.fn() },
  ensureManualKeysGroup: vi.fn(),
  findGroupBySourceUrl: vi.fn(),
  canonicalizeSubscriptionUrl: (s: string) => s,
  refreshGroup: vi.fn()
}))

beforeEach(() => {
  vi.clearAllMocks()
  vi.resetModules()
  tunnelStartedAt += 1000 // bust the per-session probe cache between cases
})

describe('tunnelHttpProbe target list', () => {
  it('contains no domain that smart-RU split routes to direct-out', () => {
    const src = readFileSync(join(__dirname, 'serverPicker.ts'), 'utf8')
    const block = src.slice(
      src.indexOf('const TUNNEL_PROBE_TARGETS'),
      src.indexOf('const TUNNEL_PROBE_SUCCESS_CACHE_MS')
    )
    expect(block).not.toMatch(/yandex\.ru/i)
    expect(block).not.toMatch(/gosuslugi/i)
    // The endpoints we DO keep are foreign anchors forced through proxy-out.
    expect(block).toMatch(/generate_204/)
  })
})

describe('tunnelHttpProbe egress validation', () => {
  it('returns a latency when a generate_204 endpoint answers 204', async () => {
    axiosGet.mockImplementation((url: string) =>
      url.includes('generate_204')
        ? Promise.resolve({ status: 204, data: '' })
        : Promise.reject(new Error('blocked'))
    )
    const { tunnelHttpProbe } = await import('./serverPicker')
    expect(await tunnelHttpProbe(true)).toBeTypeOf('number')
  })

  it('returns null when every target only yields a captive-portal style 200', async () => {
    axiosGet.mockResolvedValue({ status: 200, data: '<html>Sign in to Wi-Fi</html>' })
    const { tunnelHttpProbe } = await import('./serverPicker')
    expect(await tunnelHttpProbe(true)).toBeNull()
  })

  it('returns null when every target rejects (proxy-out not carrying traffic)', async () => {
    axiosGet.mockRejectedValue(new Error('ECONNRESET'))
    const { tunnelHttpProbe } = await import('./serverPicker')
    expect(await tunnelHttpProbe(true)).toBeNull()
  })

  it('accepts the 1.1.1.1 trace endpoint only when the body looks like a real trace', async () => {
    axiosGet.mockImplementation((url: string) =>
      url.includes('1.1.1.1')
        ? Promise.resolve({ status: 200, data: 'fl=1\nip=203.0.113.7\nts=1\n' })
        : Promise.reject(new Error('blocked'))
    )
    const { tunnelHttpProbe } = await import('./serverPicker')
    expect(await tunnelHttpProbe(true)).toBeTypeOf('number')
  })

  it('uses 8000ms timeout for tunnel probe targets to tolerate mobile hotspot jitter', () => {
    const src = readFileSync(join(__dirname, 'serverPicker.ts'), 'utf8')
    expect(src).toContain('const TUNNEL_PROBE_URL_TIMEOUT_MS = 8000')
  })

  it('retries when initial probe fails before returning null', async () => {
    let callCount = 0
    axiosGet.mockImplementation((url: string) => {
      callCount++
      // Fail all targets on attempt 1, succeed on attempt 2
      if (callCount <= 4) {
        return Promise.reject(new Error('transient hotspot hiccup'))
      }
      return url.includes('generate_204')
        ? Promise.resolve({ status: 204, data: '' })
        : Promise.reject(new Error('blocked'))
    })
    const { tunnelHttpProbe } = await import('./serverPicker')
    const latency = await tunnelHttpProbe(true)
    expect(latency).toBeTypeOf('number')
    expect(callCount).toBeGreaterThan(4)
  })
})
