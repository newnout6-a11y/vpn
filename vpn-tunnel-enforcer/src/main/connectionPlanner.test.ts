import { describe, expect, it, vi } from 'vitest'

vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))

vi.mock('child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('child_process')>()
  const exec = Object.assign(
    (_command: string, _options: unknown, callback: (error: Error | null, stdout: string, stderr: string) => void) => {
      callback(null, '', '')
    },
    {
      [Symbol.for('nodejs.util.promisify.custom')]: () => Promise.resolve({ stdout: '', stderr: '' })
    }
  )

  return { ...actual, exec, default: { ...actual, exec } }
})

const settingsGet = vi.hoisted(() => vi.fn(() => ({
  connectionMode: 'directVpn',
  proxyOverride: '127.0.0.1:10808',
  proxyType: 'socks5'
})))

vi.mock('./settings', () => ({
  settingsStore: {
    get: settingsGet
  }
}))

const getStatus = vi.hoisted(() => vi.fn(() => ({ running: false })))
const parseProxyAddress = vi.hoisted(() => vi.fn(() => ({ host: '127.0.0.1', port: 10808 })))
const probeTcp = vi.hoisted(() => vi.fn(async () => false))

vi.mock('./tunController', () => ({
  tunController: { getStatus },
  parseProxyAddress,
  probeTcp
}))

const getActiveProfile = vi.hoisted(() => vi.fn(() => ({
  id: 'profile-1',
  name: 'poland1',
  protocol: 'vless',
  server: '144.31.1.75',
  port: 443,
  status: 'unknown',
  outbound: {
    type: 'vless',
    server: '144.31.1.75',
    server_port: 443
  }
})))

vi.mock('./serverPicker', () => ({
  getActiveProfile
}))

vi.mock('./happDetector', () => ({
  happDetector: {
    detect: vi.fn(async () => null)
  }
}))

// AT-07-002 / AT-07-012: native tunnel enumeration is mocked. Default = "unavailable" (throws), which
// keeps the legacy PowerShell path (mocked exec above) under test.
const nativeTunnels = vi.hoisted(() => vi.fn((): unknown[] => { throw new Error('native unavailable') }))
vi.mock('./native/nativeNetworkReads', () => ({ nativeActiveTunnels: nativeTunnels }))

import { getRoutingPlan } from './connectionPlanner'

describe('getRoutingPlan native tunnel read', () => {
  it.skipIf(process.platform !== 'win32')('uses the native enumeration and reports a foreign tunnel from it', async () => {
    nativeTunnels.mockReturnValueOnce([{ name: 'Corp VPN', description: 'WireGuard Tunnel', address: '10.8.0.2', isVpnte: false }])

    const plan = await getRoutingPlan()

    expect(plan.activeTunnels).toEqual([{ name: 'Corp VPN', description: 'WireGuard Tunnel', address: '10.8.0.2', isVpnte: false }])
    expect(plan.blockers.length).toBeGreaterThan(0)
    expect(nativeTunnels).toHaveBeenCalledWith(expect.objectContaining({ vpnteIpv4Prefix: expect.any(String) }))
  })

  it.skipIf(process.platform !== 'win32')('falls back to the PowerShell path when the native read throws', async () => {
    const plan = await getRoutingPlan()

    expect(nativeTunnels).toHaveBeenCalled()
    expect(plan.activeTunnels).toEqual([])
  })
})

describe('getRoutingPlan', () => {
  it('does not block directVpn on an unused local proxy override', async () => {
    const plan = await getRoutingPlan()

    expect(plan.status).toBe('ready')
    expect(plan.recommendedMode).toBe('hard')
    expect(plan.title).toContain('Direct VPN')
    expect(plan.canStartHard).toBe(true)
    expect(plan.blockers).toEqual([])
    expect(plan.steps.some(step => step.label.includes('Direct VPN'))).toBe(true)
    expect(probeTcp).not.toHaveBeenCalled()
  })
})

// AT-07-002: an unread network must not be reported as "no conflicting tunnel" (fail closed on the claim).
describe('getRoutingPlan unverified tunnel read', () => {
  it('marks the plan as unverified instead of reporting a clean network', async () => {
    const plan = await getRoutingPlan({ activeTunnels: [], tunnelsVerified: false, proxyListeners: [] })

    expect(plan.steps[0]).toMatchObject({ label: 'Проверить внешние туннели', status: 'warn' })
    expect(plan.explanation).toContain('не исключён')
  })

  it('adds no warning when the read was verified', async () => {
    const plan = await getRoutingPlan({ activeTunnels: [], tunnelsVerified: true, proxyListeners: [] })

    expect(plan.steps.some(step => step.label === 'Проверить внешние туннели')).toBe(false)
    expect(plan.explanation).not.toContain('не исключён')
  })

  it('treats a caller-supplied list without a flag as verified', async () => {
    const plan = await getRoutingPlan({ activeTunnels: [], proxyListeners: [] })

    expect(plan.steps.some(step => step.status === 'warn' && step.label === 'Проверить внешние туннели')).toBe(false)
  })
})
