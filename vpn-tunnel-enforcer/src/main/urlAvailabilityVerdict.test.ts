/**
 * Tests for deriveVerdict — specifically the geo-block-aware branches added so
 * a healthy-but-geo-blocked direct path is correctly read as "works only with
 * VPN", and a VPN exit that is ITSELF geo-blocked tells the user to switch
 * server country.
 */

import { describe, it, expect, vi } from 'vitest'

// urlAvailability imports tunController (heavy). Stub the bits it touches at
// import time so deriveVerdict can be imported in isolation.
vi.mock('electron', () => ({
  ipcMain: { handle: vi.fn() },
  BrowserWindow: class {}
}))
vi.mock('electron-store', () => ({
  default: class { get() { return [] } set() {} }
}))
vi.mock('axios', () => ({ default: { get: vi.fn(), head: vi.fn() } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./tunController', () => ({
  tunController: { getStatus: () => ({ running: false }) },
  getDirectProxyPort: () => null,
  getClashApiInfo: () => null
}))

import { deriveVerdict } from './urlAvailability'

type PR = Parameters<typeof deriveVerdict>[0]

function report(over: Record<string, any> = {}): NonNullable<PR> {
  return {
    available: true,
    totalMs: 100,
    errorStage: null,
    errorMessage: null,
    dns: null,
    tcp: null,
    tls: null,
    http: { status: 200, ms: 100, server: null },
    asn: null,
    source: 'native',
    ...over
  } as NonNullable<PR>
}

describe('deriveVerdict — geo-block aware', () => {
  it('tunnel works + direct geo-blocked → works-only-with-vpn', () => {
    const tunnel = report({ available: true })
    const direct = report({ available: false, geoBlocked: true })
    const v = deriveVerdict(tunnel, direct)
    expect(v.verdict).toBe('works-only-with-vpn')
    expect(v.recommendation.toLowerCase()).toContain('регион')
  })

  it('tunnel itself geo-blocked but direct works → works-only-without-vpn', () => {
    const tunnel = report({ available: false, geoBlocked: true })
    const direct = report({ available: true, geoBlocked: false })
    const v = deriveVerdict(tunnel, direct)
    expect(v.verdict).toBe('works-only-without-vpn')
    expect(v.recommendation.toLowerCase()).toContain('сервер')
  })

  it('tunnel geo-blocked and direct also blocked → blocked-everywhere', () => {
    const tunnel = report({ available: false, geoBlocked: true })
    const direct = report({ available: false })
    const v = deriveVerdict(tunnel, direct)
    expect(v.verdict).toBe('blocked-everywhere')
  })

  it('both plainly available (no geo-block) → works-both', () => {
    expect(deriveVerdict(report(), report()).verdict).toBe('works-both')
  })

  it('classic 200-vs-403 still maps to works-only-with-vpn', () => {
    const tunnel = report({ http: { status: 200, ms: 50, server: null } })
    const direct = report({ http: { status: 403, ms: 40, server: null } })
    expect(deriveVerdict(tunnel, direct).verdict).toBe('works-only-with-vpn')
  })
})
