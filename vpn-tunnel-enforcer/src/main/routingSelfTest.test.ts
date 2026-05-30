/**
 * Tests for deriveRoutingVerdict — the pure decision behind the routing
 * self-test. Verifies the "does the split actually work" logic and the smart-RU
 * "RU goes direct" assertion.
 */

import { describe, it, expect, vi } from 'vitest'

// routingSelfTest imports tunController/settings/socks/axios at module load.
// Stub them so the pure verdict fn can be imported in isolation.
vi.mock('axios', () => ({ default: { get: vi.fn() } }))
vi.mock('socks', () => ({ SocksClient: { createConnection: vi.fn() } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./tunController', () => ({
  tunController: { getStatus: () => ({ running: false }) },
  getDirectProxyPort: () => null
}))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({ smartRuSplit: false }) } }))

import { deriveRoutingVerdict } from './routingSelfTest'

describe('deriveRoutingVerdict', () => {
  it('reports tunnel-off when not active', () => {
    const v = deriveRoutingVerdict({ tunnelActive: false, vpnIp: null, directIp: null, smartEnabled: false, ruHostIp: null })
    expect(v.verdict).toBe('tunnel-off')
  })

  it('reports inconclusive when an IP is missing', () => {
    const v = deriveRoutingVerdict({ tunnelActive: true, vpnIp: '1.2.3.4', directIp: null, smartEnabled: false, ruHostIp: null })
    expect(v.verdict).toBe('inconclusive')
  })

  it('flags a LEAK when VPN and direct IPs are identical', () => {
    const v = deriveRoutingVerdict({ tunnelActive: true, vpnIp: '5.5.5.5', directIp: '5.5.5.5', smartEnabled: false, ruHostIp: null })
    expect(v.verdict).toBe('leak')
    expect(v.splitWorks).toBe(false)
  })

  it('reports ok (no smart) when IPs differ', () => {
    const v = deriveRoutingVerdict({ tunnelActive: true, vpnIp: '9.9.9.9', directIp: '5.5.5.5', smartEnabled: false, ruHostIp: null })
    expect(v.verdict).toBe('ok')
    expect(v.splitWorks).toBe(true)
  })

  it('smart: ok when RU host egresses with the real (direct) IP', () => {
    const v = deriveRoutingVerdict({
      tunnelActive: true, vpnIp: '9.9.9.9', directIp: '5.5.5.5', smartEnabled: true, ruHostIp: '5.5.5.5'
    })
    expect(v.verdict).toBe('ok')
    expect(v.ruGoesDirect).toBe(true)
  })

  it('smart: partial when RU host wrongly went through the VPN', () => {
    const v = deriveRoutingVerdict({
      tunnelActive: true, vpnIp: '9.9.9.9', directIp: '5.5.5.5', smartEnabled: true, ruHostIp: '9.9.9.9'
    })
    expect(v.verdict).toBe('partial')
    expect(v.ruGoesDirect).toBe(false)
  })

  it('smart: partial when RU host could not be measured', () => {
    const v = deriveRoutingVerdict({
      tunnelActive: true, vpnIp: '9.9.9.9', directIp: '5.5.5.5', smartEnabled: true, ruHostIp: null
    })
    expect(v.verdict).toBe('partial')
    expect(v.splitWorks).toBe(true)
  })
})
