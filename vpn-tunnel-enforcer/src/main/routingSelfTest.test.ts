/**
 * Tests for deriveRoutingVerdict — the pure decision behind the routing
 * self-test. Verifies the "does the split actually work" logic and the smart-RU
 * "RU goes direct" assertion.
 */

import axios from 'axios'
import { beforeEach, describe, it, expect, vi } from 'vitest'

// routingSelfTest imports tunController/settings/socks/axios at module load.
// Stub them so the pure verdict fn can be imported in isolation.
const h = vi.hoisted(() => ({
  tunRunning: false,
  settings: {
    smartRuSplit: false,
    disableGeoLookup: false
  }
}))

vi.mock('axios', () => ({ default: { get: vi.fn() } }))
vi.mock('socks', () => ({ SocksClient: { createConnection: vi.fn() } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./tunController', () => ({
  tunController: { getStatus: () => ({ running: h.tunRunning }) },
  getDirectProxyPort: () => null
}))
vi.mock('./settings', () => ({ settingsStore: { get: () => h.settings } }))

import { deriveRoutingVerdict, ruEgressIp, runRoutingSelfTest } from './routingSelfTest'

beforeEach(() => {
  vi.mocked(axios.get).mockReset()
  h.tunRunning = false
  h.settings.smartRuSplit = false
  h.settings.disableGeoLookup = false
})

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

  it('measures Smart-RU egress through a non-pinned RU-domain echo page', async () => {
    vi.mocked(axios.get).mockResolvedValueOnce({ data: 'Ваш IP: 5.5.5.5' })

    await expect(ruEgressIp()).resolves.toBe('5.5.5.5')
    expect(axios.get).toHaveBeenCalledWith('https://yandex.ru/internet/', expect.objectContaining({
      responseType: 'text'
    }))
    expect(axios.get).not.toHaveBeenCalledWith('https://2ip.ru/', expect.anything())
  })

  it('ignores impossible IPv4-looking numbers on RU echo pages', async () => {
    vi.mocked(axios.get)
      .mockResolvedValueOnce({ data: '<script>var layout="384.518.844.978";</script>' })
      .mockResolvedValueOnce({ data: 'IP address: 62.118.134.108' })

    await expect(ruEgressIp()).resolves.toBe('62.118.134.108')
  })

  it('skips Smart-RU RU echo pages when geo lookup privacy is enabled', async () => {
    h.tunRunning = true
    h.settings.smartRuSplit = true
    h.settings.disableGeoLookup = true
    vi.mocked(axios.get).mockResolvedValueOnce({ data: '9.9.9.9' })

    const result = await runRoutingSelfTest()

    expect(result.smartRu.enabled).toBe(true)
    expect(result.smartRu.ruHostIp).toBeNull()
    expect(axios.get).toHaveBeenCalledTimes(1)
    expect(axios.get).not.toHaveBeenCalledWith('https://2ip.ru/', expect.anything())
  })
})
