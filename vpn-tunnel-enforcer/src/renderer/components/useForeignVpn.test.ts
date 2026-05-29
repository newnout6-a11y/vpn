/**
 * Tests for foreignVpnFriendlyName — the pure helper that turns a raw adapter
 * descriptor ("happ-tun (172.18.0.1)") into a short vendor label for the
 * warning banner. Covers the foreign-VPN detection feature added after the
 * user's "1-46 ms на всех серверах" report (Happ's TUN intercepting probes).
 */

import { describe, it, expect } from 'vitest'
import { foreignVpnFriendlyName } from './useForeignVpn'

describe('foreignVpnFriendlyName', () => {
  it('returns null for null input', () => {
    expect(foreignVpnFriendlyName(null)).toBeNull()
  })

  it('recognises Happ', () => {
    expect(foreignVpnFriendlyName('happ-tun (172.18.0.1)')).toBe('Happ')
    expect(foreignVpnFriendlyName('Happ-TUN (172.18.0.2)')).toBe('Happ')
  })

  it('recognises Hiddify', () => {
    expect(foreignVpnFriendlyName('hiddify-tunnel (10.0.0.1)')).toBe('Hiddify')
  })

  it('recognises WireGuard (name and wgN form)', () => {
    expect(foreignVpnFriendlyName('WireGuard Tunnel (10.2.0.2)')).toBe('WireGuard')
    expect(foreignVpnFriendlyName('wg0 (10.7.0.1)')).toBe('WireGuard')
  })

  it('recognises OpenVPN / tap-windows', () => {
    expect(foreignVpnFriendlyName('OpenVPN TAP-Windows6 (10.8.0.6)')).toBe('OpenVPN')
    expect(foreignVpnFriendlyName('tap-windows adapter (10.8.0.1)')).toBe('OpenVPN')
  })

  it('recognises Xray / V2Ray cores', () => {
    expect(foreignVpnFriendlyName('xray-tun (198.18.0.1)')).toBe('Xray/V2Ray')
    expect(foreignVpnFriendlyName('v2ray-tun (198.18.0.2)')).toBe('Xray/V2Ray')
    expect(foreignVpnFriendlyName('singbox-tun (198.18.0.3)')).toBe('Xray/V2Ray')
  })

  it('falls back to the adapter name (sans ip suffix) for unknown vendors', () => {
    expect(foreignVpnFriendlyName('mystery-tun (10.1.2.3)')).toBe('mystery-tun')
    expect(foreignVpnFriendlyName('Some Adapter')).toBe('Some Adapter')
  })
})
