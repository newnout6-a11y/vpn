import { describe, expect, it, vi } from 'vitest'

vi.mock('electron', () => ({
  safeStorage: {
    isEncryptionAvailable: () => false,
    encryptString: (value: string) => Buffer.from(value),
    decryptString: (value: Buffer) => value.toString('utf8')
  }
}))

vi.mock('electron-store', () => ({
  default: class MockStore {
    private values: Record<string, unknown> = { learning: {} }
    get(key: string) { return this.values[key] }
    set(key: string, value: unknown) { this.values[key] = value }
    delete(key: string) { delete this.values[key] }
  }
}))

vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))

import { nextAdaptiveMode, resolveAdaptiveCapabilities, isTunOrVpnAdapter, networkFingerprint } from './adaptiveBypass'
import * as os from 'os'

describe('adaptive bypass capability matrix', () => {
  it('keeps local external proxies externally managed', () => {
    const capabilities = resolveAdaptiveCapabilities('localProxy')

    expect(capabilities.externallyManaged).toBe(true)
    expect(nextAdaptiveMode('external-managed', capabilities)).toBeNull()
  })

  it('allows TLS compatibility for regular TLS but not Reality', () => {
    const tls = resolveAdaptiveCapabilities('directVpn', { outbound: { tls: { enabled: true } } })
    const reality = resolveAdaptiveCapabilities('directVpn', {
      outbound: { tls: { enabled: true, reality: { enabled: true } } }
    })

    expect(tls.canUseTlsCompatibility).toBe(true)
    expect(nextAdaptiveMode('baseline', tls)).toBe('tls-compatibility')
    expect(reality.canUseTlsCompatibility).toBe(false)
    expect(nextAdaptiveMode('baseline', reality)).toBe('mtu-compatibility')
  })

  it('does not loop after the MTU compatibility attempt', () => {
    const capabilities = resolveAdaptiveCapabilities('directVpn', { outbound: { tls: { enabled: true } } })

    expect(nextAdaptiveMode('tls-compatibility', capabilities)).toBe('mtu-compatibility')
    expect(nextAdaptiveMode('mtu-compatibility', capabilities)).toBeNull()
  })
})

describe('adaptive bypass network fingerprinting', () => {
  it('identifies TUN, Wintun, and VPN adapter names', () => {
    expect(isTunOrVpnAdapter('Ethernet 5')).toBe(true)
    expect(isTunOrVpnAdapter('VPNTE-TUN')).toBe(true)
    expect(isTunOrVpnAdapter('wintun-adapter')).toBe(true)
    expect(isTunOrVpnAdapter('sing-box tun')).toBe(true)
    expect(isTunOrVpnAdapter('WireGuard Tunnel')).toBe(true)
    expect(isTunOrVpnAdapter('OpenVPN TAP')).toBe(true)
    expect(isTunOrVpnAdapter('Wi-Fi')).toBe(false)
    expect(isTunOrVpnAdapter('Ethernet')).toBe(false)
  })

  it('calculates stable networkFingerprint ignoring newly spawned TUN adapter', () => {
    const physicalInterfaces = {
      'Wi-Fi': [
        {
          address: '192.168.1.100',
          netmask: '255.255.255.0',
          family: 'IPv4',
          mac: '00:11:22:33:44:55',
          internal: false,
          cidr: '192.168.1.100/24'
        } as any
      ]
    }

    const physicalWithTun = {
      ...physicalInterfaces,
      'Ethernet 5': [
        {
          address: '192.168.250.253',
          netmask: '255.255.255.252',
          family: 'IPv4',
          mac: '00:00:00:00:00:01',
          internal: false,
          cidr: '192.168.250.253/30'
        } as any
      ]
    }

    const fpBefore = networkFingerprint(physicalInterfaces)
    const fpAfter = networkFingerprint(physicalWithTun)

    expect(fpBefore).toBe(fpAfter)
    expect(fpBefore).not.toBe('')
  })
})
