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

import { nextAdaptiveMode, resolveAdaptiveCapabilities } from './adaptiveBypass'

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
