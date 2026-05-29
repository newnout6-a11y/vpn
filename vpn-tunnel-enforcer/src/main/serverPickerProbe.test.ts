/**
 * Tests for isProbablyHostOrIp() — the allow-list gate that guards the host
 * value handed to ping.exe. Regression guard for D2 (command injection via a
 * subscription-controlled host). Must reject anything with shell
 * metacharacters / whitespace and accept clean IPv4/IPv6/hostnames.
 */

import { describe, it, expect, vi } from 'vitest'

// serverPicker pulls a heavy import graph; stub the pieces that touch electron
// or the network so the module loads under vitest.
vi.mock('electron', () => ({
  app: { getPath: () => '/tmp/vpnte-test', getAppPath: () => '/tmp/vpnte-test' },
  dialog: {},
  ipcMain: { handle: vi.fn() }
}))
vi.mock('electron-store', () => ({
  default: class MockStore {
    get() { return [] }
    set() {}
  }
}))
vi.mock('axios', () => ({ default: { get: vi.fn() } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({}) } }))
vi.mock('./vpnProfiles', () => ({
  resolveVpnProfiles: vi.fn(),
  exportOutboundToUri: vi.fn()
}))
vi.mock('./tunController', () => ({
  tunController: { getStatus: () => ({ running: false }) },
  getDirectProxyPort: () => null
}))
vi.mock('./serverGroups', () => ({
  serverGroups: { getGroups: () => [], createGroup: vi.fn(), deleteGroup: vi.fn() },
  ensureManualKeysGroup: vi.fn(),
  findGroupBySourceUrl: vi.fn(),
  canonicalizeSubscriptionUrl: (s: string) => s,
  refreshGroup: vi.fn()
}))

import { isProbablyHostOrIp } from './serverPicker'

describe('isProbablyHostOrIp', () => {
  it('accepts plain IPv4', () => {
    expect(isProbablyHostOrIp('8.8.8.8')).toBe(true)
    expect(isProbablyHostOrIp('192.168.0.1')).toBe(true)
  })

  it('accepts hostnames', () => {
    expect(isProbablyHostOrIp('sub.feodorn.com')).toBe(true)
    expect(isProbablyHostOrIp('a-b.example.org')).toBe(true)
  })

  it('accepts bare IPv6', () => {
    expect(isProbablyHostOrIp('2001:db8::1')).toBe(true)
    expect(isProbablyHostOrIp('::1')).toBe(true)
  })

  it('rejects command-injection attempts', () => {
    expect(isProbablyHostOrIp('8.8.8.8 & calc')).toBe(false)
    expect(isProbablyHostOrIp('8.8.8.8 && shutdown /s')).toBe(false)
    expect(isProbablyHostOrIp('8.8.8.8 | whoami')).toBe(false)
    expect(isProbablyHostOrIp('$(calc)')).toBe(false)
    expect(isProbablyHostOrIp('`calc`')).toBe(false)
    expect(isProbablyHostOrIp('a.com; rm -rf /')).toBe(false)
    expect(isProbablyHostOrIp('a.com\nb.com')).toBe(false)
  })

  it('rejects whitespace and empty', () => {
    expect(isProbablyHostOrIp('')).toBe(false)
    expect(isProbablyHostOrIp('  ')).toBe(false)
    expect(isProbablyHostOrIp('8.8.8.8 ')).toBe(true) // trimmed → valid
    expect(isProbablyHostOrIp('8 8')).toBe(false)
  })

  it('rejects absurdly long input', () => {
    expect(isProbablyHostOrIp('a'.repeat(300))).toBe(false)
  })
})
