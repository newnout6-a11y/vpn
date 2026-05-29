/**
 * Regression: D6.5 — `pingAll` must NOT stamp tunnel-RTT onto any profile.
 *
 * Before this fix, when the tunnel was UP, `pingAll` measured a single
 * tunnel-RTT (HTTPS GET to yandex/gosuslugi) and wrote that number onto the
 * ACTIVE profile's `ping`. Result: a fast Reality tunnel (~2 ms to a CDN
 * via the active outbound) poisoned `profile.ping`, which the dropdown row
 * in ProfileSelectorInline reads directly. After disconnect the value
 * persisted, and the user saw "Текущий профиль · 2 ms" while every other
 * profile (which never got the poisoned write) showed realistic 16-817 ms.
 *
 * The fix: while the tunnel is UP, `pingAll` is a no-op on persisted state.
 * The pill button in ProfileSelectorInline still gets a live tunnel RTT
 * via its own IPC call, but nothing ever lands in the store from that
 * path. Per-server numbers are only written when the tunnel is DOWN —
 * that's when they actually mean per-server latency.
 *
 * This test creates an in-memory store mock, simulates the tunnel-up
 * scenario, and asserts no profile got mutated.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'

// In-memory store the mocked electron-store reads from / writes to. The
// test toggles tunnelRunning before invoking pingAll() to drive the two
// branches.
let mockStoreData: { profiles: any[]; activeProfileId: string | null } = {
  profiles: [],
  activeProfileId: null
}
let tunnelRunning = false

vi.mock('electron', () => ({
  app: { getPath: () => '/tmp/vpnte-test', getAppPath: () => '/tmp/vpnte-test' },
  dialog: {},
  ipcMain: { handle: vi.fn() }
}))
vi.mock('electron-store', () => ({
  default: class MockStore {
    get(key: 'profiles' | 'activeProfileId') {
      return mockStoreData[key]
    }
    set(key: 'profiles' | 'activeProfileId', value: any) {
      ;(mockStoreData as any)[key] = value
    }
  }
}))
vi.mock('axios', () => ({
  default: {
    get: vi.fn().mockImplementation(() => Promise.resolve({ status: 204 }))
  }
}))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({}) } }))
vi.mock('./vpnProfiles', () => ({
  resolveVpnProfiles: vi.fn(),
  exportOutboundToUri: vi.fn()
}))
vi.mock('./tunController', () => ({
  tunController: {
    getStatus: () => ({ running: tunnelRunning })
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

const SAMPLE_PROFILES = [
  {
    id: 'p-active',
    name: 'AE ОАЭ',
    protocol: 'vless',
    server: '5.6.7.8',
    port: 443,
    status: 'unknown',
    ping: 156,
    lastChecked: 1
  },
  {
    id: 'p-other',
    name: 'NL',
    protocol: 'vless',
    server: '1.2.3.4',
    port: 443,
    status: 'online',
    ping: 64,
    lastChecked: 2
  }
]

describe('pingAll while tunnel is UP', () => {
  beforeEach(() => {
    mockStoreData = {
      profiles: JSON.parse(JSON.stringify(SAMPLE_PROFILES)),
      activeProfileId: 'p-active'
    }
    tunnelRunning = false
    vi.resetModules()
  })

  it('does NOT mutate the active profile ping (no tunnel-RTT poisoning)', async () => {
    tunnelRunning = true
    const { pingAll } = await import('./serverPicker')
    const before = JSON.parse(JSON.stringify(mockStoreData.profiles))
    await pingAll()
    expect(mockStoreData.profiles).toEqual(before)
  })

  it('does NOT mutate any non-active profile while tunnel is up', async () => {
    tunnelRunning = true
    const { pingAll } = await import('./serverPicker')
    await pingAll()
    const other = mockStoreData.profiles.find(p => p.id === 'p-other')!
    expect(other.ping).toBe(64)
    expect(other.status).toBe('online')
    expect(other.lastChecked).toBe(2)
  })

  it('returns the profile array unchanged', async () => {
    tunnelRunning = true
    const { pingAll } = await import('./serverPicker')
    const result = await pingAll()
    expect(result).toHaveLength(2)
    expect(result.find(p => p.id === 'p-active')!.ping).toBe(156)
  })
})

describe('clearStaleStoredPings', () => {
  beforeEach(() => {
    mockStoreData = {
      profiles: JSON.parse(JSON.stringify(SAMPLE_PROFILES)),
      activeProfileId: 'p-active'
    }
    tunnelRunning = false
    vi.resetModules()
  })

  it('wipes ping/status/lastChecked from every profile', async () => {
    const { clearStaleStoredPings } = await import('./serverPicker')
    clearStaleStoredPings()
    for (const p of mockStoreData.profiles) {
      expect(p.ping).toBeNull()
      expect(p.status).toBe('unknown')
      expect(p.lastChecked).toBeUndefined()
    }
  })

  it('preserves all other profile fields', async () => {
    const { clearStaleStoredPings } = await import('./serverPicker')
    clearStaleStoredPings()
    const active = mockStoreData.profiles.find(p => p.id === 'p-active')!
    expect(active.name).toBe('AE ОАЭ')
    expect(active.server).toBe('5.6.7.8')
    expect(active.port).toBe(443)
    expect(active.protocol).toBe('vless')
  })

  it('is idempotent — second call is a no-op when already clean', async () => {
    const { clearStaleStoredPings } = await import('./serverPicker')
    clearStaleStoredPings()
    const after1 = JSON.parse(JSON.stringify(mockStoreData.profiles))
    clearStaleStoredPings()
    expect(mockStoreData.profiles).toEqual(after1)
  })

  it('handles empty profile list without throwing', async () => {
    mockStoreData = { profiles: [], activeProfileId: null }
    const { clearStaleStoredPings } = await import('./serverPicker')
    expect(() => clearStaleStoredPings()).not.toThrow()
  })
})
