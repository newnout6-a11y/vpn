/**
 * Regression tests for serverGroups.refreshGroup() dedup-merge.
 *
 * The bug (B3): existing profiles were keyed by `uri:<sourceUri>` while fresh
 * subscription profiles were keyed by `tuple:server|port|protocol`. Profiles
 * carrying a sourceUri therefore never matched their refreshed counterpart, so
 * each refresh re-added them as duplicates. These tests lock in the symmetric
 * tuple-key behaviour: refreshing must UPDATE existing keys in place, never
 * duplicate, regardless of whether the stored profile has a sourceUri.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'

// ─── Stateful electron-store mock, keyed by store name ──────────────────────
// vi.hoisted so the data object exists before the hoisted vi.mock factory runs.
const storeData = vi.hoisted(() => {
  return {
    current: {
      'server-groups': { groups: [] as any[] },
      'server-picker': { profiles: [] as any[], activeProfileId: null as string | null }
    } as Record<string, Record<string, any>>
  }
})

vi.mock('electron', () => ({
  ipcMain: { handle: vi.fn() }
}))

vi.mock('electron-store', () => ({
  default: class MockStore {
    private name: string
    constructor(opts: { name: string; defaults?: Record<string, any> }) {
      this.name = opts.name
      if (!storeData.current[this.name]) storeData.current[this.name] = { ...(opts.defaults ?? {}) }
    }
    get(key: string) {
      return storeData.current[this.name]?.[key]
    }
    set(key: string, value: any) {
      storeData.current[this.name][key] = value
    }
  }
}))

vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./settings', () => ({
  settingsStore: { get: () => ({ proxyOverride: '', proxyType: 'socks5' }) }
}))

// resolveVpnProfiles is the network boundary — we stub it per test.
const resolveVpnProfilesMock = vi.fn()
vi.mock('./vpnProfiles', () => ({
  applyClientDeviceToOutbound: (outbound: Record<string, any>, device: 'pc' | 'android' | 'ios' | 'mac' = 'pc') => {
    const result = JSON.parse(JSON.stringify(outbound || {}))
    if (result.tls && typeof result.tls === 'object' && result.tls.enabled !== false) {
      result.tls.utls = {
        ...(result.tls.utls && typeof result.tls.utls === 'object' ? result.tls.utls : {}),
        enabled: true,
        fingerprint: device === 'android' ? 'android' : device === 'ios' ? 'ios' : device === 'mac' ? 'safari' : 'chrome'
      }
    }
    return result
  },
  clientFingerprintForDevice: (device: 'pc' | 'android' | 'ios' | 'mac' = 'pc') =>
    device === 'android' ? 'android' : device === 'ios' ? 'ios' : device === 'mac' ? 'safari' : 'chrome',
  normalizeClientDevice: (value: unknown) => value === 'android' || value === 'ios' || value === 'mac' ? value : 'pc',
  resolveVpnProfiles: (...args: any[]) => resolveVpnProfilesMock(...args)
}))

import { serverGroups, refreshGroup } from './serverGroups'
import type { VpnProfile } from './vpnProfiles'

// ─── Helpers ─────────────────────────────────────────────────────────────────

function resetStores() {
  storeData.current['server-groups'] = { groups: [] }
  storeData.current['server-picker'] = { profiles: [], activeProfileId: null }
}

function makeVpnProfile(server: string, port: number, name = 'Key'): VpnProfile {
  return {
    name,
    protocol: 'vless',
    outbound: {
      type: 'vless',
      server,
      server_port: port,
      uuid: 'u-' + server,
      tls: { enabled: true, server_name: server }
    }
  } as unknown as VpnProfile
}

function pickerProfiles() {
  return storeData.current['server-picker'].profiles as any[]
}

beforeEach(() => {
  resetStores()
  resolveVpnProfilesMock.mockReset()
})

describe('refreshGroup dedup-merge', () => {
  it('updates existing profiles in place instead of duplicating (sourceUri present)', async () => {
    // Create a subscription group.
    const group = serverGroups.createGroup({
      name: 'feodorn.com',
      source: 'subscription',
      sourceUrl: 'https://sub.example.com/abc',
      importedAt: Date.now(),
      status: 'unknown'
    })

    // Seed two stored profiles that ALREADY carry a sourceUri — exactly the
    // state backfillProfileSourceUris() produces. Same connection tuples the
    // subscription will return.
    storeData.current['server-picker'].profiles = [
      {
        id: 'p1',
        name: 'DE',
        protocol: 'vless',
        server: 'de.feodorn.com',
        port: 443,
        groupId: group.id,
        sourceUri: 'vless://u-de.feodorn.com@de.feodorn.com:443',
        outbound: { type: 'vless', server: 'de.feodorn.com', server_port: 443 },
        enabled: true
      },
      {
        id: 'p2',
        name: 'NL',
        protocol: 'vless',
        server: 'nl.feodorn.com',
        port: 443,
        groupId: group.id,
        sourceUri: 'vless://u-nl.feodorn.com@nl.feodorn.com:443',
        outbound: { type: 'vless', server: 'nl.feodorn.com', server_port: 443 },
        enabled: true
      }
    ]

    // Subscription returns the SAME two servers (no per-line URI on fresh side).
    resolveVpnProfilesMock.mockResolvedValue({
      profiles: [
        makeVpnProfile('de.feodorn.com', 443, 'DE'),
        makeVpnProfile('nl.feodorn.com', 443, 'NL')
      ],
      source: 'subscription',
      fetched: true,
      userInfo: undefined
    })

    const res = await refreshGroup(group.id)
    expect(res.ok).toBe(true)
    if (!res.ok) return

    // The critical assertion: no duplicates. Still exactly 2 profiles.
    const inGroup = pickerProfiles().filter((p) => p.groupId === group.id)
    expect(inGroup).toHaveLength(2)
    expect(res.addedCount).toBe(0)
    expect(res.updatedCount).toBe(2)

    // Stable IDs preserved (active-profile pointer must not jump).
    const ids = inGroup.map((p) => p.id).sort()
    expect(ids).toEqual(['p1', 'p2'])
  })

  it('adds genuinely new servers and keeps vanished ones', async () => {
    const group = serverGroups.createGroup({
      name: 'feodorn.com',
      source: 'subscription',
      sourceUrl: 'https://sub.example.com/abc',
      importedAt: Date.now(),
      status: 'unknown'
    })

    storeData.current['server-picker'].profiles = [
      {
        id: 'p1',
        name: 'DE',
        protocol: 'vless',
        server: 'de.feodorn.com',
        port: 443,
        groupId: group.id,
        sourceUri: 'vless://x@de.feodorn.com:443',
        outbound: { type: 'vless', server: 'de.feodorn.com', server_port: 443 },
        enabled: true
      }
    ]

    // Subscription now lists DE (existing) + FR (new). NL is gone (none here).
    resolveVpnProfilesMock.mockResolvedValue({
      profiles: [
        makeVpnProfile('de.feodorn.com', 443, 'DE'),
        makeVpnProfile('fr.feodorn.com', 443, 'FR')
      ],
      source: 'subscription',
      fetched: true,
      userInfo: undefined
    })

    const res = await refreshGroup(group.id)
    expect(res.ok).toBe(true)
    if (!res.ok) return

    const inGroup = pickerProfiles().filter((p) => p.groupId === group.id)
    // DE (kept, same id) + FR (new) = 2, no duplicate DE.
    expect(inGroup).toHaveLength(2)
    expect(res.addedCount).toBe(1)
    expect(res.updatedCount).toBe(1)
    expect(inGroup.find((p) => p.server === 'de.feodorn.com')!.id).toBe('p1')
  })

  it('running refresh twice does not grow the group', async () => {
    const group = serverGroups.createGroup({
      name: 'feodorn.com',
      source: 'subscription',
      sourceUrl: 'https://sub.example.com/abc',
      importedAt: Date.now(),
      status: 'unknown'
    })

    resolveVpnProfilesMock.mockResolvedValue({
      profiles: [
        makeVpnProfile('de.feodorn.com', 443, 'DE'),
        makeVpnProfile('nl.feodorn.com', 443, 'NL'),
        makeVpnProfile('fr.feodorn.com', 443, 'FR')
      ],
      source: 'subscription',
      fetched: true,
      userInfo: undefined
    })

    await refreshGroup(group.id)
    const afterFirst = pickerProfiles().filter((p) => p.groupId === group.id).length
    await refreshGroup(group.id)
    const afterSecond = pickerProfiles().filter((p) => p.groupId === group.id).length

    expect(afterFirst).toBe(3)
    expect(afterSecond).toBe(3)
  })

  it('marks group expired when the subscription returns zero profiles', async () => {
    const group = serverGroups.createGroup({
      name: 'feodorn.com',
      source: 'subscription',
      sourceUrl: 'https://sub.example.com/abc',
      importedAt: Date.now(),
      status: 'active'
    })

    resolveVpnProfilesMock.mockResolvedValue({
      profiles: [],
      source: 'subscription',
      fetched: true,
      userInfo: undefined
    })

    await refreshGroup(group.id)
    const updated = serverGroups.getGroup(group.id)
    expect(updated?.status).toBe('expired')
  })

  it('marks elapsed subscriptions expired without hiding saved profiles', async () => {
    const group = serverGroups.createGroup({
      name: 'expired.example.com',
      source: 'subscription',
      sourceUrl: 'https://sub.example.com/expired',
      importedAt: Date.now() - 30 * 24 * 60 * 60 * 1000,
      status: 'active',
      expiresAt: Date.now() - 60_000
    })

    storeData.current['server-picker'].profiles = [
      {
        id: 'p1',
        name: 'US',
        protocol: 'vless',
        server: 'us.example.com',
        port: 443,
        groupId: group.id,
        outbound: { type: 'vless', server: 'us.example.com', server_port: 443 },
        enabled: true
      }
    ]

    const updated = serverGroups.getGroup(group.id)
    expect(updated?.status).toBe('expired')
    expect(pickerProfiles().filter((p) => p.groupId === group.id)).toHaveLength(1)
  })
})
