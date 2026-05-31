/**
 * Regression: one subscription was shattered into many bogus "subscription"
 * groups named after Reality camouflage SNIs (vk.com, ozone.ru, x5.ru, …).
 *
 * consolidateBogusSniGroups() folds every source:'subscription' group that has
 * NO sourceUrl back into the single "Ручные ключи" bucket, deletes the empty
 * bogus groups, and leaves genuine subscription groups (with a sourceUrl) and
 * the manual group untouched.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'

// Stateful picker store (profiles) — consolidation re-points groupId.
let pickerData: { profiles: any[]; activeProfileId: string | null } = {
  profiles: [],
  activeProfileId: null
}

// Stateful groups store, driven through the mocked serverGroups module.
let groupsData: any[] = []
const MANUAL_ID = 'manual-keys-group'

vi.mock('electron', () => ({
  app: { getPath: () => '/tmp/vpnte-test', getAppPath: () => '/tmp/vpnte-test' },
  dialog: {},
  ipcMain: { handle: vi.fn() }
}))
vi.mock('electron-store', () => ({
  default: class MockStore {
    get(key: 'profiles' | 'activeProfileId') {
      return pickerData[key]
    }
    set(key: 'profiles' | 'activeProfileId', value: any) {
      ;(pickerData as any)[key] = value
    }
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
  serverGroups: {
    getGroups: () => groupsData,
    createGroup: vi.fn(),
    deleteGroup: (id: string) => {
      groupsData = groupsData.filter((g) => g.id !== id)
    }
  },
  ensureManualKeysGroup: () => {
    if (!groupsData.some((g) => g.id === MANUAL_ID)) {
      groupsData.push({ id: MANUAL_ID, name: 'Ручные ключи', source: 'manual', importedAt: 0, status: 'unknown' })
    }
    return MANUAL_ID
  },
  findGroupBySourceUrl: vi.fn(),
  canonicalizeSubscriptionUrl: (s: string) => s,
  refreshGroup: vi.fn()
}))

import { consolidateBogusSniGroups } from './serverPicker'

describe('consolidateBogusSniGroups', () => {
  beforeEach(() => {
    // A real subscription group (has sourceUrl) + two bogus SNI groups.
    groupsData = [
      { id: 'real-sub', name: 'sosa.ink', source: 'subscription', sourceUrl: 'https://sosa.ink/sub/x', importedAt: 1, status: 'active' },
      { id: 'bogus-vk', name: 'vk.com', source: 'subscription', importedAt: 2, status: 'unknown' },
      { id: 'bogus-ozon', name: 'ozone.ru', source: 'subscription', importedAt: 3, status: 'unknown' }
    ]
    pickerData = {
      profiles: [
        { id: 'p1', name: 'Real', protocol: 'vless', server: 'a', port: 443, status: 'unknown', groupId: 'real-sub' },
        { id: 'p2', name: 'VK camo', protocol: 'vless', server: 'b', port: 443, status: 'unknown', groupId: 'bogus-vk' },
        { id: 'p3', name: 'Ozon camo', protocol: 'vless', server: 'c', port: 443, status: 'unknown', groupId: 'bogus-ozon' }
      ],
      activeProfileId: null
    }
  })

  it('moves profiles from bogus SNI groups into the manual bucket', () => {
    consolidateBogusSniGroups()
    const byId = Object.fromEntries(pickerData.profiles.map((p) => [p.id, p]))
    expect(byId.p2.groupId).toBe(MANUAL_ID)
    expect(byId.p3.groupId).toBe(MANUAL_ID)
  })

  it('leaves the real subscription group and its profile untouched', () => {
    consolidateBogusSniGroups()
    const byId = Object.fromEntries(pickerData.profiles.map((p) => [p.id, p]))
    expect(byId.p1.groupId).toBe('real-sub')
    expect(groupsData.some((g) => g.id === 'real-sub')).toBe(true)
  })

  it('deletes the now-empty bogus groups', () => {
    consolidateBogusSniGroups()
    expect(groupsData.some((g) => g.id === 'bogus-vk')).toBe(false)
    expect(groupsData.some((g) => g.id === 'bogus-ozon')).toBe(false)
  })

  it('is idempotent — second run is a no-op', () => {
    consolidateBogusSniGroups()
    const afterFirst = JSON.parse(JSON.stringify({ groupsData, profiles: pickerData.profiles }))
    consolidateBogusSniGroups()
    expect(groupsData).toEqual(afterFirst.groupsData)
    expect(pickerData.profiles).toEqual(afterFirst.profiles)
  })
})
