/**
 * Unit tests for profileRotation pure functions.
 */

import { beforeEach, describe, it, expect, vi } from 'vitest'
import type { RotationConfig } from '../shared/ipc-types'

const storeData = vi.hoisted(() => new Map<string, any>())
const ipcHandlers = vi.hoisted(() => new Map<string, (...args: any[]) => any>())
const browserSendMock = vi.hoisted(() => vi.fn())
const selectProfileMock = vi.hoisted(() => vi.fn())
const smartOfflinePingMock = vi.hoisted(() => vi.fn())
const tunStopMock = vi.hoisted(() => vi.fn(async () => undefined))
const tunStartMock = vi.hoisted(() => vi.fn(async () => undefined))
const settingsGetMock = vi.hoisted(() => vi.fn(() => ({
  firewallKillSwitch: true,
  publicWifiCompatibility: false,
  strictAdapterLockdown: true,
  stealthMode: true
})))
const serverProfiles = vi.hoisted(() => [] as any[])
let tunnelRunning = false

vi.mock('electron', () => ({
  ipcMain: {
    handle: vi.fn((channel: string, handler: (...args: any[]) => any) => {
      ipcHandlers.set(channel, handler)
    })
  },
  BrowserWindow: {
    getAllWindows: () => [{ webContents: { send: browserSendMock } }]
  }
}))

vi.mock('electron-store', () => ({
  default: class MockStore {
    defaults: Record<string, any>

    constructor(options: { defaults?: Record<string, any> } = {}) {
      this.defaults = options.defaults ?? {}
    }

    get(key: string, fallback?: any) {
      if (storeData.has(key)) return storeData.get(key)
      if (Object.prototype.hasOwnProperty.call(this.defaults, key)) return this.defaults[key]
      return fallback
    }

    set(key: string, value: any) {
      storeData.set(key, value)
    }
  }
}))

vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./ipcLogging', () => ({ compactForIpcLog: (args: any[]) => args }))
vi.mock('./notifications', () => ({ notify: vi.fn(async () => undefined) }))
vi.mock('./settings', () => ({ settingsStore: { get: settingsGetMock } }))
vi.mock('./serverPicker', () => ({
  smartOfflinePing: smartOfflinePingMock,
  serverPicker: {
    getProfiles: () => serverProfiles,
    selectProfile: selectProfileMock
  }
}))
vi.mock('./tunController', () => ({
  tunController: {
    getStatus: () => ({ running: tunnelRunning }),
    stop: tunStopMock,
    start: tunStartMock
  }
}))

import { clampInterval, getNextAvailableProfile, profileRotation } from './profileRotation'

describe('clampInterval', () => {
  it('returns MIN (5) for values below 5', () => {
    expect(clampInterval(0)).toBe(5)
    expect(clampInterval(-10)).toBe(5)
    expect(clampInterval(4)).toBe(5)
    expect(clampInterval(1)).toBe(5)
  })

  it('returns MAX (1440) for values above 1440', () => {
    expect(clampInterval(1441)).toBe(1440)
    expect(clampInterval(9999)).toBe(1440)
    expect(clampInterval(100000)).toBe(1440)
  })

  it('preserves values within [5, 1440]', () => {
    expect(clampInterval(5)).toBe(5)
    expect(clampInterval(30)).toBe(30)
    expect(clampInterval(60)).toBe(60)
    expect(clampInterval(1440)).toBe(1440)
    expect(clampInterval(720)).toBe(720)
  })

  it('returns MIN for NaN and Infinity', () => {
    expect(clampInterval(NaN)).toBe(5)
    expect(clampInterval(Infinity)).toBe(5)
    expect(clampInterval(-Infinity)).toBe(5)
  })
})

describe('getNextAvailableProfile', () => {
  const baseConfig: RotationConfig = {
    enabled: true,
    intervalMinutes: 30,
    order: 'sequential',
    profileIds: ['a', 'b', 'c', 'd'],
    currentIndex: 0,
    nextRotationAt: null
  }

  describe('sequential order', () => {
    it('returns the next available profile after current index', () => {
      const config = { ...baseConfig, currentIndex: 0 }
      const availability = { a: true, b: true, c: true, d: true }
      expect(getNextAvailableProfile(config, availability)).toBe('b')
    })

    it('skips unavailable profiles', () => {
      const config = { ...baseConfig, currentIndex: 0 }
      const availability = { a: true, b: false, c: true, d: true }
      expect(getNextAvailableProfile(config, availability)).toBe('c')
    })

    it('wraps around the list', () => {
      const config = { ...baseConfig, currentIndex: 3 }
      const availability = { a: true, b: true, c: true, d: true }
      expect(getNextAvailableProfile(config, availability)).toBe('a')
    })

    it('wraps around skipping unavailable', () => {
      const config = { ...baseConfig, currentIndex: 2 }
      const availability = { a: false, b: true, c: true, d: false }
      expect(getNextAvailableProfile(config, availability)).toBe('b')
    })

    it('returns null when no profiles are available', () => {
      const config = { ...baseConfig, currentIndex: 0 }
      const availability = { a: false, b: false, c: false, d: false }
      expect(getNextAvailableProfile(config, availability)).toBeNull()
    })

    it('returns null for empty profileIds', () => {
      const config = { ...baseConfig, profileIds: [], currentIndex: 0 }
      const availability = {}
      expect(getNextAvailableProfile(config, availability)).toBeNull()
    })
  })

  describe('random order', () => {
    it('returns an available profile different from current', () => {
      const config = { ...baseConfig, order: 'random' as const, currentIndex: 0 }
      const availability = { a: true, b: true, c: true, d: true }
      const result = getNextAvailableProfile(config, availability)
      expect(result).not.toBeNull()
      expect(result).not.toBe('a') // should not be current
      expect(['b', 'c', 'd']).toContain(result)
    })

    it('returns the only other available profile', () => {
      const config = { ...baseConfig, order: 'random' as const, currentIndex: 0 }
      const availability = { a: true, b: false, c: true, d: false }
      expect(getNextAvailableProfile(config, availability)).toBe('c')
    })

    it('returns current profile if it is the only one available', () => {
      const config = { ...baseConfig, order: 'random' as const, currentIndex: 0 }
      const availability = { a: true, b: false, c: false, d: false }
      expect(getNextAvailableProfile(config, availability)).toBe('a')
    })

    it('returns null when no profiles are available', () => {
      const config = { ...baseConfig, order: 'random' as const, currentIndex: 0 }
      const availability = { a: false, b: false, c: false, d: false }
      expect(getNextAvailableProfile(config, availability)).toBeNull()
    })
  })
})

describe('profile rotation IPC', () => {
  beforeEach(() => {
    profileRotation.stopTimer()
    storeData.clear()
    ipcHandlers.clear()
    browserSendMock.mockClear()
    selectProfileMock.mockClear()
    smartOfflinePingMock.mockReset()
    tunStopMock.mockClear()
    tunStartMock.mockClear()
    settingsGetMock.mockClear()
    serverProfiles.length = 0
    tunnelRunning = false
    vi.useRealTimers()
  })

  it('rotates a running direct VPN tunnel to the next usable profile and reconnects it', async () => {
    vi.useFakeTimers()
    tunnelRunning = true
    const now = Date.now()
    serverProfiles.push(
      {
        id: 'profile-a',
        name: 'Profile A',
        protocol: 'vless',
        server: '198.51.100.1',
        port: 443,
        status: 'unknown',
        lastChecked: now - 3 * 60_000,
        outbound: { type: 'vless', server: '198.51.100.1', server_port: 443 }
      },
      {
        id: 'profile-b',
        name: 'Profile B',
        protocol: 'vless',
        server: '198.51.100.2',
        port: 443,
        status: 'unknown',
        lastChecked: now - 3 * 60_000,
        outbound: { type: 'vless', server: '198.51.100.2', server_port: 443 }
      }
    )
    storeData.set('rotation', {
      enabled: true,
      intervalMinutes: 30,
      order: 'sequential',
      profileIds: ['profile-a', 'profile-b'],
      currentIndex: 0,
      nextRotationAt: null
    } satisfies RotationConfig)

    profileRotation.registerHandlers()
    const rotateNow = ipcHandlers.get('rotation:rotate-now')
    expect(rotateNow).toBeTypeOf('function')

    const result = await rotateNow!({})

    expect(result).toEqual({ success: true, newProfile: 'profile-b' })
    expect(smartOfflinePingMock).not.toHaveBeenCalled()
    expect(selectProfileMock).toHaveBeenCalledWith('profile-b')
    expect(browserSendMock).toHaveBeenCalledWith('server-active-changed', {
      profileId: 'profile-b',
      profileName: 'Profile B'
    })
    expect(tunStopMock).toHaveBeenCalledTimes(1)
    expect(tunStartMock).toHaveBeenCalledWith(expect.objectContaining({
      mode: 'directVpn',
      enableFirewallKillSwitch: true,
      enableAdapterLockdown: true,
      publicWifiCompatibility: false,
      stealthMode: true,
      vpnProfile: {
        name: 'Profile B',
        protocol: 'vless',
        outbound: { type: 'vless', server: '198.51.100.2', server_port: 443 }
      }
    }))
    expect(storeData.get('rotation')).toMatchObject({
      currentIndex: 1,
      nextRotationAt: expect.any(Number)
    })
  })

  it('seeds usable profiles when enabling rotation from an empty config', async () => {
    vi.useFakeTimers()
    serverProfiles.push(
      {
        id: 'profile-a',
        name: 'Profile A',
        protocol: 'vless',
        server: '198.51.100.1',
        port: 443,
        status: 'unknown',
        outbound: { type: 'vless', server: '198.51.100.1', server_port: 443 }
      },
      {
        id: 'profile-b',
        name: 'Profile B',
        protocol: 'vless',
        server: '198.51.100.2',
        port: 443,
        status: 'unknown',
        outbound: { type: 'vless', server: '198.51.100.2', server_port: 443 }
      },
      {
        id: 'profile-without-outbound',
        name: 'No Outbound',
        protocol: 'vless',
        server: '198.51.100.3',
        port: 443,
        status: 'unknown'
      }
    )

    profileRotation.registerHandlers()
    const setConfig = ipcHandlers.get('rotation:set-config')
    expect(setConfig).toBeTypeOf('function')

    const updated = await setConfig!({}, { enabled: true })

    expect(updated).toMatchObject({
      enabled: true,
      profileIds: ['profile-a', 'profile-b'],
      currentIndex: 0,
      nextRotationAt: expect.any(Number)
    })
    expect(storeData.get('rotation')).toMatchObject({
      profileIds: ['profile-a', 'profile-b'],
      nextRotationAt: expect.any(Number)
    })
  })

  it('skips explicitly offline profiles while rotating a running tunnel', async () => {
    vi.useFakeTimers()
    tunnelRunning = true
    serverProfiles.push(
      {
        id: 'profile-a',
        name: 'Profile A',
        protocol: 'vless',
        server: '198.51.100.1',
        port: 443,
        status: 'online',
        outbound: { type: 'vless', server: '198.51.100.1', server_port: 443 }
      },
      {
        id: 'profile-b',
        name: 'Profile B',
        protocol: 'vless',
        server: '198.51.100.2',
        port: 443,
        status: 'offline',
        outbound: { type: 'vless', server: '198.51.100.2', server_port: 443 }
      },
      {
        id: 'profile-c',
        name: 'Profile C',
        protocol: 'vless',
        server: '198.51.100.3',
        port: 443,
        status: 'unknown',
        outbound: { type: 'vless', server: '198.51.100.3', server_port: 443 }
      }
    )
    storeData.set('rotation', {
      enabled: true,
      intervalMinutes: 30,
      order: 'sequential',
      profileIds: ['profile-a', 'profile-b', 'profile-c'],
      currentIndex: 0,
      nextRotationAt: null
    } satisfies RotationConfig)

    profileRotation.registerHandlers()
    const result = await ipcHandlers.get('rotation:rotate-now')!({})

    expect(result).toEqual({ success: true, newProfile: 'profile-c' })
    expect(selectProfileMock).toHaveBeenCalledWith('profile-c')
    expect(tunStartMock).toHaveBeenCalledWith(expect.objectContaining({
      vpnProfile: expect.objectContaining({ name: 'Profile C' })
    }))
  })
})
