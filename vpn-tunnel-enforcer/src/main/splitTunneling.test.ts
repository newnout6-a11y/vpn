/**
 * Unit tests for the split tunneling service.
 * Tests the core logic: route rule generation, app management, and config persistence.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'

// Mock electron modules
vi.mock('electron', () => ({
  ipcMain: { handle: vi.fn() },
  dialog: { showOpenDialog: vi.fn() },
  app: { getPath: () => '/tmp/test' }
}))

vi.mock('electron-store', () => {
  const data: Record<string, any> = {
    splitTunnelApps: [],
    splitTunnelEnabled: true
  }
  return {
    default: class MockStore {
      constructor() {}
      get(key: string) {
        return data[key]
      }
      set(key: string, value: any) {
        data[key] = value
      }
    }
  }
})

vi.mock('./appLogger', () => ({
  logEvent: vi.fn()
}))

vi.mock('./tunController', () => ({
  tunController: {
    getStatus: () => ({ running: false }),
    stop: vi.fn().mockResolvedValue({ success: true })
  }
}))

// Import after mocks
import {
  addProcessName,
  fallbackAppNameFromPath,
  generateSplitTunnelRouteRules,
  getDirectProcessNames,
  getVpnProcessNames,
  sanitizeAppDisplayName,
  normalizeProcessName,
  splitTunneling
} from './splitTunneling'

describe('splitTunneling', () => {
  describe('generateSplitTunnelRouteRules', () => {
    it('returns empty array when no apps have rules', () => {
      const rules = generateSplitTunnelRouteRules()
      expect(rules).toEqual([])
    })
  })

  describe('getDirectProcessNames', () => {
    it('returns empty array when no apps have direct rule', () => {
      const names = getDirectProcessNames()
      expect(names).toEqual([])
    })
  })

  describe('getVpnProcessNames', () => {
    it('returns empty array when no apps have vpn rule', () => {
      const names = getVpnProcessNames()
      expect(names).toEqual([])
    })
  })

  describe('app display name sanitization', () => {
    it('cleans mojibake suffixes without losing the useful product name', () => {
      const name = sanitizeAppDisplayName(
        'Hiddify, \uFFFD\uFFFD\uFFFD\uFFFD\uFFFD 2.5.7+20507',
        'C:\\Program Files\\Hiddify\\Hiddify.exe'
      )

      expect(name).toBe('Hiddify 2.5.7+20507')
      expect(name).not.toContain('\uFFFD')
    })

    it('falls back to the application folder when the whole display name is corrupt', () => {
      expect(
        sanitizeAppDisplayName(
          '\uFFFD\uFFFD\uFFFD\uFFFD\uFFFD\uFFFD \uFFFD\uFFFD멋 5.108.3',
          'C:\\Users\\Redmi\\AppData\\Local\\Programs\\YandexMusic\\broken.exe'
        )
      ).toBe('YandexMusic')
    })

    it('drops broken architecture suffixes from otherwise readable names', () => {
      expect(
        sanitizeAppDisplayName(
          'WinRAR 7.01 (64-\uFFFD來\uFFFD\uFFFD)',
          'C:\\Program Files\\WinRAR\\Rar.exe'
        )
      ).toBe('WinRAR 7.01')
    })

    it('prefers a stable folder name over numeric executable leaves', () => {
      expect(fallbackAppNameFromPath('C:\\Program Files\\WinRAR\\Rar.exe')).toBe('WinRAR')
      expect(fallbackAppNameFromPath('C:\\Program Files\\7-Zip\\7z.exe')).toBe('7-Zip')
      expect(fallbackAppNameFromPath('C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe')).toBe('chrome')
    })
  })

  describe('process name normalization', () => {
    it('appends .exe for bare command entries and uses normalized names in rules', async () => {
      expect(normalizeProcessName('curl')).toBe('curl.exe')
      const entry = await addProcessName('yt-dlp')

      expect(entry.path).toBe('yt-dlp.exe')
      expect(getDirectProcessNames()).toContain('yt-dlp.exe')
      expect(generateSplitTunnelRouteRules()).toEqual([
        { process_name: ['yt-dlp.exe'], outbound: 'direct-out' }
      ])
    })

    it('does not emit redundant proxy-out rules for vpn entries', async () => {
      const entry = await addProcessName('curl')
      await splitTunneling.setRule(entry.id, 'vpn')

      expect(getVpnProcessNames()).toEqual(['curl.exe'])
      expect(generateSplitTunnelRouteRules().some((rule) => rule.outbound === 'proxy-out')).toBe(false)
    })
  })
})
