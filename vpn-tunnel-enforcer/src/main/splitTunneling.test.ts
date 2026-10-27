/**
 * Unit tests for the split tunneling service.
 * Tests the core logic: route rule generation, app management, and config persistence.
 */

import { describe, it, expect, vi, beforeEach, afterAll } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'

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
  getDirectProcessTargets,
  getVpnProcessNames,
  sanitizeAppDisplayName,
  normalizeProcessName,
  splitTunneling
} from './splitTunneling'
import { logEvent } from './appLogger'

beforeEach(async () => {
  for (const app of splitTunneling.getApps()) await splitTunneling.removeApp(app.id)
})

describe('splitTunneling', () => {
  describe('getDirectProcessTargets', () => {
    it('returns an empty snapshot when no apps have direct rules', async () => {
      expect(await getDirectProcessTargets()).toEqual({ names: [], paths: [] })
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
      expect(await getDirectProcessTargets()).toEqual({ names: ['yt-dlp.exe'], paths: [] })
    })

    it('does not emit redundant proxy-out rules for vpn entries', async () => {
      const entry = await addProcessName('curl')
      await splitTunneling.setRule(entry.id, 'vpn')

      expect(getVpnProcessNames()).toEqual(['curl.exe'])
      expect(await getDirectProcessTargets()).toEqual({ names: [], paths: [] })
    })
  })
})

// AT-06-008 / F-076: installed applications bypass the VPN by their full path, not by file name.
describe('split tunneling by application path', () => {
  const copyDir = mkdtempSync(join(tmpdir(), 'vpnte-split-path-'))
  const exe = join(copyDir, 'app.exe')

  beforeEach(() => { writeFileSync(exe, 'x') })
  afterAll(() => { rmSync(copyDir, { recursive: true, force: true }) })

  it('emits a path rule and no name rule for an installed application', async () => {
    const entry = await splitTunneling.addApp(exe)
    await splitTunneling.setRule(entry.id, 'direct')
    const targets = await getDirectProcessTargets()
    // The runner's temp dir can be an 8.3 path: the rule then carries both spellings, the stored one among them.
    expect(targets.paths.map((p) => p.toLowerCase())).toContain(exe.toLowerCase())
    expect(targets.names).not.toContain('app.exe')
  })

  it('drops the rule (and logs it) when the file is gone: no silent match by name', async () => {
    const entry = await splitTunneling.addApp(exe)
    await splitTunneling.setRule(entry.id, 'direct')
    rmSync(exe)
    const targets = await getDirectProcessTargets()
    expect(targets.paths.map((p) => p.toLowerCase())).not.toContain(exe.toLowerCase())
    expect(targets.names).not.toContain('app.exe')
    expect(logEvent).toHaveBeenCalledWith('warn', 'split-tunnel', expect.stringContaining('inactive'), expect.objectContaining({ reason: 'file-missing' }))
  })

  it('keeps bare process names matched by name', async () => {
    const entry = await addProcessName('curl')
    await splitTunneling.setRule(entry.id, 'direct')
    expect((await getDirectProcessTargets()).names).toContain('curl.exe')
  })
})
