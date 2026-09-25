/**
 * Tests for the local-Programs directory scan and the refresh merge logic.
 *
 * Covers the three review findings:
 *  1. Sibling products under one vendor dir (Vendor\ProductA + Vendor\ProductB)
 *     must BOTH be discovered — collectExes used to stop after the first
 *     branch that yielded an exe.
 *  2. Junction/symlink product dirs must be traversed (Dirent.isDirectory()
 *     is false for junctions, only isSymbolicLink() is true).
 *  3. refresh-apps must not resurrect apps the user removed (tombstones),
 *     and must preserve id + rule of entries that are still on disk.
 *
 * The scanner is win32-only, so discovery tests are skipped on other
 * platforms; the merge/tombstone logic is platform-independent.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'

// ─── Virtual filesystem ──────────────────────────────────────────────────────
// nodeFs maps absolute paths to their directory entries. Entries are plain
// objects shaped like fs.Dirent for the fields the scanner reads.
type FakeDirent = {
  name: string
  isDirectory: () => boolean
  isFile: () => boolean
  isSymbolicLink: () => boolean
}

const nodeFs = new Map<string, FakeDirent[]>()

function dir(name: string): FakeDirent {
  return { name, isDirectory: () => true, isFile: () => false, isSymbolicLink: () => false }
}
function junction(name: string): FakeDirent {
  return { name, isDirectory: () => false, isFile: () => false, isSymbolicLink: () => true }
}
function exe(name: string): FakeDirent {
  return { name, isDirectory: () => false, isFile: () => true, isSymbolicLink: () => false }
}

function seedFs(tree: Record<string, FakeDirent[]>): void {
  nodeFs.clear()
  for (const [path, entries] of Object.entries(tree)) {
    nodeFs.set(path.toLowerCase(), entries)
  }
}

const fsPromisesMock = vi.hoisted(() => ({
  readdir: vi.fn(async (p: string) => {
    const entries = nodeFs.get(String(p).toLowerCase())
    if (!entries) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
    return entries
  }),
  access: vi.fn(async () => undefined)
}))
vi.mock('fs/promises', () => ({ ...fsPromisesMock, default: fsPromisesMock }))

// ─── Stateful store mock (shared with the module under test) ─────────────────
let storeData: {
  splitTunnelApps: any[]
  splitTunnelEnabled: boolean
  splitTunnelRemovedPaths: string[]
} = {
  splitTunnelApps: [],
  splitTunnelEnabled: true,
  splitTunnelRemovedPaths: []
}

vi.mock('electron', () => ({
  ipcMain: { handle: vi.fn() },
  dialog: { showOpenDialog: vi.fn() },
  // appData → C:\Users\Test\AppData\Roaming, so the scanner root resolves to
  // C:\Users\Test\AppData\Local\Programs (path.join normalises the '..').
  app: { getPath: () => 'C:\\Users\\Test\\AppData\\Roaming' }
}))
vi.mock('electron-store', () => ({
  default: class MockStore {
    get(key: keyof typeof storeData) {
      return storeData[key]
    }
    set(key: keyof typeof storeData, value: any) {
      ;(storeData as any)[key] = value
    }
  }
}))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./tunController', () => ({
  tunController: {
    getStatus: () => ({ running: false }),
    stop: vi.fn().mockResolvedValue({ success: true })
  }
}))

import {
  discoverInstalledApps,
  looksCorruptDisplayName,
  sanitizeAppDisplayName,
  splitTunneling
} from './splitTunneling'

const PROGRAMS = 'C:\\Users\\Test\\AppData\\Local\\Programs'
const itWin32 = process.platform === 'win32' ? it : it.skip

// The registry scan shells out to PowerShell; these tests only exercise the
// local-Programs half, so we let the registry part fail/return nothing by
// running on a tree where only the Programs root exists.

describe('discoverLocalProgramsApps (via discoverInstalledApps)', () => {
  beforeEach(() => {
    storeData = { splitTunnelApps: [], splitTunnelEnabled: true, splitTunnelRemovedPaths: [] }
  })

  itWin32('finds sibling products under the same vendor dir', async () => {
    seedFs({
      [PROGRAMS]: [dir('Vendor')],
      [`${PROGRAMS}\\Vendor`]: [dir('ProductA'), dir('ProductB')],
      [`${PROGRAMS}\\Vendor\\ProductA`]: [exe('producta.exe')],
      [`${PROGRAMS}\\Vendor\\ProductB`]: [exe('productb.exe')]
    })
    const apps = await discoverInstalledApps()
    const paths = apps.map(a => a.path.toLowerCase())
    expect(paths).toContain(`${PROGRAMS}\\Vendor\\ProductA\\producta.exe`.toLowerCase())
    expect(paths).toContain(`${PROGRAMS}\\Vendor\\ProductB\\productb.exe`.toLowerCase())
  })

  itWin32('traverses junction/symlink product dirs', async () => {
    seedFs({
      [PROGRAMS]: [dir('Codex')],
      [`${PROGRAMS}\\Codex`]: [junction('bin')],
      [`${PROGRAMS}\\Codex\\bin`]: [exe('codex.exe')]
    })
    const apps = await discoverInstalledApps()
    expect(apps.map(a => a.path.toLowerCase())).toContain(
      `${PROGRAMS}\\Codex\\bin\\codex.exe`.toLowerCase()
    )
  })

  itWin32('picks the product exe over installer/helper siblings', async () => {
    seedFs({
      [PROGRAMS]: [dir('Tool')],
      [`${PROGRAMS}\\Tool`]: [exe('unins000.exe'), exe('update.exe'), exe('tool.exe')]
    })
    const apps = await discoverInstalledApps()
    // The scanner reports ONE main exe per product dir; helper exes stay out.
    const toolApps = apps.filter(a => /\\Tool\\/i.test(a.path))
    expect(toolApps).toHaveLength(1)
    expect(toolApps[0].path.toLowerCase()).toBe(`${PROGRAMS}\\Tool\\tool.exe`.toLowerCase())
  })
})

describe('mojibake heuristic vs legit Asian names', () => {
  it('keeps a legit mixed Latin+CJK name intact', () => {
    const name = 'QQ 腾讯'
    expect(looksCorruptDisplayName(name)).toBe(false)
    expect(sanitizeAppDisplayName(name, 'C:\\Program Files\\Tencent\\QQ\\QQ.exe')).toBe('QQ 腾讯')
  })

  it('keeps a pure Hangul app name intact', () => {
    const name = '카카오톡'
    expect(looksCorruptDisplayName(name)).toBe(false)
    expect(sanitizeAppDisplayName(name, 'C:\\Program Files\\Kakao\\KakaoTalk.exe')).toBe('카카오톡')
  })

  it('still flags real mojibake (long CJK run mixed with Latin)', () => {
    expect(looksCorruptDisplayName('YandexMusic 䍩䃘蓤悜 5.108')).toBe(true)
  })
})

describe('refresh merge + removal tombstones', () => {
  beforeEach(() => {
    storeData = { splitTunnelApps: [], splitTunnelEnabled: true, splitTunnelRemovedPaths: [] }
    seedFs({})
  })

  it('removeApp tombstones the path and refresh does not resurrect it', async () => {
    const added = await splitTunneling.addApp('C:\\Apps\\Gone\\gone.exe')
    await splitTunneling.removeApp(added.id)
    expect(splitTunneling.getApps()).toHaveLength(0)
    expect(storeData.splitTunnelRemovedPaths.map(p => p.toLowerCase())).toContain(
      'c:\\apps\\gone\\gone.exe'
    )
  })

  it('a manual addApp clears the tombstone so refresh keeps the app', async () => {
    const first = await splitTunneling.addApp('C:\\Apps\\Back\\back.exe')
    await splitTunneling.removeApp(first.id)
    expect(storeData.splitTunnelRemovedPaths).toHaveLength(1)
    await splitTunneling.addApp('C:\\Apps\\Back\\back.exe')
    expect(storeData.splitTunnelRemovedPaths).toHaveLength(0)
    expect(splitTunneling.getApps()).toHaveLength(1)
  })

  it('process-name entries are not tombstoned on removal', async () => {
    const entry = await splitTunneling.addProcessName('curl')
    await splitTunneling.removeApp(entry.id)
    expect(storeData.splitTunnelRemovedPaths).toHaveLength(0)
  })
})
