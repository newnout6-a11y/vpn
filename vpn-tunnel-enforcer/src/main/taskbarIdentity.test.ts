/**
 * Guards removeHijackingDevShortcut(): it must delete the Start Menu
 * `Electron.lnk` ONLY when packaged, on win32, and only when the file's bytes
 * still reference a node_modules Electron dist — never a look-alike shortcut the
 * user made themselves, and never in dev.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

const h = vi.hoisted(() => {
  const state = {
    isPackaged: true,
    files: new Map<string, Buffer>(),
    unlinked: [] as string[]
  }
  const readFile = vi.fn(async (p: string) => {
    const hit = state.files.get(p)
    if (!hit) {
      const err = new Error('ENOENT') as NodeJS.ErrnoException
      err.code = 'ENOENT'
      throw err
    }
    return hit
  })
  const unlink = vi.fn(async (p: string) => {
    state.unlinked.push(p)
    state.files.delete(p)
  })
  return { state, readFile, unlink }
})

vi.mock('electron', () => ({
  app: {
    get isPackaged() {
      return h.state.isPackaged
    }
  }
}))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('fs/promises', () => ({
  default: { readFile: h.readFile, unlink: h.unlink },
  readFile: h.readFile,
  unlink: h.unlink
}))

import { removeHijackingDevShortcut } from './taskbarIdentity'

const LNK =
  'C:\\Users\\dev\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Electron.lnk'
const realPlatform = process.platform

const lnkWith = (targetPath: string) =>
  Buffer.concat([
    Buffer.from('L\0\0\0', 'latin1'),
    Buffer.from(targetPath, 'utf16le'),
    Buffer.from(targetPath, 'latin1')
  ])

const setPlatform = (value: string) =>
  Object.defineProperty(process, 'platform', { value, configurable: true })

beforeEach(() => {
  h.state.isPackaged = true
  h.state.files = new Map()
  h.state.unlinked = []
  h.readFile.mockClear()
  h.unlink.mockClear()
  setPlatform('win32')
  process.env.APPDATA = 'C:\\Users\\dev\\AppData\\Roaming'
})

afterEach(() => {
  setPlatform(realPlatform)
})

describe('removeHijackingDevShortcut', () => {
  it('deletes Electron.lnk that points at a node_modules electron dist', async () => {
    h.state.files.set(LNK, lnkWith('C:\\proj\\node_modules\\electron\\dist\\electron.exe'))
    await removeHijackingDevShortcut()
    expect(h.state.unlinked).toEqual([LNK])
  })

  it('leaves a user-authored Electron.lnk that points elsewhere', async () => {
    h.state.files.set(LNK, lnkWith('C:\\Program Files\\Some Electron App\\app.exe'))
    await removeHijackingDevShortcut()
    expect(h.state.unlinked).toEqual([])
  })

  it('is a no-op when the shortcut is absent', async () => {
    await removeHijackingDevShortcut()
    expect(h.state.unlinked).toEqual([])
  })

  it('does nothing in dev (unpackaged), even with a matching shortcut', async () => {
    h.state.isPackaged = false
    h.state.files.set(LNK, lnkWith('C:\\proj\\node_modules\\electron\\dist\\electron.exe'))
    await removeHijackingDevShortcut()
    expect(h.state.unlinked).toEqual([])
  })

  it('does nothing off win32', async () => {
    setPlatform('linux')
    h.state.files.set(LNK, lnkWith('C:\\proj\\node_modules\\electron\\dist\\electron.exe'))
    await removeHijackingDevShortcut()
    expect(h.state.unlinked).toEqual([])
  })

  it('does nothing when APPDATA is unset', async () => {
    delete process.env.APPDATA
    h.state.files.set(LNK, lnkWith('C:\\proj\\node_modules\\electron\\dist\\electron.exe'))
    await removeHijackingDevShortcut()
    expect(h.state.unlinked).toEqual([])
  })
})
