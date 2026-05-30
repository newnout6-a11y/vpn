/**
 * Tests for the "bypass a command by process name" feature (split tunnel).
 *
 * normalizeProcessName is pure; addProcessName mutates a stateful store mock so
 * we can assert de-dup, .exe normalization, and the auto-'direct' rule. Covers
 * the user request: route a terminal command (curl, git, yt-dlp) around the VPN
 * by executable name rather than a full installed-app path.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'

// Stateful in-memory store so addProcessName's read-modify-write is observable.
let storeData: { splitTunnelApps: any[]; splitTunnelEnabled: boolean } = {
  splitTunnelApps: [],
  splitTunnelEnabled: true
}

vi.mock('electron', () => ({
  ipcMain: { handle: vi.fn() },
  dialog: { showOpenDialog: vi.fn() },
  app: { getPath: () => '/tmp/test' }
}))
vi.mock('electron-store', () => ({
  default: class MockStore {
    get(key: 'splitTunnelApps' | 'splitTunnelEnabled') {
      return storeData[key]
    }
    set(key: 'splitTunnelApps' | 'splitTunnelEnabled', value: any) {
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
  normalizeProcessName,
  addProcessName,
  getDirectProcessNames
} from './splitTunneling'

describe('normalizeProcessName', () => {
  it('appends .exe to a bare command name', () => {
    expect(normalizeProcessName('curl')).toBe('curl.exe')
    expect(normalizeProcessName('git')).toBe('git.exe')
  })

  it('keeps an existing extension and lower-cases', () => {
    expect(normalizeProcessName('Curl.EXE')).toBe('curl.exe')
    expect(normalizeProcessName('yt-dlp.exe')).toBe('yt-dlp.exe')
  })

  it('treats a dotted command name as already-extensioned (documents the limitation)', () => {
    // "yt-dlp" has no dot so it gets .exe; "node.js" would be misread as having
    // an extension — acceptable since real Windows executables are *.exe.
    expect(normalizeProcessName('yt-dlp')).toBe('yt-dlp.exe')
  })

  it('strips a directory and keeps only the leaf', () => {
    expect(normalizeProcessName('C:\\Windows\\System32\\curl.exe')).toBe('curl.exe')
    expect(normalizeProcessName('/usr/bin/git')).toBe('git.exe')
  })

  it('strips surrounding quotes', () => {
    expect(normalizeProcessName('"curl.exe"')).toBe('curl.exe')
    expect(normalizeProcessName("'git'")).toBe('git.exe')
  })

  it('rejects empty / whitespace-only / illegal input', () => {
    expect(normalizeProcessName('')).toBeNull()
    expect(normalizeProcessName('   ')).toBeNull()
    expect(normalizeProcessName('curl test')).toBeNull() // space inside name
    expect(normalizeProcessName('a*b')).toBeNull()       // wildcard
    expect(normalizeProcessName('a|b')).toBeNull()        // pipe
  })
})

describe('addProcessName', () => {
  beforeEach(() => {
    storeData = { splitTunnelApps: [], splitTunnelEnabled: true }
  })

  it('adds a command entry already routed direct, kind=process', () => {
    const entry = addProcessName('curl')
    expect(entry.kind).toBe('process')
    expect(entry.rule).toBe('direct')
    expect(entry.path).toBe('curl.exe')
    expect(entry.name).toBe('curl.exe')
    expect(storeData.splitTunnelApps).toHaveLength(1)
  })

  it('makes the new command show up in getDirectProcessNames', () => {
    addProcessName('yt-dlp')
    expect(getDirectProcessNames()).toContain('yt-dlp.exe')
  })

  it('de-dupes case-insensitively without adding a second entry', () => {
    const first = addProcessName('curl.exe')
    const second = addProcessName('CURL.EXE')
    expect(second.id).toBe(first.id)
    expect(storeData.splitTunnelApps).toHaveLength(1)
  })

  it('re-arms an existing entry that was set to none back to direct', () => {
    addProcessName('git')
    // Simulate the user having toggled it off.
    storeData.splitTunnelApps[0].rule = 'none'
    const again = addProcessName('git')
    expect(again.rule).toBe('direct')
    expect(storeData.splitTunnelApps[0].rule).toBe('direct')
  })

  it('throws on invalid input', () => {
    expect(() => addProcessName('')).toThrow()
    expect(() => addProcessName('bad name')).toThrow()
  })
})
