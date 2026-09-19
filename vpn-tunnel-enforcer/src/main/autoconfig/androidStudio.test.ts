import { describe, it, expect, vi, beforeEach } from 'vitest'
import { parseProxyAddr, androidStudio } from './androidStudio'
import * as fsPromises from 'fs/promises'

vi.mock('fs/promises', async () => {
  const actual = await vi.importActual<typeof fsPromises>('fs/promises')
  return {
    ...actual,
    readFile: vi.fn(),
    writeFile: vi.fn(),
    mkdir: vi.fn(),
    stat: vi.fn(),
    readdir: vi.fn(),
    unlink: vi.fn()
  }
})

describe('androidStudio autoconfig', () => {
  describe('parseProxyAddr', () => {
    it('parses standard IPv4 and hostname with port', () => {
      expect(parseProxyAddr('127.0.0.1:1080')).toEqual({ host: '127.0.0.1', port: '1080' })
      expect(parseProxyAddr('localhost:8080')).toEqual({ host: 'localhost', port: '8080' })
    })

    it('parses bracketed IPv6 with port', () => {
      expect(parseProxyAddr('[::1]:10808')).toEqual({ host: '::1', port: '10808' })
      expect(parseProxyAddr('[2001:db8::1]:8080')).toEqual({ host: '2001:db8::1', port: '8080' })
    })

    it('rejects unbracketed IPv6 or missing/invalid ports', () => {
      expect(parseProxyAddr('::1')).toBeNull()
      expect(parseProxyAddr('2001:db8::1')).toBeNull()
      expect(parseProxyAddr('127.0.0.1')).toBeNull()
      expect(parseProxyAddr('127.0.0.1:0')).toBeNull()
      expect(parseProxyAddr('127.0.0.1:70000')).toBeNull()
      expect(parseProxyAddr('127.0.0.1:abc')).toBeNull()
      expect(parseProxyAddr('')).toBeNull()
    })
  })

  describe('apply & backup preservation', () => {
    beforeEach(() => {
      vi.clearAllMocks()
    })

    it('returns false immediately on invalid proxy address', async () => {
      const res = await androidStudio.apply('invalid-address')
      expect(res).toBe(false)
    })

    it('does not overwrite existing backup on repeated apply', async () => {
      const mockReaddir = vi.mocked(fsPromises.readdir)
      const mockStat = vi.mocked(fsPromises.stat)
      const mockReadFile = vi.mocked(fsPromises.readFile)
      const mockWriteFile = vi.mocked(fsPromises.writeFile)

      mockReaddir.mockResolvedValue(['AndroidStudio2024.1'] as any)
      // File exists
      mockReadFile.mockResolvedValue('<application></application>')
      // Backup already exists!
      mockStat.mockResolvedValue({} as any)
      mockWriteFile.mockResolvedValue(undefined)

      const res = await androidStudio.apply('127.0.0.1:1080', 'socks5')
      expect(res).toBe(true)

      // Verify that writeFile was NOT called for .vpn-backup
      const backupCalls = mockWriteFile.mock.calls.filter(call => String(call[0]).endsWith('.vpn-backup'))
      expect(backupCalls.length).toBe(0)
    })
  })
})
