import { describe, it, expect, vi, beforeEach } from 'vitest'
import { parseProxyAddr, androidStudio } from './androidStudio'

const mockReadFile = vi.fn()
const mockWriteFile = vi.fn()
const mockMkdir = vi.fn()
const mockStat = vi.fn()
const mockReaddir = vi.fn()
const mockUnlink = vi.fn()

vi.mock('fs/promises', () => {
  const fns = {
    readFile: (...args: any[]) => mockReadFile(...args),
    writeFile: (...args: any[]) => mockWriteFile(...args),
    mkdir: (...args: any[]) => mockMkdir(...args),
    stat: (...args: any[]) => mockStat(...args),
    readdir: (...args: any[]) => mockReaddir(...args),
    unlink: (...args: any[]) => mockUnlink(...args)
  }
  return {
    ...fns,
    default: fns
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
      expect(parseProxyAddr('localhost:1080junk')).toBeNull()
      expect(parseProxyAddr('localhost:1.5')).toBeNull()
      expect(parseProxyAddr('[]:1080')).toBeNull()
      expect(parseProxyAddr('')).toBeNull()
    })
  })

  describe('apply & backup preservation', () => {
    beforeEach(() => {
      vi.clearAllMocks()
      mockMkdir.mockResolvedValue(undefined)
      mockReaddir.mockResolvedValue([])
    })

    it('returns false immediately on invalid proxy address', async () => {
      const res = await androidStudio.apply('invalid-address')
      expect(res).toBe(false)
    })

    it('does not overwrite existing backup on repeated apply', async () => {
      mockReaddir.mockResolvedValue(['AndroidStudio2024.1'] as any)
      // File exists
      mockReadFile.mockResolvedValue('<application></application>')
      // Backup already exists!
      mockStat.mockResolvedValue({} as any)
      mockWriteFile.mockResolvedValue(undefined)

      const res = await androidStudio.apply('127.0.0.1:1080', 'socks5')
      expect(res).toBe(true)

      // Verify that writeFile was NOT called for .vpn-backup
      const backupCalls = mockWriteFile.mock.calls.filter((call) => String(call[0]).endsWith('.vpn-backup'))
      expect(backupCalls.length).toBe(0)
    })

    it('leaves proxy disabled after apply then rollback when other.xml was initially absent', async () => {
      const files: Record<string, string> = {}
      mockReaddir.mockResolvedValue(['AndroidStudio2024.1'] as any)
      mockMkdir.mockResolvedValue(undefined)
      mockReadFile.mockImplementation(async (path: any) => {
        const val = files[String(path)]
        if (val === undefined) {
          const err = new Error('ENOENT')
          ;(err as any).code = 'ENOENT'
          throw err
        }
        return val as any
      })
      mockWriteFile.mockImplementation(async (path: any, data: any) => {
        files[String(path)] = String(data)
      })
      mockStat.mockImplementation(async (path: any) => {
        if (files[String(path)] === undefined) {
          const err = new Error('ENOENT')
          ;(err as any).code = 'ENOENT'
          throw err
        }
        return {} as any
      })
      mockUnlink.mockImplementation(async (path: any) => {
        delete files[String(path)]
      })

      expect(await androidStudio.apply('127.0.0.1:1080')).toBe(true)
      expect(await androidStudio.isApplied()).toBe(true)
      expect(await androidStudio.apply('127.0.0.1:8080', 'http')).toBe(true)
      expect(Object.keys(files).filter(p => p.endsWith('.vpn-backup'))).toEqual([])

      expect(await androidStudio.rollback()).toBe(true)
      expect(await androidStudio.isApplied()).toBe(false)
    })
  })
})

it('preserves Android restore backup and reports failure when write fails', async () => {
  vi.clearAllMocks()
  mockReaddir.mockResolvedValue(['AndroidStudio2024.1'])
  mockReadFile.mockImplementation(async (path: string) => {
    if (path.endsWith('.vpn-backup')) return 'original settings'
    throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
  })
  mockWriteFile.mockRejectedValue(new Error('EACCES'))
  expect(await androidStudio.rollback()).toBe(false)
  expect(mockUnlink).not.toHaveBeenCalled()
})
it('does not touch unowned Android proxy configuration', async () => {
  vi.clearAllMocks()
  mockReaddir.mockResolvedValue(['AndroidStudio2024.1'])
  mockReadFile.mockRejectedValue(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }))
  expect(await androidStudio.rollback()).toBe(true)
  expect(mockWriteFile).not.toHaveBeenCalled()
  expect(mockUnlink).not.toHaveBeenCalled()
})
