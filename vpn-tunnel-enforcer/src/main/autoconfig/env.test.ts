import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { homedir } from 'os'
import { join } from 'path'

const mockExecFile = vi.fn()
vi.mock('child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('child_process')>()
  const customExecFile = (...args: any[]) => {
    const callback = args[args.length - 1]
    if (typeof callback === 'function') {
      const res = mockExecFile(...args.slice(0, -1))
      if (res instanceof Error) {
        callback(res)
      } else {
        callback(null, res ?? { stdout: '', stderr: '' })
      }
    }
  }
  return {
    ...actual,
    default: {
      ...actual,
      execFile: customExecFile
    },
    execFile: customExecFile
  }
})

const mockFs: Record<string, string> = {}
vi.mock('fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof import('fs/promises')>()
  const customMethods = {
    readFile: vi.fn(async (path: string) => {
      if (mockFs[path] !== undefined) return mockFs[path]
      const err = new Error(`ENOENT: no such file or directory, open '${path}'`)
      ;(err as any).code = 'ENOENT'
      throw err
    }),
    writeFile: vi.fn(async (path: string, content: string) => {
      mockFs[path] = content
    }),
    mkdir: vi.fn(async () => undefined),
    unlink: vi.fn(async (path: string) => {
      delete mockFs[path]
    })
  }
  return {
    ...actual,
    default: {
      ...actual,
      ...customMethods
    },
    ...customMethods
  }
})

import { env } from './env'

function missingRegistryValue(message = 'The system was unable to find the specified registry key or value.'): Error {
  return Object.assign(new Error(message), { code: 1, stderr: message })
}

describe('env autoconfig backup and rollback', () => {
  const backupFile = join(homedir(), '.vpnte', 'env-proxy-backup.json')

  beforeEach(() => {
    vi.clearAllMocks()
    for (const k of Object.keys(mockFs)) delete mockFs[k]
    delete process.env.HTTP_PROXY
    delete process.env.HTTPS_PROXY
    delete process.env.ALL_PROXY
    delete process.env.NO_PROXY
  })

  afterEach(() => {
    delete process.env.HTTP_PROXY
    delete process.env.HTTPS_PROXY
    delete process.env.ALL_PROXY
    delete process.env.NO_PROXY
  })

  it('exposes scope, warning, and backupPath matching autoconfig contract', () => {
    expect(env.name).toBe('Environment Variables')
    expect(env.scope).toBe('user-global')
    expect(env.warning).toContain('pre-existing variables are backed up and restored on rollback')
    expect(env.backupPath()).toBe(backupFile)
  })

  it('backs up pre-existing user proxy environment variables on first apply', async () => {
    mockExecFile.mockImplementation((cmd: string, args: string[]) => {
      if (cmd === 'reg' && args[0] === 'query') {
        const varName = args[3]
        if (varName === 'HTTP_PROXY') {
          return { stdout: 'HKEY_CURRENT_USER\\Environment\n    HTTP_PROXY    REG_SZ    http://corporate-proxy:8080' }
        }
        if (varName === 'NO_PROXY') {
          return { stdout: 'HKEY_CURRENT_USER\\Environment\n    NO_PROXY    REG_SZ    localhost,internal.corp' }
        }
        return missingRegistryValue()
      }
      return { stdout: '', stderr: '' }
    })

    const ok = await env.apply('127.0.0.1:10808', 'socks5')
    expect(ok).toBe(true)

    expect(mockFs[backupFile]).toBeDefined()
    const saved = JSON.parse(mockFs[backupFile])
    expect(saved.httpProxy).toBe('http://corporate-proxy:8080')
    expect(saved.httpsProxy).toBeNull()
    expect(saved.allProxy).toBeNull()
    expect(saved.noProxy).toBe('localhost,internal.corp')

    // Current process.env updated to VPNTE proxy
    expect(process.env.HTTP_PROXY).toBe('socks5h://127.0.0.1:10808')
    expect(process.env.NO_PROXY).toBe('localhost,127.0.0.1,::1')
  })

  it('does not overwrite existing backup on repeated apply calls', async () => {
    mockFs[backupFile] = JSON.stringify({
      createdAt: 1000,
      httpProxy: 'http://original-proxy:8080',
      httpsProxy: null,
      allProxy: null,
      noProxy: 'localhost,original.local'
    })

    mockExecFile.mockReturnValue({ stdout: '', stderr: '' })

    const ok = await env.apply('127.0.0.1:10809', 'http')
    expect(ok).toBe(true)

    // Backup is preserved untouched
    const current = JSON.parse(mockFs[backupFile])
    expect(current.createdAt).toBe(1000)
    expect(current.httpProxy).toBe('http://original-proxy:8080')
  })

  it('restores pre-existing variables on rollback and removes the backup file', async () => {
    mockFs[backupFile] = JSON.stringify({
      createdAt: 1000,
      httpProxy: 'http://original-proxy:8080',
      httpsProxy: null,
      allProxy: null,
      noProxy: 'localhost,original.local'
    })

    const executedCommands: Array<{ cmd: string; args: string[] }> = []
    mockExecFile.mockImplementation((cmd: string, args: string[]) => {
      executedCommands.push({ cmd, args })
      return { stdout: '', stderr: '' }
    })

    const ok = await env.rollback()
    expect(ok).toBe(true)

    // HTTP_PROXY and NO_PROXY were restored via setx
    expect(executedCommands).toEqual(
      expect.arrayContaining([
        { cmd: 'setx', args: ['HTTP_PROXY', 'http://original-proxy:8080'] },
        { cmd: 'setx', args: ['NO_PROXY', 'localhost,original.local'] },
        { cmd: 'reg', args: ['delete', 'HKCU\\Environment', '/v', 'HTTPS_PROXY', '/f'] },
        { cmd: 'reg', args: ['delete', 'HKCU\\Environment', '/v', 'ALL_PROXY', '/f'] }
      ])
    )

    // process.env restored
    expect(process.env.HTTP_PROXY).toBe('http://original-proxy:8080')
    expect(process.env.NO_PROXY).toBe('localhost,original.local')
    expect(process.env.HTTPS_PROXY).toBeUndefined()
    expect(process.env.ALL_PROXY).toBeUndefined()

    // Backup file removed
    expect(mockFs[backupFile]).toBeUndefined()
  })

  it('cleanly deletes all variables if backup recorded them as unset (null)', async () => {
    mockFs[backupFile] = JSON.stringify({
      createdAt: 1000,
      httpProxy: null,
      httpsProxy: null,
      allProxy: null,
      noProxy: null
    })

    const executedCommands: Array<{ cmd: string; args: string[] }> = []
    mockExecFile.mockImplementation((cmd: string, args: string[]) => {
      executedCommands.push({ cmd, args })
      return { stdout: '', stderr: '' }
    })

    const ok = await env.rollback()
    expect(ok).toBe(true)

    expect(executedCommands).toEqual(
      expect.arrayContaining([
        { cmd: 'reg', args: ['delete', 'HKCU\\Environment', '/v', 'HTTP_PROXY', '/f'] },
        { cmd: 'reg', args: ['delete', 'HKCU\\Environment', '/v', 'HTTPS_PROXY', '/f'] },
        { cmd: 'reg', args: ['delete', 'HKCU\\Environment', '/v', 'ALL_PROXY', '/f'] },
        { cmd: 'reg', args: ['delete', 'HKCU\\Environment', '/v', 'NO_PROXY', '/f'] }
      ])
    )

    expect(process.env.HTTP_PROXY).toBeUndefined()
    expect(mockFs[backupFile]).toBeUndefined()
  })

  it('triggers compensating rollback if setting an environment variable fails midway', async () => {
    // Simulate pre-existing corporate proxy
    mockFs[backupFile] = JSON.stringify({
      createdAt: 1000,
      httpProxy: 'http://corporate:8080',
      httpsProxy: null,
      allProxy: null,
      noProxy: null
    })

    const rollbackSpy = vi.spyOn(env, 'rollback')

    // First command succeeds, third command (ALL_PROXY) throws
    mockExecFile.mockImplementation((cmd: string, args: string[]) => {
      if (cmd === 'setx' && args[0] === 'ALL_PROXY') {
        return new Error('setx failed: access denied or buffer overflow')
      }
      return { stdout: '', stderr: '' }
    })

    const ok = await env.apply('127.0.0.1:10808', 'socks5')
    expect(ok).toBe(false)
    expect(rollbackSpy).toHaveBeenCalled()
    rollbackSpy.mockRestore()
  })

  it('does NOT delete proxy variables when backup creation fails before any setx', async () => {
    const fs = await import('fs/promises')
    vi.mocked(fs.mkdir).mockRejectedValueOnce(new Error('EACCES backup directory'))
    mockExecFile.mockReturnValue({ stdout: '', stderr: '' })

    const ok = await env.apply('127.0.0.1:10808')
    expect(ok).toBe(false)
    expect(mockExecFile.mock.calls.filter(([cmd]) => cmd === 'setx')).toHaveLength(0)
    const deleted = mockExecFile.mock.calls.filter(([cmd, args]) => cmd === 'reg' && args[0] === 'delete')
    expect(deleted).toHaveLength(0)
  })

  it('reports failed rollback and preserves backup file when restore fails', async () => {
    mockFs[backupFile] = JSON.stringify({
      createdAt: 1000,
      httpProxy: 'http://corp:8080',
      httpsProxy: 'http://corp:8080',
      allProxy: 'http://corp:8080',
      noProxy: 'internal'
    })
    mockExecFile.mockImplementation((cmd: string) => (cmd === 'setx' ? new Error('Access denied') : { stdout: '', stderr: '' }))

    const ok = await env.rollback()
    expect(ok).toBe(false)
    expect(mockFs[backupFile]).toBeDefined()
  })
  it.each(['{}', '{"httpProxy":null,"httpsProxy":null,"allProxy":null}'])(
    'blocks apply and rollback on malformed or partial backup without changing registry: %s', async (backup) => {
      mockFs[backupFile] = backup
      expect(await env.apply('127.0.0.1:1080')).toBe(false)
      expect(await env.rollback()).toBe(false)
      expect(mockExecFile).not.toHaveBeenCalled()
      expect(mockFs[backupFile]).toBe(backup)
    }
  )
  it('blocks apply when reading original environment is denied', async () => {
    mockExecFile.mockReturnValue(new Error('Access denied'))
    expect(await env.apply('127.0.0.1:1080')).toBe(false)
    expect(mockExecFile.mock.calls.every(call => call[0] === 'reg' && call[1][0] === 'query')).toBe(true)
    expect(mockFs[backupFile]).toBeUndefined()
  })

  // AT-11-002 / F-183: unknown environment status must block shutdown, not skip cleanup.
  describe('strict isApplied status', () => {
    it.each([
      '    HTTP_PROXY    REG_SZ    socks5h://127.0.0.1:10808',
      '    HTTP_PROXY    REG_EXPAND_SZ    http://%PROXY_HOST%:8080',
      '    http_proxy    REG_SZ    http://corporate:8080',
      '    HTTP_PROXY    REG_SZ    '
    ])('reports a successfully read value as present, including an empty string: %s', async (valueLine) => {
      mockExecFile.mockReturnValue({ stdout: `HKEY_CURRENT_USER\\Environment\r\n${valueLine}\r\n`, stderr: '' })
      expect(await env.isApplied()).toBe(true)
      expect(mockExecFile).toHaveBeenCalledExactlyOnceWith(
        'reg', ['query', 'HKCU\\Environment', '/v', 'HTTP_PROXY'],
        { windowsHide: true, timeout: 10000, encoding: 'utf8' }
      )
    })

    it.each([
      'The system was unable to find the specified registry key or value.',
      'Не удается найти указанный раздел или параметр реестра.'
    ])('reports false only for confirmed absence: %s', async (message) => {
      mockExecFile.mockReturnValue(missingRegistryValue(message))
      expect(await env.isApplied()).toBe(false)
    })

    it.each([
      Object.assign(new Error('Access denied'), { code: 1, stderr: 'ERROR: Access is denied.' }),
      Object.assign(new Error('reg query timed out'), { code: 'ETIMEDOUT', killed: true, signal: 'SIGTERM' }),
      Object.assign(missingRegistryValue(), { killed: true, signal: 'SIGTERM' }),
      Object.assign(missingRegistryValue(), { code: 'ENOENT' })
    ])('propagates read failures and preserves backup without rollback: %s', async (error) => {
      const backup = JSON.stringify({ createdAt: 1000, httpProxy: 'http://corporate:8080', httpsProxy: null, allProxy: null, noProxy: null })
      mockFs[backupFile] = backup
      mockExecFile.mockReturnValue(error)
      const fs = await import('fs/promises')

      await expect(env.isApplied()).rejects.toBe(error)
      expect(mockFs[backupFile]).toBe(backup)
      expect(fs.writeFile).not.toHaveBeenCalled()
      expect(fs.unlink).not.toHaveBeenCalled()
      expect(mockExecFile).toHaveBeenCalledTimes(1)
      expect(mockExecFile.mock.calls[0].slice(0, 2)).toEqual(['reg', ['query', 'HKCU\\Environment', '/v', 'HTTP_PROXY']])
    })

    it.each([
      '',
      'HKEY_CURRENT_USER\\Environment\r\n',
      '    HTTP_PROXY_OTHER    REG_SZ    http://corporate:8080',
      '    HTTP_PROXY    REG_DWORD    0x1',
      '    HTTP_PROXY    unexpected output'
    ])('rejects unparseable successful output without deleting backup: %s', async (stdout) => {
      mockFs[backupFile] = 'preserve this backup'
      mockExecFile.mockReturnValue({ stdout, stderr: '' })
      const fs = await import('fs/promises')

      await expect(env.isApplied()).rejects.toThrow('Unable to parse registry value HTTP_PROXY')
      expect(mockFs[backupFile]).toBe('preserve this backup')
      expect(fs.writeFile).not.toHaveBeenCalled()
      expect(fs.unlink).not.toHaveBeenCalled()
      expect(mockExecFile).toHaveBeenCalledTimes(1)
    })
  })

  // AT-11-002 / F-183: failed backup reads must precede any environment mutation.
  it.each(['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY'])(
    'blocks apply without partial backup or registry writes when %s cannot be parsed', async (unparseableKey) => {
      mockExecFile.mockImplementation((_cmd: string, args: string[]) => ({
        stdout: args[3] === unparseableKey ? '' : `    ${args[3]}    REG_SZ    http://corporate:8080`,
        stderr: ''
      }))
      const fs = await import('fs/promises')

      expect(await env.apply('127.0.0.1:1080')).toBe(false)
      expect(mockFs[backupFile]).toBeUndefined()
      expect(fs.writeFile).not.toHaveBeenCalled()
      expect(fs.unlink).not.toHaveBeenCalled()
      expect(mockExecFile.mock.calls.every(([cmd, args]) => cmd === 'reg' && args[0] === 'query')).toBe(true)
    }
  )
})
