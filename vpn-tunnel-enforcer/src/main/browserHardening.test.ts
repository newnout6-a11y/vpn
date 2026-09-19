import { beforeEach, describe, expect, it, vi } from 'vitest'

const mockExecFile = vi.fn()
const mockExistsSync = vi.fn()
const mockReadFile = vi.fn()
const mockWriteFile = vi.fn()
const mockMkdir = vi.fn()
const mockCopyFile = vi.fn()
const mockUnlink = vi.fn()
const mockReaddir = vi.fn()

vi.mock('electron', () => ({
  app: {
    getPath: vi.fn((name: string) => (name === 'userData' ? 'C:\\MockUserData' : 'C:\\MockHome'))
  }
}))

vi.mock('child_process', () => ({
  default: {
    execFile: (file: string, args: string[], options: any, cb?: any) => {
      if (typeof options === 'function') {
        cb = options
        options = {}
      }
      return mockExecFile(file, args, options, cb)
    }
  },
  execFile: (file: string, args: string[], options: any, cb?: any) => {
    if (typeof options === 'function') {
      cb = options
      options = {}
    }
    return mockExecFile(file, args, options, cb)
  }
}))

vi.mock('fs', () => {
  const fns = {
    existsSync: (...args: any[]) => mockExistsSync(...args)
  }
  return {
    ...fns,
    default: fns
  }
})

vi.mock('fs/promises', () => {
  const fns = {
    mkdir: (...args: any[]) => mockMkdir(...args),
    readFile: (...args: any[]) => mockReadFile(...args),
    writeFile: (...args: any[]) => mockWriteFile(...args),
    unlink: (...args: any[]) => mockUnlink(...args),
    copyFile: (...args: any[]) => mockCopyFile(...args),
    readdir: (...args: any[]) => mockReaddir(...args)
  }
  return {
    ...fns,
    default: fns
  }
})

vi.mock('./appLogger', () => ({
  logEvent: vi.fn()
}))

describe('browserHardening module', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
    mockMkdir.mockResolvedValue(undefined)
    mockWriteFile.mockResolvedValue(undefined)
    mockUnlink.mockResolvedValue(undefined)
    mockCopyFile.mockResolvedValue(undefined)
    mockReaddir.mockResolvedValue([])
    mockExistsSync.mockReturnValue(false)
  })

  it('returns skipped message on non-Windows', async () => {
    Object.defineProperty(process, 'platform', { value: 'linux', configurable: true })
    const { applyBrowserLeakProtection, rollbackBrowserLeakProtection } = await import('./browserHardening')

    const applyRes = await applyBrowserLeakProtection()
    expect(applyRes.success).toBe(false)
    expect(applyRes.message).toContain('только на Windows')

    const rollbackRes = await rollbackBrowserLeakProtection()
    expect(rollbackRes.success).toBe(false)
  })

  it('handles case where no browser profiles exist', async () => {
    const { applyBrowserLeakProtection } = await import('./browserHardening')

    const res = await applyBrowserLeakProtection()
    expect(res.success).toBe(true)
    expect(res.changed).toBe(false)
    expect(res.message).toContain('не найдены')
  })

  it('applies WebRTC policy when Chromium profile is detected', async () => {
    mockExistsSync.mockImplementation((p: string) => {
      return typeof p === 'string' && p.includes('Google\\Chrome\\User Data')
    })
    let queryCount = 0
    mockExecFile.mockImplementation((file: string, args: string[], _opts: any, cb: any) => {
      if (args[0] === 'query') {
        queryCount++
        if (queryCount <= 2) {
          cb(new Error('not found'), null)
        } else {
          cb(null, { stdout: '    WebRtcIPHandlingPolicy    REG_SZ    disable_non_proxied_udp\r\n', stderr: '' })
        }
      } else {
        cb(null, { stdout: '', stderr: '' })
      }
    })

    const { applyBrowserLeakProtection } = await import('./browserHardening')
    const res = await applyBrowserLeakProtection()

    expect(res.success).toBe(true)
    expect(mockExecFile).toHaveBeenCalledWith(
      'reg.exe',
      expect.arrayContaining(['add', 'HKLM\\Software\\Policies\\Google\\Chrome']),
      expect.any(Object),
      expect.any(Function)
    )
  })

  it('returns success: false when policy write is not confirmed by read-back', async () => {
    mockExistsSync.mockImplementation((p: string) => {
      return typeof p === 'string' && p.includes('Google\\Chrome\\User Data')
    })
    mockExecFile.mockImplementation((file: string, args: string[], _opts: any, cb: any) => {
      if (args[0] === 'query') {
        // Always return not found, simulating read-back failure
        cb(new Error('not found'), null)
      } else {
        cb(null, { stdout: '', stderr: '' })
      }
    })

    const { applyBrowserLeakProtection } = await import('./browserHardening')
    const res = await applyBrowserLeakProtection()

    expect(res.success).toBe(false)
    expect(res.changed).toBe(false)
    expect(res.message).toContain('не была подтверждена при обратном чтении')
  })

  it('rolls back browser hardening from manifest', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({
      createdAt: 123456789,
      registryBackups: [
        { key: 'HKLM\\Software\\Policies\\Google\\Chrome', backupPath: 'C:\\MockUserData\\chrome.reg' }
      ],
      fileBackups: [
        { path: 'C:\\MockUserData\\Preferences', backupPath: 'C:\\MockUserData\\Preferences.bak', existed: true }
      ]
    }))
    mockExistsSync.mockReturnValue(true)
    mockExecFile.mockImplementation((_file: string, _args: string[], _opts: any, cb: any) => {
      cb(null, { stdout: '', stderr: '' })
    })

    const { rollbackBrowserLeakProtection } = await import('./browserHardening')
    const res = await rollbackBrowserLeakProtection()

    expect(res.success).toBe(true)
    expect(res.changed).toBe(true)
    // imports registry backup
    expect(mockExecFile).toHaveBeenCalledWith(
      'reg.exe',
      ['import', 'C:\\MockUserData\\chrome.reg'],
      expect.any(Object),
      expect.any(Function)
    )
    // copies file backup
    expect(mockCopyFile).toHaveBeenCalledWith('C:\\MockUserData\\Preferences.bak', 'C:\\MockUserData\\Preferences')
    // unlinks manifest
    expect(mockUnlink).toHaveBeenCalledWith(expect.stringContaining('latest-browser-hardening.json'))
  })
})
