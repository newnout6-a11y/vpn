import { beforeEach, describe, expect, it, vi } from 'vitest'

const mockExecFile = vi.fn()
const mockExecElevated = vi.fn()
const mockUnlink = vi.fn()
const mockWriteFile = vi.fn()
const mockReadFile = vi.fn()
const mockMkdir = vi.fn()

vi.mock('electron', () => ({
  app: {
    getPath: vi.fn(() => 'C:\\MockProgramData')
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

vi.mock('./admin', () => ({
  execElevated: (...args: any[]) => mockExecElevated(...args)
}))

vi.mock('fs/promises', () => {
  const fns = {
    mkdir: (...args: any[]) => mockMkdir(...args),
    readFile: (...args: any[]) => mockReadFile(...args),
    writeFile: (...args: any[]) => mockWriteFile(...args),
    unlink: (...args: any[]) => mockUnlink(...args)
  }
  return {
    ...fns,
    default: fns
  }
})

describe('locationPrivacy module', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockMkdir.mockResolvedValue(undefined)
    mockWriteFile.mockResolvedValue(undefined)
    mockUnlink.mockResolvedValue(undefined)
  })

  it('detects when location is allowed/default', async () => {
    mockExecFile.mockImplementation((file: string, args: string[], _opts: any, cb: any) => {
      // simulate reg query not finding deny/disabled
      cb(new Error('The system was unable to find the specified registry key or value'), null)
    })

    const { getLocationPrivacyStatus } = await import('./locationPrivacy')
    const status = await getLocationPrivacyStatus()

    expect(status.userDenied).toBe(false)
    expect(status.policyDisabled).toBe(false)
    expect(status.applied).toBe(false)
  })

  it('detects when user has denied location in HKCU', async () => {
    mockExecFile.mockImplementation((file: string, args: string[], _opts: any, cb: any) => {
      if (args[0] === 'query' && args[1].includes('ConsentStore\\location')) {
        cb(null, { stdout: '    Value    REG_SZ    Deny\r\n', stderr: '' })
      } else {
        cb(new Error('not found'), null)
      }
    })

    const { getLocationPrivacyStatus } = await import('./locationPrivacy')
    const status = await getLocationPrivacyStatus()

    expect(status.userDenied).toBe(true)
    expect(status.applied).toBe(true)
  })

  it('applies location privacy by creating backup, setting HKCU and HKLM policies', async () => {
    mockExecFile.mockImplementation((file: string, args: string[], _opts: any, cb: any) => {
      cb(null, { stdout: '', stderr: '' })
    })
    mockExecElevated.mockResolvedValue({ stdout: '', stderr: '' })

    const { applyLocationPrivacy } = await import('./locationPrivacy')
    await applyLocationPrivacy()

    expect(mockMkdir).toHaveBeenCalled()
    expect(mockWriteFile).toHaveBeenCalled()
    // reg add for HKCU
    expect(mockExecFile).toHaveBeenCalledWith(
      'reg.exe',
      expect.arrayContaining(['add', expect.stringContaining('ConsentStore\\location'), '/d', 'Deny']),
      expect.any(Object),
      expect.any(Function)
    )
    // execElevated for HKLM
    expect(mockExecElevated).toHaveBeenCalledWith(
      expect.stringContaining('DisableLocation'),
      expect.objectContaining({ timeout: 30000 })
    )
  })

  it('rolls back location privacy and cleans up manifest', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({
      hkcuBackup: 'C:\\MockProgramData\\hkcu.reg',
      hklmBackup: 'C:\\MockProgramData\\hklm.reg',
      createdAt: Date.now()
    }))
    mockExecFile.mockImplementation((file: string, args: string[], _opts: any, cb: any) => {
      cb(null, { stdout: '', stderr: '' })
    })
    mockExecElevated.mockResolvedValue({ stdout: '', stderr: '' })

    const { rollbackLocationPrivacy } = await import('./locationPrivacy')
    await rollbackLocationPrivacy()

    // reg import for HKCU
    expect(mockExecFile).toHaveBeenCalledWith(
      'reg.exe',
      expect.arrayContaining(['import', 'C:\\MockProgramData\\hkcu.reg']),
      expect.any(Object),
      expect.any(Function)
    )
    // reg import for HKLM
    expect(mockExecElevated).toHaveBeenCalledWith(
      expect.stringContaining('reg import "C:\\MockProgramData\\hklm.reg"'),
      expect.any(Object)
    )
    // manifest cleaned up
    expect(mockUnlink).toHaveBeenCalledWith(
      expect.stringContaining('latest-location-backup.json')
    )
  })

  it('aborts and throws without modifying HKLM if HKLM backup fails', async () => {
    mockExecFile.mockImplementation((file: string, args: string[], _opts: any, cb: any) => {
      // simulate key exists on query, but export fails on HKLM
      if (args[0] === 'query') {
        cb(null, { stdout: 'key exists', stderr: '' })
      } else if (args[0] === 'export' && args[1].includes('LocationAndSensors')) {
        cb(new Error('export failed: access denied'), null)
      } else {
        cb(null, { stdout: '', stderr: '' })
      }
    })

    const { applyLocationPrivacy } = await import('./locationPrivacy')
    await expect(applyLocationPrivacy()).rejects.toThrow('Не удалось создать backup HKLM')

    // execElevated must NOT have been called
    expect(mockExecElevated).not.toHaveBeenCalled()
  })
})
