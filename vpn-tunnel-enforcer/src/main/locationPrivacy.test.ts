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
    mockReadFile.mockRejectedValue(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }))
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

    const manifest = await mockReadFile()
    mockReadFile.mockImplementation(async (path: string) => path.endsWith('.reg') ? 'Windows Registry Editor Version 5.00\r\n' : manifest)
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
    mockExecElevated.mockRejectedValue(new Error('export failed: access denied (elevated)'))

    const { applyLocationPrivacy } = await import('./locationPrivacy')
    await expect(applyLocationPrivacy()).rejects.toThrow('Не удалось создать backup HKLM')

    // execElevated must NOT have been called to add/modify registry
    expect(mockExecElevated).not.toHaveBeenCalledWith(expect.stringContaining('reg add'), expect.any(Object))
  })

  it('aborts and does not modify registry when HKLM query fails with Access Denied', async () => {
    mockExecFile.mockImplementation((file: string, args: string[], _opts: any, cb: any) => {
      if (args[0] === 'query' && args[1].includes('LocationAndSensors')) {
        cb(new Error('Access is denied'), null)
      } else {
        cb(null, { stdout: '', stderr: '' })
      }
    })
    mockExecElevated.mockRejectedValue(new Error('Access is denied (elevated)'))

    const { applyLocationPrivacy } = await import('./locationPrivacy')
    await expect(applyLocationPrivacy()).rejects.toThrow('Не удалось проверить состояние реестра HKLM')
    expect(mockExecElevated).not.toHaveBeenCalledWith(expect.stringContaining('reg add'), expect.any(Object))
  })

  it('preserves rollback manifest when registry import fails', async () => {
    mockReadFile.mockResolvedValue(
      JSON.stringify({
        hkcuBackup: 'C:\\MockProgramData\\old-cu.reg',
        hklmBackup: 'C:\\MockProgramData\\old-lm.reg',
        hkcuKeyExisted: true,
        hklmKeyExisted: true
      })
    )
    mockExecFile.mockImplementation((file: string, _args: string[], _opts: any, cb: any) => {
      cb(new Error('Import failed'), null)
    })
    mockExecElevated.mockRejectedValue(new Error('Elevation denied'))

    const { rollbackLocationPrivacy } = await import('./locationPrivacy')
    await expect(rollbackLocationPrivacy()).rejects.toThrow('Не удалось полностью восстановить настройки реестра')
    expect(mockUnlink).not.toHaveBeenCalledWith(expect.stringContaining('latest-location-backup.json'))
  })
  it('deletes values absent in original key without deleting unrelated values', async () => {
    const snapshot = { hkcuBackup: 'cu.reg', hkcuKeyExisted: true, hklmBackup: 'lm.reg', hklmKeyExisted: true }
    mockReadFile.mockImplementation(async (path: string) => path.endsWith('.reg')
      ? 'Windows Registry Editor Version 5.00\r\n[HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors]\r\n"Unrelated"=dword:00000001\r\n'
      : JSON.stringify(snapshot))
    mockExecFile.mockImplementation((_f: string, _a: string[], _o: any, cb: any) => cb(null, { stdout: '', stderr: '' }))
    mockExecElevated.mockResolvedValue({ stdout: '', stderr: '' })
    const { rollbackLocationPrivacy } = await import('./locationPrivacy')
    await rollbackLocationPrivacy()
    const deletes = mockExecFile.mock.calls.filter(call => call[1][0] === 'delete').map(call => call[1][3])
    expect(deletes).toEqual(['Value', 'DisableLocation', 'DisableWindowsLocationProvider'])
    expect(mockUnlink).toHaveBeenCalled()
  })
  it('preserves absent-key manifest when value deletion fails', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({ hkcuBackup: null, hkcuKeyExisted: false, hklmBackup: null, hklmKeyExisted: false }))
    mockExecFile.mockImplementation((_f: string, _a: string[], _o: any, cb: any) => cb(new Error('Access denied')))
    mockExecElevated.mockRejectedValue(new Error('Access denied'))
    const { rollbackLocationPrivacy } = await import('./locationPrivacy')
    await expect(rollbackLocationPrivacy()).rejects.toThrow('Резервная копия сохранена')
    expect(mockUnlink).not.toHaveBeenCalled()
  })

})
