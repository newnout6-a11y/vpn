import { beforeEach, describe, expect, it, vi } from 'vitest'

const mockExecFile = vi.fn()
const mockExec = vi.fn()
const mockSudoExec = vi.fn()

vi.mock('child_process', () => ({
  default: {
    execFile: (file: string, args: string[], options: any, cb?: any) => {
      if (typeof options === 'function') {
        cb = options
        options = {}
      }
      return mockExecFile(file, args, options, cb)
    },
    exec: (cmd: string, options: any, cb?: any) => {
      if (typeof options === 'function') {
        cb = options
        options = {}
      }
      return mockExec(cmd, options, cb)
    }
  },
  execFile: (file: string, args: string[], options: any, cb?: any) => {
    if (typeof options === 'function') {
      cb = options
      options = {}
    }
    return mockExecFile(file, args, options, cb)
  },
  exec: (cmd: string, options: any, cb?: any) => {
    if (typeof options === 'function') {
      cb = options
      options = {}
    }
    return mockExec(cmd, options, cb)
  }
}))

vi.mock('sudo-prompt', () => ({
  default: {
    exec: (cmd: string, opts: any, cb: any) => mockSudoExec(cmd, opts, cb)
  }
}))

describe('admin module', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
  })

  // AT-03-007 / F-033: generated recovery commands bypass the shell boundary.
  it('runs long generated PowerShell directly when already elevated', async () => {
    const { execElevated, clearElevatedCache } = await import('./admin')
    clearElevatedCache()
    mockExecFile.mockImplementationOnce((_file: string, _args: string[], _opts: any, cb: any) => {
      cb(null, { stdout: 'true', stderr: '' })
    })
    mockExecFile.mockImplementationOnce((_file: string, _args: string[], _opts: any, cb: any) => {
      cb(null, { stdout: 'RECOVERY_OK', stderr: '' })
    })
    const payload = Buffer.from("Write-Output 'RECOVERY_OK'\n#" + 'x'.repeat(5000), 'utf16le').toString('base64')
    const command = `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ${payload}`
    expect(command.length).toBeGreaterThan(8191)
    expect((await execElevated(command, { timeout: 12345, maxBuffer: 45678 })).stdout).toBe('RECOVERY_OK')
    expect(mockExecFile).toHaveBeenLastCalledWith('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', payload
    ], expect.objectContaining({ timeout: 12345, maxBuffer: 45678, windowsHide: true }), expect.any(Function))
    expect(mockExec).not.toHaveBeenCalled()
    expect(mockSudoExec).not.toHaveBeenCalled()
  })

  it('does not reinterpret a shell suffix as PowerShell arguments', async () => {
    const { execElevated, clearElevatedCache } = await import('./admin')
    clearElevatedCache()
    mockExecFile.mockImplementationOnce((_file: string, _args: string[], _opts: any, cb: any) => cb(null, { stdout: 'true', stderr: '' }))
    mockExec.mockImplementationOnce((_command: string, _opts: any, cb: any) => cb(null, { stdout: '', stderr: '' }))
    const command = 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand QQ== & echo tail'
    await execElevated(command)
    expect(mockExec).toHaveBeenCalledWith(command, expect.any(Object), expect.any(Function))
    expect(mockExecFile).toHaveBeenCalledTimes(1)
  })

  it('returns false immediately on non-win32 platforms', async () => {
    Object.defineProperty(process, 'platform', { value: 'darwin', configurable: true })
    const { isProcessElevated, clearElevatedCache } = await import('./admin')
    clearElevatedCache()

    const result = await isProcessElevated()
    expect(result).toBe(false)
    expect(mockExecFile).not.toHaveBeenCalled()
  })

  it('detects elevation from fast net session check and caches result', async () => {
    const { isProcessElevated, clearElevatedCache } = await import('./admin')
    clearElevatedCache()

    mockExecFile.mockImplementationOnce((file: string, _args: string[], _opts: any, cb: any) => {
      expect(file).toBe('cmd.exe')
      cb(null, { stdout: 'true\r\n', stderr: '' })
    })

    const result1 = await isProcessElevated()
    expect(result1).toBe(true)

    // Second call should hit the cache without calling execFile again
    const result2 = await isProcessElevated()
    expect(result2).toBe(true)
    expect(mockExecFile).toHaveBeenCalledTimes(1)
  })

  it('falls back to PowerShell check if fast net session fails', async () => {
    const { isProcessElevated, clearElevatedCache } = await import('./admin')
    clearElevatedCache()

    // Fast check fails
    mockExecFile.mockImplementationOnce((_file: string, _args: string[], _opts: any, cb: any) => {
      cb(new Error('Access denied'), null)
    })
    // PS check succeeds
    mockExecFile.mockImplementationOnce((file: string, _args: string[], _opts: any, cb: any) => {
      expect(file).toBe('powershell.exe')
      cb(null, { stdout: 'True\r\n', stderr: '' })
    })

    const result = await isProcessElevated()
    expect(result).toBe(true)
    expect(mockExecFile).toHaveBeenCalledTimes(2)
  })

  it('deduplicates concurrent in-flight calls to isProcessElevated', async () => {
    const { isProcessElevated, clearElevatedCache } = await import('./admin')
    clearElevatedCache()

    let resolveCmd: any
    mockExecFile.mockImplementationOnce((_file: string, _args: string[], _opts: any, cb: any) => {
      resolveCmd = () => cb(null, { stdout: 'true\r\n', stderr: '' })
    })

    const p1 = isProcessElevated()
    const p2 = isProcessElevated()
    const p3 = isProcessElevated()

    resolveCmd()
    const [r1, r2, r3] = await Promise.all([p1, p2, p3])
    expect(r1).toBe(true)
    expect(r2).toBe(true)
    expect(r3).toBe(true)
    expect(mockExecFile).toHaveBeenCalledTimes(1)
  })

  it('executes via normal exec when process is already elevated', async () => {
    const { isProcessElevated, execElevated, clearElevatedCache } = await import('./admin')
    clearElevatedCache()

    mockExecFile.mockImplementationOnce((_file: string, _args: string[], _opts: any, cb: any) => {
      cb(null, { stdout: 'true\r\n', stderr: '' })
    })
    mockExec.mockImplementationOnce((_cmd: string, _opts: any, cb: any) => {
      cb(null, { stdout: 'success', stderr: '' })
    })

    await isProcessElevated()
    const result = await execElevated('netsh advfirewall show allprofiles')
    expect(result.stdout).toBe('success')
    expect(mockExec).toHaveBeenCalledWith(
      'netsh advfirewall show allprofiles',
      expect.objectContaining({ windowsHide: true, encoding: 'utf8' }),
      expect.any(Function)
    )
    expect(mockSudoExec).not.toHaveBeenCalled()
  })
})
