// AT-02-001: stale records cannot block startup or authorize stopping foreign processes.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { cleanupManagedChildPidFile } from './managedChildProcess'
import * as fsPromises from 'fs/promises'

const boundary = vi.hoisted(() => ({ execFile: vi.fn() }))
vi.mock('child_process', () => ({ execFile: boundary.execFile }))
const platform = Object.getOwnPropertyDescriptor(process, 'platform')!
const entry = { pid: 1234, owner: 'my-owner', exePath: 'C:\\runtime\\xray.exe', configPath: 'C:\\runtime\\xray-a.json', createdAt: 1 }

vi.mock('fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof fsPromises>()
  const readFile = vi.fn()
  const rm = vi.fn()
  return {
    ...actual,
    default: { ...actual, readFile, rm },
    readFile,
    rm
  }
})

describe('cleanupManagedChildPidFile', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    Object.defineProperty(process, 'platform', { value: 'win32' })
  })
  afterEach(() => { Object.defineProperty(process, 'platform', platform) })

  it.each(['missing', 'mismatch', 'stopped'])('removes a confirmed %s record so a later startup can proceed (AT-02-001)', async outcome => {
    vi.mocked(fsPromises.readFile).mockResolvedValue(JSON.stringify(entry))
    boundary.execFile.mockImplementation((_file, _args, _options, callback) => callback(null, outcome, ''))
    const log = vi.fn()
    expect(await cleanupManagedChildPidFile('/path/to/child.pid', 'my-owner', log)).toBe(true)
    expect(fsPromises.rm).toHaveBeenCalledExactlyOnceWith('/path/to/child.pid', { force: true })
    const [file, args, options] = boundary.execFile.mock.calls[0]
    expect(file).toBe('powershell.exe')
    expect(args).toHaveLength(5)
    expect(args[4]).toContain(`-TargetPid 1234 -ExePath '${entry.exePath}' -ConfigPath '${entry.configPath}'`)
    expect(options).toEqual({ windowsHide: true, timeout: 5000 })
    if (outcome !== 'stopped') expect(log).toHaveBeenCalledWith('managed child stale pidfile removed', expect.objectContaining({ outcome }))
  })

  it.each(['unconfirmed', 'missing extra output', ''])('preserves the record when the ownership response is %j (AT-02-001)', async stdout => {
    vi.mocked(fsPromises.readFile).mockResolvedValue(JSON.stringify(entry))
    boundary.execFile.mockImplementation((_file, _args, _options, callback) => callback(null, stdout, ''))
    expect(await cleanupManagedChildPidFile('/path/to/child.pid', 'my-owner')).toBe(false)
    expect(fsPromises.rm).not.toHaveBeenCalled()
  })

  it.each(['identity query failed', 'stop failed', 'ETIMEDOUT', 'EACCES'])('keeps cleanup unconfirmed after %s (AT-02-001)', async message => {
    vi.mocked(fsPromises.readFile).mockResolvedValue(JSON.stringify(entry))
    boundary.execFile.mockImplementation((_file, _args, _options, callback) => callback(new Error(message), 'missing', ''))
    expect(await cleanupManagedChildPidFile('/path/to/child.pid', 'my-owner')).toBe(false)
    expect(fsPromises.rm).not.toHaveBeenCalled()
  })

  it('does not confirm stale cleanup when the record cannot be removed', async () => {
    vi.mocked(fsPromises.readFile).mockResolvedValue(JSON.stringify(entry))
    vi.mocked(fsPromises.rm).mockRejectedValue(new Error('record locked'))
    boundary.execFile.mockImplementation((_file, _args, _options, callback) => callback(null, 'mismatch', ''))
    expect(await cleanupManagedChildPidFile('/path/to/child.pid', 'my-owner')).toBe(false)
  })

  it('does not query or stop a process without any recorded identity', async () => {
    vi.mocked(fsPromises.readFile).mockResolvedValue(JSON.stringify({ ...entry, exePath: undefined, configPath: undefined }))
    expect(await cleanupManagedChildPidFile('/path/to/child.pid', 'my-owner')).toBe(false)
    expect(boundary.execFile).not.toHaveBeenCalled()
    expect(fsPromises.rm).not.toHaveBeenCalled()
  })

  it.skipIf(platform.value !== 'win32').each([
    ['reused PID', "@{ExecutablePath='C:\\foreign\\xray.exe';CommandLine='foreign'}", 'mismatch'],
    ['same executable, another config', "@{ExecutablePath='C:\\runtime\\xray.exe';CommandLine='xray run -c C:\\runtime\\other.json'}", 'mismatch'],
    ['config suffix', "@{ExecutablePath='C:\\runtime\\xray.exe';CommandLine='xray run -c C:\\runtime\\xray-a.json.backup'}", 'mismatch'],
    ['config prefix', "@{ExecutablePath='C:\\runtime\\xray.exe';CommandLine='xray run -c prefix-C:\\runtime\\xray-a.json'}", 'mismatch'],
    ['config in another flag', "@{ExecutablePath='C:\\runtime\\xray.exe';CommandLine='xray run --log C:\\runtime\\xray-a.json'}", 'mismatch'],
    ['config in another quoted value', `@{ExecutablePath='C:\\runtime\\xray.exe';CommandLine='xray run --log "-c C:\\runtime\\xray-a.json"'}`, 'mismatch'],
    ['extra argument after config', "@{ExecutablePath='C:\\runtime\\xray.exe';CommandLine='xray run -c C:\\runtime\\xray-a.json --foreign'}", 'mismatch'],
    ['unreadable executable', "@{ExecutablePath=$null;CommandLine='xray -c C:\\runtime\\xray-a.json'}", 'unconfirmed'],
    ['unreadable command line', "@{ExecutablePath='C:\\runtime\\xray.exe';CommandLine=$null}", 'unconfirmed'],
    ['exited PID', '$null', 'missing'],
    ['matching owner', "@{ExecutablePath='C:\\runtime\\xray.exe';CommandLine='xray run -c C:\\runtime\\xray-a.json'}", 'stopped'],
    ['matching quoted owner', `@{ExecutablePath='C:\\runtime\\xray.exe';CommandLine='"C:\\runtime\\xray.exe" run -c "C:\\runtime\\xray-a.json"'}`, 'stopped']
  ])('executes the Windows identity guard for %s without stopping any real process (AT-02-001)', async (_name, processValue, outcome) => {
    vi.mocked(fsPromises.readFile).mockResolvedValue(JSON.stringify(entry))
    boundary.execFile.mockImplementation((_file, _args, _options, callback) => callback(null, 'unconfirmed', ''))
    await cleanupManagedChildPidFile('/path/to/child.pid', 'my-owner')
    const source = boundary.execFile.mock.calls[0][1][4]
    const native = await vi.importActual<typeof import('node:child_process')>('node:child_process')
    const stub = `function Get-CimInstance { param($ClassName,$Filter); if ($Filter -ne 'ProcessId=1234') { throw 'PID not bound' }; ${processValue} }; function Stop-Process { param($Id); ${outcome === 'stopped' ? "if ($Id -ne 1234) { throw 'wrong PID' }" : "throw 'foreign stop attempted'"} }; `
    const command = `${stub}${source}`
    const stdout = native.execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', command],
      { windowsHide: true, encoding: 'utf8', timeout: 5000 })
    expect(stdout.trim()).toBe(outcome)
  }, 10000)

  it.skipIf(platform.value !== 'win32')('binds recorded paths containing quotes and wildcard characters as literals', async () => {
    vi.mocked(fsPromises.readFile).mockResolvedValue(JSON.stringify({ ...entry,
      exePath: "C:\\runtime's\\xray.exe", configPath: "C:\\runtime's\\xray-[a].json" }))
    boundary.execFile.mockImplementation((_file, _args, _options, callback) => callback(null, 'unconfirmed', ''))
    await cleanupManagedChildPidFile('/path/to/child.pid', 'my-owner')
    const native = await vi.importActual<typeof import('node:child_process')>('node:child_process')
    const stub = "function Get-CimInstance { @{ExecutablePath='C:\\runtime''s\\xray.exe';CommandLine='xray run -c C:\\runtime''s\\xray-[a].json'} }; function Stop-Process { param($Id); if ($Id -ne 1234) { throw 'wrong PID' } }; "
    expect(native.execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', stub + boundary.execFile.mock.calls[0][1][4]],
      { windowsHide: true, encoding: 'utf8', timeout: 5000 }).trim()).toBe('stopped')
  }, 10000)

  it.skipIf(platform.value !== 'win32').each([false, true])('requires an exact config token with whitespace, quoted=%s (AT-02-001)', async quoted => {
    vi.mocked(fsPromises.readFile).mockResolvedValue(JSON.stringify({ ...entry,
      exePath: 'C:\\runtime folder\\xray.exe', configPath: 'C:\\runtime folder\\xray-a.json' }))
    boundary.execFile.mockImplementation((_file, _args, _options, callback) => callback(null, 'unconfirmed', ''))
    await cleanupManagedChildPidFile('/path/to/child.pid', 'my-owner')
    const native = await vi.importActual<typeof import('node:child_process')>('node:child_process')
    const configArgument = quoted ? '"C:\\runtime folder\\xray-a.json"' : 'C:\\runtime folder\\xray-a.json'
    const stub = `function Get-CimInstance { @{ExecutablePath='C:\\runtime folder\\xray.exe';CommandLine='"C:\\runtime folder\\xray.exe" run -c ${configArgument}'} }; function Stop-Process { ${quoted ? '' : "throw 'foreign stop attempted'"} }; `
    expect(native.execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', stub + boundary.execFile.mock.calls[0][1][4]],
      { windowsHide: true, encoding: 'utf8', timeout: 5000 }).trim()).toBe(quoted ? 'stopped' : 'mismatch')
  }, 10000)

  it('does not treat an unreadable PID record as absent (AT-02-001)', async () => {
    vi.mocked(fsPromises.readFile).mockRejectedValue(Object.assign(new Error('denied'), { code: 'EACCES' }))
    expect(await cleanupManagedChildPidFile('/path/to/child.pid', 'my-owner')).toBe(false)
    expect(boundary.execFile).not.toHaveBeenCalled()
    expect(fsPromises.rm).not.toHaveBeenCalled()
  })

  it('leaves PID file untouched and returns false when entry belongs to another owner', async () => {
    const mockReadFile = vi.mocked(fsPromises.readFile)
    const mockRm = vi.mocked(fsPromises.rm)
    const logSpy = vi.fn()

    mockReadFile.mockResolvedValue(JSON.stringify({
      pid: 1234,
      owner: 'other-app-instance',
      role: 'sidecar',
      startedAt: Date.now()
    }))

    const result = await cleanupManagedChildPidFile('/path/to/child.pid', 'my-owner', logSpy)

    expect(result).toBe(false)
    // Must NOT delete the other owner's pid file!
    expect(mockRm).not.toHaveBeenCalled()
    expect(logSpy).toHaveBeenCalledWith(
      expect.stringContaining('belongs to different owner'),
      expect.objectContaining({ expectedOwner: 'my-owner', actualOwner: 'other-app-instance' })
    )
  })

  it('removes corrupted/unparseable PID file and returns true', async () => {
    const mockReadFile = vi.mocked(fsPromises.readFile)
    const mockRm = vi.mocked(fsPromises.rm)

    mockReadFile.mockResolvedValue('not-valid-json{{{')
    mockRm.mockResolvedValue(undefined as any)

    const result = await cleanupManagedChildPidFile('/path/to/child.pid', 'my-owner')

    expect(result).toBe(true)
    expect(mockRm).toHaveBeenCalledWith('/path/to/child.pid', { force: true })
  })

  it('returns true when PID file does not exist', async () => {
    const mockReadFile = vi.mocked(fsPromises.readFile)
    const mockRm = vi.mocked(fsPromises.rm)

    mockReadFile.mockRejectedValue(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }))

    const result = await cleanupManagedChildPidFile('/path/to/child.pid', 'my-owner')

    expect(result).toBe(true)
    expect(mockRm).not.toHaveBeenCalled()
  })
})
