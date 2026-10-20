import { beforeEach, describe, expect, it, vi } from 'vitest'
import { classifyIpcError, ipcError, IpcFault } from '../shared/ipc-result'
import { currentCorrelationId } from './actionCorrelation'

const boundary = vi.hoisted(() => ({ handlers: new Map<string, (...args: any[]) => Promise<any>>() }))

const mockExecFile = vi.fn()
const mockExistsSync = vi.fn()
const mockReadFile = vi.fn()
const mockWriteFile = vi.fn()
const mockMkdir = vi.fn()
const mockCopyFile = vi.fn()
const mockUnlink = vi.fn()
const mockReaddir = vi.fn()

vi.mock('electron', () => ({
  ipcMain: { handle: (channel: string, handler: any) => boundary.handlers.set(channel, handler) },
  app: {
    getPath: vi.fn((name: string) => (name === 'userData' ? 'C:\\MockUserData' : 'C:\\MockHome'))
  }
}))
import { ipcMain } from 'electron'
import { installTrustedIpcBoundary } from './ipcSecurity'
import { logEvent } from './appLogger'

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
    mockReadFile.mockRejectedValue(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }))
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

describe('Audit remaining hardening result defects', () => {
  it('keeps verified preference fallback successful on repeated apply', async () => {
    vi.clearAllMocks()
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
    let prefs = '{}'
    mockExistsSync.mockImplementation((p: string) => p.includes('Google\\Chrome\\User Data'))
    mockReaddir.mockResolvedValue([{ name: 'Default', isDirectory: () => true }])
    mockMkdir.mockResolvedValue(undefined)
    mockCopyFile.mockResolvedValue(undefined)
    mockReadFile.mockImplementation(async (p: string) => {
      if (p.endsWith('Preferences')) return prefs
      throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
    })
    mockWriteFile.mockImplementation(async (p: string, value: string) => { if(p.endsWith('Preferences')) prefs = value })
    mockExecFile.mockImplementation((_file: string, args: string[], _opts: any, cb: any) => {
      if(args[0] === 'query') cb(new Error('Read-back unavailable'), null)
      else cb(null, { stdout: '', stderr: '' })
    })
    const { applyBrowserLeakProtection } = await import('./browserHardening')
    const first = await applyBrowserLeakProtection()
    const second = await applyBrowserLeakProtection()
    expect(first.success).toBe(true)
    expect(first.details.some(d => d.includes('not confirmed'))).toBe(true)
    expect(second.success).toBe(true)
    expect(second.details.some(d => d.includes('уже защищён'))).toBe(true)
  })
  it('reports failure when Firefox-only write fails', async () => {
    vi.clearAllMocks()
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
    mockExistsSync.mockImplementation((p: string) => p.endsWith('Mozilla\\Firefox\\Profiles'))
    mockReaddir.mockResolvedValue([{ name: 'test.default', isDirectory: () => true }])
    mockMkdir.mockResolvedValue(undefined)
    mockReadFile.mockRejectedValue(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }))
    mockWriteFile.mockImplementation(async (p: string) => { if(p.endsWith('user.js')) throw new Error('EACCES') })
    const { applyBrowserLeakProtection } = await import('./browserHardening')
    const result = await applyBrowserLeakProtection()
    expect(result.success).toBe(false)
    expect(result.changed).toBe(false)
    expect(result.details.some(d => d.includes('не удалось обновить'))).toBe(true)
  })
})

it('keeps browser hardening manifest after failed restoration', async () => {
  vi.clearAllMocks()
  Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
  mockReadFile.mockResolvedValue(JSON.stringify({ createdAt: 1, registryBackups: [], fileBackups: [{ path: 'prefs', backupPath: 'prefs.bak', existed: true }] }))
  mockExistsSync.mockReturnValue(true)
  mockCopyFile.mockRejectedValue(new Error('EACCES'))
  const { rollbackBrowserLeakProtection } = await import('./browserHardening')
  expect((await rollbackBrowserLeakProtection()).success).toBe(false)
  expect(mockUnlink).not.toHaveBeenCalled()
})

// AT-00-001/004/005, F-074/F-138/F-143: domain failures, independent restore, actual IPC.
describe('browser hardening error taxonomy', () => {
  const raw = 'FAKE-SECRET at C:\\private\\credentials.json\n at unsafe (C:\\private\\app.js:1:2)'
  const failures = [
    ['permission', () => Object.assign(new Error(raw), { code: 'EACCES' })],
    ['timeout', () => Object.assign(new Error(raw), { code: 'ETIMEDOUT' })],
    ['network', () => Object.assign(new Error(raw), { code: 'ECONNRESET' })],
    ['cancelled', () => Object.assign(new Error(raw), { name: 'AbortError' })],
    ['validation', () => new IpcFault('validation')],
    ['conflict', () => new IpcFault('conflict')],
    ['internal', () => new Error(raw)]
  ] as const
  const channels = ['apply-browser-leak-protection', 'rollback-browser-leak-protection'] as const
  let invoke: (channel: typeof channels[number]) => Promise<any>
  beforeEach(async () => {
    vi.resetAllMocks()
    boundary.handlers.clear()
    installTrustedIpcBoundary()
    Object.defineProperty(process, 'platform', { value: 'win32', configurable: true })
    mockReadFile.mockRejectedValue(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }))
    mockExistsSync.mockReturnValue(false)
    mockReaddir.mockResolvedValue([])
    mockMkdir.mockResolvedValue(undefined)
    mockWriteFile.mockResolvedValue(undefined)
    mockCopyFile.mockResolvedValue(undefined)
    mockUnlink.mockResolvedValue(undefined)
    mockExecFile.mockImplementation((_file: string, _args: string[], _opts: any, cb: any) => cb(null, { stdout: '', stderr: '' }))
    const fs = await vi.importActual<typeof import('node:fs')>('node:fs')
    const ts = await import('typescript')
    const source = ts.createSourceFile('index.ts', fs.readFileSync('src/main/index.ts', 'utf8'), ts.ScriptTarget.Latest, true)
    const registrations: string[] = []
    function visit(node: import('typescript').Node) {
      if (ts.isCallExpression(node) && node.expression.getText(source) === 'handleLogged'
        && ts.isStringLiteral(node.arguments[0]) && channels.includes(node.arguments[0].text as typeof channels[number])) registrations.push(node.getText(source))
      ts.forEachChild(node, visit)
    }
    visit(source)
    expect(registrations).toHaveLength(channels.length)
    const handle = source.statements.find(n => ts.isFunctionDeclaration(n) && n.name?.text === 'handleLogged')!
    const js = ts.transpileModule(`${handle.getText(source)}\n${registrations.join('\n')}`, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
    const hardening = await import('./browserHardening')
    const deps = { ipcMain, ipcError, classifyIpcError, logEvent, compactForLog: JSON.stringify, ...hardening }
    new Function(...Object.keys(deps), js)(...Object.values(deps))
    invoke = channel => boundary.handlers.get(channel)!({ sender: {} })
  })
  function firefox() {
    mockExistsSync.mockImplementation((p: string) => p.endsWith('Mozilla\\Firefox\\Profiles'))
    mockReaddir.mockResolvedValue([{ name: 'private.default', isDirectory: () => true }])
  }
  function restore() {
    mockReadFile.mockResolvedValue(JSON.stringify({ createdAt: 1, registryBackups: [], fileBackups: [
      { path: 'C:\\private\\first', backupPath: 'C:\\private\\first.bak', existed: true },
      { path: 'C:\\private\\second', backupPath: 'C:\\private\\second.bak', existed: true }
    ] }))
    mockExistsSync.mockReturnValue(true)
  }
  function safe(result: unknown) {
    expect(JSON.stringify(result)).not.toMatch(/FAKE-SECRET|private|unsafe|[A-Z]:\\\\| at /)
  }
  for (const channel of channels) it.each(failures)(`${channel} retains returned %s and correlated private diagnostics`, async (category, create) => {
    const error = create()
    const ids: Array<string | undefined> = []
    vi.mocked(logEvent).mockImplementation(() => { ids.push(currentCorrelationId()) })
    if (channel === 'apply-browser-leak-protection') {
      firefox()
      mockWriteFile.mockImplementation(async (p: string) => { if (p.endsWith('user.js')) throw error })
    } else {
      restore()
      mockCopyFile.mockRejectedValueOnce(error)
    }
    const response = await invoke(channel)
    expect(response).toMatchObject({ ok: true, result: { success: false, error: ipcError(category) } })
    safe(response)
    expect(logEvent).toHaveBeenCalledWith('warn', 'browser-hardening', 'browser hardening step failed', expect.objectContaining({ error }))
    expect(ids.length).toBeGreaterThan(0)
    expect(ids.every(id => id === response.correlationId)).toBe(true)
    if (channel === 'rollback-browser-leak-protection') {
      expect(mockCopyFile).toHaveBeenCalledTimes(2)
      expect(mockUnlink).not.toHaveBeenCalled()
      expect(response.result).toMatchObject({ changed: true, restartRequired: true })
    }
  })
  it.each(failures)('classifies registry write %s without guessing localized text', async (category, create) => {
    mockExistsSync.mockImplementation((p: string) => p.includes('Google\\Chrome\\User Data'))
    mockExecFile.mockImplementation((_file: string, args: string[], _opts: any, cb: any) => {
      if (args[0] === 'add') cb(create(), null)
      else cb(null, { stdout: '', stderr: '' })
    })
    const response = await invoke('apply-browser-leak-protection')
    expect(response.result).toMatchObject({ success: false, changed: false, error: ipcError(category) })
    safe(response)
  })
  it('does not classify reg.exe exit 1 with access-denied text as structured permission', async () => {
    mockExistsSync.mockImplementation((p: string) => p.includes('Google\\Chrome\\User Data'))
    mockExecFile.mockImplementation((_file: string, args: string[], _opts: any, cb: any) => {
      if (args[0] === 'add') cb(Object.assign(new Error('Access denied ' + raw), { code: 1 }), null)
      else cb(null, { stdout: '', stderr: '' })
    })
    const response = await invoke('apply-browser-leak-protection')
    expect(response.result.error).toEqual(ipcError('internal'))
    safe(response)
  })
  it('retains partial writes and restart requirement when another Firefox profile fails', async () => {
    firefox()
    mockReaddir.mockResolvedValue([{ name: 'one', isDirectory: () => true }, { name: 'two', isDirectory: () => true }])
    let first = ''
    mockReadFile.mockImplementation(async (p: string) => {
      if (p.endsWith('one\\user.js')) return first
      throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
    })
    mockWriteFile.mockImplementation(async (p: string, data: string) => {
      if (p.endsWith('one\\user.js')) first = data
      if (p.endsWith('two\\user.js')) throw Object.assign(new Error(raw), { code: 'EPERM' })
    })
    const response = await invoke('apply-browser-leak-protection')
    expect(response.result).toMatchObject({ success: false, changed: true, restartRequired: true, error: ipcError('permission') })
    safe(response)
  })
  it('keeps a verified Chromium preference fallback successful despite registry permission failures', async () => {
    mockExistsSync.mockImplementation((p: string) => p.includes('Google\\Chrome\\User Data'))
    mockReaddir.mockResolvedValue([{ name: 'Default', isDirectory: () => true }])
    let prefs = '{}'
    mockReadFile.mockImplementation(async (p: string) => {
      if (p.endsWith('Preferences')) return prefs
      throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
    })
    mockWriteFile.mockImplementation(async (p: string, value: string) => { if (p.endsWith('Preferences')) prefs = value })
    mockExecFile.mockImplementation((_file: string, _args: string[], _opts: any, cb: any) => cb(Object.assign(new Error(raw), { code: 'EACCES' }), null))
    for (let i = 0; i < 2; i++) {
      const response = await invoke('apply-browser-leak-protection')
      expect(response.result.success).toBe(true)
      expect(response.result).not.toHaveProperty('error')
      safe(response)
    }
  })
  it('reports permission if deleting the fully restored manifest fails', async () => {
    restore()
    mockUnlink.mockRejectedValue(Object.assign(new Error(raw), { code: 'EACCES' }))
    const response = await invoke('rollback-browser-leak-protection')
    expect(response.result).toMatchObject({ success: false, changed: true, error: ipcError('permission') })
    expect(mockCopyFile).toHaveBeenCalledTimes(2)
    safe(response)
  })
  it('retains structured permission when registry backup and its verification are denied', async () => {
    mockExistsSync.mockImplementation((p: string) => p.includes('Google\\Chrome\\User Data'))
    mockExecFile.mockImplementation((_file: string, _args: string[], _opts: any, cb: any) => cb(Object.assign(new Error(raw), { code: 'EPERM' }), null))
    const response = await invoke('apply-browser-leak-protection')
    expect(response.result).toMatchObject({ success: false, changed: false, error: ipcError('permission') })
    expect(mockExecFile.mock.calls.every(call => call[1][0] !== 'add')).toBe(true)
    safe(response)
  })
  it('retains a timed-out registry read-back without claiming a confirmed change', async () => {
    mockExistsSync.mockImplementation((p: string) => p.includes('Google\\Chrome\\User Data'))
    mockExecFile.mockImplementation((_file: string, args: string[], _opts: any, cb: any) => {
      if (args[0] === 'query') cb(Object.assign(new Error(raw), { code: 'ETIMEDOUT' }), null)
      else cb(null, { stdout: '', stderr: '' })
    })
    const response = await invoke('apply-browser-leak-protection')
    expect(response.result).toMatchObject({ success: false, changed: false, error: ipcError('timeout') })
    safe(response)
  })
  it('retains a completed write when Firefox read-back is inconsistent', async () => {
    firefox()
    const response = await invoke('apply-browser-leak-protection')
    expect(response.result).toMatchObject({ success: false, changed: true, restartRequired: true, error: ipcError('internal') })
    safe(response)
  })
  it('prioritizes permission across independent restore failures', async () => {
    restore()
    mockCopyFile.mockRejectedValueOnce(new Error(raw)).mockRejectedValueOnce(Object.assign(new Error(raw), { code: 'EACCES' }))
    const response = await invoke('rollback-browser-leak-protection')
    expect(response.result.error).toEqual(ipcError('permission'))
    expect(mockCopyFile).toHaveBeenCalledTimes(2)
    expect(mockUnlink).not.toHaveBeenCalled()
    safe(response)
  })
  it('continues restoring files after a registry import failure', async () => {
    restore()
    mockReadFile.mockResolvedValue(JSON.stringify({ createdAt: 1,
      registryBackups: [{ key: 'HKCU\\private', backupPath: 'C:\\private\\policy.reg' }],
      fileBackups: [{ path: 'C:\\private\\prefs', backupPath: 'C:\\private\\prefs.bak', existed: true }] }))
    mockExecFile.mockImplementation((_file: string, args: string[], _opts: any, cb: any) => {
      if (args[0] === 'import') cb(Object.assign(new Error(raw), { code: 'EACCES' }), null)
      else cb(null, { stdout: '', stderr: '' })
    })
    const response = await invoke('rollback-browser-leak-protection')
    expect(response.result.error).toEqual(ipcError('permission'))
    expect(mockCopyFile).toHaveBeenCalledOnce()
    expect(mockUnlink).not.toHaveBeenCalled()
    safe(response)
  })
  it.each(channels)('%s sanitizes a pre-mutation manifest read failure', async channel => {
    firefox()
    mockReadFile.mockRejectedValue(Object.assign(new Error(raw), { code: 'EACCES' }))
    const response = await invoke(channel)
    expect(response).toMatchObject({ ok: false, error: ipcError('permission') })
    expect(mockWriteFile).not.toHaveBeenCalled()
    expect(mockCopyFile).not.toHaveBeenCalled()
    safe(response)
  })
  it('does not claim success if later Firefox discovery fails after Chromium policy writes', async () => {
    mockExistsSync.mockImplementation((p: string) => p.includes('Google\\Chrome\\User Data') || p.endsWith('Mozilla\\Firefox\\Profiles'))
    mockReaddir.mockResolvedValueOnce([]).mockResolvedValueOnce([]).mockRejectedValueOnce(Object.assign(new Error(raw), { code: 'EACCES' }))
    let added = false
    mockExecFile.mockImplementation((_file: string, args: string[], _opts: any, cb: any) => {
      if (args[0] === 'add') added = true
      cb(null, { stdout: args[0] === 'query' && added ? 'WebRtcIPHandlingPolicy    REG_SZ    disable_non_proxied_udp' : '', stderr: '' })
    })
    const response = await invoke('apply-browser-leak-protection')
    expect(response.result).toMatchObject({ success: false, changed: true, restartRequired: true, error: ipcError('permission') })
    safe(response)
  })
  it('keeps a fully restored result successful without exposing profile paths', async () => {
    restore()
    const response = await invoke('rollback-browser-leak-protection')
    expect(response.result.success).toBe(true)
    expect(response.result).not.toHaveProperty('error')
    safe(response)
  })
  it('reports missing existing-file backups as internal and still restores valid neighbours', async () => {
    restore()
    mockExistsSync.mockImplementation((p: string) => !p.endsWith('first.bak'))
    const response = await invoke('rollback-browser-leak-protection')
    expect(response.result).toMatchObject({ success: false, error: ipcError('internal') })
    expect(response.result.details.some((d: string) => d.includes('Skipped'))).toBe(true)
    expect(mockCopyFile).toHaveBeenCalledTimes(1)
    expect(mockUnlink).not.toHaveBeenCalled()
    safe(response)
  })
  it('types absent rollback state without mutation', async () => {
    const response = await invoke('rollback-browser-leak-protection')
    expect(response.result).toMatchObject({ success: false, changed: false, error: ipcError('conflict') })
    expect(mockCopyFile).not.toHaveBeenCalled()
    expect(mockExecFile).not.toHaveBeenCalled()
  })
  it.each(channels)('%s types unsupported platforms', async channel => {
    Object.defineProperty(process, 'platform', { value: 'linux', configurable: true })
    expect((await invoke(channel)).result).toMatchObject({ success: false, error: ipcError('conflict') })
    expect(mockWriteFile).not.toHaveBeenCalled()
  })
})
