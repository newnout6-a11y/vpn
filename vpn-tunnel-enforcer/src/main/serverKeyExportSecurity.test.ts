import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { closeSync, existsSync, openSync, readFileSync, renameSync, rmSync, writeFileSync } from 'fs'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { privateExportDirectory } from './testFixtures/privateExportDirectory'
import { join } from 'path'

const state = vi.hoisted(() => ({
  nativePrompt: vi.fn(), saveDialog: vi.fn(), uri: vi.fn(), proxyLine: vi.fn(),
  clipboardText: '', clipboardWrite: vi.fn(),
  writeAttempt: vi.fn(),
  writeFailure: undefined as unknown,
  onOpened: undefined as ((path: string) => Promise<void>) | undefined,
  beforeOpen: undefined as ((path: string) => void) | undefined,
  storeData: new Map<string, any>(),
  ipcHandlers: new Map<string, (...args: any[]) => any>(),
  profiles: [] as any[],
  tunnelStatus: { running: true, mode: 'directVpn' },
  restartProtected: vi.fn(),
  stop: vi.fn(async () => undefined),
  ipMonitor: {
    getCurrentIp: vi.fn(async () => ({ ip: '198.51.100.1' })),
    deferResume: vi.fn(),
    releaseDeferredResume: vi.fn(),
    clearVpnIp: vi.fn(),
    resume: vi.fn(),
    probeCurrentIp: vi.fn(async () => '198.51.100.2'),
    recheck: vi.fn(async () => ({ ip: '198.51.100.2' }))
  }
}))

vi.mock('fs/promises', async importOriginal => {
  const actual = await importOriginal<typeof import('fs/promises')>()
  return { ...actual, open: async (...args: Parameters<typeof actual.open>) => {
    state.beforeOpen?.(String(args[0]))
    const file = await actual.open(...args), write = file.writeFile.bind(file)
    try { await state.onOpened?.(String(args[0])) } catch (error) { await file.close(); throw error }
    file.writeFile = (...writeArgs) => {
      state.writeAttempt()
      return state.writeFailure ? Promise.reject(state.writeFailure) : write(...writeArgs)
    }
    return file
  } }
})

vi.mock('electron', () => ({
  app: { getPath: () => '/tmp/vpnte-test', getAppPath: () => '/tmp/vpnte-test' },
  BrowserWindow: { fromWebContents: () => null },
  clipboard: {
    writeText: async (text: string) => { await state.clipboardWrite(text); state.clipboardText = text },
    readText: async () => state.clipboardText,
    read: async () => [{ types: ['text/plain'] }], clear: () => { state.clipboardText = '' }
  },
  dialog: { showMessageBox: state.nativePrompt, showSaveDialog: state.saveDialog },
  ipcMain: {
    handle: vi.fn((channel: string, handler: (...args: any[]) => any) => {
      state.ipcHandlers.set(channel, handler)
    })
  }
}))

vi.mock('electron-store', () => ({
  default: class MockStore {
    defaults: Record<string, any>

    constructor(options: { defaults?: Record<string, any> } = {}) {
      this.defaults = options.defaults ?? {}
    }

    get(key: string, fallback?: unknown) {
      return state.storeData.has(key) ? state.storeData.get(key) : this.defaults[key] ?? fallback
    }
    get store() { return Object.fromEntries(state.storeData) }
    set store(value: Record<string, unknown>) {
      state.storeData.clear()
      for (const [key, item] of Object.entries(value)) state.storeData.set(key, item)
    }
    get path() { return '/missing-vpnte-key-export-test/server-picker.json' }

    set(key: string, value: any) {
      state.storeData.set(key, value)
    }
  }
}))

vi.mock('axios', () => ({ default: { get: vi.fn() } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./ipcLogging', () => ({ compactForIpcLog: (args: any[]) => args }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({}) } }))
vi.mock('./vpnProfiles', () => ({
  applyClientDeviceToOutbound: vi.fn(),
  clientFingerprintForDevice: vi.fn(),
  normalizeClientDevice: vi.fn(),
  resolveVpnProfiles: vi.fn(),
  exportOutboundToUri: state.uri,
  exportOutboundForSharing: (...args: any[]) => { const content = state.uri(...args); return content ? { content, format: content.startsWith('{') ? 'json' : 'uri' } : null },
  exportOutboundToProxyLine: state.proxyLine
}))
vi.mock('./tunController', () => ({
  getDirectProxyPort: () => 1080,
  tunController: {
    getStatus: () => state.tunnelStatus,
    getLastStartOptions: () => null,
    restartProtected: (...args: any[]) => state.restartProtected(...args),
    stop: () => state.stop(),
    areTunRoutesActive: vi.fn(async () => true),
    setWatchdogProbeConfirmationChecker: vi.fn()
  }
}))
vi.mock('./adaptiveBypass', () => ({ beginAdaptiveConnection: () => ({ mode: 'disabled' }) }))
vi.mock('./ipMonitor', () => ({ ipMonitor: state.ipMonitor }))
vi.mock('./serverGroups', () => ({
  serverGroups: { getGroups: () => [], createGroup: vi.fn(), deleteGroup: vi.fn() },
  ensureManualKeysGroup: vi.fn(),
  findGroupBySourceUrl: vi.fn(),
  canonicalizeSubscriptionUrl: (value: string) => value,
  refreshGroup: vi.fn()
}))



const channels = ['servers:export-key', 'servers:copy-key', 'servers:export-key-file', 'servers:export-all-keys-file', 'servers:export-all-proxies-file']
const secretUri = 'vless://FAKE-PRIVATE-KEY@server.test:443'
let destroyed = false
let exportDirectory = ''
let exportPath = ''
const sender = { isDestroyed: () => destroyed }
function invoke(channel: string) {
  return state.ipcHandlers.get(channel)!({ sender }, ...(channel.startsWith('servers:export-all-') ? [] : ['a']))
}

beforeEach(async () => {
  vi.resetModules(); vi.clearAllMocks(); state.storeData.clear(); state.ipcHandlers.clear(); destroyed = false
  state.writeFailure = undefined
  state.onOpened = undefined
  state.beforeOpen = undefined
  exportDirectory = privateExportDirectory('.vpnte-export-consent-')
  exportPath = join(exportDirectory, 'keys.txt')
  state.storeData.set('profiles', [{ id: 'a', name: 'Profile', protocol: 'vless', outbound: { type: 'vless', server: 'server.test', server_port: 443, uuid: 'FAKE-PRIVATE-KEY' } }])
  state.nativePrompt.mockReset().mockResolvedValue({ response: 0 })
  state.saveDialog.mockReset().mockResolvedValue({ canceled: false, filePath: exportPath })
  state.uri.mockReset().mockReturnValue(secretUri)
  state.proxyLine.mockReset().mockReturnValue('server.test:443:FAKE-PRIVATE-KEY')
  const serverPicker = await import('./serverPicker')
  serverPicker.registerServerPickerHandlers()
})
afterEach(async () => {
  const { clearOwnedSecretClipboard } = await import('./secretClipboard')
  await (await import('./operations')).operations.close()
  await clearOwnedSecretClipboard()
  rmSync(exportDirectory, { recursive: true, force: true })
})

describe('main-owned export approval (AT-01-008)', () => {
  it.each(channels)('preserves typed state failures through the actual IPC boundary: %s (AT-00-001/004/005)', async channel => {
    const { ipcMain } = await import('electron')
    const originalHandle = ipcMain.handle
    const { installTrustedIpcBoundary } = await import('./ipcSecurity')
    const { ipcError, unwrapIpcResult } = await import('../shared/ipc-result')
    try {
      installTrustedIpcBoundary()
      ;(await import('./serverPicker')).registerServerPickerHandlers()
      state.nativePrompt.mockResolvedValue({ response: 1 })
      state.storeData.set('profiles', [])
      const response = await invoke(channel)
      const result = unwrapIpcResult(structuredClone(response))
      expect(result).toEqual({ ok: false, reason: channel.startsWith('servers:export-all-') ? 'no-profiles' : 'profile-not-found', error: ipcError('conflict') })
      const { operations } = await import('./operations')
      expect(operations.list()).toMatchObject([{ status: 'error', category: 'conflict', correlationId: response.correlationId }])
      expect(state.nativePrompt).toHaveBeenCalledOnce()
      expect(state.saveDialog).not.toHaveBeenCalled()
      expect(state.clipboardWrite).not.toHaveBeenCalled()
      expect(state.writeAttempt).not.toHaveBeenCalled()
      expect(JSON.stringify(response)).not.toMatch(/FAKE-PRIVATE-KEY|stack|vpnte-test/)
    } finally {
      ipcMain.handle = originalHandle
      Reflect.deleteProperty(ipcMain, Symbol.for('vpnte.ipc.trusted-boundary.installed'))
    }
  })
  it.each(channels)('classifies missing and unsupported saved outbounds without side effects: %s (AT-00-004)', async channel => {
    state.nativePrompt.mockResolvedValue({ response: 1 })
    const { ipcError } = await import('../shared/ipc-result')
    const { operations } = await import('./operations')
    const bulk = channel.startsWith('servers:export-all-')
    for (const missing of [true, false]) {
      state.storeData.set('profiles', [{ id: 'a', name: 'Private', protocol: 'custom', ...(missing ? {} : { outbound: { type: 'custom' } }) }])
      state.uri.mockReturnValue(null); state.proxyLine.mockReturnValue(null)
      expect(await invoke(channel)).toEqual({ ok: false, reason: bulk ? 'unsupported-all' : missing ? 'no-outbound' : 'unsupported-protocol',
        error: ipcError('conflict'), ...(!bulk && !missing ? { protocol: 'custom' } : {}),
        ...(channel === 'servers:export-all-proxies-file' ? { skipped: 1, total: 1 } : {}) })
    }
    expect(operations.list()).toMatchObject([{ status: 'error', category: 'conflict' }, { status: 'error', category: 'conflict' }])
    expect(state.saveDialog).not.toHaveBeenCalled(); expect(state.clipboardWrite).not.toHaveBeenCalled(); expect(state.writeAttempt).not.toHaveBeenCalled()
  })
  it.skipIf(process.platform !== 'win32')('rejects a substituted staging file before writing any secret through a retained reader', async () => {
    writeFileSync(exportPath, 'old destination')
    state.nativePrompt.mockResolvedValue({ response: 1 })
    let reader: number | undefined, substituted = ''
    state.beforeOpen = path => {
      substituted = path
      renameSync(path, path + '.original')
      writeFileSync(path, 'attacker content')
      reader = openSync(path, 'r')
    }
    try {
      await expect(invoke('servers:export-key-file')).rejects.toMatchObject({ category: 'conflict' })
      expect(readFileSync(reader!, 'utf8')).toBe('attacker content')
      expect(readFileSync(exportPath, 'utf8')).toBe('old destination')
      expect(readFileSync(substituted, 'utf8')).toBe('attacker content')
    } finally { if (reader !== undefined) closeSync(reader) }
  })
  it.skipIf(process.platform !== 'win32').each(channels.filter(channel => channel.endsWith('-file')))('restricts a broadly readable destination through the actual key handler: %s (AT-00-003)', async channel => {
    const encodedPath = Buffer.from(exportPath, 'utf8').toString('base64')
    const powershell = async (script: string) => (await promisify(execFile)('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand',
      Buffer.from(`$ErrorActionPreference='Stop';$path=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encodedPath}'));` + script, 'utf16le').toString('base64')], { windowsHide: true, timeout: 15_000 })).stdout.trim()
    writeFileSync(exportPath, 'old')
    await powershell(`$acl=[IO.File]::GetAccessControl($path);$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-5-19')),'Read','Allow')));[IO.File]::SetAccessControl($path,$acl)`)
    await powershell(`$parent=[IO.Path]::GetDirectoryName($path);$acl=[IO.Directory]::GetAccessControl($parent);$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-5-19')),'Read','ContainerInherit,ObjectInherit','None','Allow')));[IO.Directory]::SetAccessControl($parent,$acl)`)
    const opened = vi.fn()
    state.onOpened = async path => {
      opened()
      const stagedPath = Buffer.from(path, 'utf8').toString('base64')
      const staged = JSON.parse(await powershell(`$path=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${stagedPath}'));$acl=[IO.File]::GetAccessControl($path);[ordered]@{protected=$acl.AreAccessRulesProtected;user=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {$_.IdentityReference.Value})}|ConvertTo-Json -Compress`))
      expect(staged.protected).toBe(true)
      expect(staged.rules.sort()).toEqual([...new Set([staged.user, 'S-1-5-18'])].sort())
    }
    state.nativePrompt.mockResolvedValue({ response: 1 })
    expect((await invoke(channel)).ok).toBe(true)
    expect(readFileSync(exportPath, 'utf8')).toContain('FAKE-PRIVATE-KEY')
    expect(opened).toHaveBeenCalledTimes(1)
    const acl = JSON.parse(await powershell(`$acl=[IO.File]::GetAccessControl($path);[ordered]@{protected=$acl.AreAccessRulesProtected;user=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;rules=@($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|ForEach-Object {$_.IdentityReference.Value})}|ConvertTo-Json -Compress`))
    expect(acl.protected).toBe(true)
    expect(acl.rules.sort()).toEqual([...new Set([acl.user, 'S-1-5-18'])].sort())
  }, 15_000)
  it.each(channels.filter(channel => channel.endsWith('-file')))('maps a malformed write exception to a bounded error (AT-00-001/004): %s', async channel => {
    state.nativePrompt.mockResolvedValue({ response: 1 })
    state.writeFailure = { message: { malformed: true } }
    await expect(invoke(channel)).rejects.toMatchObject({ category: 'internal', message: 'Не удалось выполнить операцию' })
    expect(state.writeAttempt).toHaveBeenCalledOnce()
    expect(existsSync(exportPath)).toBe(false)
  // Reaching the injected write fault performs the same real PowerShell ACL
  // preparation as the adjacent file-export cases on Windows CI.
  }, 15_000)
  it('saves native JSON with a JSON file suggestion and preserves main-owned clipboard handling', async () => {
    const secretJson = JSON.stringify({ remarks: 'Native', outbounds: [{ protocol: 'vless', settings: { id: 'FAKE-PRIVATE-KEY' } }], routing: { balancers: [{ tag: 'bridge' }] } })
    state.uri.mockReturnValue(secretJson)
    state.nativePrompt.mockResolvedValue({ response: 1 })
    expect((await invoke('servers:export-key-file')).ok).toBe(true)
    expect(state.saveDialog.mock.calls[0][0].defaultPath).toMatch(/\.json$/)
    expect(readFileSync(exportPath, 'utf8').trim()).toBe(secretJson)
    const copied = await invoke('servers:copy-key')
    expect(state.clipboardWrite).toHaveBeenCalledWith(secretJson)
    expect(JSON.stringify(copied)).not.toContain('FAKE-PRIVATE-KEY')
    expect((await invoke('servers:export-key')).format).toBe('json')
    expect((await invoke('servers:export-all-keys-file')).exported).toBe(1)
    expect(readFileSync(exportPath, 'utf8')).toContain(secretJson)
  // Both file exports perform actual PowerShell ACL checks on Windows.
  }, 15_000)
  it('exports a mixed set as a complete JSON array instead of ambiguous JSON/URI lines', async () => {
    state.nativePrompt.mockResolvedValue({ response: 1 })
    const profiles = state.storeData.get('profiles')
    state.storeData.set('profiles', [...profiles, { ...profiles[0], id: 'native', name: 'Native' }])
    const native = { remarks: 'Native', outbounds: [{ protocol: 'vless' }], routing: { balancers: [{ tag: 'bridge' }] } }
    state.uri.mockImplementation(profile => profile.name === 'Native' ? JSON.stringify(native) : secretUri)
    const result = await invoke('servers:export-all-keys-file')
    expect(result).toMatchObject({ ok: true, total: 2, exported: 2, skipped: 0 })
    expect(state.saveDialog.mock.calls[0][0].defaultPath).toMatch(/\.json$/)
    expect(JSON.parse(readFileSync(exportPath, 'utf8'))).toEqual([secretUri, native])
  })
  it.each(channels)('a direct IPC call cannot bypass native consent: %s', async channel => {
    const result = await invoke(channel)
    expect(result).toEqual({ ok: false, cancelled: true })
    expect((await import('./operations')).operations.list()).toMatchObject([{ status: 'cancelled', category: 'cancelled' }])
    expect(state.uri).not.toHaveBeenCalled(); expect(state.proxyLine).not.toHaveBeenCalled()
    expect(state.clipboardWrite).not.toHaveBeenCalled()
    expect(state.saveDialog).not.toHaveBeenCalled()
    expect(existsSync(exportPath)).toBe(false)
    expect(JSON.stringify(state.nativePrompt.mock.calls)).not.toContain('FAKE-PRIVATE-KEY')
    expect(state.nativePrompt.mock.calls[0][0]).toMatchObject({ defaultId: 0, cancelId: 0, type: 'warning' })
  })
  it.each(channels)('only explicit native approval permits the requested operation: %s', async channel => {
    state.nativePrompt.mockResolvedValue({ response: 1 })
    const result = await invoke(channel)
    expect(result.ok).toBe(true)
    if (channel === 'servers:export-key') expect(result.uri).toBe(secretUri)
    else expect(JSON.stringify(result)).not.toContain('FAKE-PRIVATE-KEY')
    if (channel === 'servers:copy-key') {
      expect(state.clipboardWrite).toHaveBeenCalledWith(secretUri)
      expect(result.clearAfterMs).toBe(60_000)
    } else if (channel.endsWith('-file')) expect(readFileSync(exportPath, 'utf8')).toContain('FAKE-PRIVATE-KEY')
  // File cases run actual PowerShell ACL checks, as do the adjacent native fixtures.
  }, 15_000)
  it('renderer closure while consent is pending prevents disclosure', async () => {
    let approve!: (value: { response: number }) => void
    state.nativePrompt.mockImplementationOnce(() => new Promise(resolve => { approve = resolve }))
    const pending = invoke('servers:copy-key')
    destroyed = true; approve({ response: 1 })
    expect(await pending).toEqual({ ok: false, cancelled: true })
    expect(state.clipboardWrite).not.toHaveBeenCalled(); expect(state.uri).not.toHaveBeenCalled()
  })
  it('a native dialog failure never proceeds to export', async () => {
    state.nativePrompt.mockRejectedValueOnce(new Error('native consent unavailable'))
    await expect(invoke('servers:export-key-file')).rejects.toMatchObject({ category: 'internal' })
    expect(state.uri).not.toHaveBeenCalled()
    expect(existsSync(exportPath)).toBe(false)
  })
  it('a rejected native clipboard write never returns a success acknowledgement', async () => {
    state.nativePrompt.mockResolvedValue({ response: 1 })
    state.clipboardWrite.mockRejectedValueOnce(new Error('clipboard busy'))
    await expect(invoke('servers:copy-key')).rejects.toMatchObject({ category: 'internal' })
  })
})
