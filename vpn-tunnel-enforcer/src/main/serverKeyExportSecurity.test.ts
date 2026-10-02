import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'

const state = vi.hoisted(() => ({
  nativePrompt: vi.fn(), saveDialog: vi.fn(), uri: vi.fn(), proxyLine: vi.fn(),
  clipboardText: '', clipboardWrite: vi.fn(),
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

    get(key: string) {
      return state.storeData.has(key) ? state.storeData.get(key) : this.defaults[key]
    }

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
function invoke(channel: string) { return state.ipcHandlers.get(channel)!({ sender }, 'a') }

beforeEach(async () => {
  vi.resetModules(); vi.clearAllMocks(); state.storeData.clear(); state.ipcHandlers.clear(); destroyed = false
  exportDirectory = mkdtempSync(join(tmpdir(), 'vpnte-export-consent-'))
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
  await clearOwnedSecretClipboard()
  rmSync(exportDirectory, { recursive: true, force: true })
})

describe('main-owned export approval (AT-01-008)', () => {
  it.each(channels)('a direct IPC call cannot bypass native consent: %s', async channel => {
    const result = await invoke(channel)
    expect(result).toEqual({ ok: false, cancelled: true })
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
  })
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
    await expect(invoke('servers:export-key-file')).rejects.toThrow('native consent unavailable')
    expect(state.uri).not.toHaveBeenCalled()
    expect(existsSync(exportPath)).toBe(false)
  })
  it('a rejected native clipboard write never returns a success acknowledgement', async () => {
    state.nativePrompt.mockResolvedValue({ response: 1 })
    state.clipboardWrite.mockRejectedValueOnce(new Error('clipboard busy'))
    await expect(invoke('servers:copy-key')).rejects.toThrow('clipboard busy')
  })
})
