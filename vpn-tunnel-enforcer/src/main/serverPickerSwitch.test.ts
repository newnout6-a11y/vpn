import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
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
  dialog: {},
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
  exportOutboundToUri: vi.fn(),
  exportOutboundToProxyLine: vi.fn()
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

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason?: unknown) => void
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

function profile(id: string) {
  return {
    id,
    name: `Profile ${id}`,
    protocol: 'vless',
    server: `${id}.example.test`,
    port: 443,
    enabled: true,
    outbound: { type: 'vless', server: `${id}.example.test`, server_port: 443 }
  }
}

let selectProfileHandler: (...args: any[]) => Promise<unknown>
let cancelSwitchHandler: (...args: any[]) => Promise<unknown>

beforeEach(async () => {
  vi.resetModules()
  state.storeData.clear()
  state.ipcHandlers.clear()
  state.profiles = [profile('a'), profile('b')]
  state.storeData.set('profiles', state.profiles)
  state.tunnelStatus = { running: true, mode: 'directVpn' }
  state.restartProtected.mockReset().mockResolvedValue({ success: true })
  state.stop.mockClear()
  for (const mock of Object.values(state.ipMonitor)) mock.mockClear()

  const serverPicker = await import('./serverPicker')
  serverPicker.registerServerPickerHandlers()
  selectProfileHandler = state.ipcHandlers.get('servers:select')!
  cancelSwitchHandler = state.ipcHandlers.get('servers:cancel-switch')!
})

describe('server profile switching', () => {
  it('rejects a second selection before changing the selected profile', async () => {
    const pendingRestart = deferred<{ success: boolean }>()
    state.restartProtected.mockReturnValueOnce(pendingRestart.promise)

    const firstSwitch = selectProfileHandler({}, 'a')
    await vi.waitFor(() => expect(state.restartProtected).toHaveBeenCalledTimes(1))

    await expect(selectProfileHandler({}, 'b')).rejects.toThrow('Переключение сервера уже выполняется')
    expect(state.storeData.get('activeProfileId')).toBe('a')
    expect(state.restartProtected).toHaveBeenCalledTimes(1)

    pendingRestart.resolve({ success: true })
    await expect(firstSwitch).resolves.toBeUndefined()

    // A completed switch releases the backend guard for the next request.
    await expect(selectProfileHandler({}, 'b')).resolves.toBeUndefined()
    expect(state.storeData.get('activeProfileId')).toBe('b')
  })

  it('releases the guard when restarting the tunnel fails', async () => {
    state.restartProtected.mockResolvedValueOnce({ success: false, error: 'restart failed' })

    await expect(selectProfileHandler({}, 'a')).rejects.toThrow('restart failed')
    await expect(selectProfileHandler({}, 'b')).resolves.toBeUndefined()
    expect(state.storeData.get('activeProfileId')).toBe('b')
  })

  it('keeps explicit cancellation working and releases the guard afterward', async () => {
    const pendingRestart = deferred<{ success: boolean }>()
    state.restartProtected.mockReturnValueOnce(pendingRestart.promise)

    const firstSwitch = selectProfileHandler({}, 'a')
    await vi.waitFor(() => expect(state.restartProtected).toHaveBeenCalledTimes(1))
    await expect(cancelSwitchHandler({})).resolves.toEqual({ cancelled: true })

    pendingRestart.resolve({ success: true })
    await expect(firstSwitch).rejects.toThrow('Переключение сервера отменено')
    expect(state.stop).toHaveBeenCalledTimes(1)

    await expect(selectProfileHandler({}, 'b')).resolves.toBeUndefined()
    expect(state.storeData.get('activeProfileId')).toBe('b')
  })
})
