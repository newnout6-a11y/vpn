import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  storeData: new Map<string, any>(),
  ipcHandlers: new Map<string, (...args: any[]) => any>(),
  profiles: [] as any[],
  tunnelStatus: { running: true, mode: 'directVpn' },
  restartProtected: vi.fn(),
  networkIdentity: vi.fn(), settings: {} as Record<string, any>,
  stop: vi.fn(async () => undefined),
  ipMonitor: {
    getCurrentIp: vi.fn(async () => ({ ip: '198.51.100.1' })),
    invalidateVpnIpBaseline: vi.fn(),
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
vi.mock('./settings', () => ({ settingsStore: { get: () => state.settings } }))
vi.mock('./vpnProfiles', () => ({
  applyClientDeviceToOutbound: vi.fn(),
  clientFingerprintForDevice: vi.fn(),
  normalizeClientDevice: vi.fn(),
  resolveVpnProfiles: vi.fn(),
  exportOutboundToUri: vi.fn(),
  exportOutboundForSharing: vi.fn(),
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
vi.mock('./adaptiveBypass', () => ({ beginAdaptiveConnection: () => ({ mode: 'disabled' }), readAdaptiveNetworkFingerprint: state.networkIdentity }))
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
  state.settings = {}
  state.networkIdentity.mockReset().mockResolvedValue('fixture-network-hmac')
  state.restartProtected.mockReset().mockResolvedValue({ success: true })
  state.stop.mockClear()
  for (const mock of Object.values(state.ipMonitor)) mock.mockClear()

  const serverPicker = await import('./serverPicker')
  serverPicker.registerServerPickerHandlers()
  selectProfileHandler = state.ipcHandlers.get('servers:select')!
  cancelSwitchHandler = state.ipcHandlers.get('servers:cancel-switch')!
})

describe('server profile switching', () => {
  it('invalidates adaptive work before selecting or waiting for network identity (AT-10-003)', async () => {
    const { setProfileSwitchHooks } = await import('./serverPicker')
    const end = vi.fn()
    const gate = deferred<void>()
    const begin = vi.fn(() => gate.promise)
    setProfileSwitchHooks({ begin, end })
    const pending = selectProfileHandler({}, 'a')
    expect(begin).toHaveBeenCalledOnce()
    expect(state.storeData.get('activeProfileId')).toBeUndefined()
    expect(state.restartProtected).not.toHaveBeenCalled()
    gate.resolve()
    await pending
    expect(state.storeData.get('activeProfileId')).toBe('a')
    expect(end).toHaveBeenCalledOnce()
  })
  it('does not wait for an unreachable old server IP (AT-07-012)', async () => {
    state.ipMonitor.getCurrentIp.mockImplementationOnce(() => new Promise(() => {}))
    await selectProfileHandler({}, 'a')
    expect(state.ipMonitor.getCurrentIp).not.toHaveBeenCalled()
    expect(state.restartProtected).toHaveBeenCalledOnce()
    expect(state.ipMonitor.recheck).toHaveBeenCalledOnce()
  })
  it('retries a failed fresh baseline instead of releasing deferred monitoring with cached data (AT-07-012)', async () => {
    state.ipMonitor.recheck.mockResolvedValueOnce({ ip: null as any })
    await expect(selectProfileHandler({}, 'a')).resolves.toBeUndefined()
    expect(state.ipMonitor.recheck).toHaveBeenCalledTimes(2)
    expect(state.ipMonitor.getCurrentIp).not.toHaveBeenCalled()
    expect(state.ipMonitor.releaseDeferredResume).toHaveBeenCalledOnce()
    expect(state.ipMonitor.releaseDeferredResume.mock.invocationCallOrder[0]).toBeGreaterThan(state.ipMonitor.recheck.mock.invocationCallOrder[1])
  })
  it('does not restart after cancellation during the new network-identity read (AT-02-004)', async () => {
    state.settings = { adaptiveBypassEnabled: true }
    const identity = deferred<string>()
    state.networkIdentity.mockReturnValue(identity.promise)
    const pending = selectProfileHandler({}, 'a')
    const rejected = expect(pending).rejects.toThrow('Переключение сервера отменено')
    await vi.waitFor(() => expect(state.networkIdentity).toHaveBeenCalledOnce())
    await cancelSwitchHandler({})
    identity.resolve('fixture-network-hmac')
    await rejected
    expect(state.restartProtected).not.toHaveBeenCalled()
  })
  it('does not restart a tunnel stopped while the network identity was pending', async () => {
    state.settings = { adaptiveBypassEnabled: true }
    const identity = deferred<string>()
    state.networkIdentity.mockReturnValue(identity.promise)
    const pending = selectProfileHandler({}, 'a')
    await vi.waitFor(() => expect(state.networkIdentity).toHaveBeenCalledOnce())
    state.tunnelStatus.running = false
    identity.resolve('fixture-network-hmac')
    await pending
    expect(state.restartProtected).not.toHaveBeenCalled()
  })
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
