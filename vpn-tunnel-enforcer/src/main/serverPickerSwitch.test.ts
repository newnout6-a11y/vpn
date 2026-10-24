import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  storeData: new Map<string, any>(),
  ipcHandlers: new Map<string, (...args: any[]) => any>(),
  profiles: [] as any[],
  tunnelStatus: { running: true, mode: 'directVpn' },
  restartProtected: vi.fn(),
  switchOutbound: vi.fn(),
  lastOptions: null as any,
  restore: vi.fn(),
  cancelTransition: vi.fn(),
  networkIdentity: vi.fn(), settings: {} as Record<string, any>,
  stop: vi.fn(async (): Promise<any> => undefined),
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

    get(key: string, fallback?: unknown) {
      return state.storeData.has(key) ? state.storeData.get(key) : this.defaults[key] ?? fallback
    }
    get store() { return Object.fromEntries(state.storeData) }
    set store(value: Record<string, unknown>) {
      state.storeData.clear()
      for (const [key, item] of Object.entries(value)) state.storeData.set(key, item)
    }
    get path() { return '/missing-vpnte-picker-switch-test/server-picker.json' }

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
    getLastStartOptions: () => state.lastOptions,
    cancelTransition: state.cancelTransition,
    restartProtected: (...args: any[]) => state.restartProtected(...args),
    switchOutbound: (...args: any[]) => state.switchOutbound(...args),
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
  state.switchOutbound.mockReset().mockResolvedValue(null)
  state.stop.mockReset().mockResolvedValue({ success: true, networkCleanup: { baseline: true, firewall: true, adapters: true } })
  state.lastOptions = { mode: 'directVpn', vpnProfile: { name: 'Profile a', protocol: 'vless', outbound: profile('a').outbound }, proxyEngine: 'xray', adaptiveMode: 'disabled', enableFirewallKillSwitch: true }
  state.restore.mockReset().mockResolvedValue({ success: true })
  state.cancelTransition.mockReset()
  for (const mock of Object.values(state.ipMonitor)) mock.mockClear()

  const serverPicker = await import('./serverPicker')
  serverPicker.setProfileSwitchHooks({ begin: () => {}, end: () => {}, restore: state.restore })
  serverPicker.registerServerPickerHandlers()
  selectProfileHandler = state.ipcHandlers.get('servers:select')!
  cancelSwitchHandler = state.ipcHandlers.get('servers:cancel-switch')!
})

describe('server profile switching', () => {
  it('uses a confirmed upstream receipt without restarting the TUN (AT-00-003 / AT-02-002)', async () => {
    state.switchOutbound.mockImplementationOnce(async (_next, options) => {
      options.onCommit()
      return { outcome: 'success', committed: true, activeSlot: 'b', previousPreserved: false,
        candidateStopped: false, previousStopped: true, failures: [] }
    })
    await expect(selectProfileHandler({}, 'b')).resolves.toBeUndefined()
    expect(state.storeData.get('activeProfileId')).toBe('b')
    expect(state.restartProtected).not.toHaveBeenCalled()
    expect(state.stop).not.toHaveBeenCalled()
    expect(state.restore).not.toHaveBeenCalled()
    expect(state.ipMonitor.recheck).not.toHaveBeenCalled()
  })

  it('cancels a candidate with proved previous upstream using no full stop or restore (AT-00-003)', async () => {
    state.storeData.set('activeProfileId', 'a')
    const held = deferred<any>()
    state.switchOutbound.mockReturnValueOnce(held.promise)
    const pending = selectProfileHandler({}, 'b')
    await vi.waitFor(() => expect(state.switchOutbound).toHaveBeenCalledOnce())
    const options = state.switchOutbound.mock.calls[0][1]
    await cancelSwitchHandler({})
    expect(options.signal.aborted).toBe(true)
    expect(options.isOwner()).toBe(true)
    held.resolve({ outcome: 'cancelled', committed: false, activeSlot: 'a', previousPreserved: true,
      candidateStopped: true, previousStopped: false, failures: [] })
    await expect(pending).resolves.toEqual({ cancelled: true })
    expect(state.storeData.get('activeProfileId')).toBe('a')
    expect(state.stop).not.toHaveBeenCalled()
    expect(state.restore).not.toHaveBeenCalled()
    expect(state.restartProtected).not.toHaveBeenCalled()
    expect(state.ipMonitor.clearVpnIp).not.toHaveBeenCalled()
  })

  it('ignores user cancellation after upstream commit while previous cleanup drains (AT-00-003)', async () => {
    state.storeData.set('activeProfileId', 'a')
    const held = deferred<any>()
    state.switchOutbound.mockImplementationOnce((_next, options) => { options.onCommit(); return held.promise })
    const pending = selectProfileHandler({}, 'b')
    await vi.waitFor(() => expect(state.switchOutbound).toHaveBeenCalledOnce())
    const options = state.switchOutbound.mock.calls[0][1]
    await cancelSwitchHandler({})
    expect(options.signal.aborted).toBe(false)
    held.resolve({ outcome: 'success', committed: true, activeSlot: 'b', previousPreserved: false,
      candidateStopped: false, previousStopped: true, failures: [] })
    await expect(pending).resolves.toBeUndefined()
    expect(state.storeData.get('activeProfileId')).toBe('b')
    expect(state.stop).not.toHaveBeenCalled()
    expect(state.restore).not.toHaveBeenCalled()
  })

  it.each([false, true])('disconnect supersedes a staged upstream even after commit=%s (AT-00-003)', async committed => {
    const held = deferred<any>()
    state.storeData.set('activeProfileId', 'a')
    state.switchOutbound.mockImplementationOnce((_next, options) => {
      if (committed) options.onCommit()
      return held.promise
    })
    const pending = selectProfileHandler({}, 'b')
    await vi.waitFor(() => expect(state.switchOutbound).toHaveBeenCalledOnce())
    const options = state.switchOutbound.mock.calls[0][1]
    const { abandonProfileSwitch } = await import('./serverPicker')
    abandonProfileSwitch()
    expect(options.signal.aborted).toBe(true)
    expect(options.isOwner()).toBe(false)
    held.resolve({ outcome: 'cancelled', committed, activeSlot: null, previousPreserved: false,
      candidateStopped: !committed, previousStopped: committed, failures: [] })
    await expect(pending).resolves.toEqual({ cancelled: true })
    expect(state.storeData.get('activeProfileId')).toBe(committed ? 'b' : 'a')
    expect(state.stop).not.toHaveBeenCalled()
    expect(state.restore).not.toHaveBeenCalled()
  })

  it.each([false, true])('failed candidate with previous proof=%s uses only required cleanup (AT-02-011)', async previousPreserved => {
    state.storeData.set('activeProfileId', 'a')
    state.switchOutbound.mockResolvedValueOnce({ outcome: 'failed', committed: false, activeSlot: previousPreserved ? 'a' : null,
      previousPreserved, candidateStopped: true, previousStopped: false, failures: [] })
    await expect(selectProfileHandler({}, 'b')).rejects.toThrow('upstream')
    expect(state.storeData.get('activeProfileId')).toBe('a')
    expect(state.stop).toHaveBeenCalledTimes(previousPreserved ? 0 : 1)
    expect(state.restore).not.toHaveBeenCalled()
    expect(state.restartProtected).not.toHaveBeenCalled()
  })

  it.each([false, true])('native owner loss during switch preserves successor recovery, committed=%s (AT-00-007 / AT-02-011)', async committed => {
    state.storeData.set('activeProfileId', 'a')
    state.switchOutbound.mockImplementationOnce(async (_next, options) => {
      if (committed) options.onCommit()
      return { outcome: 'cancelled', committed, activeSlot: null, previousPreserved: false,
        candidateStopped: !committed, previousStopped: committed, ownershipLost: true, failures: [] }
    })
    await expect(selectProfileHandler({}, 'b')).resolves.toEqual({ cancelled: true })
    expect(state.storeData.get('activeProfileId')).toBe(committed ? 'b' : 'a')
    expect(state.stop).not.toHaveBeenCalled()
    expect(state.restore).not.toHaveBeenCalled()
    expect(state.restartProtected).not.toHaveBeenCalled()
    expect(state.ipMonitor.clearVpnIp).not.toHaveBeenCalled()
  })

  it('retains the committed profile when old cleanup fails instead of restarting it (AT-02-011)', async () => {
    state.storeData.set('activeProfileId', 'a')
    state.switchOutbound.mockImplementationOnce(async (_next, options) => {
      options.onCommit()
      return { outcome: 'failed', committed: true, activeSlot: 'b', previousPreserved: false,
        candidateStopped: false, previousStopped: false, failures: [{ phase: 'stop-previous', message: 'unknown' }] }
    })
    await expect(selectProfileHandler({}, 'b')).rejects.toThrow('upstream')
    expect(state.storeData.get('activeProfileId')).toBe('b')
    expect(state.stop).not.toHaveBeenCalled()
    expect(state.restore).not.toHaveBeenCalled()
  })

  it('reports unconfirmed rollback after a failed upstream instead of silently succeeding (AT-02-004)', async () => {
    state.switchOutbound.mockResolvedValueOnce({ outcome: 'failed', committed: false, activeSlot: null,
      previousPreserved: false, candidateStopped: false, previousStopped: false, failures: [] })
    state.stop.mockResolvedValueOnce({ success: true, networkCleanup: { baseline: true, firewall: false, adapters: true } })
    await expect(selectProfileHandler({}, 'b')).rejects.toThrow('Очистка')
    expect(state.restore).not.toHaveBeenCalled()
  })

  it.each(['complete', 'baseline', 'firewall', 'adapters', 'failed', 'missing'] as const)(
    'reuses only complete cleanup from this cancelled restart: %s (AT-00-003 / AT-03-007)', async kind => {
      const restart = deferred<{ success: boolean; error?: string }>()
      state.restartProtected.mockReturnValueOnce(restart.promise)
      state.storeData.set('activeProfileId', 'a')
      const pending = selectProfileHandler({}, 'b')
      await vi.waitFor(() => expect(state.restartProtected).toHaveBeenCalledOnce())
      await cancelSwitchHandler({})
      const receipt = { success: kind !== 'failed', networkCleanup: kind === 'missing' ? undefined : {
        baseline: kind !== 'baseline', firewall: kind !== 'firewall', adapters: kind !== 'adapters'
      } }
      state.restartProtected.mock.calls[0][2].onCleanup?.(receipt)
      expect(state.restore).not.toHaveBeenCalled()
      state.tunnelStatus.running = false
      restart.resolve({ success: false, error: 'new startup cancelled' })
      await expect(pending).resolves.toEqual({ cancelled: true })
      expect(state.stop).toHaveBeenCalledTimes(kind === 'complete' ? 0 : 1)
      expect(state.restore).toHaveBeenCalledExactlyOnceWith(state.lastOptions)
      expect(state.storeData.get('activeProfileId')).toBe('a')
    })
  it('does not attach geo evidence to an in-progress profile switch (AT-00-003)', async () => {
    const held = deferred<{ success: boolean }>()
    state.restartProtected.mockReturnValueOnce(held.promise)
    const pending = selectProfileHandler({}, 'a')
    await vi.waitFor(() => expect(state.restartProtected).toHaveBeenCalledOnce())
    expect(await state.ipcHandlers.get('servers:verify-active-country')!({}, '198.51.100.20'))
      .toMatchObject({ok:false,reason:'profile-switch-in-progress'})
    held.resolve({success:true})
    await pending
  })
  it('invalidates adaptive work before selecting or waiting for network identity (AT-10-003)', async () => {
    const { setProfileSwitchHooks } = await import('./serverPicker')
    const end = vi.fn()
    const gate = deferred<void>()
    const begin = vi.fn(() => gate.promise)
    setProfileSwitchHooks({ begin, end })
    const pending = selectProfileHandler({}, 'a')
    expect(begin).toHaveBeenCalledOnce()
    expect(state.storeData.get('activeProfileId') ?? null).toBeNull()
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
    const cancelled = expect(pending).resolves.toEqual({ cancelled: true })
    await vi.waitFor(() => expect(state.networkIdentity).toHaveBeenCalledOnce())
    await cancelSwitchHandler({})
    identity.resolve('fixture-network-hmac')
    await cancelled
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
    await expect(firstSwitch).resolves.toEqual({ cancelled: true })
    expect(state.stop).toHaveBeenCalledTimes(1)

    await expect(selectProfileHandler({}, 'b')).resolves.toBeUndefined()
    expect(state.storeData.get('activeProfileId')).toBe('b')
  })

  it('returns cancellation after Xray startup rollback, holds the guard until cleanup completes (AT-00-003)', async () => {
    const restart = deferred<{ success: boolean; error?: string }>()
    state.restartProtected.mockReturnValueOnce(restart.promise)
    const pending = selectProfileHandler({}, 'a')
    await vi.waitFor(() => expect(state.restartProtected).toHaveBeenCalledOnce())
    await cancelSwitchHandler({})
    await expect(selectProfileHandler({}, 'b')).rejects.toThrow('уже выполняется')
    state.tunnelStatus.running = false
    restart.resolve({ success: false, error: 'Ошибка запуска движка xray-core: Xray startup cancelled' })
    await expect(pending).resolves.toEqual({ cancelled: true })
    await expect(selectProfileHandler({}, 'b')).resolves.toBeUndefined()
    expect(state.restartProtected).toHaveBeenCalledOnce()
  })

  it('preserves a real startup failure without a cancellation request (AT-00-004)', async () => {
    state.restartProtected.mockResolvedValueOnce({ success: false, error: 'Xray startup failed' })
    await expect(selectProfileHandler({}, 'a')).rejects.toThrow('Xray startup failed')
  })

  it('does not disguise failed cancellation cleanup as an ordinary cancelled result (AT-00-004)', async () => {
    const restart = deferred<{ success: boolean }>()
    state.restartProtected.mockReturnValueOnce(restart.promise)
    state.stop.mockRejectedValueOnce(new Error('Owned runtime exit not proven'))
    const pending = selectProfileHandler({}, 'a')
    await vi.waitFor(() => expect(state.restartProtected).toHaveBeenCalledOnce())
    await cancelSwitchHandler({})
    restart.resolve({ success: true })
    await expect(pending).rejects.toThrow('Owned runtime exit not proven')
    expect(state.ipMonitor.clearVpnIp).not.toHaveBeenCalled()
  })

  it('cancels before profile selection when begin is still pending (AT-00-003)', async () => {
    const { setProfileSwitchHooks } = await import('./serverPicker')
    const gate = deferred<void>()
    const end = vi.fn()
    setProfileSwitchHooks({ begin: () => gate.promise, end })
    const pending = selectProfileHandler({}, 'a')
    await cancelSwitchHandler({})
    gate.resolve()
    await expect(pending).resolves.toEqual({ cancelled: true })
    expect(state.storeData.get('activeProfileId') ?? null).toBeNull()
    expect(state.restartProtected).not.toHaveBeenCalled()
    expect(end).toHaveBeenCalledOnce()
  })
  it('restores the exact former runtime and selected profile after a cancelled new startup (AT-02-004 / AT-00-003)', async () => {
    state.storeData.set('activeProfileId', 'a')
    const restart = deferred<{ success: boolean; error?: string }>()
    state.restartProtected.mockReturnValueOnce(restart.promise)
    const pending = selectProfileHandler({}, 'b')
    await vi.waitFor(() => expect(state.restartProtected).toHaveBeenCalledOnce())
    await cancelSwitchHandler({})
    expect(state.cancelTransition).toHaveBeenCalledOnce()
    expect(state.restartProtected.mock.calls[0][2].signal.aborted).toBe(true)
    expect(state.restore).not.toHaveBeenCalled()
    state.tunnelStatus.running = false
    restart.resolve({ success: false, error: 'new startup cancelled' })
    await expect(pending).resolves.toEqual({ cancelled: true })
    expect(state.restore).toHaveBeenCalledExactlyOnceWith(state.lastOptions)
    expect(state.storeData.get('activeProfileId')).toBe('a')
    expect(state.restore.mock.invocationCallOrder[0]).toBeGreaterThan(state.stop.mock.invocationCallOrder[0])
  })
  it('holds the switch guard through restoration and ignores repeated cancellation (AT-00-003)', async () => {
    const restart = deferred<{ success: boolean }>(), restore = deferred<{ success: boolean }>()
    state.restartProtected.mockReturnValueOnce(restart.promise)
    state.restore.mockReturnValueOnce(restore.promise)
    const pending = selectProfileHandler({}, 'b')
    await vi.waitFor(() => expect(state.restartProtected).toHaveBeenCalledOnce())
    await cancelSwitchHandler({})
    restart.resolve({ success: true })
    await vi.waitFor(() => expect(state.restore).toHaveBeenCalledOnce())
    await expect(selectProfileHandler({}, 'a')).rejects.toThrow('уже выполняется')
    await cancelSwitchHandler({})
    expect(state.cancelTransition).toHaveBeenCalledOnce()
    restore.resolve({ success: true })
    await expect(pending).resolves.toEqual({ cancelled: true })
  })
  it('keeps the old live runtime when cancelled before native restart (AT-02-004)', async () => {
    state.settings = { adaptiveBypassEnabled: true }
    state.storeData.set('activeProfileId', 'a')
    const identity = deferred<string>()
    state.networkIdentity.mockReturnValue(identity.promise)
    const pending = selectProfileHandler({}, 'b')
    await vi.waitFor(() => expect(state.networkIdentity).toHaveBeenCalledOnce())
    await cancelSwitchHandler({})
    identity.resolve('fixture-network-hmac')
    await expect(pending).resolves.toEqual({ cancelled: true })
    expect(state.storeData.get('activeProfileId')).toBe('a')
    expect(state.cancelTransition).not.toHaveBeenCalled()
    expect(state.stop).not.toHaveBeenCalled()
    expect(state.restore).not.toHaveBeenCalled()
  })
  it('reports restoration failure instead of ordinary cancellation (AT-00-004)', async () => {
    const restart = deferred<{ success: boolean }>()
    state.restartProtected.mockReturnValueOnce(restart.promise)
    state.restore.mockResolvedValueOnce({ success: false, error: 'old server unreachable' })
    const pending = selectProfileHandler({}, 'b')
    const rejected = expect(pending).rejects.toThrow('old server unreachable')
    await vi.waitFor(() => expect(state.restartProtected).toHaveBeenCalledOnce())
    await cancelSwitchHandler({})
    restart.resolve({ success: true })
    await rejected
  })
  it('does not start the old runtime after incomplete cleanup (AT-03-007)', async () => {
    const restart = deferred<{ success: boolean }>()
    state.restartProtected.mockReturnValueOnce(restart.promise)
    state.stop.mockResolvedValueOnce({ success: false, error: 'firewall rollback unconfirmed' } as any)
    const pending = selectProfileHandler({}, 'b')
    const rejected = expect(pending).rejects.toThrow('firewall rollback unconfirmed')
    await vi.waitFor(() => expect(state.restartProtected).toHaveBeenCalledOnce())
    await cancelSwitchHandler({})
    restart.resolve({ success: true })
    await rejected
    expect(state.restore).not.toHaveBeenCalled()
  })
  it('lets disconnect or shutdown supersede cancellation while the new attempt drains (AT-02-004)', async () => {
    const restart = deferred<{ success: boolean }>()
    state.restartProtected.mockReturnValueOnce(restart.promise)
    const pending = selectProfileHandler({}, 'b')
    await vi.waitFor(() => expect(state.restartProtected).toHaveBeenCalledOnce())
    await cancelSwitchHandler({})
    const { abandonProfileSwitch } = await import('./serverPicker')
    abandonProfileSwitch()
    restart.resolve({ success: true })
    await expect(pending).resolves.toEqual({ cancelled: true })
    expect(state.restore).not.toHaveBeenCalled()
  })
  it('does not leave a cancellation flag when no switch exists (AT-00-003)', async () => {
    await cancelSwitchHandler({})
    expect(state.cancelTransition).not.toHaveBeenCalled()
    await expect(selectProfileHandler({}, 'b')).resolves.toBeUndefined()
  })

  it('lets disconnect win while cancellation cleanup is still draining (AT-02-004)', async () => {
    const restart = deferred<{ success: boolean }>(), cleanup = deferred<any>()
    state.restartProtected.mockReturnValueOnce(restart.promise)
    state.stop.mockReturnValueOnce(cleanup.promise)
    const pending = selectProfileHandler({}, 'b')
    await vi.waitFor(() => expect(state.restartProtected).toHaveBeenCalledOnce())
    await cancelSwitchHandler({})
    restart.resolve({ success: true })
    await vi.waitFor(() => expect(state.stop).toHaveBeenCalledOnce())
    ;(await import('./serverPicker')).abandonProfileSwitch()
    cleanup.resolve({ success: true, networkCleanup: { baseline: true, firewall: true, adapters: true } })
    await expect(pending).resolves.toEqual({ cancelled: true })
    expect(state.restore).not.toHaveBeenCalled()
  })
  it('does not invent former runtime options when they are unavailable (AT-00-004)', async () => {
    state.lastOptions = null
    const restart = deferred<{ success: boolean }>()
    state.restartProtected.mockReturnValueOnce(restart.promise)
    const pending = selectProfileHandler({}, 'b')
    const rejected = expect(pending).rejects.toThrow('параметры запуска недоступны')
    await vi.waitFor(() => expect(state.restartProtected).toHaveBeenCalledOnce())
    await cancelSwitchHandler({})
    restart.resolve({ success: true })
    await rejected
    expect(state.restore).not.toHaveBeenCalled()
  })
  it('cancels during fresh IP acquisition after the new runtime has already started (AT-07-012)', async () => {
    state.storeData.set('activeProfileId', 'a')
    const ip = deferred<{ ip: string }>()
    state.ipMonitor.recheck.mockReturnValueOnce(ip.promise)
    const pending = selectProfileHandler({}, 'b')
    await vi.waitFor(() => expect(state.ipMonitor.recheck).toHaveBeenCalledOnce())
    await cancelSwitchHandler({})
    expect(state.cancelTransition).not.toHaveBeenCalled()
    ip.resolve({ ip: '198.51.100.99' })
    await expect(pending).resolves.toEqual({ cancelled: true })
    expect(state.restore).toHaveBeenCalledExactlyOnceWith(state.lastOptions)
    expect(state.storeData.get('activeProfileId')).toBe('a')
    expect(state.ipMonitor.recheck).toHaveBeenCalledTimes(2)
  })

})
