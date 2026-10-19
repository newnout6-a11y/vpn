// AT-00-003/005/007: actual picker, refresh, registry and IPC guard; controlled resolver boundary.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({ data: new Map<string, Record<string, any>>(), write: vi.fn(), resolve: vi.fn(), log: vi.fn(), handle: vi.fn(), handlers: new Map<string, (...args: any[]) => any>() }))
vi.mock('electron', () => ({ app: { isPackaged: false, getPath: () => '/tmp/unused-import-fixture' }, dialog: {}, ipcMain: { handle: state.handle } }))
vi.mock('electron-store', () => ({ default: class {
  readonly name: string
  constructor(options: { name: string; defaults?: object }) { this.name = options.name; if (!state.data.has(this.name)) state.data.set(this.name, structuredClone(options.defaults ?? {})) }
  get(key: string, fallback?: unknown) { return state.data.get(this.name)?.[key] ?? fallback }
  set(key: string, value: unknown) { state.write(this.name, key, value); state.data.get(this.name)![key] = structuredClone(value) }
  get path() { return `/tmp/unused-import-fixture/${this.name}.json` }
  get store() { return state.data.get(this.name) }
  set store(value: Record<string, any> | undefined) { state.write(this.name, 'store', value); state.data.set(this.name, structuredClone(value ?? {})) }
} }))
vi.mock('./appLogger', () => ({ logEvent: state.log }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({ disableGeoLookup: true, bootstrapRouteMode: 'direct' }) } }))
vi.mock('./vpnProfiles', async () => {
  const actual = await vi.importActual<typeof import('./vpnProfiles')>('./vpnProfiles')
  return { ...actual, resolveVpnProfiles: (...args: any[]) => state.resolve(...args) }
})
vi.mock('./tunController', () => ({ getDirectProxyPort: () => 1080, tunController: { getStatus: () => ({ running: false }), setWatchdogProbeConfirmationChecker: vi.fn() } }))
vi.mock('./adaptiveBypass', () => ({ beginAdaptiveConnection: vi.fn(), readAdaptiveNetworkFingerprint: vi.fn() }))
vi.mock('./ipMonitor', () => ({ ipMonitor: {} }))

let picker: typeof import('./serverPicker'), groups: typeof import('./serverGroups').serverGroups, registry: typeof import('./operations').operations
const releases = new Set<() => void>()
function response(server = 'new.example.test') { return { profiles: [{ name: server, protocol: 'vless', outbound: { type: 'vless', server, server_port: 443 } }], source: 'fixture', fetched: true } }
function held(server = 'late.example.test') {
  let release!: () => void
  const promise = new Promise<ReturnType<typeof response>>(done => { release = () => done(response(server)) })
  releases.add(release)
  return { promise, release }
}
const snapshot = () => JSON.stringify([...state.data.entries()])

beforeEach(async () => {
  vi.resetModules()
  vi.clearAllMocks()
  state.log.mockReset()
  state.data.clear()
  // These rollback cases start with existing canonical empty stores. A fresh
  // read deliberately no longer persists defaults as a fake legacy migration.
  state.data.set('server-picker', { profiles: [], schemaVersion: 2, activeProfileId: null })
  state.data.set('server-groups', { groups: [] })
  state.write.mockReset()
  state.handlers.clear()
  state.resolve.mockReset().mockResolvedValue(response())
  state.handle.mockImplementation((channel, handler) => state.handlers.set(channel, handler))
  const { ipcMain } = await import('electron')
  ipcMain.handle = state.handle
  delete (ipcMain as any)[Symbol.for('vpnte.ipc.trusted-boundary.installed')]
  ;(await import('./ipcSecurity')).installTrustedIpcBoundary()
  picker = await import('./serverPicker')
  groups = (await import('./serverGroups')).serverGroups
  const operations = await import('./operations')
  registry = operations.operations
  operations.registerOperationHandlers()
  picker.registerServerPickerHandlers()
  // Main startup preflights persisted stores before accepting feature actions.
  picker.serverPicker.getProfiles()
  groups.getGroups()
  state.write.mockClear()
})
afterEach(async () => {
  const closing = registry?.close()
  for (const release of releases) release()
  releases.clear()
  await closing
  vi.useRealTimers()
})

describe('profile import operation ownership', () => {
  it.each(['https://sub.example.test/new', 'vless://fixture@uri.example.test:443'])('cancels %s during resolution without a late group or profile', async input => {
    const gate = held(), controller = new AbortController(), before = snapshot()
    state.resolve.mockReturnValue(gate.promise)
    const run = picker.addFromInput(input, { signal: controller.signal })
    const rejected = expect(run).rejects.toMatchObject({ category: 'cancelled' })
    await vi.waitFor(() => expect(state.resolve).toHaveBeenCalledOnce())
    const signal = state.resolve.mock.calls[0][1].signal
    const start = performance.now()
    controller.abort()
    await rejected
    expect(performance.now() - start).toBeLessThan(900)
    expect(signal.aborted).toBe(true)
    await expect(picker.addFromInput(input)).rejects.toMatchObject({ category: 'conflict' })
    gate.release()
    await registry.close()
    expect(snapshot()).toBe(before)
    expect(state.log.mock.calls.some(call => /added from|appended to/.test(call[2]))).toBe(false)
  })

  it.each(['subscription', 'uri', 'target'])('does not commit a queued %s import after cancellation', async kind => {
    const gate = held(), controller = new AbortController()
    const target = kind === 'target' ? groups.createGroup({ name: 'Target', source: 'manual', status: 'unknown', importedAt: 1 }) : null
    const before = snapshot()
    const { withProfileStoreWriteLock } = await import('./profileStoreQueue')
    const blocking = withProfileStoreWriteLock(() => gate.promise)
    const input = kind === 'uri' ? 'vless://fixture@uri.example.test:443' : 'https://sub.example.test/new'
    const run = target ? picker.addFromInputToGroup(input, target.id, { signal: controller.signal }) : picker.addFromInput(input, { signal: controller.signal })
    const rejected = expect(run).rejects.toMatchObject({ category: 'cancelled' })
    await vi.waitFor(() => expect(state.resolve).toHaveBeenCalledOnce())
    expect(snapshot()).toBe(before)
    controller.abort()
    await rejected
    gate.release()
    await blocking
    await registry.close()
    expect(snapshot()).toBe(before)
  })

  it('cancels a held import at shutdown and waits for its physical drain', async () => {
    const gate = held(), before = snapshot()
    state.resolve.mockReturnValue(gate.promise)
    const run = picker.addFromInput('https://sub.example.test/new')
    const rejected = expect(run).rejects.toMatchObject({ category: 'cancelled' })
    let drained = false
    const closing = registry.close().then(() => { drained = true })
    await rejected
    expect(drained).toBe(false)
    expect(registry.list()).toMatchObject([{ status: 'cancelled' }])
    gate.release()
    await closing
    expect(snapshot()).toBe(before)
    expect(drained).toBe(true)
  })

  it.each(['profiles', 'activeProfileId', 'groups'])('rolls back a failed %s write including the new group', async key => {
    const before = snapshot()
    let fail = true
    state.write.mockImplementation((_name: string, writeKey: string) => {
      if (fail && writeKey === key) { fail = false; throw new Error('fixture write failed') }
    })
    await expect(picker.addFromInput('https://sub.example.test/new')).rejects.toThrow('fixture write failed')
    expect(snapshot()).toBe(before)
    expect(registry.list()).toMatchObject([{ kind: 'import', status: 'error' }])
    expect(state.log.mock.calls.some(call => /added from|appended to/.test(call[2]))).toBe(false)
  })

  it('reports an internal failure when a partial commit cannot be restored', async () => {
    let written = false
    state.write.mockImplementation((_name: string, key: string) => {
      if (key === 'activeProfileId') throw Object.assign(new Error('private-import-path'), { code: 'EACCES' })
      if (key === 'profiles' && written) throw new Error('fixture disk unavailable')
      if (key === 'profiles') written = true
    })
    await expect(picker.addFromInput('https://sub.example.test/new')).rejects.toMatchObject({ category: 'internal' })
    expect(state.log).toHaveBeenCalledWith('error', 'server-picker', 'profile import rollback failed', { category: 'internal', causeCategory: 'permission', commitStep: 'active-profile' })
    expect(JSON.stringify(state.log.mock.calls)).not.toContain('private-import-path')
    expect(registry.list()).toMatchObject([{ status: 'error', category: 'internal' }])
    expect(state.log.mock.calls.some(call => /added from|appended to/.test(call[2]))).toBe(false)
  })

  it('times out a stalled import and keeps its raw work owned until drain', async () => {
    const gate = held()
    state.resolve.mockReturnValue(gate.promise)
    vi.useFakeTimers()
    const run = picker.addFromInput('https://sub.example.test/new')
    const rejected = expect(run).rejects.toMatchObject({ category: 'timeout' })
    await vi.advanceTimersByTimeAsync(120_000)
    await rejected
    expect(registry.list()).toMatchObject([{ kind: 'import', status: 'error', category: 'timeout' }])
    gate.release()
    await registry.close()
    expect(groups.getGroups()).toEqual([])
    expect(picker.serverPicker.getProfiles()).toEqual([])
  })

  it('rejects a deleted append target instead of resurrecting orphan profiles', async () => {
    const target = groups.createGroup({ name: 'Target', source: 'manual', status: 'unknown', importedAt: 1 })
    const gate = held()
    state.resolve.mockReturnValue(gate.promise)
    const run = picker.addFromInputToGroup('https://sub.example.test/new', target.id)
    const rejected = expect(run).rejects.toMatchObject({ category: 'conflict' })
    groups.deleteGroup(target.id)
    gate.release()
    await rejected
    expect(picker.serverPicker.getProfiles()).toEqual([])
    expect(groups.getGroups()).toEqual([])
  })

  it('rejects an append target whose source changed while the resolver was pending', async () => {
    const target = groups.createGroup({ name: 'Target', source: 'subscription', sourceUrl: 'https://sub.example.test/old', status: 'active', importedAt: 1 })
    const gate = held()
    state.resolve.mockReturnValue(gate.promise)
    const run = picker.addFromInputToGroup('https://sub.example.test/new', target.id)
    const rejected = expect(run).rejects.toMatchObject({ category: 'conflict' })
    groups.updateGroup(target.id, { sourceUrl: 'https://sub.example.test/replacement' })
    gate.release()
    await rejected
    expect(picker.serverPicker.getProfiles()).toEqual([])
    expect(groups.getGroup(target.id)?.sourceUrl).toBe('https://sub.example.test/replacement')
  })

  it('owns a re-pasted subscription as one cancellable refresh and returns only that group additions', async () => {
    const target = groups.createGroup({ name: 'Existing', source: 'subscription', sourceUrl: 'https://sub.example.test/existing', status: 'active', importedAt: 1 })
    const gate = held(), controller = new AbortController()
    state.resolve.mockReturnValue(gate.promise)
    const run = picker.addFromInput(target.sourceUrl!, { signal: controller.signal })
    const rejected = expect(run).rejects.toMatchObject({ category: 'cancelled' })
    expect(registry.list()).toMatchObject([{ kind: 'refresh', status: 'running' }])
    controller.abort()
    await rejected
    gate.release()
    await registry.close()
    expect(picker.serverPicker.getProfiles()).toEqual([])
    expect(groups.getGroups()).toHaveLength(1)
  })

  it('keeps a committed re-paste successful when its signal aborts at terminal publication', async () => {
    const target = groups.createGroup({ name: 'Existing', source: 'subscription', sourceUrl: 'https://sub.example.test/existing', status: 'active', importedAt: 1 })
    const controller = new AbortController()
    state.log.mockImplementation((_level, _scope, message, details) => {
      if (message === 'feature operation' && details.kind === 'refresh' && details.status === 'success') controller.abort()
    })
    const imported = await picker.addFromInput(target.sourceUrl!, { signal: controller.signal })
    expect(controller.signal.aborted).toBe(true)
    expect(imported).toHaveLength(1)
    expect(picker.serverPicker.getProfiles()).toEqual(imported)
    expect(registry.list()).toMatchObject([{ kind: 'refresh', status: 'success' }])
  })

  it('keeps independent concurrent imports and serializes their commits', async () => {
    const gates = [held('one.example.test'), held('two.example.test')]
    state.resolve.mockImplementation((input: string) => gates[input.endsWith('/one') ? 0 : 1].promise)
    const one = picker.addFromInput('https://sub.example.test/one')
    const two = picker.addFromInput('https://sub.example.test/two')
    gates[1].release()
    const second = await two
    gates[0].release()
    const first = await one
    expect(groups.getGroups()).toHaveLength(2)
    expect(picker.serverPicker.getProfiles()).toHaveLength(2)
    expect(new Set([...first, ...second].map(profile => profile.id)).size).toBe(2)
    expect(registry.list().map(op => op.status)).toEqual(['success', 'success'])
  })

  it('uses one group for concurrent device variants of a new subscription', async () => {
    const gates = [held('pc.example.test'), held('android.example.test')]
    state.resolve.mockImplementation((_input: string, options: { clientDevice: string }) => gates[options.clientDevice === 'pc' ? 0 : 1].promise)
    const one = picker.addFromInput('https://sub.example.test/new', { clientDevice: 'pc' })
    const two = picker.addFromInput('https://sub.example.test/new', { clientDevice: 'android' })
    gates.forEach(gate => gate.release())
    const [pc, android] = await Promise.all([one, two])
    expect(groups.getGroups()).toHaveLength(1)
    expect(picker.serverPicker.getProfiles()).toHaveLength(2)
    expect(pc[0].groupId).toBe(android[0].groupId)
  })

  it('returns only its own refreshed group when another import completes concurrently', async () => {
    const target = groups.createGroup({ name: 'Existing', source: 'subscription', sourceUrl: 'https://sub.example.test/existing', status: 'active', importedAt: 1 })
    const gate = held('refreshed.example.test')
    state.resolve.mockImplementation((input: string) => input === target.sourceUrl ? gate.promise : Promise.resolve(response('other.example.test')))
    const refreshed = picker.addFromInput(target.sourceUrl!)
    const imported = await picker.addFromInput('https://sub.example.test/other')
    gate.release()
    const result = await refreshed
    expect(result).toHaveLength(1)
    expect(result[0].groupId).toBe(target.id)
    expect(result[0].id).not.toBe(imported[0].id)
    expect(picker.serverPicker.getProfiles()).toHaveLength(2)
  })

  it('cancels through guarded IPC with the original correlation and no late persistence', async () => {
    const gate = held()
    state.resolve.mockReturnValue(gate.promise)
    const run = state.handlers.get('servers:add')!({}, 'https://sub.example.test/new')
    const listing = await state.handlers.get('operations:list')!({})
    const operation = listing.result[0]
    expect(operation).toMatchObject({ kind: 'import', owner: 'manual', source: 'ipc' })
    expect(await state.handlers.get('operations:cancel')!({}, operation.operationId)).toMatchObject({ ok: true, result: true })
    expect(await run).toMatchObject({ ok: false, correlationId: operation.correlationId, error: { category: 'cancelled', code: 'IPC_CANCELLED' } })
    gate.release()
    await registry.close()
    expect(groups.getGroups()).toEqual([])
    expect(picker.serverPicker.getProfiles()).toEqual([])
  })
})
