// AT-00-003/004/005/008: production health workers with controlled OS boundaries.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { checkGroupHealth } from './keyHealthChecker'
import { operations } from './operations'
import { logEvent } from './appLogger'
import { withProfileStoreWriteLock } from './profileStoreQueue'
import { withCorrelation } from './actionCorrelation'
import { OPERATION_DEADLINES } from '../shared/operation'
import { classifyIpcError } from '../shared/ipc-result'

const state = vi.hoisted(() => ({
  profiles: [] as any[], groups: [] as any[], writes: vi.fn(),
  boundary: vi.fn(async (_stage: string) => {}), children: [] as any[],
  holdClose: false, sockets: [] as any[], tlsThrows: false,
  spawnError: undefined as Error | undefined, spawnThrows: false
}))
vi.mock('electron', () => ({ ipcMain: { handle: vi.fn() } }))
vi.mock('./sharedStores', () => ({
  serverGroupsStore: { get: () => state.groups },
  serverPickerStore: { get: () => state.profiles, set: (_key: string, value: any[]) => { state.writes(value); state.profiles = value } }
}))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({ proxyEngine: 'sing-box' }) } }))
vi.mock('./proxyEngine', () => ({ resolveProxyEngine: () => 'sing-box' }))
vi.mock('./xrayEngine', () => ({ buildXrayProbeConfig: vi.fn(), resolveXrayConfigEndpoints: vi.fn() }))
vi.mock('./nativeXrayProfile', () => ({ getNativeXrayProfile: () => null }))
vi.mock('./xrayDns', () => ({ resolveXrayEndpoint: vi.fn() }))
vi.mock('./managedChildProcess', () => ({
  cleanupManagedChildPidDirs: () => state.boundary('startup'),
  writeManagedChildPidFile: () => state.boundary('pidfile'),
  removeManagedChildPidFile: () => state.boundary('remove-pid')
}))
vi.mock('fs/promises', () => ({
  mkdtemp: async () => { await state.boundary('directory'); return '/controlled/key-probe' },
  writeFile: () => state.boundary('config'), readFile: async () => '',
  rm: () => state.boundary('remove-directory')
}))
vi.mock('./physicalAdapterLockdown', () => ({ getPhysicalAdapterDnsSources: async () => { await state.boundary('adapter'); return [] } }))
vi.mock('./tunController', () => ({
  tunController: { getStatus: () => ({ running: false }) }, getDirectProxyPort: () => null,
  getBundledResource: () => '/controlled/sing-box.exe',
  pickFreeLocalPort: async () => { await state.boundary('port'); return 50123 },
  sanitizeProxyOutbound: (outbound: unknown) => ({ outbound, needsBootstrapDns: false })
}))
vi.mock('child_process', async () => {
  const { EventEmitter } = await import('node:events')
  return { spawn: vi.fn(() => {
    if (state.spawnThrows) throw state.spawnError
    const child = Object.assign(new EventEmitter(), {
      pid: 100 + state.children.length, killed: false, exitCode: null, signalCode: null,
      stdout: new EventEmitter(), stderr: new EventEmitter(),
      kill: vi.fn(() => { child.killed = true; if (!state.holdClose) queueMicrotask(() => child.emit('close', 0)); return true })
    })
    state.children.push(child)
    if (state.spawnError) queueMicrotask(() => { child.emit('error', state.spawnError); child.emit('close', -1) })
    return child
  }) }
})
vi.mock('net', async importOriginal => {
  const original = await importOriginal<typeof import('net')>()
  const { EventEmitter } = await import('node:events')
  return { ...original, Socket: class extends EventEmitter {
    destroy = vi.fn(() => { queueMicrotask(() => this.emit('close')); return this })
    setTimeout() { return this }
    connect() { void state.boundary('inbound').then(() => this.emit('connect')); return this }
  } }
})
vi.mock('socks', async () => {
  const { EventEmitter } = await import('node:events')
  return { SocksClient: { createConnection: async () => {
  await state.boundary('socks')
  const socket = Object.assign(new EventEmitter(), { destroy: vi.fn(() => { void state.boundary('socket-close').then(() => socket.emit('close')) }) })
  state.sockets.push(socket)
  return { socket }
} } } })
vi.mock('tls', async () => {
  const { EventEmitter } = await import('node:events')
  return { connect: () => {
    if (state.tlsThrows) throw new Error('FAKE-TLS setup failure')
    const tls = Object.assign(new EventEmitter(), { destroy: vi.fn(() => { void state.boundary('tls-close').then(() => tls.emit('close')) }), write: vi.fn() })
    void state.boundary('tls').then(() => {
      tls.emit('secureConnect')
      tls.emit('data', Buffer.from('HTTP/1.1 200 OK\r\n\r\nip=8.8.8.8\nloc=US\n'))
    })
    return tls
  } }
})

const releases = new Set<() => void>()
function hold(stage: string) {
  let release!: () => void
  const pending = new Promise<void>(done => { release = done })
  releases.add(release)
  state.boundary.mockImplementation(async current => { if (current === stage) await pending })
  return release
}
const flush = async () => { for (let i = 0; i < 60; i++) await Promise.resolve() }
const signalOptions = (signal: AbortSignal) => ({ signal })
beforeEach(() => {
  state.profiles = [{ id: 'p', groupId: 'g', protocol: 'vless', server: 'vpn.example.test', port: 443, outbound: { type: 'vless', server: 'vpn.example.test', server_port: 443, uuid: 'test' } }]
  state.groups = [{ id: 'g' }]
  state.children = []; state.sockets = []; state.holdClose = false; state.tlsThrows = false
  state.spawnError = undefined; state.spawnThrows = false
  state.writes.mockClear(); state.boundary.mockReset().mockResolvedValue(undefined)
  vi.mocked(logEvent).mockClear()
})
afterEach(async () => {
  for (const release of releases) release()
  releases.clear()
  for (const child of state.children) child.emit('close', 0)
  for (const socket of state.sockets) socket.destroy()
  await operations.close()
  operations.resumeAdmission()
  vi.useRealTimers()
})

describe('owned group health', () => {
  it.each(['sync', 'async'].flatMap(mode => ['EACCES', 'ENOENT'].map(code => ({ mode, code }))))
  ('preserves a $mode spawn $code failure without declaring keys offline', async ({ mode, code }) => {
    state.spawnThrows = mode === 'sync'
    state.spawnError = Object.assign(new Error('FAKE-private engine path'), { code })
    const error = await checkGroupHealth('g').catch(error => error)
    expect(classifyIpcError(error)).toBe(code === 'EACCES' ? 'permission' : 'internal')
    expect(state.writes).not.toHaveBeenCalled()
  })

  it('keeps remote SOCKS failures as sanitized per-key observations', async () => {
    state.boundary.mockImplementation(async stage => { if (stage === 'socks') throw new Error('FAKE-private reason at C:\\socks') })
    const result = await checkGroupHealth('g')
    expect(result).toMatchObject({ ok: true, results: [{ profileId: 'p', online: false, reason: 'handshake-failed' }] })
    expect(JSON.stringify(result)).not.toContain('FAKE-private')
  })

  it.each(['directory', 'config', 'pidfile'])('does not mark a key offline when local %s I/O is denied', async stage => {
    state.boundary.mockImplementation(async current => {
      if (current === stage) throw Object.assign(new Error('FAKE-private C:\\probe at write'), { code: 'EACCES' })
    })
    const failure = await checkGroupHealth('g').catch(error => error)
    expect(classifyIpcError(failure)).toBe('permission')
    expect(operations.list().at(-1)).toMatchObject({ status: 'error', category: 'permission' })
    expect(state.writes).not.toHaveBeenCalled()
  })

  it('destroys the original SOCKS socket when TLS construction throws', async () => {
    state.tlsThrows = true
    let result: unknown
    const task = checkGroupHealth('g').then(value => { result = value }, error => { result = error })
    void task.catch(() => {})
    await flush()
    expect(result).toMatchObject({ category: 'internal' })
    expect(state.writes).not.toHaveBeenCalled()
    expect(state.sockets.every(socket => socket.destroy.mock.calls.length > 0)).toBe(true)
    await task
  })
  it.each(['directory', 'port', 'adapter', 'config', 'pidfile', 'inbound', 'socks', 'tls'])
  ('cancels at %s without late success/history/persistence and retains physical work', async stage => {
    const release = hold(stage), controller = new AbortController()
    const task = checkGroupHealth('g', signalOptions(controller.signal))
    const result = task.then(value => value, error => error)
    await flush()
    expect(state.boundary).toHaveBeenCalledWith(stage)
    controller.abort()
    await flush()
    const operation = operations.list().at(-1)
    expect(operation).toMatchObject({ kind: 'health-check', status: 'cancelled' })
    expect(await result).toMatchObject({ category: 'cancelled' })
    let drained = false
    const closing = operations.close().then(() => { drained = true })
    await flush()
    expect(drained).toBe(stage === 'tls')
    release()
    await closing
    expect(state.writes).not.toHaveBeenCalled()
    expect(vi.mocked(logEvent).mock.calls.some(call => call[2] === 'group probe finished' || call[2] === 'outbound probe ok' || call[2] === 'outbound probe failed')).toBe(false)
    expect(state.sockets.every(socket => socket.destroy.mock.calls.length > 0)).toBe(true)
    if (['directory', 'port', 'adapter', 'config'].includes(stage)) expect(state.children).toHaveLength(0)
  })

  it('retains the child until close, even after kill has returned', async () => {
    hold('socks'); state.holdClose = true
    const controller = new AbortController()
    const result = checkGroupHealth('g', signalOptions(controller.signal)).catch(error => error)
    await flush()
    controller.abort()
    await flush()
    expect(await result).toMatchObject({ category: 'cancelled' })
    expect(state.children[0].kill).toHaveBeenCalledOnce()
    for (const release of releases) release()
    await flush()
    let drained = false
    const closing = operations.close().then(() => { drained = true })
    await flush()
    expect(drained).toBe(false)
    expect(state.boundary).not.toHaveBeenCalledWith('remove-pid')
    state.children[0].emit('close', 0)
    await closing
    expect(state.boundary).toHaveBeenCalledWith('remove-pid')
  })

  it.each(['socket-close', 'tls-close'])('retains %s until physical close after cancellation', async stage => {
    const release = hold(stage), controller = new AbortController()
    const result = checkGroupHealth('g', signalOptions(controller.signal)).catch(error => error)
    await flush()
    expect(state.boundary).toHaveBeenCalledWith(stage)
    controller.abort(); await flush()
    expect(await result).toMatchObject({ category: 'cancelled' })
    let drained = false
    const closing = operations.close().then(() => { drained = true })
    await flush()
    expect(drained).toBe(false)
    release(); await closing
    expect(state.writes).not.toHaveBeenCalled()
  })

  it('runs at most five workers and never starts later profiles after cancellation', async () => {
    state.profiles = Array.from({ length: 12 }, (_, index) => ({ ...state.profiles[0], id: `p${index}` }))
    const release = hold('adapter'), controller = new AbortController()
    const result = checkGroupHealth('g', signalOptions(controller.signal)).catch(error => error)
    await flush()
    expect(state.boundary.mock.calls.filter(([stage]) => stage === 'adapter')).toHaveLength(5)
    controller.abort(); await flush()
    expect(await result).toMatchObject({ category: 'cancelled' })
    release(); await operations.close()
    expect(state.boundary.mock.calls.filter(([stage]) => stage === 'adapter')).toHaveLength(5)
    expect(state.children).toHaveLength(0)
  })

  it.each(['removed', 'archived', 'outbound', 'group'])('rejects stale %s snapshots without publishing health', async change => {
    const release = hold('adapter')
    const result = checkGroupHealth('g').catch(error => error)
    await flush()
    if (change === 'removed') state.profiles = []
    if (change === 'archived') state.profiles[0] = { ...state.profiles[0], removedFromSubscriptionAt: Date.now() }
    if (change === 'outbound') state.profiles[0] = { ...state.profiles[0], outbound: { ...state.profiles[0].outbound, uuid: 'new-credential' } }
    if (change === 'group') state.groups = []
    release()
    expect(await result).toMatchObject({ category: 'conflict' })
    expect(state.writes).not.toHaveBeenCalled()
  })

  it('makes persistence terminal against reentrant cancellation', async () => {
    const controller = new AbortController()
    state.writes.mockImplementationOnce(() => controller.abort())
    const result = await checkGroupHealth('g', signalOptions(controller.signal))
    expect(result.ok).toBe(true)
    expect(operations.list().at(-1)).toMatchObject({ status: 'success' })
  })

  it('has a work deadline and rejects overlapping groups until native drain', async () => {
    vi.useFakeTimers()
    const release = hold('adapter')
    const result = checkGroupHealth('g').catch(error => error)
    await flush()
    await vi.advanceTimersByTimeAsync(OPERATION_DEADLINES['health-check'])
    expect(await result).toMatchObject({ category: 'timeout' })
    await expect(checkGroupHealth('g')).rejects.toMatchObject({ category: 'conflict' })
    release()
    await operations.close()
    expect(state.writes).not.toHaveBeenCalled()
  })

  it('fences a cancelled commit queued behind another profile writer', async () => {
    let release!: () => void
    const gate = new Promise<void>(done => { release = done }); releases.add(release)
    const locked = withProfileStoreWriteLock(() => gate)
    const controller = new AbortController()
    const result = checkGroupHealth('g', signalOptions(controller.signal)).catch(error => error)
    await flush()
    controller.abort()
    await flush()
    expect(await result).toMatchObject({ category: 'cancelled' })
    release(); await locked; await operations.close()
    expect(state.writes).not.toHaveBeenCalled()
  })

  it('commits a current result once and carries the action correlation', async () => {
    const correlationId = 'ipc_d5abf17ebf694f239e3cb69ed0b32089'
    const result = await withCorrelation(correlationId, () => checkGroupHealth('g'))
    expect(result).toMatchObject({ ok: true, results: [{ profileId: 'p', online: true }] })
    expect(state.writes).toHaveBeenCalledOnce()
    expect(state.profiles[0]).toMatchObject({ status: 'online', healthStatus: 'online' })
    expect(operations.list().at(-1)).toMatchObject({ kind: 'health-check', correlationId, owner: 'manual', status: 'success' })
  })

  it('rejects missing/empty groups with typed validation', async () => {
    state.profiles = []
    await expect(checkGroupHealth('g')).rejects.toMatchObject({ category: 'validation' })
    await expect(checkGroupHealth('missing')).rejects.toMatchObject({ category: 'validation' })
    expect(state.writes).not.toHaveBeenCalled()
  })
})
