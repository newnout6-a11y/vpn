// AT-00-003/005/007: actual refresh/registry/curl, loopback HTTP and Conf disk.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createServer, type Server, type ServerResponse } from 'node:http'
import type { Socket } from 'node:net'
import type { ChildProcess } from 'node:child_process'
import { mkdir, mkdtemp, rm } from 'node:fs/promises'
import { join } from 'node:path'

const state = vi.hoisted(() => ({ dir: '', picker: undefined as any, groups: undefined as any, children: [] as ChildProcess[], log: vi.fn(), handle: vi.fn(), handlers: new Map<string, (...args: any[]) => any>() }))
vi.mock('electron', () => ({ ipcMain: { handle: state.handle }, app: { isPackaged: false } }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({ bootstrapRouteMode: 'direct' }) } }))
vi.mock('./appLogger', () => ({ logEvent: state.log }))
vi.mock('child_process', async () => {
  const actual = await vi.importActual<typeof import('child_process')>('child_process')
  return { ...actual, spawn: (...args: Parameters<typeof actual.spawn>) => {
    const child = actual.spawn(...args)
    state.children.push(child)
    return child
  } }
})
vi.mock('electron-store', async () => {
  const { default: Conf } = await vi.importActual<typeof import('conf')>('conf')
  return { default: class extends Conf {
    constructor(options: Record<string, unknown>) { super({ ...options, cwd: state.dir, configName: String(options.name), projectVersion: '1.1.24' }) }
  } }
})
vi.mock('./sharedStores', () => ({ get serverPickerStore() { return state.picker }, get serverGroupsStore() { return state.groups } }))

let server: Server, base: string, service: typeof import('./serverGroups'), registry: typeof import('./operations').operations
const sockets = new Set<Socket>(), replies = new Map<string, ServerResponse>()
const body = 'vless://00000000-0000-4000-8000-000000000000@fixture.example.com:443?security=tls#Fixture'

beforeEach(async () => {
  vi.resetModules()
  vi.clearAllMocks()
  state.children = []
  replies.clear()
  await mkdir('.tmp', { recursive: true })
  state.dir = await mkdtemp(join(process.cwd(), '.tmp', 'subscription-operations-'))
  const { default: Conf } = await vi.importActual<typeof import('conf')>('conf')
  state.picker = new Conf({ cwd: state.dir, configName: 'server-picker', projectVersion: '1.1.24', defaults: { profiles: [], activeProfileId: null } })
  state.groups = new Conf({ cwd: state.dir, configName: 'server-groups', projectVersion: '1.1.24', defaults: { groups: [] } })
  server = createServer((req, res) => { replies.set(req.url!, res) })
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)) })
  await new Promise<void>(done => server.listen(0, '127.0.0.1', done))
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`
  state.handlers.clear()
  state.handle.mockImplementation((channel, handler) => state.handlers.set(channel, handler))
  const { ipcMain } = await import('electron')
  ipcMain.handle = state.handle
  delete (ipcMain as any)[Symbol.for('vpnte.ipc.trusted-boundary.installed')]
  ;(await import('./ipcSecurity')).installTrustedIpcBoundary()
  service = await import('./serverGroups')
  const operationService = await import('./operations')
  registry = operationService.operations
  operationService.registerOperationHandlers()
  service.registerServerGroupsHandlers()
})

afterEach(async () => {
  service?.stopServerGroupAutoRefresh()
  const closing = registry?.close()
  for (const socket of sockets) socket.destroy()
  for (const child of state.children) if (child.exitCode === null && child.signalCode === null) child.kill()
  await closing
  await new Promise<void>(done => server.close(() => done()))
  await rm(state.dir, { recursive: true, force: true })
})

async function disk(name: string) {
  const { default: Conf } = await vi.importActual<typeof import('conf')>('conf')
  return new Conf({ cwd: state.dir, configName: name, projectVersion: '1.1.24' }).store
}
function group(path: string) {
  return service.createGroup({ name: 'Local fixture', source: 'subscription', sourceUrl: base + path, status: 'active', importedAt: 1 })
}

describe('subscription network ownership', () => {
  it('returns typed cancellation through the actual IPC guard with one action correlation', async () => {
    const subscription = group('/ipc')
    const run = state.handlers.get('groups:refresh')!({}, subscription.id)
    await vi.waitFor(() => expect(replies.has('/ipc')).toBe(true))
    const listing = await state.handlers.get('operations:list')!({})
    const operation = listing.result.find((op: any) => op.status === 'running')
    expect(operation).toMatchObject({ kind: 'refresh', owner: 'manual', source: 'ipc' })
    expect(await state.handlers.get('operations:cancel')!({}, operation.operationId)).toMatchObject({ ok: true, result: true })
    expect(await run).toMatchObject({ ok: false, correlationId: operation.correlationId, error: { category: 'cancelled', code: 'IPC_CANCELLED' } })
    await vi.waitFor(() => expect(registry.isBusy(`refresh:${subscription.id}`)).toBe(false))
    const events = state.log.mock.calls.filter(call => call[2] === 'feature operation').map(call => call[3])
    expect(events.map(op => op.status)).toEqual(['running', 'cancelled'])
    expect(events.every(op => op.correlationId === operation.correlationId)).toBe(true)
    expect(await disk('server-picker')).toEqual({ profiles: [], activeProfileId: null })
  })

  it('aborts an actual curl process/socket and leaves disk unchanged after a late HTTP response', async () => {
    const subscription = group('/held')
    const beforeGroups = await disk('server-groups'), beforeProfiles = await disk('server-picker')
    const run = service.refreshGroup(subscription.id)
    const rejected = expect(run).rejects.toMatchObject({ category: 'cancelled' })
    await vi.waitFor(() => expect(replies.has('/held')).toBe(true))
    const operation = registry.list().find(op => op.status === 'running')!
    const start = performance.now()
    expect(registry.cancel(operation.operationId)).toBe(true)
    await rejected
    expect(performance.now() - start).toBeLessThan(900)
    await vi.waitFor(() => expect(registry.isBusy(`refresh:${subscription.id}`)).toBe(false))
    await vi.waitFor(() => expect(sockets.size).toBe(0))
    expect(state.children).toHaveLength(1)
    expect(state.children[0].exitCode !== null || state.children[0].signalCode !== null).toBe(true)
    replies.get('/held')!.end(body)
    expect(await disk('server-groups')).toEqual(beforeGroups)
    expect(await disk('server-picker')).toEqual(beforeProfiles)
    expect(registry.list().find(op => op.operationId === operation.operationId)?.status).toBe('cancelled')
    expect(state.log.mock.calls.some(call => call[2] === 'group refreshed')).toBe(false)
  })

  it('commits parallel subscriptions and an import against the latest disk snapshot', async () => {
    const first = group('/first'), second = group('/second')
    const one = service.refreshGroup(first.id), two = service.refreshGroup(second.id)
    await vi.waitFor(() => expect(replies.size).toBe(2))
    replies.get('/second')!.end(body)
    expect(await two).toMatchObject({ ok: true })
    const { serverPickerStore } = await import('./sharedStores')
    const { withProfileStoreWriteLock } = await import('./profileStoreQueue')
    await withProfileStoreWriteLock(() => {
      const profiles = serverPickerStore.get('profiles')
      serverPickerStore.set('profiles', [...profiles, { id: 'import-fixture', name: 'Concurrent import', protocol: 'vless', groupId: 'manual', server: 'import.example.com', port: 443, status: 'unknown' }])
    })
    replies.get('/first')!.end(body)
    expect(await one).toMatchObject({ ok: true })
    const saved = await disk('server-picker') as { profiles: Array<{ id: string; groupId: string }> }
    expect(saved.profiles).toHaveLength(3)
    expect(saved.profiles.map(profile => profile.groupId).sort()).toEqual([first.id, second.id, 'manual'].sort())
    expect(registry.list().filter(op => op.status === 'success')).toHaveLength(2)
  })
})
