// AT-00-003/005/007: actual refresh/import/registry/curl, loopback HTTP and Conf disk.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createServer, type Server, type ServerResponse } from 'node:http'
import type { Socket } from 'node:net'
import type { ChildProcess } from 'node:child_process'
import { mkdir, mkdtemp, rm, readFile } from 'node:fs/promises'
import { join } from 'node:path'

const state = vi.hoisted(() => ({ dir: '', picker: undefined as any, groups: undefined as any, children: [] as ChildProcess[], log: vi.fn(), handle: vi.fn(), handlers: new Map<string, (...args: any[]) => any>() }))
vi.mock('electron', () => ({ ipcMain: { handle: state.handle }, app: { isPackaged: false, getPath: () => state.dir }, shell: {} }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({ bootstrapRouteMode: 'direct' }) } }))
vi.mock('./tunController', () => ({ getDirectProxyPort: () => 1080, tunController: { getStatus: () => ({ running: false }), setWatchdogProbeConfirmationChecker: vi.fn() } }))
vi.mock('./adaptiveBypass', () => ({ beginAdaptiveConnection: vi.fn(), readAdaptiveNetworkFingerprint: vi.fn() }))
vi.mock('./ipMonitor', () => ({ ipMonitor: {} }))
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
  state.log = vi.spyOn(await import('./appLogger'), 'logEvent')
  for (const method of ['log', 'warn', 'error'] as const) vi.spyOn(console, method).mockImplementation(() => {})
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
  // Drain the actual logger's serialized disk queue before removing its folder.
  const logger = await import('./appLogger')
  await expect.poll(async () => {
    try { return (await readFile(logger.getAppLogPath(), 'utf8')).trim().split('\n').length }
    catch { return 0 }
  }).toBe(state.log.mock.calls.length)
  vi.restoreAllMocks()
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
  it.each(['new', 'target'])('cancels an actual %s profile import and leaves no late disk commit or live curl', async kind => {
    const picker = await import('./serverPicker')
    const target = kind === 'target' ? service.createGroup({ name: 'Target', source: 'manual', importedAt: 1, status: 'unknown' }) : null
    const beforeProfiles = await disk('server-picker'), beforeGroups = await disk('server-groups')
    const input = base + '/import-held'
    const run = target ? picker.addFromInputToGroup(input, target.id) : picker.addFromInput(input)
    const rejected = expect(run).rejects.toMatchObject({ category: 'cancelled' })
    // Network/process startup under concurrent Windows CI load is preparation;
    // the cancellation budget starts only after the held request is admitted.
    await vi.waitFor(() => expect(replies.has('/import-held')).toBe(true), { timeout: 5_000 })
    const operation = registry.list().find(op => op.status === 'running')!
    expect(operation.kind).toBe('import')
    const start = performance.now()
    registry.cancel(operation.operationId)
    await rejected
    expect(performance.now() - start).toBeLessThan(900)
    await registry.close()
    await vi.waitFor(() => expect(sockets.size).toBe(0))
    expect(state.children).toHaveLength(1)
    expect(state.children[0].exitCode !== null || state.children[0].signalCode !== null).toBe(true)
    replies.get('/import-held')!.end(body)
    expect(await disk('server-picker')).toEqual(beforeProfiles)
    expect(await disk('server-groups')).toEqual(beforeGroups)
    expect(state.log.mock.calls.some(call => /added from|appended to/.test(call[2]))).toBe(false)
  }, 15_000)

  it('retains actual concurrent import identities through IPC, JSONL, diagnostics and disk reload', async () => {
    const picker = await import('./serverPicker')
    picker.registerServerPickerHandlers()
    const one = state.handlers.get('servers:add')!({}, base + '/import-cancelled')
    const two = state.handlers.get('servers:add')!({}, base + '/import-successful')
    await vi.waitFor(() => expect(replies.size).toBe(2))
    const records = registry.list()
    expect(records).toHaveLength(2)
    expect(records.every(op => op.kind === 'import' && op.owner === 'manual' && op.source === 'ipc')).toBe(true)
    registry.cancel(records[0].operationId)
    expect(await one).toMatchObject({ ok: false, correlationId: records[0].correlationId, error: { code: 'IPC_CANCELLED', category: 'cancelled' } })
    replies.get('/import-successful')!.end(body)
    const result = await two
    expect(result).toMatchObject({ ok: true, correlationId: records[1].correlationId })
    expect(result.result).toHaveLength(1)
    const uri = body.replace('fixture.example.com', 'uri.example.com')
    const manual = await picker.addFromInput(uri)
    expect(manual).toHaveLength(1)
    await registry.close()
    const saved = await disk('server-picker') as { profiles: Array<{ id: string; groupId: string }>; activeProfileId: string }
    const savedGroups = await disk('server-groups') as { groups: Array<{ id: string; sourceUrl?: string }> }
    expect(saved.profiles.map(profile => profile.id).sort()).toEqual([result.result[0].id, manual[0].id].sort())
    expect(saved.activeProfileId).toBe(result.result[0].id)
    expect(savedGroups.groups).toHaveLength(2)
    expect(savedGroups.groups.some(group => group.sourceUrl === base + '/import-cancelled')).toBe(false)
    expect(savedGroups.groups.some(group => group.sourceUrl === base + '/import-successful' && group.id === result.result[0].groupId)).toBe(true)
    const { getAppLogPath, getFullLogs } = await import('./appLogger')
    let raw = ''
    await expect.poll(async () => {
      raw = await readFile(getAppLogPath(), 'utf8')
      return raw.trim().split('\n').length
    }).toBe(state.log.mock.calls.length)
    const events = raw.trim().split('\n').map(line => JSON.parse(line)).filter(row => row.message === 'feature operation')
    expect(new Set(events.map(row => row.details.operationKey)).size).toBe(3)
    for (const [index, record] of records.entries()) {
      const operationEvents = events.filter(row => row.details.operationKey === 'op_' + record.operationId.replaceAll('-', ''))
      expect(operationEvents.map(row => row.details.status)).toEqual(['running', index === 0 ? 'cancelled' : 'success'])
      expect(operationEvents.every(row => row.correlationId === record.correlationId && row.details.correlationId === record.correlationId)).toBe(true)
      expect(raw).not.toContain(record.operationId)
    }
    expect(raw).not.toContain('00000000-0000-4000-8000-000000000000')
    const diagnostic = (await getFullLogs()).find(file => file.path === getAppLogPath())!
    expect(diagnostic.exists).toBe(true)
    expect(diagnostic.content.trim().split('\n').map(line => JSON.parse(line)).filter(row => row.message === 'feature operation')).toEqual(events)
  })

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
    const beforeProfiles = await disk('server-picker')
    const run = service.refreshGroup(subscription.id)
    const rejected = expect(run).rejects.toMatchObject({ category: 'cancelled' })
    await vi.waitFor(() => expect(replies.has('/held')).toBe(true))
    const beforeGroups = await disk('server-groups') // The admitted attempt is recorded before cancellation.
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

  it('preserves two real refresh identities and action correlations through JSONL and diagnostic redaction (AT-00-005)', async () => {
    const first = group('/cancelled'), second = group('/successful')
    const one = state.handlers.get('groups:refresh')!({}, first.id)
    const two = state.handlers.get('groups:refresh')!({}, second.id)
    await vi.waitFor(() => expect(replies.size).toBe(2))
    const records = registry.list()
    expect(records).toHaveLength(2)
    registry.cancel(records[0].operationId)
    const cancelled = await one
    replies.get('/successful')!.end(body)
    const successful = await two
    expect(cancelled).toMatchObject({ ok: false, error: { category: 'cancelled' } })
    expect(successful.ok).toBe(true)
    expect(cancelled.correlationId).not.toBe(successful.correlationId)
    await registry.close()
    const { getAppLogPath, getFullLogs, logEvent } = await import('./appLogger')
    logEvent('info', 'fixture', 'secret masking check', { password: 'private-refresh-password' })
    let raw = ''
    await expect.poll(async () => {
      raw = await readFile(getAppLogPath(), 'utf8')
      return raw.trim().split('\n').length
    }).toBe(state.log.mock.calls.length)
    const events = raw.trim().split('\n').map(line => JSON.parse(line)).filter(row => row.message === 'feature operation')
    const keys = records.map(op => 'op_' + op.operationId.replaceAll('-', ''))
    expect(new Set(events.map(row => row.details.operationKey))).toEqual(new Set(keys))
    for (const [index, key] of keys.entries()) {
      const group = events.filter(row => row.details.operationKey === key)
      expect(group.map(row => row.details.status)).toEqual(['running', index === 0 ? 'cancelled' : 'success'])
      expect(group.every(row => row.correlationId === records[index].correlationId && row.details.correlationId === records[index].correlationId)).toBe(true)
      expect(raw).not.toContain(records[index].operationId)
    }
    expect(raw).not.toContain('private-refresh-password')
    const diagnostic = (await getFullLogs()).find(file => file.path === getAppLogPath())!
    expect(diagnostic.exists).toBe(true)
    expect(diagnostic.content.trim().split('\n').map(line => JSON.parse(line)).filter(row => row.message === 'feature operation')).toEqual(events)
    expect(diagnostic.content).not.toContain('private-refresh-password')
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
