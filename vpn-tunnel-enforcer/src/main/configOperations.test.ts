// AT-00-003/005/007: production config/registry/guard, real files/Conf/logger;
// native dialogs and the Electron/DPAPI store boundary are replaced.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { EventEmitter } from 'events'
import { readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { privateExportDirectory } from './testFixtures/privateExportDirectory'
import { join } from 'path'

const state = vi.hoisted(() => ({
  dir: '', stores: {} as Record<string, any>, handles: [] as Array<{ closed: boolean }>,
  handlers: new Map<string, (...args: any[]) => any>(), handle: vi.fn(),
  openDialog: vi.fn(), saveDialog: vi.fn(), consent: vi.fn(), log: vi.fn(),
  hold: '', reached: 0, gate: Promise.resolve(), writeFault: false, renameFault: false, removeFault: false, afterRename: undefined as (() => void) | undefined
}))
vi.mock('electron', () => ({
  app: { isPackaged: false, getPath: () => state.dir }, ipcMain: { handle: state.handle },
  BrowserWindow: { fromWebContents: () => null },
  dialog: { showOpenDialog: state.openDialog, showSaveDialog: state.saveDialog, showMessageBox: state.consent }
}))
vi.mock('electron-store', async () => {
  const { default: Conf } = await vi.importActual<typeof import('conf')>('conf')
  return { default: class extends Conf {
    constructor(options: Record<string, unknown>) { super({ ...options, cwd: state.dir, configName: String(options.name), projectVersion: '1.1.24' }) }
  } }
})
vi.mock('./sharedStores', () => ({
  get serverPickerStore() { return state.stores.picker }, get serverGroupsStore() { return state.stores.groups },
  get granularKillSwitchStore() { return state.stores.killSwitch }
}))
vi.mock('fs', async original => {
  const actual = await original<typeof import('fs')>()
  return { ...actual, renameSync: (...args: Parameters<typeof actual.renameSync>) => {
    if (state.renameFault) throw Object.assign(new Error('private-file-path'), { code: 'EACCES' })
    actual.renameSync(...args); state.afterRename?.()
  } }
})
vi.mock('fs/promises', async original => {
  const actual = await original<typeof import('fs/promises')>()
  return { ...actual, rm: async (...args: Parameters<typeof actual.rm>) => {
    if (state.removeFault && String(args[0]).includes('.vpnte-export-')) throw Object.assign(new Error('private-cleanup-path'), { code: 'EBUSY' })
    return actual.rm(...args)
  }, open: async (...args: Parameters<typeof actual.open>) => {
    const file = await actual.open(...args), tracked = { closed: false }
    state.handles.push(tracked)
    const close = file.close.bind(file)
    file.close = async () => { try { return await close() } finally { tracked.closed = true } }
    const pause = async (step: string) => { if (state.hold === step) { state.reached++; await state.gate } }
    const read = file.read.bind(file), write = file.writeFile.bind(file), sync = file.sync.bind(file)
    file.read = (async (...readArgs: Parameters<typeof read>) => {
      const result = await read(...readArgs); await pause('read'); return result
    }) as typeof file.read
    file.writeFile = async (...writeArgs) => {
      if (state.writeFault) throw Object.assign(new Error('private-file-path'), { code: 'EACCES' })
      const result = await write(...writeArgs); await pause('write'); return result
    }
    file.sync = async () => { const result = await sync(); await pause('sync'); return result }
    await pause('open')
    return file
  } }
})

class Sender extends EventEmitter {
  destroyed = false
  isDestroyed() { return this.destroyed }
  destroy() { this.destroyed = true; this.emit('destroyed') }
}
let sender: Sender, manager: typeof import('./configManager'), registry: typeof import('./operations').operations
let selected: string, destination: string
const releases = new Set<() => void>()
function held<T>(value: T) {
  let release!: () => void
  const promise = new Promise<T>(done => { release = () => done(value) })
  releases.add(release)
  return { promise, release }
}
const invoke = (channel: string, ...args: unknown[]) => state.handlers.get(channel)!({ sender }, ...args)
async function disk(name: string) {
  const { default: Conf } = await vi.importActual<typeof import('conf')>('conf')
  return new Conf({ cwd: state.dir, configName: name, projectVersion: '1.1.24' }).store
}
async function logRows() {
  const logger = await import('./appLogger')
  let raw = ''
  await expect.poll(async () => {
    try { raw = await readFile(logger.getAppLogPath(), 'utf8'); return raw.trim().split('\n').length }
    catch { return 0 }
  }).toBe(state.log.mock.calls.length)
  return { raw, rows: raw.trim().split('\n').map(line => JSON.parse(line)) }
}

beforeEach(async () => {
  vi.resetModules(); vi.clearAllMocks()
  state.hold = ''; state.reached = 0; state.writeFault = false; state.renameFault = false; state.removeFault = false; state.handles = []; state.afterRename = undefined
  state.dir = privateExportDirectory('.vpnte-config-operations-')
  sender = new Sender()
  state.log = vi.spyOn(await import('./appLogger'), 'logEvent')
  for (const method of ['log', 'warn', 'error'] as const) vi.spyOn(console, method).mockImplementation(() => {})
  const { default: Conf } = await vi.importActual<typeof import('conf')>('conf')
  const store = (name: string, defaults: Record<string, unknown>) => new Conf({ cwd: state.dir, configName: name, projectVersion: '1.1.24', defaults })
  state.stores = {
    picker: store('server-picker', { profiles: [], activeProfileId: null }), groups: store('server-groups', { groups: [] }),
    killSwitch: store('granular-kill-switch', { killSwitchLevel: 'off', killSwitchExceptions: [] })
  }
  state.handlers.clear()
  state.handle.mockImplementation((channel, handler) => state.handlers.set(channel, handler))
  const { ipcMain } = await import('electron')
  ipcMain.handle = state.handle
  delete (ipcMain as any)[Symbol.for('vpnte.ipc.trusted-boundary.installed')]
  ;(await import('./ipcSecurity')).installTrustedIpcBoundary()
  manager = await import('./configManager')
  const operations = await import('./operations')
  registry = operations.operations
  operations.registerOperationHandlers()
  manager.registerConfigManagerIpcHandlers()
  selected = join(state.dir, 'selected.json'); destination = join(state.dir, 'destination.json')
  const config = manager.collectCurrentConfig(); config.notifications.sound = false
  await writeFile(selected, JSON.stringify(config))
  await writeFile(destination, 'previous export')
  state.openDialog.mockReset().mockResolvedValue({ canceled: false, filePaths: [selected] })
  state.saveDialog.mockReset().mockResolvedValue({ canceled: false, filePath: destination })
  state.consent.mockReset().mockResolvedValue({ response: 1 })
})

afterEach(async () => {
  const closing = registry?.close()
  for (const release of releases) release()
  releases.clear()
  await closing
  sender.destroy()
  vi.useRealTimers()
  expect(state.handles.every(file => file.closed)).toBe(true)
  await logRows()
  vi.restoreAllMocks()
  await rm(state.dir, { recursive: true, force: true })
})

describe('configuration operation lifetime', () => {
  it.each(['import', 'export'])('cancels %s during a native dialog with one original IPC correlation', async kind => {
    vi.useFakeTimers()
    const gate = held(kind === 'import' ? { canceled: false, filePaths: [selected] } : { canceled: false, filePath: destination })
    ;(kind === 'import' ? state.openDialog : state.saveDialog).mockReturnValue(gate.promise)
    const run = kind === 'import' ? invoke('config:browse-import') : invoke('config:export', 'redacted')
    const operation = registry.list().find(op => op.status === 'running')!
    const finished = vi.fn()
    void run.then(finished)
    expect(await invoke('operations:cancel', operation.operationId)).toMatchObject({ ok: true, result: true })
    await vi.advanceTimersByTimeAsync(0)
    expect(finished).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ ok: false, correlationId: operation.correlationId, error: expect.objectContaining({ code: 'IPC_CANCELLED' }) }))
    let drained = false
    const closing = registry.close().then(() => { drained = true })
    await Promise.resolve(); expect(drained).toBe(false)
    gate.release(); await closing
    expect(await readFile(destination, 'utf8')).toBe('previous export')
    expect(await invoke('config:import', selected)).toMatchObject({ ok: false, error: { category: 'permission' } })
    expect(state.handles).toHaveLength(0)
  })

  it('does not open a save dialog or write after cancelling held secret consent', async () => {
    const gate = held({ response: 1 })
    state.consent.mockReturnValue(gate.promise)
    const run = invoke('config:export', 'secrets')
    registry.cancel(registry.list().find(op => op.status === 'running')!.operationId)
    expect(await run).toMatchObject({ ok: false, error: { category: 'cancelled' } })
    gate.release(); await registry.close()
    expect(state.saveDialog).not.toHaveBeenCalled()
    expect(await readFile(destination, 'utf8')).toBe('previous export')
  })

  it.each(['open', 'read', 'write', 'sync'])('drains a held actual file %s without a late grant, destination overwrite or orphan temp', async step => {
    const gate = held(undefined)
    state.hold = step; state.gate = gate.promise
    const run = step === 'open' || step === 'read' ? invoke('config:browse-import') : invoke('config:export', 'redacted')
    await vi.waitFor(() => expect(state.reached).toBe(1))
    registry.cancel(registry.list().find(op => op.status === 'running')!.operationId)
    expect(await run).toMatchObject({ ok: false, error: { category: 'cancelled' } })
    expect(await readFile(destination, 'utf8')).toBe('previous export')
    gate.release(); await registry.close()
    expect(await readFile(destination, 'utf8')).toBe('previous export')
    expect((await readdir(state.dir)).filter(name => name.startsWith('.vpnte-export-'))).toEqual([])
    expect(await invoke('config:import', selected)).toMatchObject({ ok: false, error: { category: 'permission' } })
    expect(state.handles.every(file => file.closed)).toBe(true)
    expect(state.log.mock.calls.some(call => ['config exported', 'import applied'].includes(call[2]))).toBe(false)
  })

  it.each(['cancel', 'destroy', 'expire', 'replacement', 'shutdown'])('does not apply a queued snapshot after %s and consumes only its own authority', async reason => {
    expect(await invoke('config:browse-import')).toMatchObject({ ok: true, result: selected })
    const gate = held(undefined)
    const { withProfileStoreWriteLock } = await import('./profileStoreQueue')
    const blocking = withProfileStoreWriteLock(() => gate.promise)
    const before = await disk('notification-prefs')
    const run = invoke('config:import-apply', selected, ['notifications'], 'replace')
    expect(await invoke('config:import-apply', selected, ['notifications'], 'replace')).toMatchObject({ ok: false, error: { category: 'permission' } })
    await new Promise<void>(done => setImmediate(done))
    await new Promise<void>(done => setImmediate(done))
    let closing: Promise<void> | undefined
    if (reason === 'cancel') registry.cancel(registry.list().find(op => op.status === 'running')!.operationId)
    if (reason === 'destroy') sender.destroy()
    if (reason === 'expire') vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 60_001)
    if (reason === 'replacement') expect(await invoke('config:browse-import')).toMatchObject({ ok: true, result: selected })
    if (reason === 'shutdown') closing = registry.close()
    if (['cancel', 'destroy', 'shutdown'].includes(reason)) expect(await run).toMatchObject({ ok: false, error: { category: 'cancelled' } })
    expect(await disk('notification-prefs')).toEqual(before)
    gate.release(); await blocking; await closing
    expect(await run).toMatchObject({ ok: false, error: { category: ['expire', 'replacement'].includes(reason) ? 'permission' : 'cancelled' } })
    expect(await disk('notification-prefs')).toEqual(before)
    if (reason === 'replacement') expect(await invoke('config:import', selected)).toMatchObject({ ok: true })
  })

  it('merges against the actual profile snapshot inside the shared queue', async () => {
    const profile = (id: string) => ({ id, name: id, protocol: 'vless', server: id + '.example.test', port: 443, status: 'unknown' })
    await writeFile(selected, JSON.stringify({ version: '2.0', profiles: [profile('imported')] }))
    await invoke('config:browse-import')
    const gate = held(undefined), { withProfileStoreWriteLock } = await import('./profileStoreQueue')
    const blocking = withProfileStoreWriteLock(async () => { await gate.promise; state.stores.picker.set('profiles', [profile('concurrent')]) })
    const run = invoke('config:import-apply', selected, ['profiles'], 'merge')
    gate.release(); await blocking
    expect(await run).toMatchObject({ ok: true, result: { success: true } })
    expect((await disk('server-picker') as any).profiles.map((entry: any) => entry.id).sort()).toEqual(['concurrent', 'imported'])
  })

  it.each(['write', 'rename'])('leaves an existing destination intact and removes staging after a file %s error', async step => {
    state.writeFault = step === 'write'; state.renameFault = step === 'rename'
    expect(await invoke('config:export', 'redacted')).toMatchObject({ ok: false, error: { category: 'permission' } })
    expect(await readFile(destination, 'utf8')).toBe('previous export')
    expect((await readdir(state.dir)).filter(name => name.startsWith('.vpnte-export-'))).toEqual([])
    expect(JSON.stringify(state.log.mock.calls)).not.toContain('private-file-path')
  })

  it.each([false, true])('does not publish success when persistence fails (rollback failure: %s)', async rollbackFails => {
    const before = await disk('server-picker')
    const config = manager.collectCurrentConfig()
    config.profiles = [{ id: 'imported', name: 'Imported', protocol: 'vless', server: 'imported.example.test', port: 443, status: 'unknown' }]
    await writeFile(selected, JSON.stringify(config))
    await invoke('config:browse-import')
    vi.spyOn(state.stores.groups, 'set').mockImplementationOnce(() => { throw Object.assign(new Error('private-write-path'), { code: 'EACCES' }) })
    if (rollbackFails) {
      const write = state.stores.picker.set.bind(state.stores.picker)
      vi.spyOn(state.stores.picker, 'set').mockImplementationOnce(write)
        .mockImplementationOnce(() => { throw new Error('private-rollback-path') })
    }
    expect(await invoke('config:import-apply', selected, ['profiles', 'serverGroups'], 'replace')).toMatchObject({ ok: false, error: { category: 'permission' } })
    if (!rollbackFails) expect(await disk('server-picker')).toEqual(before)
    expect(registry.list().find(op => op.status === 'error')).toMatchObject({ category: 'permission' })
    expect(state.log.mock.calls.some(call => call[2] === 'config import rollback failed')).toBe(rollbackFails)
    expect(state.log.mock.calls.some(call => call[2] === 'import applied')).toBe(false)
    expect(JSON.stringify(state.log.mock.calls)).not.toMatch(/private-(write|rollback)-path/)
    expect(await invoke('config:import', selected)).toMatchObject({ ok: false, error: { category: 'permission' } })
  })

  it('keeps an atomically saved export successful when its external signal aborts at the synchronous rename commit', async () => {
    const controller = new AbortController()
    state.afterRename = () => controller.abort()
    expect(await manager.configManager.exportConfig(sender as any, 'redacted', { signal: controller.signal })).toEqual({ success: true, path: destination })
    expect(controller.signal.aborted).toBe(true)
    expect(JSON.parse(await readFile(destination, 'utf8')).version).toBe('2.0')
    expect(registry.list()).toMatchObject([{ status: 'success' }])
  })

  it('does not time out a user decision, and still cancels it without a late grant', async () => {
    const gate = held({ canceled: false, filePaths: [selected] })
    state.openDialog.mockReturnValue(gate.promise)
    vi.useFakeTimers()
    const run = invoke('config:browse-import')
    await vi.advanceTimersByTimeAsync(600_000)
    const operation = registry.list().find(op => op.status === 'running')!
    expect(operation.deadline).toBeNull()
    expect(registry.cancel(operation.operationId)).toBe(true)
    expect(await run).toMatchObject({ ok: false, error: { category: 'cancelled' } })
    gate.release(); await registry.close()
    expect(state.handles).toEqual([])
    expect(await invoke('config:import', selected)).toMatchObject({ ok: false, error: { category: 'permission' } })
  })

  it('accepts the selected file after a long user decision and starts the work budget afterwards', async () => {
    const gate = held({ canceled: false, filePaths: [selected] })
    state.openDialog.mockReturnValue(gate.promise)
    vi.useFakeTimers()
    const run = invoke('config:browse-import')
    await vi.advanceTimersByTimeAsync(600_000)
    expect(registry.list()[0].status).toBe('running')
    vi.useRealTimers(); gate.release()
    expect(await run).toMatchObject({ ok: true, result: selected })
    expect(await invoke('config:import', selected)).toMatchObject({ ok: true })
  })

  it('still times out actual file work after the picker while retaining the raw handle until drain', async () => {
    const gate = held(undefined)
    state.hold = 'read'; state.gate = gate.promise
    vi.useFakeTimers()
    const run = invoke('config:browse-import')
    await vi.waitFor(() => expect(state.reached).toBe(1))
    await vi.advanceTimersByTimeAsync(120_000)
    expect(await run).toMatchObject({ ok: false, error: { category: 'timeout' } })
    expect(state.handles.some(file => !file.closed)).toBe(true)
    gate.release(); await registry.close()
    expect(state.handles.every(file => file.closed)).toBe(true)
    expect(await invoke('config:import', selected)).toMatchObject({ ok: false, error: { category: 'permission' } })
  })

  it.each(['cancel', 'rename'])('reports residual staging cleanup failure without replacing %s outcome', async reason => {
    state.removeFault = true
    const gate = held(undefined)
    if (reason === 'cancel') { state.hold = 'sync'; state.gate = gate.promise }
    else state.renameFault = true
    const run = invoke('config:export', 'secrets')
    const operation = registry.list().find(op => op.status === 'running')!
    if (reason === 'cancel') {
      // Real Windows creation/handle-identity preparation precedes fsync.
      await vi.waitFor(() => expect(state.reached).toBe(1), { timeout: 5000 })
      registry.cancel(operation.operationId)
    }
    expect(await run).toMatchObject({ ok: false, correlationId: operation.correlationId, error: { category: reason === 'cancel' ? 'cancelled' : 'permission' } })
    gate.release(); await registry.close()
    expect(await readFile(destination, 'utf8')).toBe('previous export')
    expect((await readdir(state.dir)).filter(name => name.startsWith('.vpnte-export-'))).toHaveLength(1)
    const cleanup = (await logRows()).rows.find(row => row.message === 'config export cleanup failed')
    expect(cleanup).toMatchObject({ correlationId: operation.correlationId, details: {
      cleanupFailed: true, operationKey: 'op_' + operation.operationId.replaceAll('-', '')
    } })
    expect(JSON.stringify(cleanup)).not.toContain('private-cleanup-path')
  }, 15_000)

  it('preserves concurrent import/export identities and redaction through actual IPC/JSONL/diagnostics', async () => {
    state.stores.picker.set('profiles', [{ id: 'p1', name: 'Profile', protocol: 'vless', server: 'vpn.test', port: 443, status: 'unknown',
      outbound: { type: 'vless', server: 'vpn.test', server_port: 443, password: 'private-config-password' } }])
    const gate = held({ canceled: false, filePaths: [selected] })
    state.openDialog.mockReturnValue(gate.promise)
    const one = invoke('config:browse-import'), two = invoke('config:export', 'redacted')
    const records = registry.list()
    const exported = await two
    expect(exported).toMatchObject({ ok: true, result: { success: true, path: destination } })
    registry.cancel(records[0].operationId)
    const cancelled = await one
    expect(cancelled).toMatchObject({ ok: false, correlationId: records[0].correlationId, error: { category: 'cancelled' } })
    gate.release(); await registry.close()
    const { raw, rows } = await logRows()
    const events = rows.filter(row => row.message === 'feature operation')
    for (const [index, record] of records.entries()) {
      const grouped = events.filter(row => row.details.operationKey === 'op_' + record.operationId.replaceAll('-', ''))
      expect(grouped.map(row => row.details.status)).toEqual(['running', index === 0 ? 'cancelled' : 'success'])
      expect(grouped.every(row => row.correlationId === record.correlationId && row.details.correlationId === record.correlationId)).toBe(true)
      expect(raw).not.toContain(record.operationId)
    }
    expect(exported.correlationId).toBe(records[1].correlationId)
    expect(raw).not.toContain('private-config-password')
    expect(await readFile(destination, 'utf8')).not.toContain('private-config-password')
    const logger = await import('./appLogger'), diagnostic = (await logger.getFullLogs()).find(file => file.path === logger.getAppLogPath())!
    expect(diagnostic.content.trim().split('\n').map(line => JSON.parse(line)).filter(row => row.message === 'feature operation')).toEqual(events)
  })
})
