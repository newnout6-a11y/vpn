import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { readFile, rm } from 'node:fs/promises'
import { privateExportDirectory } from './testFixtures/privateExportDirectory'
import { EventEmitter } from 'events'
import { join } from 'path'

const state = vi.hoisted(() => ({
  nativePrompt: vi.fn(), saveDialog: vi.fn(),
  clipboardText: '', clipboardWrite: vi.fn(),
  hold: '', reached: 0, gate: Promise.resolve(), writeFailure: undefined as unknown,
  handles: [] as Array<{ closed: boolean }>, afterRename: undefined as (() => void) | undefined, log: vi.fn(), dir: '',
  ipcHandlers: new Map<string, (...args: any[]) => any>(),
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

vi.mock('fs/promises', async original => {
  const actual = await original<typeof import('fs/promises')>()
  return { ...actual, open: async (...args: Parameters<typeof actual.open>) => {
    const file = await actual.open(...args), tracked = { closed: false }
    state.handles.push(tracked)
    const close = file.close.bind(file), write = file.writeFile.bind(file), sync = file.sync.bind(file)
    const pause = async (step: string) => { if (state.hold === step) { state.reached++; await state.gate } }
    file.close = async () => { try { return await close() } finally { tracked.closed = true } }
    file.writeFile = async (...writeArgs) => {
      if (state.writeFailure) throw state.writeFailure
      const result = await write(...writeArgs); await pause('write'); return result
    }
    file.sync = async () => { const result = await sync(); await pause('sync'); return result }
    await pause('open')
    return file
  } }
})
vi.mock('fs', async original => {
  const actual = await original<typeof import('fs')>()
  return { ...actual, renameSync: (...args: Parameters<typeof actual.renameSync>) => {
    actual.renameSync(...args); state.afterRename?.()
  } }
})

vi.mock('electron', () => ({
  app: { isPackaged: false, getPath: () => state.dir, getAppPath: () => state.dir },
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

vi.mock('electron-store', async () => {
  const { default: Conf } = await vi.importActual<typeof import('conf')>('conf')
  return { default: class extends Conf {
    constructor(options: Record<string, unknown>) { super({ ...options, cwd: state.dir, configName: String(options.name), projectVersion: '1.1.24' }) }
  } }
})

vi.mock('axios', () => ({ default: { get: vi.fn() } }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({}) } }))
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




// AT-00-003/004/005/007: actual picker/registry/IPC guard, Conf, files and JSONL.
// Native dialogs/clipboard and Electron's DPAPI boundary are replaced.
const channels = ['servers:export-key', 'servers:copy-key', 'servers:export-key-file', 'servers:export-all-keys-file', 'servers:export-all-proxies-file']
const files = channels.filter(channel => channel.endsWith('-file'))
const secret = 'FAKE-key-operation-password'
class Sender extends EventEmitter {
  destroyed = false
  isDestroyed() { return this.destroyed }
  destroy() { this.destroyed = true; this.emit('destroyed') }
}
let sender: Sender, destination: string, registry: typeof import('./operations').operations
const releases = new Set<() => void>()
function held<T>(value: T) {
  let release!: () => void
  const promise = new Promise<T>(resolve => { release = () => resolve(value) })
  releases.add(release)
  return { promise, release }
}
const invoke = (channel: string, ...args: unknown[]) => state.ipcHandlers.get(channel)!({ sender }, ...args)
const invokeExport = (channel: string) => invoke(channel, ...(channel.startsWith('servers:export-all-') ? [] : ['a']))
const running = () => registry.list().find(operation => operation.status === 'running')!
const temporaries = () => readdirSync(state.dir).filter(name => name.startsWith('.vpnte-export-'))

async function logRows() {
  const logger = await import('./appLogger')
  let raw = ''
  await expect.poll(async () => {
    try { raw = await readFile(logger.getAppLogPath(), 'utf8'); return raw.trim().split('\n').length }
    catch { return 0 }
  }, { timeout: 5_000 }).toBe(state.log.mock.calls.length)
  return { raw, logger }
}

beforeEach(async () => {
  vi.resetModules(); vi.clearAllMocks()
  state.hold = ''; state.reached = 0; state.writeFailure = undefined; state.handles = []; state.afterRename = undefined
  state.dir = privateExportDirectory('.vpnte-key-operations-')
  sender = new Sender(); destination = join(state.dir, 'destination.txt')
  writeFileSync(destination, 'previous export')
  state.clipboardText = ''; state.clipboardWrite.mockReset().mockResolvedValue(undefined)
  state.log = vi.spyOn(await import('./appLogger'), 'logEvent')
  for (const method of ['log', 'warn', 'error'] as const) vi.spyOn(console, method).mockImplementation(() => {})
  state.ipcHandlers.clear()
  const { ipcMain } = await import('electron')
  ipcMain.handle = vi.fn((channel, handler) => { state.ipcHandlers.set(channel, handler) })
  delete (ipcMain as any)[Symbol.for('vpnte.ipc.trusted-boundary.installed')]
  ;(await import('./ipcSecurity')).installTrustedIpcBoundary()
  const picker = await import('./serverPicker')
  const { serverPickerStore } = await import('./sharedStores')
  serverPickerStore.set('profiles', [{ id: 'a', name: 'Test', protocol: 'naive', server: 'example.test', port: 1080, status: 'unknown',
    outbound: { type: 'naive', server: 'example.test', server_port: 1080, username: 'test', password: secret } }])
  const operations = await import('./operations'); registry = operations.operations
  operations.registerOperationHandlers(); picker.registerServerPickerHandlers()
  state.nativePrompt.mockReset().mockResolvedValue({ response: 1 })
  state.saveDialog.mockReset().mockResolvedValue({ canceled: false, filePath: destination })
})
afterEach(async () => {
  for (const release of releases) release()
  releases.clear(); await registry?.close()
  await (await import('./secretClipboard')).clearOwnedSecretClipboard()
  vi.useRealTimers()
  expect(state.handles.every(file => file.closed)).toBe(true)
  await logRows() // Drain the actual append queue before this mutable fixture directory is reused.
  vi.restoreAllMocks()
  await rm(state.dir, { recursive: true, force: true, maxRetries: 8, retryDelay: 25 })
})

describe('VPN key operation lifetime', () => {
  // AT-00-001/003: a SPA page knows its token before the native consent opens.
  it.each(channels)('cancels %s by requester token without disclosure or late effects', async channel => {
    const token = '11111111-1111-4111-8111-111111111111'
    const gate = held({ response: 1 }); state.nativePrompt.mockReturnValueOnce(gate.promise)
    const run = invoke(channel, ...(channel.startsWith('servers:export-all-') ? [] : ['a']), token)
    await vi.waitFor(() => expect(state.nativePrompt).toHaveBeenCalledOnce())
    const operation = running(), foreign = new Sender(), cancel = state.ipcHandlers.get('operations:cancel-request')!
    expect(operation.operationId).not.toBe(token)
    expect(await cancel({ sender: foreign }, token)).toMatchObject({ ok: true, result: false })
    expect(await cancel({ sender }, token)).toMatchObject({ ok: true, result: true })
    expect(await run).toMatchObject({ ok: false, correlationId: operation.correlationId, error: { category: 'cancelled' } })
    expect(await cancel({ sender }, token)).toMatchObject({ ok: true, result: false })
    expect(registry.isBusy('keys:' + (channel.endsWith('-file') ? 'file' : channel.includes('copy') ? 'clipboard' : 'renderer'))).toBe(true)
    gate.release(); await registry.close()
    expect(state.saveDialog).not.toHaveBeenCalled(); expect(state.clipboardWrite).not.toHaveBeenCalled()
    expect(readFileSync(destination, 'utf8')).toBe('previous export')
    expect(sender.eventNames()).toEqual([])
  })

  it('rejects malformed and duplicate tokens without disturbing the active consent', async () => {
    expect(await invoke('servers:copy-key', 'a', 'invalid')).toMatchObject({ ok: false, error: { category: 'validation' } })
    expect(state.nativePrompt).not.toHaveBeenCalled()
    const token = '11111111-1111-4111-8111-111111111111', gate = held({ response: 1 })
    state.nativePrompt.mockReturnValueOnce(gate.promise)
    const run = invoke('servers:copy-key', 'a', token)
    await vi.waitFor(() => expect(state.nativePrompt).toHaveBeenCalledOnce())
    expect(await invoke('servers:export-key', 'a', token)).toMatchObject({ ok: false, error: { category: 'conflict' } })
    expect(running().status).toBe('running')
    expect(await invoke('operations:cancel-request', token)).toMatchObject({ ok: true, result: true })
    expect(await run).toMatchObject({ ok: false, error: { category: 'cancelled' } })
    gate.release()
  })

  it.each(files)('cancels %s by requester token during save selection', async channel => {
    const token = '11111111-1111-4111-8111-111111111111'
    const gate = held({ canceled: false, filePath: destination }); state.saveDialog.mockReturnValueOnce(gate.promise)
    const run = invoke(channel, ...(channel.startsWith('servers:export-all-') ? [] : ['a']), token)
    await vi.waitFor(() => expect(state.saveDialog).toHaveBeenCalledOnce())
    expect(await invoke('operations:cancel-request', token)).toMatchObject({ ok: true, result: true })
    expect(await run).toMatchObject({ ok: false, error: { category: 'cancelled' } })
    gate.release(); await registry.close()
    expect(readFileSync(destination, 'utf8')).toBe('previous export'); expect(temporaries()).toEqual([])
  })

  it.each(channels.flatMap(channel => ['render-process-gone', 'did-navigate'].map(event => ({ channel, event }))))
  ('cancels $channel on requester $event before secret consent completes', async ({ channel, event }) => {
    const gate = held({ response: 1 }); state.nativePrompt.mockReturnValueOnce(gate.promise)
    const run = invokeExport(channel)
    await vi.waitFor(() => expect(state.nativePrompt).toHaveBeenCalledOnce())
    const operation = running()
    sender.emit(event, { isMainFrame: true, isSameDocument: false })
    expect(registry.list().find(op => op.operationId === operation.operationId)?.status).toBe('cancelled')
    expect(await run).toMatchObject({ ok: false, correlationId: operation.correlationId, error: { category: 'cancelled' } })
    gate.release(); await registry.close()
    expect(state.saveDialog).not.toHaveBeenCalled(); expect(state.clipboardWrite).not.toHaveBeenCalled()
    expect(readFileSync(destination, 'utf8')).toBe('previous export')
    expect(sender.eventNames()).toEqual([])
  })

  it.each(channels)('cancels held consent promptly, drains it and prevents late effects: %s', async channel => {
    const gate = held({ response: 1 }); state.nativePrompt.mockReturnValueOnce(gate.promise)
    const run = invokeExport(channel)
    await vi.waitFor(() => expect(state.nativePrompt).toHaveBeenCalledOnce())
    expect(running()).toMatchObject({ kind: 'export', owner: 'manual', deadline: null })
    const operation = running(), start = performance.now()
    expect(registry.cancel(operation.operationId)).toBe(true)
    expect(await run).toMatchObject({ ok: false, correlationId: operation.correlationId, error: { category: 'cancelled' } })
    expect(performance.now() - start).toBeLessThan(900)
    expect(await invokeExport(channel)).toMatchObject({ ok: false, error: { category: 'conflict' } })
    gate.release(); await registry.close()
    expect(state.saveDialog).not.toHaveBeenCalled(); expect(state.clipboardWrite).not.toHaveBeenCalled()
    expect(readFileSync(destination, 'utf8')).toBe('previous export'); expect(temporaries()).toEqual([])
    expect(registry.list()).toHaveLength(1)
    expect(registry.list()[0]).toMatchObject({ status: 'cancelled', category: 'cancelled' })
  })
  it.each(files)('cancels a held save picker on sender destruction: %s', async channel => {
    const gate = held({ canceled: false, filePath: destination }); state.saveDialog.mockReturnValueOnce(gate.promise)
    const run = invokeExport(channel)
    await vi.waitFor(() => expect(state.saveDialog).toHaveBeenCalledOnce())
    sender.destroy()
    expect(await run).toMatchObject({ ok: false, error: { category: 'cancelled' } })
    gate.release(); await registry.close()
    expect(readFileSync(destination, 'utf8')).toBe('previous export'); expect(temporaries()).toEqual([])
    expect(sender.listenerCount('destroyed')).toBe(0)
  })
  it.each(['open', 'write', 'sync'])('retains destination and physical lease until cancelled %s drains', async step => {
    const gate = held(undefined); state.hold = step; state.gate = gate.promise
    const token = '11111111-1111-4111-8111-111111111111'
    const run = invoke('servers:export-key-file', 'a', token)
    // Native creation/identity and ACL preparation each have a 15s child budget.
    // Wait for the held boundary before testing cancellation, even on loaded CI.
    await vi.waitFor(() => expect(state.reached).toBe(1), { timeout: 35_000 })
    expect(await invoke('operations:cancel-request', token)).toMatchObject({ ok: true, result: true })
    expect(await run).toMatchObject({ ok: false, error: { category: 'cancelled' } })
    expect(await invoke('servers:export-all-proxies-file')).toMatchObject({ ok: false, error: { category: 'conflict' } })
    expect(readFileSync(destination, 'utf8')).toBe('previous export')
    gate.release(); await registry.close()
    expect(readFileSync(destination, 'utf8')).toBe('previous export'); expect(temporaries()).toEqual([])
    expect(state.handles.every(file => file.closed)).toBe(true)
  }, 45_000)
  it.each(files)('maps native file errors without exposing paths/secrets: %s', async channel => {
    state.writeFailure = Object.assign(new Error('C:\\private\\' + secret + '\n at private stack'), { code: 'EACCES' })
    const result = await invokeExport(channel)
    expect(result).toMatchObject({ ok: false, error: { category: 'permission', code: 'IPC_PERMISSION_DENIED' } })
    expect(JSON.stringify(result)).not.toContain(secret)
    expect(readFileSync(destination, 'utf8')).toBe('previous export'); expect(temporaries()).toEqual([])
    expect(JSON.stringify(state.log.mock.calls)).not.toContain(secret)
  })
  it.each(files.flatMap(channel => ['ENOSPC', 'EBUSY', 'ENOENT'].map(code => [channel, code])))('retains bounded cause %s / %s in persistent diagnostics', async (channel, code) => {
    state.writeFailure = Object.assign(new Error('private-' + secret), { code })
    const result = await invokeExport(channel)
    expect(result).toMatchObject({ ok: false, error: { category: 'internal' } })
    const { raw } = await logRows()
    const failed = raw.trim().split('\n').map(line => JSON.parse(line)).find(row => row.message === 'key export failed')
    expect(failed).toMatchObject({ correlationId: result.correlationId, details: { destination: 'file', reason: 'internal', ioCode: code } })
    expect(raw).not.toContain(secret)
    expect(readFileSync(destination, 'utf8')).toBe('previous export'); expect(temporaries()).toEqual([])
  })
  it.each(files.filter(channel => channel.includes('export-all')))('persists nonsecret success counts for %s', async channel => {
    const { serverPickerStore } = await import('./sharedStores')
    const profiles = serverPickerStore.get('profiles')
    serverPickerStore.set('profiles', [...profiles, { ...profiles[0], id: 'unsupported', outbound: undefined }])
    const result = await invokeExport(channel)
    expect(result).toMatchObject({ ok: true, result: { ok: true, total: 2, exported: 1, skipped: 1 } })
    const { raw } = await logRows()
    const success = raw.trim().split('\n').map(line => JSON.parse(line)).find(row => row.message === channel.slice('servers:'.length))
    expect(success).toMatchObject({ correlationId: result.correlationId, details: { total: 2, exported: 1, skipped: 1 } })
    expect(Object.keys(success.details).sort()).toEqual(['exported', 'skipped', 'total'])
    expect(raw).not.toContain(secret)
  }, 15_000) // Includes real Windows ACL/file preparation, like the native consent fixtures.
  it('shutdown cancels held native clipboard write, then removes only the drained secret', async () => {
    const gate = held(undefined); state.clipboardWrite.mockReturnValueOnce(gate.promise)
    const run = invoke('servers:copy-key', 'a')
    await vi.waitFor(() => expect(state.clipboardWrite).toHaveBeenCalledOnce())
    const closed = vi.fn(); const closing = registry.close().then(closed)
    expect(await run).toMatchObject({ ok: false, error: { category: 'cancelled' } })
    expect(closed).not.toHaveBeenCalled()
    gate.release(); await closing
    expect(state.clipboardText).toBe('')
    expect(registry.list()[0]).toMatchObject({ status: 'cancelled' })
  })
  it('request cancellation drains a held clipboard write and clears only the owned secret', async () => {
    const token = '11111111-1111-4111-8111-111111111111'
    const gate = held(undefined); state.clipboardWrite.mockReturnValueOnce(gate.promise)
    const run = invoke('servers:copy-key', 'a', token)
    await vi.waitFor(() => expect(state.clipboardWrite).toHaveBeenCalledOnce())
    expect(await invoke('operations:cancel-request', token)).toMatchObject({ ok: true, result: true })
    expect(await run).toMatchObject({ ok: false, error: { category: 'cancelled' } })
    expect(registry.isBusy('keys:clipboard')).toBe(true)
    gate.release(); await registry.close()
    expect(state.clipboardText).toBe('')
  })
  it.each(files)('keeps terminal file success after reentrant cancellation: %s', async channel => {
    const token = '11111111-1111-4111-8111-111111111111'
    const { cancelRequesterOperation } = await import('./requesterOperation')
    state.afterRename = () => {
      expect(registry.cancel(running().operationId)).toBe(false)
      expect(cancelRequesterOperation(sender as never, token)).toBe(false)
    }
    const result = await invoke(channel, ...(channel.startsWith('servers:export-all-') ? [] : ['a']), token)
    expect(result).toMatchObject({ ok: true, result: { ok: true, path: destination } })
    expect(readFileSync(destination, 'utf8')).toContain(secret)
    expect(registry.list()[0]).toMatchObject({ status: 'success' })
    expect(JSON.stringify(result)).not.toContain(secret)
    expect(await invoke('operations:cancel-request', token)).toMatchObject({ ok: true, result: false })
  })
  it.each(channels)('allows a long consent decision without spending work budget: %s', async channel => {
    const gate = held({ response: 1 }); state.nativePrompt.mockReturnValueOnce(gate.promise)
    vi.useFakeTimers()
    const run = invokeExport(channel)
    await vi.advanceTimersByTimeAsync(600_000)
    expect(running()).toMatchObject({ deadline: null })
    vi.useRealTimers(); gate.release()
    expect(await run).toMatchObject({ ok: true, result: { ok: true } })
    expect(sender.listenerCount('destroyed')).toBe(0)
  }, 15_000) // Native private-file preparation follows the simulated user wait.
  it('still times out actual native clipboard work and drains before cleanup', async () => {
    const gate = held(undefined); state.clipboardWrite.mockReturnValueOnce(gate.promise)
    vi.useFakeTimers()
    const run = invoke('servers:copy-key', 'a')
    await vi.waitFor(() => expect(state.clipboardWrite).toHaveBeenCalledOnce())
    await vi.advanceTimersByTimeAsync(120_000)
    expect(await run).toMatchObject({ ok: false, error: { category: 'timeout' } })
    expect(registry.isBusy('keys:clipboard')).toBe(true)
    gate.release(); await registry.close()
    expect(state.clipboardText).toBe(''); expect(registry.isBusy('keys:clipboard')).toBe(false)
  })
  it('preserves concurrent operation identities and redaction in real JSONL and diagnostic read-back', async () => {
    const gate = held({ response: 1 }); state.nativePrompt.mockReturnValueOnce(gate.promise)
    const one = invoke('servers:export-key', 'a'), two = invoke('servers:export-all-proxies-file')
    const records = registry.list()
    expect(records).toHaveLength(2)
    const result = await two
    registry.cancel(records[0].operationId)
    expect(await one).toMatchObject({ ok: false, correlationId: records[0].correlationId, error: { category: 'cancelled' } })
    expect(result).toMatchObject({ ok: true, correlationId: records[1].correlationId })
    gate.release(); await registry.close()
    const { raw, logger } = await logRows()
    const events = raw.trim().split('\n').map(line => JSON.parse(line)).filter(row => row.message === 'feature operation')
    for (const [index, record] of records.entries()) {
      const grouped = events.filter(row => row.details.operationKey === 'op_' + record.operationId.replaceAll('-', ''))
      expect(grouped.map(row => row.details.status)).toEqual(['running', index === 0 ? 'cancelled' : 'success'])
      expect(grouped.every(row => row.correlationId === record.correlationId && row.details.correlationId === record.correlationId)).toBe(true)
      expect(raw).not.toContain(record.operationId)
    }
    expect(raw).not.toContain(secret)
    const diagnostic = (await logger.getFullLogs()).find(file => file.path === logger.getAppLogPath())!
    expect(diagnostic.content.trim().split('\n').map(line => JSON.parse(line)).filter(row => row.message === 'feature operation')).toEqual(events)
  })
  it('user dismissal remains quiet and has a cancelled terminal record', async () => {
    state.nativePrompt.mockResolvedValueOnce({ response: 0 })
    expect(await invoke('servers:export-key', 'a')).toMatchObject({ ok: true, result: { ok: false, cancelled: true } })
    expect(registry.list()[0]).toMatchObject({ status: 'cancelled', category: 'cancelled' })
  })
})
