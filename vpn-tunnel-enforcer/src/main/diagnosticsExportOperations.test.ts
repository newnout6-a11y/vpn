// AT-00-003/004/005: actual ZIP exporter/registry/request ownership and file I/O.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { EventEmitter } from 'node:events'
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { join } from 'node:path'

const state = vi.hoisted(() => ({ dir: '', prompt: vi.fn(), snapshot: vi.fn(), diagnostics: vi.fn(), compress: vi.fn(), log: vi.fn(),
  cleanupFails: false, temporaryCleanupFails: false, work: '', writes: [] as string[], writeGate: null as null | Promise<unknown>, fileGate: null as null | Promise<unknown> }))
vi.mock('fs/promises', async importOriginal => {
  const real = await importOriginal<typeof import('node:fs/promises')>()
  return { ...real,
    mkdtemp: async (...args: Parameters<typeof real.mkdtemp>) => { const path = await real.mkdtemp(...args); state.work = String(path); return path },
    writeFile: async (...args: Parameters<typeof real.writeFile>) => {
      state.writes.push(String(args[0]))
      if (String(args[0]).endsWith('settings.json') && state.writeGate) await state.writeGate
      return real.writeFile(...args)
    },
    open: async (...args: Parameters<typeof real.open>) => {
      const file = await real.open(...args)
      if (String(args[0]).includes('.vpnte-export-') && state.fileGate) {
        const write = file.writeFile.bind(file)
        file.writeFile = async (...values: Parameters<typeof file.writeFile>) => { await state.fileGate; return write(...values) }
      }
      return file
    },
    rm: async (...args: Parameters<typeof real.rm>) => {
      if (state.temporaryCleanupFails && String(args[0]).includes('.vpnte-export-')) throw Object.assign(new Error('private residue'), { code: 'EACCES' })
      if (state.cleanupFails && String(args[0]) === state.work) throw Object.assign(new Error('private cleanup detail'), { code: 'EACCES' })
      return real.rm(...args)
    }
  }
})
vi.mock('electron', () => ({ app: { getPath: () => state.dir, getVersion: () => 'test' }, dialog: { showSaveDialog: state.prompt }, ipcMain: { handle: vi.fn() } }))
vi.mock('child_process', () => ({ execFile: Object.assign((...args: unknown[]) => state.compress(...args), {
  [Symbol.for('nodejs.util.promisify.custom')]: (...args: unknown[]) => new Promise((resolve, reject) => {
    state.compress(...args, (error: unknown, stdout: string, stderr: string) => error ? reject(error) : resolve({ stdout, stderr }))
  })
}) }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({}) } }))
vi.mock('./systemDiagnostics', () => ({ runSystemDiagnostics: state.diagnostics }))
vi.mock('./systemSnapshot', () => ({ captureSnapshot: state.snapshot }))
vi.mock('./trafficForensics', () => ({ stageTrafficForensicsArtifacts: async () => false }))
vi.mock('./tunController', () => ({ getTunRuntimeDir: () => join(state.dir, 'missing') }))
vi.mock('./systemNetwork', () => ({ validateNetworkBackupManifest: (v: unknown) => v }))
vi.mock('./firewallKillSwitch', () => ({ validateFirewallManifest: (v: unknown) => v }))
vi.mock('./physicalAdapterLockdown', () => ({ validateLockdownManifest: (v: unknown) => v }))
vi.mock('./recoveryManifest', () => ({ readRecoveryManifest: async () => null, validateBootRecoveryReport: (v: unknown) => v }))
vi.mock('./appLogger', () => ({ logEvent: state.log, getFullLogs: async () => [] }))
vi.mock('./vpnProfiles', () => ({ redactSensitiveConfig: (v: unknown) => v, redactSensitiveText: (v: string) => v, redactSettingsForDiagnostics: (v: unknown) => v }))

import { exportDiagnosticsZip } from './diagnosticsExport'
import { operations } from './operations'
import { cancelRequesterOperation } from './requesterOperation'
const token = '11111111-1111-4111-8111-111111111111'
class Sender extends EventEmitter { send = vi.fn(); isDestroyed() { return false } }
let sender: Sender, target: string
const releases: Array<() => void> = []
function held<T>(value: T) {
  let release!: () => void
  const promise = new Promise<T>(done => { release = () => done(value) })
  releases.push(release)
  return { promise, release }
}
const run = () => exportDiagnosticsZip(sender as never, token)
beforeEach(async () => {
  vi.clearAllMocks(); operations.resumeAdmission()
  state.cleanupFails = false; state.temporaryCleanupFails = false; state.work = ''; state.writeGate = null; state.fileGate = null; state.writes = []
  state.dir = await mkdtemp(join(process.cwd(), '.tmp', 'diagnostics-owned-'))
  target = join(state.dir, 'destination.zip'); await writeFile(target, 'old archive')
  sender = new Sender()
  state.snapshot.mockReset().mockResolvedValue(null)
  state.diagnostics.mockReset().mockResolvedValue({})
  state.prompt.mockReset().mockResolvedValue({ canceled: false, filePath: target })
  state.compress.mockReset().mockImplementation((_exe, args: string[], _options, callback) => {
    const script = Buffer.from(args.at(-1)!, 'base64').toString('utf16le')
    if (script.includes('CONFIG_EXPORT_ACL_VERIFIED')) { callback(null, 'CONFIG_EXPORT_ACL_VERIFIED', ''); return }
    const path = script.match(/\$target='([^']+)'/)![1]
    void writeFile(path, Buffer.from([80, 75, 0, 255, 1])).then(() => callback(null, '', ''), callback)
  })
})
afterEach(async () => {
  for (const release of releases.splice(0)) release()
  await operations.close(); vi.useRealTimers()
  state.cleanupFails = false; state.temporaryCleanupFails = false
  if (state.work) await rm(state.work, { recursive: true, force: true, maxRetries: 8, retryDelay: 25 })
  await rm(state.dir, { recursive: true, force: true, maxRetries: 8, retryDelay: 25 })
})
describe('diagnostic ZIP lifetime', () => {
  it('streams binary bytes unchanged, commits once, cleans staging and forgets the token', async () => {
    expect(await run()).toEqual({ success: true, path: target })
    expect(await readFile(target)).toEqual(Buffer.from([80, 75, 0, 255, 1]))
    expect(operations.list().at(-1)?.status).toBe('success')
    expect(cancelRequesterOperation(sender as never, token)).toBe(false)
    expect(await readdir(state.dir)).toEqual(['destination.zip'])
    expect(await readdir(state.work).catch(() => null)).toBeNull()
    expect(sender.eventNames()).toEqual([])
    expect(state.log).toHaveBeenCalledWith('info', 'diag-export', 'diagnostics zip written', { destination: 'selected-file' })
    expect(state.snapshot).toHaveBeenCalledWith('manual', expect.objectContaining({ signal: expect.any(AbortSignal), assertActive: expect.any(Function) }))
  })

  it.each(['snapshot', 'collection', 'staging', 'compression', 'destination'] as const)
  ('cancels at %s, drains its raw effect and blocks all later writes', async phase => {
    const gate = held(phase === 'snapshot' ? null : {})
    let reached = () => false
    if (phase === 'snapshot') { state.snapshot.mockReturnValueOnce(gate.promise); reached = () => state.snapshot.mock.calls.length > 0 }
    if (phase === 'collection') { state.diagnostics.mockReturnValueOnce(gate.promise); reached = () => state.diagnostics.mock.calls.length > 0 }
    if (phase === 'staging') { state.writeGate = gate.promise; reached = () => state.writes.some(path => path.endsWith('settings.json')) }
    if (phase === 'destination') { state.fileGate = gate.promise; reached = () => state.compress.mock.calls.length > 0 }
    if (phase === 'compression') {
      const compress = state.compress.getMockImplementation()!
      state.compress.mockImplementationOnce((...args) => { void gate.promise.then(() => compress(...args)) })
      reached = () => state.compress.mock.calls.length > 0
    }
    const result = run(); void result.catch(() => {})
    await vi.waitFor(() => expect(reached()).toBe(true))
    if (phase === 'destination') await vi.waitFor(async () => expect((await readdir(state.dir)).some(name => name.startsWith('.vpnte-export-'))).toBe(true))
    const start = performance.now()
    expect(cancelRequesterOperation(sender as never, token)).toBe(true)
    await expect(result).rejects.toMatchObject({ category: 'cancelled' })
    expect(performance.now() - start).toBeLessThan(900)
    expect(operations.isBusy('diagnostics:export')).toBe(true)
    const writes = () => state.writes.filter(path => !path.endsWith('diagnostics.zip')).length
    const count = writes()
    gate.release(); await operations.close()
    expect(writes()).toBe(count)
    expect(await readFile(target, 'utf8')).toBe('old archive')
    expect(await readdir(state.dir)).toEqual(['destination.zip'])
    if (phase === 'snapshot') expect(state.prompt).not.toHaveBeenCalled()
    expect(sender.eventNames()).toEqual([])
    expect(operations.list().at(-1)?.status).toBe('cancelled')
  })

  it('expires the work budget while collection is pending and retains the lease until drain', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const gate = held({}); state.diagnostics.mockReturnValueOnce(gate.promise)
    const result = run(); void result.catch(() => {})
    await vi.waitFor(() => expect(state.diagnostics).toHaveBeenCalledOnce())
    await vi.advanceTimersByTimeAsync(120_001)
    expect(operations.list().at(-1)?.status).toBe('running')
    await vi.advanceTimersByTimeAsync(480_000)
    await expect(result).rejects.toMatchObject({ category: 'timeout' })
    expect(operations.isBusy('diagnostics:export')).toBe(true)
    gate.release(); await operations.close()
    expect(await readFile(target, 'utf8')).toBe('old archive')
    expect(state.compress).not.toHaveBeenCalled()
  })

  it('reports cleanup failure alongside a successfully committed archive', async () => {
    state.cleanupFails = true
    expect(await run()).toEqual({ success: true, path: target, warning: 'cleanup-failed' })
    expect(state.log).toHaveBeenCalledWith('warn', 'diag-export', 'diagnostics cleanup failed', { reason: 'permission', ioCode: 'EACCES' })
    expect(await readFile(target)).toEqual(Buffer.from([80, 75, 0, 255, 1]))
  })

  it('notifies once when cancelled destination staging cannot be deleted', async () => {
    const gate = held(undefined); state.fileGate = gate.promise; state.temporaryCleanupFails = true
    const result = run(); void result.catch(() => {})
    await vi.waitFor(async () => expect((await readdir(state.dir)).some(name => name.startsWith('.vpnte-export-'))).toBe(true))
    expect(cancelRequesterOperation(sender as never, token)).toBe(true)
    await expect(result).rejects.toMatchObject({ category: 'cancelled' })
    gate.release(); await operations.close()
    expect(sender.send).toHaveBeenCalledExactlyOnceWith('inapp-notification', expect.objectContaining({ level: 'warn', title: 'Очистка диагностики не завершена' }))
    expect(await readFile(target, 'utf8')).toBe('old archive')
    expect((await readdir(state.dir)).some(name => name.startsWith('.vpnte-export-'))).toBe(true)
  })

  it('returns only a bounded typed fault after a compression failure', async () => {
    state.compress.mockImplementationOnce((_exe, _args, _options, callback) => callback(Object.assign(new Error('C:\\private\\secret raw process output'), { code: 'EACCES' })))
    await expect(run()).rejects.toMatchObject({ category: 'permission', message: 'Недостаточно прав для операции' })
    expect(await readFile(target, 'utf8')).toBe('old archive')
    expect(await readdir(state.work).catch(() => null)).toBeNull()
  })

  it('rejects malformed and duplicate requester ids without a second snapshot', async () => {
    await expect(exportDiagnosticsZip(sender as never, 'bad')).rejects.toMatchObject({ category: 'validation' })
    expect(state.snapshot).not.toHaveBeenCalled()
    const gate = held(null); state.snapshot.mockReturnValueOnce(gate.promise)
    const result = run(); void result.catch(() => {})
    await expect(run()).rejects.toMatchObject({ category: 'conflict' })
    expect(state.snapshot).toHaveBeenCalledOnce()
    sender.emit('destroyed')
    await expect(result).rejects.toMatchObject({ category: 'cancelled' })
    gate.release(); await operations.close()
    expect(state.prompt).not.toHaveBeenCalled()
  })
  it('owns and cancels a held save picker without replacing the old destination', async () => {
    const gate = held({ canceled: false, filePath: target }); state.prompt.mockReturnValueOnce(gate.promise)
    const result = run(); void result.catch(() => {})
    await vi.waitFor(() => expect(state.prompt).toHaveBeenCalledOnce())
    expect(operations.list().at(-1)).toMatchObject({ kind: 'export', owner: 'manual', status: 'running', deadline: null })
    expect(cancelRequesterOperation(new Sender() as never, token)).toBe(false)
    const start = performance.now()
    expect(cancelRequesterOperation(sender as never, token)).toBe(true)
    await expect(result).rejects.toMatchObject({ category: 'cancelled' })
    expect(performance.now() - start).toBeLessThan(900)
    expect(operations.isBusy('diagnostics:export')).toBe(true)
    gate.release(); await operations.close()
    expect(await readFile(target, 'utf8')).toBe('old archive')
    expect(state.compress).not.toHaveBeenCalled()
    expect(sender.eventNames()).toEqual([])
  })
})
