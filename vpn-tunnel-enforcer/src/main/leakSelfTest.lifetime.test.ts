// AT-00-003/005: subscriber cancellation and physical drain are separate.
import { EventEmitter } from 'node:events'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({ exec: vi.fn(), execFile: vi.fn(), native: vi.fn(), forensic: vi.fn(), log: vi.fn() }))
vi.mock('child_process', () => ({ exec: state.exec, execFile: state.execFile }))
vi.mock('electron', () => ({ ipcMain: { handle: vi.fn() } }))
vi.mock('./native/nativeNetworkReads', () => ({ nativePhysicalIpv4Sources: state.native }))
vi.mock('./appLogger', () => ({ logEvent: state.log }))
type Callback = (error: Error | null, stdout: string, stderr: string) => void
class Child extends EventEmitter {
  kill = vi.fn(() => true)
  closed = false
  replied = false
  constructor(readonly file: string, readonly args: string[], private callback: Callback) { super() }
  finish(stdout = '', code = 0) {
    this.reply(stdout, code); this.close(code)
  }
  reply(stdout = '', code = 0) {
    if (this.replied) return
    this.replied = true
    this.callback(code ? Object.assign(new Error('blocked'), { code }) : null, stdout, code ? 'blocked' : '')
  }
  close(code = 0) {
    if (this.closed) return
    this.closed = true
    this.emit('close', code)
  }
}
let children: Child[] = []
let releaseImport: (() => void) | undefined
beforeEach(() => {
  vi.resetModules(); vi.clearAllMocks(); children = []; releaseImport = undefined
  state.native.mockResolvedValue([{ alias: 'Wi-Fi', ipv4: '192.0.2.10' }])
  state.execFile.mockImplementation((file: string, args: string[], _options: unknown, callback: Callback) => {
    const child = new Child(file, args, callback); children.push(child); return child
  })
  state.exec.mockImplementation((file: string, _options: unknown, callback: Callback) => {
    const child = new Child(file, [], callback); children.push(child); return child
  })
  for (const fn of [state.exec, state.execFile]) {
    Object.assign(fn, { [Symbol.for('nodejs.util.promisify.custom')]: (...args: unknown[]) => new Promise((yes, no) => {
      fn(...args, (error: Error | null, stdout: string, stderr: string) => error ? no(Object.assign(error, { stdout, stderr })) : yes({ stdout, stderr }))
    }) })
  }
  vi.doMock('./trafficForensics', () => ({ recordTrafficForensicsAppEvent: state.forensic }))
})
afterEach(async () => {
  releaseImport?.()
  for (const child of children) child.finish()
  const { cancelLeakSelfTest } = await import('./leakSelfTest')
  cancelLeakSelfTest()
  await Promise.resolve()
  for (const child of children) child.finish()
})
async function finishCheck() {
  await vi.waitFor(() => expect(children.length).toBeGreaterThan(0)); children[0].finish('198.51.100.1')
  await vi.waitFor(() => expect(children.length).toBe(2)); children[1].finish('', 7)
  await vi.waitFor(() => expect(children.length).toBe(3)); children[2].finish('ip=198.51.100.1')
}

describe('leak self-test lifetime', () => {
  it('cancels one subscriber promptly without stopping the shared check for another', async () => {
    const { runLeakSelfTest } = await import('./leakSelfTest'), controller = new AbortController()
    const { currentCorrelationId } = await import('./actionCorrelation')
    let rootId: string | undefined, resultId: string | undefined
    state.log.mockImplementation((_level, module, message) => { if (module === 'leak-test' && String(message).startsWith('OK:')) resultId = currentCorrelationId() })
    const a = runLeakSelfTest({ signal: controller.signal, onOperation: lease => { rootId = lease.operation.correlationId } }).catch(error => error)
    const b = runLeakSelfTest()
    await vi.waitFor(() => expect(children).toHaveLength(1))
    controller.abort()
    expect(await a).toMatchObject({ category: 'cancelled' })
    expect(children[0].kill).not.toHaveBeenCalled()
    await finishCheck()
    expect((await b).physicalAdapterInspectionComplete).toBe(true)
    expect(children).toHaveLength(3)
    expect(resultId).toBe(rootId)
  })
  it('kills the last subscriber child but retains admission until physical close', async () => {
    const { runLeakSelfTest } = await import('./leakSelfTest'), controller = new AbortController()
    let drained = false
    const pending = runLeakSelfTest({ signal: controller.signal, onOperation: lease => { void lease.drained.then(() => { drained = true }) } }).catch(error => error)
    await vi.waitFor(() => expect(children).toHaveLength(1)); controller.abort()
    expect(await pending).toMatchObject({ category: 'cancelled' })
    expect(children[0].kill).toHaveBeenCalledOnce()
    expect(drained).toBe(false)
    await expect(runLeakSelfTest()).rejects.toMatchObject({ category: 'conflict' })
    children[0].finish('198.51.100.1')
    await vi.waitFor(() => expect(drained).toBe(true))
    expect(children).toHaveLength(1)
    expect(state.forensic).not.toHaveBeenCalled()
  })
  it('global stop promptly returns the legacy cancelled view and kills physical work', async () => {
    const { runLeakSelfTest, cancelLeakSelfTest } = await import('./leakSelfTest')
    const pending = runLeakSelfTest()
    await vi.waitFor(() => expect(children).toHaveLength(1)); cancelLeakSelfTest()
    expect(children[0].kill).toHaveBeenCalledOnce()
    expect(await pending).toMatchObject({ physicalAdapterInspectionComplete: false, summary: expect.stringContaining('отменён') })
    children[0].finish('198.51.100.1')
    expect(state.forensic).not.toHaveBeenCalled()
  })
  it('expires a subscriber with a typed timeout and kills its last physical child', async () => {
    const { runLeakSelfTest } = await import('./leakSelfTest')
    const pending = runLeakSelfTest({ timeoutMs: 30 }).catch(error => error)
    await vi.waitFor(() => expect(children).toHaveLength(1))
    expect(await pending).toMatchObject({ category: 'timeout' })
    expect(children[0].kill).toHaveBeenCalledOnce()
    children[0].finish()
  })
  it('retains a noncancellable native read without starting its PowerShell fallback after cancel', async () => {
    let finishNative!: (rows: []) => void
    state.native.mockImplementation(() => new Promise<[]>(yes => { finishNative = yes }))
    const { runLeakSelfTest } = await import('./leakSelfTest'), controller = new AbortController()
    let drained = false
    const pending = runLeakSelfTest({ signal: controller.signal, onOperation: lease => { void lease.drained.then(() => { drained = true }) } }).catch(error => error)
    await vi.waitFor(() => expect(children).toHaveLength(1)); children[0].finish('198.51.100.1')
    await vi.waitFor(() => expect(state.native).toHaveBeenCalledOnce())
    controller.abort(); expect(await pending).toMatchObject({ category: 'cancelled' })
    expect(drained).toBe(false)
    await expect(runLeakSelfTest()).rejects.toMatchObject({ category: 'conflict' })
    finishNative([]); await vi.waitFor(() => expect(drained).toBe(true))
    expect(children).toHaveLength(1)
  })
  it('kills a PowerShell fallback and prevents later probes', async () => {
    state.native.mockRejectedValue(new Error('native unavailable'))
    const { runLeakSelfTest } = await import('./leakSelfTest'), controller = new AbortController()
    const pending = runLeakSelfTest({ signal: controller.signal }).catch(error => error)
    await vi.waitFor(() => expect(children).toHaveLength(1)); children[0].finish('198.51.100.1')
    await vi.waitFor(() => expect(children).toHaveLength(2))
    expect(children[1].file).toBe('powershell.exe')
    controller.abort(); expect(await pending).toMatchObject({ category: 'cancelled' })
    expect(children[1].kill).toHaveBeenCalledOnce(); children[1].finish('[]')
    await Promise.resolve(); expect(children).toHaveLength(2)
  })
  it('does not release physical admission on an early process callback before close', async () => {
    const { runLeakSelfTest } = await import('./leakSelfTest'), controller = new AbortController()
    let drained = false
    const pending = runLeakSelfTest({ signal: controller.signal, onOperation: lease => { void lease.drained.then(() => { drained = true }) } }).catch(error => error)
    await vi.waitFor(() => expect(children).toHaveLength(1)); children[0].reply('198.51.100.1')
    for (let i = 0; i < 10; i++) await Promise.resolve()
    expect(state.native).not.toHaveBeenCalled()
    controller.abort(); expect(await pending).toMatchObject({ category: 'cancelled' })
    expect(drained).toBe(false); children[0].close()
    await vi.waitFor(() => expect(drained).toBe(true))
  })
  it('fences a delayed forensic import after global stop and retains it until settlement', async () => {
    let entered = false
    const gate = new Promise<void>(yes => { releaseImport = yes })
    vi.doMock('./trafficForensics', async () => { entered = true; await gate; return { recordTrafficForensicsAppEvent: state.forensic } })
    const { runLeakSelfTest, cancelLeakSelfTest } = await import('./leakSelfTest')
    let drained = false
    const pending = runLeakSelfTest({ onOperation: lease => { void lease.drained.then(() => { drained = true }) } })
    await finishCheck(); await vi.waitFor(() => expect(entered).toBe(true))
    cancelLeakSelfTest()
    expect((await pending).physicalAdapterInspectionComplete).toBe(false)
    expect(drained).toBe(false)
    await expect(runLeakSelfTest()).rejects.toMatchObject({ category: 'conflict' })
    releaseImport!(); await vi.waitFor(() => expect(drained).toBe(true))
    expect(state.forensic).not.toHaveBeenCalled()
  })
  it('physically cancels a periodic run when periodic testing stops', async () => {
    const { startPeriodicLeakTest, stopPeriodicLeakTest } = await import('./leakSelfTest')
    vi.useFakeTimers()
    try {
      startPeriodicLeakTest(100)
      await vi.advanceTimersByTimeAsync(100)
      expect(children).toHaveLength(1)
      stopPeriodicLeakTest()
      expect(children[0].kill).toHaveBeenCalledOnce()
    } finally { stopPeriodicLeakTest(); vi.useRealTimers() }
  })
  it('rejects an already cancelled subscriber without spawning work', async () => {
    const { runLeakSelfTest } = await import('./leakSelfTest'), controller = new AbortController()
    controller.abort()
    await expect(runLeakSelfTest({ signal: controller.signal })).rejects.toMatchObject({ category: 'cancelled' })
    expect(children).toHaveLength(0)
  })
  it('returns detached views to coalesced subscribers', async () => {
    const { runLeakSelfTest } = await import('./leakSelfTest')
    const a = runLeakSelfTest(), b = runLeakSelfTest()
    await finishCheck()
    const [first, second] = await Promise.all([a, b])
    first.perAdapter[0].alias = 'caller mutation'
    expect(second.perAdapter[0].alias).toBe('Wi-Fi')
  })
  it('drains a real owned child process after cancellation without making network requests', async () => {
    const { execFile } = await vi.importActual<typeof import('node:child_process')>('node:child_process')
    let child: import('node:child_process').ChildProcess | undefined, closed = false
    state.execFile.mockImplementation((_file, _args, _options, callback) => {
      child = execFile(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { windowsHide: true, timeout: 5000, encoding: 'utf8' }, callback)
      child.once('close', () => { closed = true })
      return child
    })
    const { runLeakSelfTest } = await import('./leakSelfTest'), controller = new AbortController()
    let drain = Promise.resolve()
    const pending = runLeakSelfTest({ signal: controller.signal, onOperation: lease => { drain = lease.drained } }).catch(error => error)
    try {
      await vi.waitFor(() => expect(child?.pid).toBeGreaterThan(0))
      controller.abort(); expect(await pending).toMatchObject({ category: 'cancelled' })
      await drain
      expect(closed).toBe(true)
      expect(child?.killed).toBe(true)
      expect(state.native).not.toHaveBeenCalled()
    } finally { if (child && child.exitCode === null && child.signalCode === null) child.kill() }
  }, 15000)
})
