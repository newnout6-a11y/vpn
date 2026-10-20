// AT-00-003/005: subscriber cancellation and physical drain are separate.
import { EventEmitter } from 'node:events'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import ts from 'typescript'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({ exec: vi.fn(), execFile: vi.fn(), native: vi.fn(), forensic: vi.fn(), log: vi.fn(), snapshot: vi.fn() }))
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
  state.forensic.mockResolvedValue(true)
  state.snapshot.mockResolvedValue(null)
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

// Exercise the actual main handler with the production requester/operation registries.
async function invokeRequester(owner: EventEmitter, token?: string) {
  const source = readFileSync(join(process.cwd(), 'src/main/index.ts'), 'utf8')
  const ast = ts.createSourceFile('index.ts', source, ts.ScriptTarget.Latest, true)
  let listener: ts.Expression | undefined
  const visit = (node: ts.Node) => {
    if (ts.isCallExpression(node) && node.expression.getText(ast) === 'handleLogged'
      && ts.isStringLiteral(node.arguments[0]) && node.arguments[0].text === 'run-leak-self-test') listener = node.arguments[1]
    ts.forEachChild(node, visit)
  }
  visit(ast)
  if (!listener) throw new Error('Missing production leak handler')
  const compiled = ts.transpileModule(`return (${listener.getText(ast)})`, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
  const deps = { runLeakSelfTest: (await import('./leakSelfTest')).runLeakSelfTest,
    runRequesterOperation: (await import('./requesterOperation')).runRequesterOperation,
    operations: (await import('./operations')).operations, captureSnapshot: state.snapshot }
  const handler = new Function(...Object.keys(deps), compiled)(...Object.values(deps))
  return handler({ sender: owner }, token)
}
const sender = () => Object.assign(new EventEmitter(), { isDestroyed: () => false })
describe('leak requester main handler', () => {
  it.each(['destroyed', 'did-navigate', 'render-process-gone'])('cancels legacy document work on %s', async event => {
    const owner = sender(), task = invokeRequester(owner).catch(error => error)
    await vi.waitFor(() => expect(children).toHaveLength(1))
    owner.emit(event)
    expect(children[0].kill).toHaveBeenCalledOnce()
    expect(await task).toMatchObject({ category: 'cancelled' })
    children[0].finish()
    expect(state.snapshot).not.toHaveBeenCalled()
    expect(owner.eventNames()).toEqual([])
  })
  it('returns a known leak promptly while shutdown drains its background snapshot', async () => {
    let release!: () => void
    state.snapshot.mockImplementationOnce(() => new Promise<void>(yes => { release = yes }))
    const owner = sender()
    let settled = false
    const task = invokeRequester(owner, '11111111-1111-4111-8111-111111111111').catch(error => error).finally(() => { settled = true })
    try {
      await finishCheck(true); await vi.waitFor(() => expect(state.snapshot).toHaveBeenCalledOnce())
      await vi.waitFor(() => expect(settled).toBe(true))
      expect(await task).toMatchObject({ physicalAdapterReached: true })
      owner.emit('did-navigate')
      expect(state.snapshot.mock.calls[0][1].signal.aborted).toBe(false)
      const { operations } = await import('./operations')
      expect(operations.list().find(row => row.kind === 'snapshot')).toMatchObject({ status: 'running', owner: 'manual' })
      let drained = false
      const closing = operations.close().then(() => { drained = true })
      await Promise.resolve(); expect(drained).toBe(false)
      expect(state.snapshot.mock.calls[0][1].signal.aborted).toBe(true)
      release(); await closing
      expect(owner.eventNames()).toEqual([])
    } finally { release?.() }
  })
  it('rejects duplicate/malformed tokens and lets another sender keep the shared check alive', async () => {
    const owner = sender(), peer = sender(), token = '11111111-1111-4111-8111-111111111111'
    const first = invokeRequester(owner, token).catch(error => error), second = invokeRequester(peer, token)
    await vi.waitFor(() => expect(children).toHaveLength(1))
    await expect(invokeRequester(owner, token)).rejects.toMatchObject({ category: 'conflict' })
    await expect(invokeRequester(owner, 'malformed')).rejects.toMatchObject({ category: 'validation' })
    const { cancelRequesterOperation } = await import('./requesterOperation')
    expect(cancelRequesterOperation(sender() as never, token)).toBe(false)
    expect(cancelRequesterOperation(owner as never, token)).toBe(true)
    expect(await first).toMatchObject({ category: 'cancelled' })
    expect(children[0].kill).not.toHaveBeenCalled()
    await finishCheck()
    expect((await second).physicalAdapterInspectionComplete).toBe(true)
    expect(cancelRequesterOperation(peer as never, token)).toBe(false)
    expect(state.snapshot).not.toHaveBeenCalled()
    expect(owner.eventNames()).toEqual([]); expect(peer.eventNames()).toEqual([])
  })
  it('preserves active legacy success while awaiting a best-effort diagnostic snapshot', async () => {
    state.snapshot.mockRejectedValueOnce(new Error('snapshot unavailable'))
    const owner = sender(), task = invokeRequester(owner)
    await finishCheck(true)
    expect((await task).physicalAdapterReached).toBe(true)
    expect(state.snapshot.mock.calls[0]).toEqual(['leak-detected', { signal: expect.any(AbortSignal) }])
    expect(owner.eventNames()).toEqual([])
  })
  it('does not retract an observed leak when a global stop arrives during its snapshot', async () => {
    let release!: () => void
    state.snapshot.mockImplementationOnce(() => new Promise<void>(yes => { release = yes }))
    const owner = sender()
    let settled = false
    const task = invokeRequester(owner).then(result => { settled = true; return result })
    try {
      await finishCheck(true); await vi.waitFor(() => expect(settled).toBe(true))
      const { cancelLeakSelfTest } = await import('./leakSelfTest')
      cancelLeakSelfTest()
      expect(await task).toMatchObject({ physicalAdapterReached: true })
      expect(state.snapshot.mock.calls[0][1].signal.aborted).toBe(false)
      release()
      expect(owner.eventNames()).toEqual([])
    } finally { release?.() }
  })
  it('does not let a background snapshot deadline replace the delivered leak verdict', async () => {
    let release!: () => void
    state.snapshot.mockImplementationOnce(() => new Promise<void>(yes => { release = yes }))
    const { operations } = await import('./operations')
    vi.useFakeTimers()
    try {
      let settled = false
      const task = invokeRequester(sender()).then(result => { settled = true; return result })
      await finishCheck(true); await vi.waitFor(() => expect(settled).toBe(true))
      expect(await task).toMatchObject({ physicalAdapterReached: true })
      await vi.advanceTimersByTimeAsync(60_000)
      expect(operations.list().find(row => row.kind === 'snapshot')).toMatchObject({ status: 'error', category: 'timeout' })
      expect(state.snapshot.mock.calls[0][1].signal.aborted).toBe(true)
      release(); await operations.close()
    } finally { release?.(); vi.useRealTimers() }
  })
  it('shares one retained evidence capture for concurrent leak verdicts', async () => {
    let release!: () => void
    state.snapshot.mockImplementationOnce(() => new Promise<void>(yes => { release = yes }))
    const first = invokeRequester(sender()), second = invokeRequester(sender())
    try {
      await finishCheck(true)
      expect((await first).physicalAdapterReached).toBe(true)
      expect((await second).physicalAdapterReached).toBe(true)
      expect(state.snapshot).toHaveBeenCalledOnce()
      const { operations } = await import('./operations')
      const closing = operations.close(); release(); await closing
    } finally { release?.() }
  })
  it('keeps the request correlation on the independent snapshot operation', async () => {
    const { withCorrelation, currentCorrelationId } = await import('./actionCorrelation')
    const { operations } = await import('./operations')
    const correlationId = 'ipc_11111111111141118111111111111111'
    let snapshotId: string | undefined
    state.snapshot.mockImplementationOnce(async () => { snapshotId = currentCorrelationId() })
    const task = withCorrelation(correlationId, () => invokeRequester(sender()))
    await finishCheck(true); await task; await operations.close()
    expect(snapshotId).toBe(correlationId)
    expect(operations.list().map(row => row.correlationId)).toEqual([correlationId, correlationId])
  })
})

afterEach(async () => {
  releaseImport?.()
  for (const child of children) child.finish()
  const { cancelLeakSelfTest } = await import('./leakSelfTest')
  cancelLeakSelfTest()
  await Promise.resolve()
  for (const child of children) child.finish()
})
async function finishCheck(leaked = false) {
  await vi.waitFor(() => expect(children.length).toBeGreaterThan(0)); children[0].finish('198.51.100.1')
  await vi.waitFor(() => expect(children.length).toBe(2)); children[1].finish(leaked ? '203.0.113.5' : '', leaked ? 0 : 7)
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
    await finishCheck(true); await vi.waitFor(() => expect(entered).toBe(true))
    expect(state.log.mock.calls.filter(([, module, message]) => module === 'leak-test' && String(message).startsWith('УТЕЧКА'))).toEqual([])
    cancelLeakSelfTest()
    expect((await pending).physicalAdapterInspectionComplete).toBe(false)
    expect(drained).toBe(false)
    await expect(runLeakSelfTest()).rejects.toMatchObject({ category: 'conflict' })
    releaseImport!(); await vi.waitFor(() => expect(drained).toBe(true))
    expect(state.forensic).not.toHaveBeenCalled()
    expect(state.log.mock.calls.filter(([, module, message]) => module === 'leak-test' && String(message).startsWith('УТЕЧКА'))).toEqual([])
  })
  it('retains the forensic write promise through cancellation and handles its rejection', async () => {
    let rejectWrite!: (error: Error) => void
    state.forensic.mockImplementation(() => new Promise<boolean>((_yes, no) => { rejectWrite = no }))
    const { runLeakSelfTest } = await import('./leakSelfTest'), controller = new AbortController()
    let drained = false
    const pending = runLeakSelfTest({ signal: controller.signal, onOperation: lease => { void lease.drained.then(() => { drained = true }) } }).catch(error => error)
    await finishCheck(); await vi.waitFor(() => expect(state.forensic).toHaveBeenCalledOnce())
    controller.abort(); await pending
    expect(drained).toBe(false)
    await expect(runLeakSelfTest()).rejects.toMatchObject({ category: 'conflict' })
    rejectWrite(new Error('manifest unavailable'))
    await vi.waitFor(() => expect(drained).toBe(true))
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
