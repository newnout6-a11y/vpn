import { EventEmitter } from 'node:events'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { createServer, Socket } from 'node:net'
import ts from 'typescript'
import { afterEach, describe, expect, it, vi } from 'vitest'

const source = readFileSync(join(process.cwd(), 'src/main/xrayEngine.ts'), 'utf8')
const ast = ts.createSourceFile('xrayEngine.ts', source, ts.ScriptTarget.Latest, true)
const declaration = ast.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'waitForLocalSocks')
if (!declaration) throw new Error('Production SOCKS readiness function missing')
const compiled = ts.transpileModule(declaration.getText(ast), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS }
}).outputText
const load = (socket: unknown) => new Function('Socket', `${compiled}; return waitForLocalSocks`)(socket) as
  (port: number, timeoutMs: number, signal?: AbortSignal) => Promise<void>

class FixtureSocket extends EventEmitter {
  static created: FixtureSocket[] = []
  connect = vi.fn()
  setTimeout = vi.fn()
  destroy = vi.fn()
  constructor() { super(); FixtureSocket.created.push(this) }
}
afterEach(() => { FixtureSocket.created = []; vi.useRealTimers() })

describe('interruptible production SOCKS readiness (AT-00-003/007; AT-02-004/005)', () => {
  it('cancels a held connect immediately and destroys the owned socket', async () => {
    vi.useFakeTimers()
    const controller = new AbortController()
    const waiting = load(FixtureSocket)(50123, 3500, controller.signal)
    const failed = expect(waiting).rejects.toThrow('Xray startup cancelled')
    const socket = FixtureSocket.created[0]
    expect(socket.connect).toHaveBeenCalledWith(50123, '127.0.0.1')
    controller.abort()
    await failed
    expect(socket.destroy).toHaveBeenCalledOnce()
    expect(vi.getTimerCount()).toBe(0)
    socket.emit('connect') // A queued event cannot resurrect readiness.
    socket.emit('error', new Error('late connect failure'))
    expect(socket.destroy).toHaveBeenCalledOnce()
  })
  it('interrupts the retry delay without another connect attempt', async () => {
    vi.useFakeTimers()
    const controller = new AbortController()
    const waiting = load(FixtureSocket)(50123, 3500, controller.signal)
    const failed = expect(waiting).rejects.toThrow('Xray startup cancelled')
    FixtureSocket.created[0].emit('error', new Error('connection refused'))
    await vi.advanceTimersByTimeAsync(0)
    expect(vi.getTimerCount()).toBe(1)
    controller.abort()
    await failed
    await vi.advanceTimersByTimeAsync(1000)
    expect(FixtureSocket.created).toHaveLength(1)
    expect(vi.getTimerCount()).toBe(0)
  })
  it('rejects an already aborted signal without creating a socket', async () => {
    const controller = new AbortController()
    controller.abort()
    await expect(load(FixtureSocket)(50123, 3500, controller.signal)).rejects.toThrow('Xray startup cancelled')
    expect(FixtureSocket.created).toHaveLength(0)
  })
  it('removes the abort listener after success and destroys the successful socket', async () => {
    const controller = new AbortController()
    const remove = vi.spyOn(controller.signal, 'removeEventListener')
    const waiting = load(FixtureSocket)(50123, 3500, controller.signal)
    FixtureSocket.created[0].emit('connect')
    await expect(waiting).resolves.toBeUndefined()
    expect(remove).toHaveBeenCalledWith('abort', expect.any(Function))
    controller.abort()
    expect(FixtureSocket.created[0].destroy).toHaveBeenCalledOnce()
  })
  it('retains retry/error reporting and the original bounded deadline without cancellation', async () => {
    vi.useFakeTimers()
    class RefusedSocket extends FixtureSocket {
      connect = vi.fn(() => { this.emit('error', new Error('connection refused')) })
    }
    const waiting = load(RefusedSocket)(50123, 350)
    const failed = expect(waiting).rejects.toThrow('connection refused')
    await vi.advanceTimersByTimeAsync(350)
    await failed
    expect(FixtureSocket.created).toHaveLength(4)
    expect(FixtureSocket.created.every(socket => socket.destroy.mock.calls.length === 1)).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
  })
  it('does not report ready when cancellation races with a successful connect', async () => {
    const controller = new AbortController()
    const waiting = load(FixtureSocket)(50123, 3500, controller.signal)
    const failed = expect(waiting).rejects.toThrow('Xray startup cancelled')
    FixtureSocket.created[0].emit('connect')
    controller.abort()
    await failed
  })
  it('passes the startup owner signal to readiness and preserves cancellation classification', () => {
    expect(source).toContain('waitForLocalSocks(socksPort, SOCKS_PROBE_TIMEOUT_MS, options.signal)')
    expect(source).toContain("if (options.signal?.aborted) throw new Error('Xray startup cancelled')")
  })
  it('executes successful readiness and cancellation with real loopback sockets', async () => {
    const server = createServer(socket => socket.end())
    await new Promise<void>((resolve, reject) => {
      server.once('error', reject)
      server.listen(0, '127.0.0.1', () => resolve())
    })
    const address = server.address()
    if (!address || typeof address === 'string') throw new Error('Loopback fixture port missing')
    try { await expect(load(Socket)(address.port, 3500)).resolves.toBeUndefined() }
    finally { await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())) }
    const controller = new AbortController()
    const waiting = load(Socket)(address.port, 3500, controller.signal)
    const failed = expect(waiting).rejects.toThrow('Xray startup cancelled')
    await new Promise(resolve => setTimeout(resolve, 30))
    const began = performance.now()
    controller.abort()
    await failed
    expect(performance.now() - began).toBeLessThan(1000)
  }, 10000)
})
