// AT-00-003 / AT-02-004 / AT-02-006: real preflight boundary, fake owned child.
import { EventEmitter } from 'node:events'
import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { spawn } from 'node:child_process'
import { logEvent } from './appLogger'
import { runXrayConfigPreflight, stopXrayPreflights } from './xrayPreflight'
const mocks = vi.hoisted(() => ({ spawn: vi.fn() }))
vi.mock('node:child_process', () => ({ spawn: mocks.spawn, default: { spawn: mocks.spawn } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))

type FakeChild = EventEmitter & { pid?: number; stdout: EventEmitter; stderr: EventEmitter; kill: Mock<(signal?: string) => boolean>; signal?: AbortSignal }
const children: FakeChild[] = []
function finish(child: FakeChild, code: number | null = 0) { child.emit('exit', code); child.emit('close', code) }
beforeEach(() => {
  vi.useFakeTimers()
  vi.mocked(logEvent).mockClear()
  vi.mocked(spawn).mockReset().mockImplementation((_exe, _args, options: any) => {
    const child: FakeChild = Object.assign(new EventEmitter(), { pid: children.length + 100, stdout: new EventEmitter(), stderr: new EventEmitter(), kill: vi.fn(() => true), signal: options.signal })
    options.signal.addEventListener('abort', () => {
      child.kill('SIGKILL')
      child.emit('error', Object.assign(new Error('The operation was aborted'), { name: 'AbortError' }))
    }, { once: true })
    children.push(child)
    return child as any
  })
})
afterEach(async () => {
  children.forEach(child => finish(child))
  children.length = 0
  await stopXrayPreflights()
  vi.clearAllTimers()
  vi.useRealTimers()
})
const run = (signal?: AbortSignal) => runXrayConfigPreflight('owned.exe', 'trusted-runtime', 'protected-config.json', signal)

describe('Xray preflight deadline and ownership', () => {
  it('does not spawn for an already cancelled owner', async () => {
    const controller = new AbortController()
    controller.abort()
    await expect(run(controller.signal)).rejects.toThrow('cancelled')
    expect(spawn).not.toHaveBeenCalled()
  })
  it('uses a hidden direct spawn and resolves only after zero close', async () => {
    const settled = vi.fn()
    const pending = run().then(settled)
    expect(spawn).toHaveBeenCalledWith('owned.exe', ['run', '-test', '-c', 'protected-config.json'], expect.objectContaining({ cwd: 'trusted-runtime', windowsHide: true, killSignal: 'SIGKILL', signal: expect.any(AbortSignal) }))
    children[0].emit('exit', 0)
    await Promise.resolve()
    expect(settled).not.toHaveBeenCalled()
    children[0].emit('close', 0)
    await pending
    expect(settled).toHaveBeenCalledOnce()
    expect(vi.getTimerCount()).toBe(0)
  })
  it('aborts at the normative 5-second deadline and waits for exit confirmation', async () => {
    const pending = run()
    const rejected = expect(pending).rejects.toThrow('timed out after 5000 ms')
    await vi.advanceTimersByTimeAsync(4999)
    expect(children[0].kill).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(1)
    expect(children[0].signal?.aborted).toBe(true)
    finish(children[0], null)
    await rejected
    expect(vi.getTimerCount()).toBe(0)
  })
  it('never interprets AbortError or a late zero exit as successful validation', async () => {
    const controller = new AbortController()
    const settled = vi.fn()
    const pending = run(controller.signal).catch(error => { settled(); throw error })
    const rejected = expect(pending).rejects.toThrow('cancelled')
    controller.abort()
    await Promise.resolve()
    expect(settled).not.toHaveBeenCalled()
    finish(children[0], 0)
    await rejected
  })
  it('does not label an observed exit as unconfirmed when inherited stdio delays close', async () => {
    const owner = new AbortController()
    const pending = run(owner.signal)
    const rejected = expect(pending).rejects.toThrow('cancelled')
    children[0].emit('exit', 0)
    owner.abort()
    await rejected
    expect(children[0].kill).not.toHaveBeenCalled()
    expect(vi.getTimerCount()).toBe(0)
    expect(logEvent).not.toHaveBeenCalled()
  })
  it('retains and retries an unconfirmed child rather than reporting cleanup success', async () => {
    const controller = new AbortController()
    const pending = run(controller.signal)
    const rejected = expect(pending).rejects.toThrow('exit not confirmed')
    controller.abort()
    await vi.advanceTimersByTimeAsync(1000)
    await rejected
    expect(logEvent).toHaveBeenCalledWith('warn', 'xray', 'preflight exit not confirmed', { pendingProcesses: 1 })
    const cleanup = expect(stopXrayPreflights()).rejects.toThrow('exit not confirmed')
    await vi.advanceTimersByTimeAsync(1000)
    await cleanup
    expect(children[0].kill.mock.calls.length).toBeGreaterThan(1)
    finish(children[0], null)
    await expect(stopXrayPreflights()).resolves.toBeUndefined()
  })
  it('drains huge output into bounded tails and logs one truncation event', async () => {
    const pending = run()
    const rejected = expect(pending).rejects.toThrow('tail-error')
    for (let i = 0; i < 100; i++) {
      children[0].stdout.emit('data', Buffer.alloc(1024 * 1024, 'a'))
      children[0].stderr.emit('data', Buffer.alloc(1024 * 1024, 'b'))
    }
    children[0].stderr.emit('data', Buffer.from('tail-error'))
    finish(children[0], 1)
    await rejected
    const error = await pending.then(() => new Error('unexpected success'), (error: Error) => error)
    expect(Buffer.byteLength(error.message)).toBeLessThan(64 * 1024 + 100)
    expect(vi.mocked(logEvent).mock.calls.filter(call => call[2] === 'stderr.truncated')).toHaveLength(1)
  })
  it('cleans listeners/timers on missing executable without inventing a child', async () => {
    const pending = run()
    const rejected = expect(pending).rejects.toThrow('missing executable')
    children[0].pid = undefined
    children[0].emit('error', new Error('missing executable'))
    await rejected
    await stopXrayPreflights()
    expect(children[0].kill).not.toHaveBeenCalled()
    expect(vi.getTimerCount()).toBe(0)
  })
  it('propagates a synchronous spawn error with no remaining timer', async () => {
    vi.mocked(spawn).mockImplementation(() => { throw new Error('spawn refused') })
    await expect(run()).rejects.toThrow('spawn refused')
    expect(vi.getTimerCount()).toBe(0)
  })
  it('stops every owned preflight and waits for all children, with no name-based kill', async () => {
    const first = run(), second = run()
    const checks = [expect(first).rejects.toThrow('cancelled'), expect(second).rejects.toThrow('cancelled')]
    const done = vi.fn()
    const cleanup = stopXrayPreflights().then(done)
    finish(children[0], null)
    await Promise.resolve()
    expect(done).not.toHaveBeenCalled()
    finish(children[1], null)
    await cleanup
    await Promise.all(checks)
    expect(done).toHaveBeenCalledOnce()
    expect(spawn).toHaveBeenCalledTimes(2)
  })
})
