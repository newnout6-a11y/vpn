// AT-00-003/007: production live-check queue/process boundaries; controlled native close.
import { EventEmitter } from 'node:events'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const state = vi.hoisted(() => ({ spawn: vi.fn() }))
vi.mock('electron', () => ({ app: { getPath: () => '/tmp/test-userdata' }, ipcMain: { handle: vi.fn() } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({ disableGeoLookup: true }) } }))
vi.mock('./serverPicker', () => ({ serverPicker: { getProfiles: () => [], getActiveProfile: () => null } }))
vi.mock('./tunController', () => ({ tunController: { getStatus: () => ({ running: false }) } }))
vi.mock('child_process', async original => ({ ...await original<typeof import('child_process')>(), spawn: state.spawn }))
import { execPs, withHandshakeWorkerLock } from './liveServerProbe'
const flush = async () => { for (let i = 0; i < 50; i++) await Promise.resolve() }
const releases = new Set<() => void>(), tasks = new Set<Promise<unknown>>()
let children: Array<ReturnType<typeof child>>
function child() { return Object.assign(new EventEmitter(), { stdout: new EventEmitter(), stderr: new EventEmitter(), kill: vi.fn(() => true) }) }
function held() { let release!: () => void; const promise = new Promise<void>(resolve => { release = resolve }); releases.add(release); return { promise, release } }
function track<T>(task: Promise<T>) { tasks.add(task); return task }
beforeEach(() => {
  vi.useFakeTimers(); children = []
  state.spawn.mockReset().mockImplementation(() => { const value = child(); children.push(value); return value })
})
afterEach(async () => {
  for (const release of releases) release()
  releases.clear()
  for (const value of children) value.emit('close', 0)
  if (vi.isFakeTimers()) await vi.runAllTimersAsync()
  await Promise.allSettled(tasks); tasks.clear(); vi.useRealTimers()
})
describe('live PowerShell physical drain', () => {
  it.each(['cancel', 'timeout', 'error'])('retains process/pipe ownership after %s until actual close', async boundary => {
    const controller = new AbortController(); let settled = false, result: unknown
    track(execPs('fixture', 1000, controller.signal).then(value => { settled = true; result = value }, error => { settled = true; result = error }))
    const process = children[0]
    if (boundary === 'cancel') controller.abort()
    if (boundary === 'timeout') await vi.advanceTimersByTimeAsync(1001)
    if (boundary === 'error') process.emit('error', new Error('injected spawn failure'))
    await flush(); expect(settled).toBe(false)
    expect(process.kill).toHaveBeenCalledOnce()
    process.emit('close', null); await flush()
    expect(settled).toBe(true); expect(result).toBeInstanceOf(Error)
    expect(process.eventNames()).toEqual([])
    expect(process.stdout.eventNames()).toEqual([]); expect(process.stderr.eventNames()).toEqual([])
  })
  it('returns complete UTF-8 output after normal close without killing the exited child', async () => {
    const run = track(execPs('fixture', 1000)), process = children[0]
    const bytes = Buffer.from('Проверка')
    process.stdout.emit('data', bytes.subarray(0, 3)); process.stdout.emit('data', bytes.subarray(3))
    process.stderr.emit('data', Buffer.from('warning'))
    process.emit('close', 0)
    expect(await run).toEqual({ stdout: 'Проверка', stderr: 'warning' })
    expect(process.kill).not.toHaveBeenCalled()
  })
  it('does not spawn after an already cancelled request and rejects a synchronous spawn failure', async () => {
    const controller = new AbortController(); controller.abort()
    await expect(track(execPs('fixture', 1000, controller.signal))).rejects.toThrow('Cancelled')
    expect(state.spawn).not.toHaveBeenCalled()
    state.spawn.mockImplementation(() => { throw new Error('sync spawn') })
    await expect(track(execPs('fixture', 1000))).rejects.toThrow('sync spawn')
  })
  it.skipIf(process.platform !== 'win32').each(['cancel', 'timeout'])('native PowerShell %s returns only after process close', async boundary => {
    vi.useRealTimers()
    const actual = await vi.importActual<typeof import('child_process')>('child_process')
    let native: ReturnType<typeof actual.spawn> | undefined, closed = false, closing = Promise.resolve()
    state.spawn.mockImplementation((...args: Parameters<typeof actual.spawn>) => {
      native = actual.spawn(...args)
      closing = new Promise(resolve => native!.once('close', () => { closed = true; resolve() }))
      return native
    })
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined
    try {
      const run = track(execPs('Start-Sleep -Seconds 20', 400, controller.signal))
      if (boundary === 'cancel') timer = setTimeout(() => controller.abort(), 100)
      await expect(run).rejects.toThrow(boundary === 'cancel' ? 'Cancelled' : 'timeout')
      expect(closed).toBe(true)
    } finally {
      clearTimeout(timer)
      if (native && !closed) { native.kill(); await closing }
    }
  }, 15_000)
})
describe('live handshake physical queue', () => {
  it.each(['cancel', 'timeout'])('keeps a %s queued slot behind the active worker', async boundary => {
    const firstGate = held(), order: string[] = []
    const first = track(withHandshakeWorkerLock(async () => { order.push('first'); await firstGate.promise }))
    await flush()
    const controller = new AbortController()
    const discarded = track(withHandshakeWorkerLock(async () => { order.push('discarded') }, { signal: controller.signal, queueTimeoutMs: 100 }))
    const rejection = expect(discarded).rejects.toThrow(boundary === 'cancel' ? 'Cancelled' : 'timeout')
    if (boundary === 'cancel') controller.abort()
    else await vi.advanceTimersByTimeAsync(101)
    await rejection
    const next = track(withHandshakeWorkerLock(async () => { order.push('next') }))
    await flush(); expect(order).toEqual(['first'])
    firstGate.release(); await Promise.all([first, next])
    expect(order).toEqual(['first', 'next'])
  })
  it('does not enter a queued worker when its signal aborts as its predecessor completes', async () => {
    const gate = held(), fn = vi.fn(async () => {})
    const first = track(withHandshakeWorkerLock(() => gate.promise)); await flush()
    const controller = new AbortController()
    const second = track(withHandshakeWorkerLock(fn, { signal: controller.signal }))
    gate.release(); controller.abort()
    await expect(second).rejects.toThrow('Cancelled'); await first
    expect(fn).not.toHaveBeenCalled()
    await track(withHandshakeWorkerLock(async () => {}))
  })
})
