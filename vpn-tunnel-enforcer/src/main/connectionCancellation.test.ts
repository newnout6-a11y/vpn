// AT-00-003/007: a caller settles promptly while native work keeps its lease.
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ConnectionLifecycle } from './connectionLifecycle'
import type { ConnectionOperation } from '../shared/operation'

function held<T>() {
  let resolve!: (value: T) => void, reject!: (error: Error) => void
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}
afterEach(() => vi.useRealTimers())

describe('prompt connection cancellation with native drain', () => {
  it.each([10, 50, 90])('returns cancellation at %i percent before native settlement (AT-00-003)', async progress => {
    vi.useFakeTimers()
    const native = held<void>(), cleanup = held<{ success: true }>(), entered = held<void>()
    const stopEffect = vi.fn(() => cleanup.promise), late = vi.fn(), observed = vi.fn()
    const events: ConnectionOperation[] = []
    const lane = new ConnectionLifecycle(vi.fn(), undefined, op => events.push(op))
    const started = lane.start(async owner => {
      for (let step = 10; step <= 100; step += 10) {
        if (step === progress) { entered.resolve(); await owner.wait(native.promise) }
        else await owner.wait(Promise.resolve())
      }
      late()
      return { success: true }
    }).then(observed)
    await entered.promise
    const stopped = lane.stop(stopEffect)
    await vi.advanceTimersByTimeAsync(1)
    expect(observed).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ success: false, code: 'OPERATION_CANCELLED' }))
    expect(lane.starting).toBe(true)
    expect(lane.busy).toBe(true)
    expect(stopEffect).not.toHaveBeenCalled()
    expect(await lane.start(async () => ({ success: true }))).toMatchObject({ code: 'OPERATION_CONFLICT' })
    native.resolve()
    await vi.advanceTimersByTimeAsync(1)
    expect(stopEffect).toHaveBeenCalledOnce()
    expect(lane.busy).toBe(true)
    expect(late).not.toHaveBeenCalled()
    cleanup.resolve({ success: true })
    await stopped
    await started
    expect(lane.busy).toBe(false)
    const connect = events.filter(op => op.kind === 'connect')
    expect(connect.map(op => op.status)).toEqual(['running', 'cancelled'])
    expect(await lane.start(async () => ({ success: true }))).toMatchObject({ success: true })
  })

  it('returns timeout before a raw native promise settles and drains its late rejection (AT-00-003)', async () => {
    vi.useFakeTimers()
    const native = held<void>(), cleanup = vi.fn(async () => ({ success: true })), observed = vi.fn()
    const events: ConnectionOperation[] = []
    const lane = new ConnectionLifecycle(vi.fn(), cleanup, op => events.push(op))
    const started = lane.start(async () => { await native.promise; return { success: true } }, { timeoutMs: 50 }).then(observed)
    await vi.advanceTimersByTimeAsync(51)
    expect(observed).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ code: 'OPERATION_TIMEOUT', category: 'timeout' }))
    expect(lane.busy).toBe(true)
    expect(cleanup).not.toHaveBeenCalled()
    native.reject(new Error('late native failure'))
    await vi.advanceTimersByTimeAsync(1)
    await started
    expect(cleanup).toHaveBeenCalledOnce()
    expect(lane.busy).toBe(false)
    expect(events.filter(op => op.kind === 'connect').map(op => op.status)).toEqual(['running', 'error'])
    expect(vi.getTimerCount()).toBe(0)
  })

  it('settles the start caller during shutdown while close still waits for retained effects (AT-00-003)', async () => {
    vi.useFakeTimers()
    const native = held<void>(), observed = vi.fn(), closed = vi.fn()
    const lane = new ConnectionLifecycle(vi.fn())
    const started = lane.start(async owner => { owner.retain(native.promise); return { success: true } }).then(observed)
    const closing = lane.close().then(closed)
    await vi.advanceTimersByTimeAsync(1)
    expect(observed).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ code: 'OPERATION_CANCELLED' }))
    expect(closed).not.toHaveBeenCalled()
    expect(lane.starting).toBe(true)
    native.resolve()
    await closing
    await started
    expect(lane.starting).toBe(false)
    expect(lane.busy).toBe(true)
    expect(await lane.start(async () => ({ success: true }))).toMatchObject({ code: 'OPERATION_CONFLICT' })
  })

  it('does not start effects when an observer cancels synchronously during admission (AT-00-007)', async () => {
    const effect = vi.fn(async () => ({ success: true })), cleanup = vi.fn(async () => ({ success: true }))
    let stopped!: Promise<unknown>
    const lane = new ConnectionLifecycle(vi.fn(), undefined, operation => {
      if (operation.kind === 'connect' && operation.status === 'running') stopped = lane.stop(cleanup)
    })
    expect(await lane.start(effect)).toMatchObject({ code: 'OPERATION_CANCELLED' })
    await stopped
    expect(effect).not.toHaveBeenCalled()
    expect(cleanup).toHaveBeenCalledOnce()
    expect(lane.busy).toBe(false)
  })
})
