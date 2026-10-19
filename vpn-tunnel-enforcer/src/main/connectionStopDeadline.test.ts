// AT-00-002/003/005/007: stop result is bounded; actual cleanup retains admission.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ConnectionLifecycle } from './connectionLifecycle'
import { TunnelStateMachine } from './tunnelStateMachine'
import { OperationRegistry } from './operationRegistry'
import { currentCorrelationId, withCorrelation } from './actionCorrelation'

const releases = new Set<() => void>()
function held() {
  let resolve!: () => void, reject!: (error: Error) => void
  const promise = new Promise<void>((yes, no) => { resolve = yes; reject = no })
  releases.add(resolve)
  return { promise, resolve, reject }
}
beforeEach(() => vi.useFakeTimers())
afterEach(async () => {
  for (const release of releases) release()
  releases.clear()
  await vi.advanceTimersByTimeAsync(0)
  vi.useRealTimers()
})

describe('bounded stop with physical drain', () => {
  it('keeps default metadata and original correlation through a successful stop, clearing the timer', async () => {
    const observed = vi.fn(), lane = new ConnectionLifecycle(vi.fn(), undefined, observed)
    const key = 'ipc_3d49f22af56f4eb795812df333b9aa55'
    expect(await withCorrelation(key, () => lane.stop(async owner => {
      expect(owner.signal).toBeInstanceOf(AbortSignal)
      expect(owner.operation.deadline! - owner.operation.startedAt).toBe(120_000)
      expect(owner.operation.operationId).toMatch(/^[0-9a-f-]{36}$/)
      expect(owner.operation).not.toHaveProperty('signal')
      expect(currentCorrelationId()).toBe(key)
      return { success: true }
    }, { owner: 'schedule' }))).toEqual({ success: true })
    expect(observed.mock.calls.map(([operation]) => operation.status)).toEqual(['running', 'success'])
    expect(observed.mock.calls.every(([operation]) => operation.correlationId === key && operation.owner === 'schedule')).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('publishes one timeout while cleanup keeps the native lane; late success cannot rewrite it', async () => {
    const cleanup = held(), observed = vi.fn(), finished = vi.fn()
    const evidence = { running: false, pid: null as number | null, softApplied: false }
    const fsm = new TunnelStateMachine(() => evidence)
    const lane = new ConnectionLifecycle(vi.fn(), undefined, observed, fsm)
    await lane.start(async () => { evidence.running = true; evidence.pid = 10; return { success: true } })
    let signal!: AbortSignal
    const stopping = lane.stop(async owner => {
      signal = owner.signal
      await cleanup.promise
      evidence.running = false; evidence.pid = null
      return { success: true }
    }, { timeoutMs: 50 }).then(finished)
    await vi.advanceTimersByTimeAsync(49)
    expect(finished).not.toHaveBeenCalled()
    expect(signal.aborted).toBe(false)
    await vi.advanceTimersByTimeAsync(1)
    expect(finished).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ success: false, code: 'OPERATION_TIMEOUT', category: 'timeout' }))
    expect(signal.aborted).toBe(true)
    expect(fsm.snapshot).toMatchObject({ state: 'error', transition: null, operation: { kind: 'disconnect', status: 'error', category: 'timeout' } })
    expect(lane.busy).toBe(true)
    expect(await lane.start(async () => ({ success: true }))).toMatchObject({ category: 'conflict' })
    cleanup.resolve(); await stopping
    await vi.advanceTimersByTimeAsync(0)
    expect(lane.busy).toBe(false)
    const events = observed.mock.calls.map(([operation]) => operation).filter(operation => operation.kind === 'disconnect')
    expect(events.map(operation => operation.status)).toEqual(['running', 'error'])
    expect(events[1]).toMatchObject({ category: 'timeout', deadline: events[0].startedAt + 50 })
    expect(fsm.snapshot.operation?.status).toBe('error')
  })

  it('counts startup drain in the stop deadline and still runs required cleanup afterwards', async () => {
    const native = held(), cleanup = held(), effect = vi.fn(() => cleanup.promise), finished = vi.fn()
    const lane = new ConnectionLifecycle(vi.fn())
    const started = lane.start(async owner => { await owner.wait(native.promise); return { success: true } })
    void lane.stop(effect, { timeoutMs: 50 }).then(finished)
    await vi.advanceTimersByTimeAsync(50)
    expect(finished).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ category: 'timeout' }))
    expect(effect).not.toHaveBeenCalled()
    expect(lane.busy).toBe(true)
    native.resolve(); await started; await vi.advanceTimersByTimeAsync(0)
    expect(effect).toHaveBeenCalledOnce()
    expect(lane.busy).toBe(true)
    cleanup.resolve(); await vi.advanceTimersByTimeAsync(0)
    expect(lane.busy).toBe(false)
  })

  it('coalesces callers after timeout and makes shutdown await physical cleanup', async () => {
    const cleanup = held(), effect = vi.fn(() => cleanup.promise), closed = vi.fn()
    const lane = new ConnectionLifecycle(vi.fn())
    const first = lane.stop(effect, { owner: 'recovery', timeoutMs: 50 })
    await vi.advanceTimersByTimeAsync(50)
    const second = lane.stop(effect, { owner: 'manual' })
    expect(second).toBe(first)
    expect(await second).toMatchObject({ category: 'timeout' })
    const closing = lane.close().then(closed)
    await vi.advanceTimersByTimeAsync(0)
    expect(closed).not.toHaveBeenCalled()
    cleanup.resolve(); await closing
    expect(effect).toHaveBeenCalledOnce()
  })

  it('cancels the caller promptly but never abandons an admitted rollback', async () => {
    const cleanup = held(), controller = new AbortController(), observed = vi.fn()
    const lane = new ConnectionLifecycle(vi.fn(), undefined, observed)
    let signal!: AbortSignal
    const stopping = lane.stop(async owner => { signal = owner.signal; await cleanup.promise; return { success: true } }, { signal: controller.signal })
    await vi.advanceTimersByTimeAsync(0)
    controller.abort()
    expect(await stopping).toMatchObject({ category: 'cancelled', code: 'OPERATION_CANCELLED' })
    expect(signal.aborted).toBe(true)
    expect(lane.busy).toBe(true)
    cleanup.resolve(); await vi.advanceTimersByTimeAsync(0)
    expect(lane.busy).toBe(false)
    expect(observed.mock.calls.map(([operation]) => operation.status)).toEqual(['running', 'cancelled'])
  })

  it('does not admit effects for a signal already aborted', async () => {
    const controller = new AbortController(), effect = vi.fn(async () => true), cancel = vi.fn()
    controller.abort()
    const lane = new ConnectionLifecycle(cancel)
    expect(await lane.stop(effect, { signal: controller.signal })).toMatchObject({ category: 'cancelled' })
    expect(effect).not.toHaveBeenCalled(); expect(cancel).not.toHaveBeenCalled()
    expect(lane.busy).toBe(false)
  })

  it('consumes a late cleanup rejection without changing the timeout; shutdown still sees the physical failure', async () => {
    const cleanup = held(), observed = vi.fn(), lane = new ConnectionLifecycle(vi.fn(), undefined, observed)
    const stopping = lane.stop(() => cleanup.promise, { timeoutMs: 50 })
    await vi.advanceTimersByTimeAsync(50)
    expect(await stopping).toMatchObject({ category: 'timeout' })
    const closing = lane.close().catch(error => error)
    cleanup.reject(new Error('physical rollback failed'))
    expect((await closing).message).toBe('physical rollback failed')
    expect(observed.mock.calls.map(([operation]) => operation.status)).toEqual(['running', 'error'])
  })

  it.each([
    { failure: 'result', timing: 'waiting' }, { failure: 'result', timing: 'settled' },
    { failure: 'throw', timing: 'waiting' }, { failure: 'throw', timing: 'settled' }
  ])('retains physical $failure failure for shutdown when drain is $timing', async ({ failure, timing }) => {
    const cleanup = held(), observed = vi.fn(), lane = new ConnectionLifecycle(vi.fn(), undefined, observed)
    const stopping = lane.stop(async () => {
      await cleanup.promise
      if (failure === 'throw') throw new Error('physical rollback failed')
      return { success: false, error: 'physical rollback failed' }
    }, { timeoutMs: 50 })
    await vi.advanceTimersByTimeAsync(50)
    expect(await stopping).toMatchObject({ category: 'timeout' })
    let closing: Promise<unknown> | undefined
    if (timing === 'waiting') closing = lane.close().then(() => 'unexpected success', error => error)
    cleanup.resolve(); await vi.advanceTimersByTimeAsync(0)
    closing ??= lane.close().then(() => 'unexpected success', error => error)
    expect(await closing).toBeInstanceOf(Error)
    expect(observed.mock.calls.map(([operation]) => operation.status)).toEqual(['running', 'error'])
  })

  it('clears a retained physical failure only after a successful cleanup retry', async () => {
    const cleanup = held(), lane = new ConnectionLifecycle(vi.fn())
    const stopping = lane.stop(async () => { await cleanup.promise; return { success: false } }, { timeoutMs: 50 })
    await vi.advanceTimersByTimeAsync(50)
    expect(await stopping).toMatchObject({ category: 'timeout' })
    cleanup.resolve(); await vi.advanceTimersByTimeAsync(0)
    await expect(lane.close()).rejects.toThrow('Runtime cleanup confirmation missing')
    expect(await lane.stop(async () => ({ success: false }))).toEqual({ success: false })
    await expect(lane.close()).rejects.toThrow('Runtime cleanup confirmation missing')
    expect(await lane.stop(async () => ({ success: true }))).toEqual({ success: true })
    await expect(lane.close()).resolves.toBeUndefined()
  })

  it('retains a cancelled rotation registry lease through physical cleanup after the stop deadline', async () => {
    const native = held(), cleanup = held(), registry = new OperationRegistry(), closed = vi.fn()
    const lane = new ConnectionLifecycle(vi.fn(), async () => { await cleanup.promise; return { success: true } })
    const rotation = registry.run('rotation', lease => lane.rotate(lease, async owner => {
      owner.beginRestart(); await owner.wait(native.promise)
      return owner.complete(() => ({ success: true }))
    }), { owner: 'rotation' }).catch(error => error)
    await vi.advanceTimersByTimeAsync(0)
    registry.cancel(registry.list()[0].operationId)
    expect(await rotation).toMatchObject({ category: 'cancelled' })
    native.resolve(); await vi.advanceTimersByTimeAsync(0)
    const closing = registry.close().then(closed)
    await vi.advanceTimersByTimeAsync(120_001)
    expect(lane.busy).toBe(true)
    expect(registry.isBusy('rotation')).toBe(true)
    expect(closed).not.toHaveBeenCalled()
    cleanup.resolve(); await closing
    expect(registry.isBusy('rotation')).toBe(false)
    expect(lane.busy).toBe(false)
  })

  it.each([0, -1, 0.5, Infinity, 2 ** 31])('rejects invalid timeout %s before cancellation or cleanup', timeoutMs => {
    const cancel = vi.fn(), effect = vi.fn(async () => true), lane = new ConnectionLifecycle(cancel)
    expect(() => lane.stop(effect, { timeoutMs })).toThrow('Invalid operation timeout')
    expect(cancel).not.toHaveBeenCalled(); expect(effect).not.toHaveBeenCalled()
  })
})
