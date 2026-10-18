// AT-00-003/007, F-125/F-133: exercise the production connection admission lane.
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ConnectionLifecycle } from './connectionLifecycle'
import { OPERATION_PRIORITY, type OperationOwner } from '../shared/operation'

function held<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(done => { resolve = done })
  return { promise, resolve }
}

afterEach(() => vi.useRealTimers())

describe('connection operation ownership', () => {
  it.each(['manual', 'schedule'] as const)('joins an in-flight recovery stop for %s without duplicate cleanup (AT-00-007)', async owner => {
    const gate = held<{ success: boolean }>(), cleanup = vi.fn(() => gate.promise)
    const lane = new ConnectionLifecycle(vi.fn())
    const recovery = lane.stop(cleanup, { owner: 'recovery' })
    const joined = lane.stop(cleanup, { owner })
    expect(joined).toBe(recovery)
    gate.resolve({ success: true })
    expect(await joined).toEqual({ success: true })
    expect(cleanup).toHaveBeenCalledOnce()
  })

  it('assigns UUIDv4, owner and deadline without exposing the AbortSignal in snapshots (AT-00-003)', async () => {
    const lane = new ConnectionLifecycle(vi.fn())
    await lane.start(async owner => {
      expect(owner.operation).toMatchObject({ owner: 'schedule', kind: 'connect', status: 'running' })
      expect(owner.operation.operationId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
      expect(owner.operation.deadline! - owner.operation.startedAt).toBe(2000)
      expect(lane.operation).toEqual(owner.operation)
      expect(lane.operation).not.toHaveProperty('signal')
      return { success: true }
    }, { owner: 'schedule', timeoutMs: 2000 })
    expect(lane.operation).toMatchObject({ status: 'success', owner: 'schedule' })
  })

  it('manual start aborts background work, drains its native effect and cleans up before starting (AT-00-003/007)', async () => {
    const events: string[] = [], native = held<void>()
    const lane = new ConnectionLifecycle(vi.fn(), async () => { events.push('cleanup'); return { success: true } })
    let signal!: AbortSignal
    const background = lane.start(async owner => {
      signal = owner.signal
      await owner.wait(native.promise)
      events.push('late-publish')
      return { success: true }
    }, { owner: 'schedule' })
    const manual = lane.start(async () => { events.push('manual'); return { success: true } })
    expect(signal.aborted).toBe(true)
    expect(events).toEqual([])
    native.resolve()
    expect(await background).toMatchObject({ success: false, category: 'cancelled', code: 'OPERATION_CANCELLED' })
    expect(await manual).toMatchObject({ success: true })
    expect(events).toEqual(['cleanup', 'manual'])
  })

  it('rejects lower priority stop without aborting recovery or running cleanup (AT-00-007)', async () => {
    const lane = new ConnectionLifecycle(vi.fn()), gate = held<void>(), cleanup = vi.fn()
    let signal!: AbortSignal
    const recovery = lane.start(async owner => { signal = owner.signal; await owner.wait(gate.promise); return { success: true } }, { owner: 'recovery' })
    expect(await lane.stop(cleanup, { owner: 'schedule' })).toMatchObject({ success: false, category: 'conflict', code: 'OPERATION_CONFLICT' })
    expect(signal.aborted).toBe(false)
    expect(cleanup).not.toHaveBeenCalled()
    gate.resolve()
    await recovery
  })

  it('deadline aborts promptly but keeps native ownership until real settlement and cleanup (AT-00-003)', async () => {
    vi.useFakeTimers()
    const native = held<void>(), cleanup = vi.fn(async () => ({ success: true })), cancel = vi.fn()
    const lane = new ConnectionLifecycle(cancel, cleanup)
    let signal!: AbortSignal
    const publish = vi.fn()
    const started = lane.start(async owner => { signal = owner.signal; await owner.wait(native.promise); publish(); return { success: true } }, { timeoutMs: 100 })
    await vi.advanceTimersByTimeAsync(100)
    expect(signal.aborted).toBe(true)
    expect(lane.operation).toMatchObject({ status: 'error', category: 'timeout' })
    expect(lane.busy).toBe(true)
    expect(cleanup).not.toHaveBeenCalled()
    expect(await lane.start(async () => ({ success: true }))).toMatchObject({ success: false, category: 'conflict' })
    native.resolve()
    expect(await started).toMatchObject({ success: false, category: 'timeout', code: 'OPERATION_TIMEOUT' })
    await vi.waitFor(() => expect(cleanup).toHaveBeenCalledOnce())
    expect(publish).not.toHaveBeenCalled()
    await vi.waitFor(() => expect(lane.busy).toBe(false))
  })

  it('does not admit a replacement if cancellation cleanup fails (AT-00-007)', async () => {
    const native = held<void>(), replacement = vi.fn()
    const lane = new ConnectionLifecycle(vi.fn(), async () => ({ success: false, error: 'rollback failed' }))
    const old = lane.start(async owner => { await owner.wait(native.promise); return { success: true } }, { owner: 'rotation' })
    const next = lane.start(replacement)
    native.resolve()
    await old
    expect(await next).toMatchObject({ success: false })
    expect(replacement).not.toHaveBeenCalled()
  })

  it('rejects invalid deadline configuration before any effect (AT-00-003)', async () => {
    const lane = new ConnectionLifecycle(vi.fn()), effect = vi.fn()
    for (const timeoutMs of [0, -1, NaN, Infinity, 2 ** 31]) {
      await expect(lane.start(effect, { timeoutMs })).rejects.toThrow('Invalid operation timeout')
    }
    expect(effect).not.toHaveBeenCalled()
    expect(lane.busy).toBe(false)
  })

  it('enforces every pair in recovery > manual > schedule > rotation > autopilot > adaptive retry (AT-00-007)', async () => {
    for (const current of Object.keys(OPERATION_PRIORITY) as OperationOwner[]) {
      for (const incoming of Object.keys(OPERATION_PRIORITY) as OperationOwner[]) {
        const gate = held<void>(), cancel = vi.fn(), cleanup = vi.fn(async () => ({ success: true }))
        const lane = new ConnectionLifecycle(cancel, cleanup)
        let signal!: AbortSignal
        const running = lane.start(async owner => { signal = owner.signal; await owner.wait(gate.promise); return { success: true } }, { owner: current })
        const nextEffect = vi.fn(async () => ({ success: true }))
        const next = lane.start(nextEffect, { owner: incoming })
        const preempts = OPERATION_PRIORITY[incoming] > OPERATION_PRIORITY[current]
        expect(signal.aborted).toBe(preempts)
        gate.resolve()
        const [oldResult, nextResult] = await Promise.all([running, next])
        expect(oldResult.success).toBe(!preempts)
        expect(nextResult.success).toBe(preempts)
        expect(cleanup).toHaveBeenCalledTimes(preempts ? 1 : 0)
        expect(nextEffect).toHaveBeenCalledTimes(preempts ? 1 : 0)
      }
    }
  })

  it.each([10, 50, 90])('suppresses late callbacks at %i percent while retaining native ownership (AT-00-003 subset)', async progress => {
    const gate = held<void>(), cleanup = vi.fn(async () => ({ success: true })), publish = vi.fn()
    const lane = new ConnectionLifecycle(vi.fn(), cleanup)
    const reached = held<void>(), completed: number[] = []
    let signal!: AbortSignal
    const task = lane.start(async owner => {
      signal = owner.signal
      for (let step = 1; step <= 10; step++) {
        completed.push(step)
        if (step === progress / 10) {
          reached.resolve()
          await owner.wait(gate.promise)
        } else await owner.wait(Promise.resolve())
      }
      publish()
      return { success: true }
    })
    await reached.promise
    const stopped = lane.stop(cleanup)
    expect(signal.aborted).toBe(true)
    await Promise.resolve()
    expect(lane.busy).toBe(true)
    expect(cleanup).not.toHaveBeenCalled()
    gate.resolve()
    expect(await task).toMatchObject({ success: false, category: 'cancelled' })
    await stopped
    expect(publish).not.toHaveBeenCalled()
    expect(completed).toEqual(Array.from({ length: progress / 10 }, (_, index) => index + 1))
    expect(cleanup).toHaveBeenCalledOnce()
    expect(lane.busy).toBe(false)
  })

  it('does not relabel manual cancellation as timeout while native cleanup is pending (AT-00-003)', async () => {
    vi.useFakeTimers()
    const gate = held<void>(), lane = new ConnectionLifecycle(vi.fn())
    const running = lane.start(async owner => { await owner.wait(gate.promise); return { success: true } }, { timeoutMs: 100 })
    const stopped = lane.stop(async () => ({ success: true }))
    await vi.advanceTimersByTimeAsync(200)
    gate.resolve()
    expect(await running).toMatchObject({ category: 'cancelled' })
    await stopped
    expect(vi.getTimerCount()).toBe(0)
  })

  it('keeps cleanup and admission intact when operation logging throws (AT-00-007)', async () => {
    const lane = new ConnectionLifecycle(vi.fn(), undefined, () => { throw new Error('log failed') })
    expect(await lane.start(async () => ({ success: true }))).toMatchObject({ success: true })
    expect(await lane.stop(async () => ({ success: true }))).toMatchObject({ success: true })
    expect(lane.busy).toBe(false)
  })
})
