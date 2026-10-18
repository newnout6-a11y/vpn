// AT-00-003/005/007: shared registry; real feature integration is in speedTestOperations.test.
import { afterEach, describe, expect, it, vi } from 'vitest'
import { OperationRegistry, type OperationLease } from './operationRegistry'
import { OPERATION_DEADLINES, type ManagedOperation, type ManagedOperationKind } from '../shared/operation'
import { currentCorrelationId, currentActionMetadata, withCorrelation } from './actionCorrelation'

function held<T>() {
  let resolve!: (value: T) => void, reject!: (error: Error) => void
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}
afterEach(() => vi.useRealTimers())
const kinds = Object.keys(OPERATION_DEADLINES) as ManagedOperationKind[]

describe('long operation registry', () => {
  it.each(kinds.flatMap(kind => [10, 50, 90].map(progress => ({ kind, progress }))))('cancels $kind at $progress percent without late publication or releasing its lease', async ({ kind, progress }) => {
    const events: ManagedOperation[] = [], registry = new OperationRegistry(operation => events.push(operation))
    const gate = held<void>(), entered = held<void>(), controller = new AbortController(), publish = vi.fn()
    let signal!: AbortSignal
    const work = registry.run(kind, async lease => {
      signal = lease.signal
      for (let step = 1; step <= 10; step++) {
        if (step === progress / 10) { entered.resolve(); await lease.wait(gate.promise) }
        lease.assertActive()
        publish(step)
      }
      return { success: true }
    }, { signal: controller.signal })
    const outcome = work.catch(error => error)
    await entered.promise
    const before = publish.mock.calls.length
    controller.abort()
    expect(await outcome).toMatchObject({ category: 'cancelled' })
    expect(signal.aborted).toBe(true)
    expect(registry.list()).toMatchObject([{ kind, status: 'cancelled' }])
    expect(registry.isBusy(kind)).toBe(true)
    await expect(registry.run(kind, async () => true)).rejects.toMatchObject({ category: 'conflict' })
    gate.resolve()
    await vi.waitFor(() => expect(registry.isBusy(kind)).toBe(false))
    expect(publish).toHaveBeenCalledTimes(before)
    expect(events.map(event => event.status)).toEqual(['running', 'cancelled'])
  })

  it.each(kinds)('returns a typed deadline for %s while shutdown still waits for the actual late effect', async kind => {
    vi.useFakeTimers()
    const registry = new OperationRegistry(), gate = held<void>(), publish = vi.fn()
    const task = registry.run(kind, async lease => { await lease.wait(gate.promise); publish() }, { timeoutMs: 100 })
    const outcome = task.catch(error => error)
    await vi.advanceTimersByTimeAsync(100)
    expect(await outcome).toMatchObject({ category: 'timeout' })
    expect(registry.list()).toMatchObject([{ status: 'error', category: 'timeout' }])
    const closed = vi.fn(), closing = registry.close().then(closed)
    await Promise.resolve()
    expect(closed).not.toHaveBeenCalled()
    gate.resolve()
    await closing
    expect(publish).not.toHaveBeenCalled()
    await expect(registry.run(kind, async () => true)).rejects.toMatchObject({ category: 'conflict' })
    expect(vi.getTimerCount()).toBe(0)
  })

  it('assigns main UUID/deadline and original IPC correlation/source; snapshots cannot mutate registry state', async () => {
    const registry = new OperationRegistry(), id = 'ipc_3d49f22af56f4eb795812df333b9aa55'
    await withCorrelation(id, () => registry.run('refresh', async lease => {
      expect(lease.operation).toMatchObject({ correlationId: id, source: 'ipc', owner: 'schedule', kind: 'refresh', status: 'running' })
      expect(lease.operation.operationId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
      expect(lease.operation.deadline - lease.operation.startedAt).toBe(2000)
      expect(currentCorrelationId()).toBe(id)
      expect(currentActionMetadata()).toEqual({ source: 'ipc', owner: 'schedule' })
      expect(lease.operation).not.toHaveProperty('signal')
      Object.assign(registry.list()[0], { status: 'error' })
      expect(lease.operation.status).toBe('running')
      return { ok: true }
    }, { owner: 'schedule', timeoutMs: 2000 }))
    expect(registry.list()).toMatchObject([{ status: 'success' }])
  })

  it('higher priority work cancels its predecessor but waits for drain before admission', async () => {
    const registry = new OperationRegistry(), gate = held<void>(), replacement = vi.fn(async () => true)
    const previous = registry.run('refresh', async lease => { await lease.wait(gate.promise); return true }, { owner: 'schedule' }).catch(error => error)
    const next = registry.run('refresh', replacement)
    expect(await previous).toMatchObject({ category: 'cancelled' })
    expect(replacement).not.toHaveBeenCalled()
    gate.resolve()
    expect(await next).toBe(true)
    expect(registry.list().map(operation => operation.status)).toEqual(['cancelled', 'success'])
  })

  it('shutdown aborts every resource and refuses new work, including a replacement already awaiting drain', async () => {
    const registry = new OperationRegistry(), first = held<void>(), second = held<void>(), replacement = vi.fn(async () => true)
    const a = registry.run('refresh', async lease => { await lease.wait(first.promise) }, { owner: 'schedule' }).catch(error => error)
    const b = registry.run('speed-test', async lease => { await lease.wait(second.promise) }).catch(error => error)
    const c = registry.run('refresh', replacement).catch(error => error)
    const closing = registry.close()
    expect(await a).toMatchObject({ category: 'cancelled' })
    expect(await b).toMatchObject({ category: 'cancelled' })
    first.resolve(); second.resolve()
    await closing
    expect(await c).toMatchObject({ category: 'conflict' })
    expect(replacement).not.toHaveBeenCalled()
  })

  it.each(['cancelled', 'timeout', 'conflict'] as const)('returns %s promptly for a replacement awaiting native drain', async category => {
    vi.useFakeTimers()
    const registry = new OperationRegistry(), gate = held<void>(), controller = new AbortController(), replacement = vi.fn(async () => true)
    const previous = registry.run('refresh', async lease => lease.wait(gate.promise), { owner: 'schedule' }).catch(error => error)
    const finished = vi.fn()
    const next = registry.run('refresh', replacement, { signal: controller.signal, timeoutMs: 100 }).catch(finished)
    let closing: Promise<void> | undefined
    try {
      if (category === 'cancelled') controller.abort()
      if (category === 'timeout') await vi.advanceTimersByTimeAsync(100)
      if (category === 'conflict') closing = registry.close()
      await vi.advanceTimersByTimeAsync(1)
      expect(finished).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ category }))
      expect(registry.isBusy('refresh')).toBe(true)
      expect(replacement).not.toHaveBeenCalled()
    } finally { gate.resolve(); await previous; await next; await closing; await registry.close() }
    expect(vi.getTimerCount()).toBe(0)
  })

  it('counts admission wait against the deadline and ignores calendar clock changes', async () => {
    vi.useFakeTimers()
    const registry = new OperationRegistry(), first = held<void>(), second = held<void>()
    const previous = registry.run('refresh', async lease => lease.wait(first.promise), { owner: 'schedule' }).catch(error => error)
    const replacement = vi.fn(async (lease: OperationLease) => lease.wait(second.promise))
    const next = registry.run('refresh', replacement, { timeoutMs: 100 }).catch(error => error)
    await vi.advanceTimersByTimeAsync(60)
    vi.setSystemTime(Date.now() - 86_400_000)
    first.resolve()
    await previous
    await vi.advanceTimersByTimeAsync(0)
    expect(replacement).toHaveBeenCalledOnce()
    await vi.advanceTimersByTimeAsync(40)
    expect(await next).toMatchObject({ category: 'timeout' })
    expect(registry.isBusy('refresh')).toBe(true)
    second.resolve()
    await registry.close()
    expect(vi.getTimerCount()).toBe(0)
  })

  it('resumes only drained work after refused quit and never revives an old queued replacement', async () => {
    const registry = new OperationRegistry(), gate = held<void>(), replacement = vi.fn(async () => true)
    const first = registry.run('refresh', async lease => lease.wait(gate.promise), { owner: 'schedule' }).catch(error => error)
    const waiting = registry.run('refresh', replacement).catch(error => error)
    const closing = registry.close()
    expect(registry.resumeAdmission()).toBe(false)
    gate.resolve()
    await closing
    expect(registry.resumeAdmission()).toBe(true)
    expect(await first).toMatchObject({ category: 'cancelled' })
    expect(await waiting).toMatchObject({ category: 'conflict' })
    expect(replacement).not.toHaveBeenCalled()
    expect(await registry.run('refresh', async () => 'fresh')).toBe('fresh')
    await registry.close()
    await expect(registry.run('refresh', async () => true)).rejects.toMatchObject({ category: 'conflict' })
  })

  it('cancels only the requested live operation and consumes late native rejection', async () => {
    const registry = new OperationRegistry(), gate = held<void>()
    const task = registry.run('import', async lease => { await lease.wait(gate.promise) }).catch(error => error)
    expect(registry.cancel('unknown')).toBe(false)
    const id = registry.list()[0].operationId
    expect(registry.cancel(id)).toBe(true)
    expect(registry.cancel(id)).toBe(false)
    expect(await task).toMatchObject({ category: 'cancelled' })
    gate.reject(new Error('late native error'))
    await registry.close()
    expect(registry.list()).toMatchObject([{ status: 'cancelled' }])
  })

  it.each([0, -1, NaN, Infinity, 2 ** 31])('rejects invalid deadline %s before admission', async timeoutMs => {
    const registry = new OperationRegistry(), effect = vi.fn()
    await expect(registry.run('export', effect, { timeoutMs })).rejects.toMatchObject({ category: 'validation' })
    expect(effect).not.toHaveBeenCalled()
    expect(registry.list()).toEqual([])
  })

  it('keeps observers from stranding leases and waits for effects even if feature forgot its final await', async () => {
    const registry = new OperationRegistry(() => { throw new Error('observer') }), gate = held<void>()
    const task = registry.run('export', async lease => { void lease.wait(gate.promise); return { success: true } })
    expect(registry.list()[0].status).toBe('running')
    gate.resolve()
    expect(await task).toEqual({ success: true })
    expect(registry.isBusy('export')).toBe(false)
    expect(registry.list()[0].status).toBe('success')
  })

  it('retains the original error category while aborting sibling requests and draining', async () => {
    const registry = new OperationRegistry(), gate = held<void>()
    let signal!: AbortSignal
    const task = registry.run('export', async lease => {
      signal = lease.signal
      void lease.wait(gate.promise).catch(() => {})
      throw Object.assign(new Error('denied'), { code: 'EACCES' })
    }).catch(error => error)
    await Promise.resolve()
    expect(signal.aborted).toBe(true)
    expect(registry.list()).toMatchObject([{ status: 'error', category: 'permission' }])
    gate.resolve()
    expect(await task).toMatchObject({ code: 'EACCES' })
  })
})
