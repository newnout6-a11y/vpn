// AT-00-003/005/007: shared registry; real feature integration is in speedTestOperations.test.
import { afterEach, describe, expect, it, vi } from 'vitest'
import { OperationRegistry, type OperationLease } from './operationRegistry'
import { OPERATION_DEADLINES, type ManagedOperation, type ManagedOperationKind } from '../shared/operation'
import { currentCorrelationId, currentActionMetadata, withCorrelation } from './actionCorrelation'
import { redactSensitiveConfig } from './vpnProfiles'
import { IPC_ERRORS, ipcError, type IpcErrorCategory } from '../shared/ipc-result'

function held<T>() {
  let resolve!: (value: T) => void, reject!: (error: Error) => void
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}
afterEach(() => vi.useRealTimers())
const kinds = Object.keys(OPERATION_DEADLINES) as ManagedOperationKind[]

describe('long operation registry', () => {
  it.each(Object.keys(IPC_ERRORS) as IpcErrorCategory[])('keeps flattened connection %s failures in operation history (AT-00-004/005)', async category => {
    const registry = new OperationRegistry(), error = ipcError(category)
    const result = { success: false, error: error.message, code: error.code, category }
    expect(await registry.run('rotation', async () => result)).toBe(result)
    expect(registry.list()).toMatchObject([{ status: category === 'cancelled' ? 'cancelled' : 'error', category }])
    await registry.close()
  })
  it.each((Object.keys(IPC_ERRORS) as IpcErrorCategory[]).flatMap(category =>
    [false, true].map(commit => ({ category, commit }))))('records canonical $category returned failures, commit=$commit (AT-00-004/005)', async ({ category, commit }) => {
    const abort = new AbortController()
    const registry = new OperationRegistry(operation => { if (operation.status !== 'running') abort.abort() })
    const result = { ok: false as const, reason: 'preserved-domain-reason', error: ipcError(category) }
    expect(await registry.run('export', async lease => commit ? lease.commit(() => result) : result,
      { signal: abort.signal })).toBe(result)
    expect(registry.list()).toMatchObject([{ status: category === 'cancelled' ? 'cancelled' : 'error', category }])
    expect(registry.cancel(registry.list()[0].operationId)).toBe(false)
    await registry.close()
  })
  it.each([undefined, 'permission', { category: 'permission' },
    { ...ipcError('permission'), code: IPC_ERRORS.network.code },
    { category: '__proto__', code: 'IPC_PERMISSION_DENIED' },
    { get category() { throw new Error('private diagnostic') } }])('does not infer returned categories from incomplete or malformed errors (AT-00-004)', async error => {
    const registry = new OperationRegistry()
    const result = { success: false, error }
    expect(await registry.run('export', async () => result)).toBe(result)
    expect(registry.list()).toMatchObject([{ status: 'error', category: 'internal' }])
    await registry.close()
  })
  it('does not treat a successful payload containing error metadata as a failure (AT-00-005)', async () => {
    const registry = new OperationRegistry()
    await registry.run('export', async () => ({ ok: true, error: ipcError('network') }))
    expect(registry.list()).toMatchObject([{ status: 'success' }])
    expect(registry.list()[0]).not.toHaveProperty('category')
    await registry.close()
  })
  it('lets a coordinator expire failed cleanup promptly while retaining the physical resource', async () => {
    const registry = new OperationRegistry(), gate = held<void>()
    let owned!: OperationLease
    const task = registry.run('server-probe', async lease => { owned = lease; await lease.wait(gate.promise) }).catch(error => error)
    expect(owned.expire()).toBe(true)
    expect(await task).toMatchObject({ category: 'timeout' })
    expect(registry.list()[0]).toMatchObject({ status: 'error', category: 'timeout' })
    expect(registry.isBusy('server-probe')).toBe(true); expect(owned.expire()).toBe(false)
    gate.resolve(); await registry.close(); expect(registry.isBusy('server-probe')).toBe(false)
  })
  it('keeps receipts distinguishable after credential redaction without changing cancellation UUIDs', async () => {
    const registry = new OperationRegistry(), gate = held<void>()
    const first = registry.run('health-check', async lease => { await lease.wait(gate.promise) }, { resource: 'first' }).catch(error => error)
    await registry.run('health-check', async () => {}, { resource: 'second' })
    const receipts = registry.list()
    const sanitized = redactSensitiveConfig(receipts) as typeof receipts
    expect(sanitized.map(receipt => receipt.operationKey)).toEqual(receipts.map(receipt => 'op_' + receipt.operationId.replaceAll('-', '')))
    expect(new Set(sanitized.map(receipt => receipt.operationKey)).size).toBe(2)
    expect(sanitized.map(receipt => receipt.correlationId)).toEqual(receipts.map(receipt => receipt.correlationId))
    expect(JSON.stringify(sanitized)).not.toContain(receipts[0].operationId)
    expect(registry.cancel(receipts[0].operationId)).toBe(true)
    expect(await first).toMatchObject({ category: 'cancelled' })
    gate.resolve(); await registry.close()
  })
  it('preserves quiet user dismissal while recording a cancelled terminal outcome', async () => {
    const registry = new OperationRegistry()
    expect(await registry.run('export', async () => ({ ok: false, cancelled: true }))).toEqual({ ok: false, cancelled: true })
    expect(registry.list()).toMatchObject([{ status: 'cancelled', category: 'cancelled' }])
    expect(await registry.run('export', async () => ({ ok: false, cancelled: false }))).toEqual({ ok: false, cancelled: false })
    expect(registry.list()[1]).toMatchObject({ status: 'error' })
    await registry.close()
  })
  it('pauses only user decision time, then enforces the remaining work budget and drains timeout', async () => {
    vi.useFakeTimers()
    const registry = new OperationRegistry(), dialog = held<void>(), work = held<void>()
    const run = registry.run('export', async lease => { await lease.waitForUser(dialog.promise); await lease.wait(work.promise) }, { timeoutMs: 100 }).catch(error => error)
    expect(registry.list()[0].deadline).toBeNull()
    await vi.advanceTimersByTimeAsync(600_000)
    expect(registry.list()[0].status).toBe('running')
    dialog.resolve()
    await vi.advanceTimersByTimeAsync(0)
    expect(registry.list()[0].deadline).toBe(Date.now() + 100)
    await vi.advanceTimersByTimeAsync(100)
    expect(await run).toMatchObject({ category: 'timeout' })
    expect(registry.isBusy('export')).toBe(true)
    work.resolve(); await registry.close()
    expect(vi.getTimerCount()).toBe(0)
  })

  it('cancels user waits promptly and never restarts the deadline after late dialog completion', async () => {
    vi.useFakeTimers()
    const registry = new OperationRegistry(), dialog = held<void>(), effect = vi.fn()
    const run = registry.run('import', async lease => { await lease.waitForUser(dialog.promise); effect() }).catch(error => error)
    expect(registry.cancel(registry.list()[0].operationId)).toBe(true)
    expect(await run).toMatchObject({ category: 'cancelled' })
    dialog.resolve(); await registry.close()
    expect(effect).not.toHaveBeenCalled()
    expect(vi.getTimerCount()).toBe(0)
  })

  it('publishes a synchronous final commit before a late abort can relabel persisted success', async () => {
    const controller = new AbortController(), persist = vi.fn()
    const registry = new OperationRegistry(operation => { if (operation.status === 'success') controller.abort() })
    const result = await registry.run('export', async lease => lease.commit(() => {
      persist()
      return { success: true, path: 'selected.json' }
    }), { signal: controller.signal })
    expect(result).toEqual({ success: true, path: 'selected.json' })
    expect(persist).toHaveBeenCalledOnce()
    expect(controller.signal.aborted).toBe(true)
    expect(registry.list()).toMatchObject([{ status: 'success' }])
    expect(registry.cancel(registry.list()[0].operationId)).toBe(false)
    await registry.close()
  })

  it('refuses a final commit while tracked I/O is still physically pending', async () => {
    const registry = new OperationRegistry(), gate = held<void>(), persist = vi.fn()
    const task = registry.run('export', async lease => {
      void lease.wait(gate.promise).catch(() => {})
      return lease.commit(persist)
    }).catch(error => error)
    await Promise.resolve()
    expect(persist).not.toHaveBeenCalled()
    gate.resolve()
    expect(await task).toMatchObject({ category: 'conflict' })
    expect(registry.list()).toMatchObject([{ status: 'error', category: 'conflict' }])
    await registry.close()
  })

  it('preserves a failed final commit as an error and does not claim persisted success', async () => {
    const registry = new OperationRegistry()
    await expect(registry.run('import', async lease => lease.commit(() => {
      throw Object.assign(new Error('denied'), { code: 'EACCES' })
    }))).rejects.toMatchObject({ code: 'EACCES' })
    expect(registry.list()).toMatchObject([{ status: 'error', category: 'permission' }])
    await registry.close()
  })

  it('does not interrupt the synchronous commit from a reentrant cancellation observer', async () => {
    const controller = new AbortController(), registry = new OperationRegistry(), persist = vi.fn()
    expect(await registry.run('export', async lease => lease.commit(() => {
      persist('before')
      expect(registry.cancel(lease.operation.operationId)).toBe(false)
      controller.abort()
      persist('after')
      return 'saved'
    }), { signal: controller.signal })).toBe('saved')
    expect(persist.mock.calls).toEqual([['before'], ['after']])
    expect(registry.list()).toMatchObject([{ status: 'success' }])
    await registry.close()
  })

  it('retains the committed result if feature code mistakenly throws after final publication', async () => {
    const diagnostics = vi.fn(), registry = new OperationRegistry(undefined, diagnostics)
    expect(await registry.run('export', async lease => {
      lease.commit(() => 'persisted')
      throw new Error('post-commit bug')
    })).toBe('persisted')
    expect(registry.list()).toMatchObject([{ status: 'success' }])
    expect(diagnostics).toHaveBeenCalledWith(expect.objectContaining({ status: 'success' }), 'internal')
    expect(JSON.stringify(diagnostics.mock.calls)).not.toContain('post-commit bug')
    await registry.close()
  })

  it.each(['async', 'bound', 'bound-tagged'])('rejects a %s commit callback before starting any effects', async form => {
    const registry = new OperationRegistry(), gate = held<void>(), entered = vi.fn(), persist = vi.fn()
    const callback = async () => { entered(); await gate.promise; persist() }
    const candidate = form === 'async' ? callback : callback.bind(null)
    if (form === 'bound-tagged') Object.defineProperty(candidate, Symbol.toStringTag, { value: 'Function' })
    const task = registry.run('export', async lease => {
      // @ts-expect-error Promise-returning callbacks are forbidden; exercise the runtime guard too.
      return lease.commit(candidate)
    }).catch(error => error)
    try {
      await Promise.resolve()
      expect(entered).not.toHaveBeenCalled()
      expect(await task).toMatchObject({ category: 'validation' })
      expect(registry.list()).toMatchObject([{ status: 'error', category: 'validation' }])
      expect(registry.isBusy('export')).toBe(false)
    } finally { gate.resolve(); await task; await registry.close() }
    expect(persist).not.toHaveBeenCalled()
  })

  it('types terminal commits as synchronous while preserving nullable/primitive results', async () => {
    const registry = new OperationRegistry()
    await registry.run('export', async lease => {
      if (false) {
        // @ts-expect-error A regular function returning a Promise is forbidden too.
        lease.commit(() => Promise.resolve('late'))
        // @ts-expect-error Thenables are asynchronous even without Promise's other methods.
        lease.commit(() => ({ then: (resolve: (value: boolean) => void) => resolve(true) }))
      }
      return lease.commit(() => null)
    })
    expect(await registry.run('export', async lease => lease.commit(() => undefined))).toBeUndefined()
    expect(await registry.run('export', async lease => lease.commit(() => 42))).toBe(42)
    await registry.close()
  })

  it('drains an untyped synchronous callback returning a thenable before publishing its validation error', async () => {
    const order: string[] = [], gate = held<void>()
    const registry = new OperationRegistry(operation => { order.push(operation.status) })
    let signal!: AbortSignal
    const task = registry.run('export', async lease => {
      signal = lease.signal
      // Simulate JavaScript bypassing the typed contract; retain its already-started work.
      return Reflect.apply(lease.commit, lease, [() => gate.promise.then(() => { order.push('effect') })])
    }).catch(error => error)
    try {
      await Promise.resolve()
      expect(signal.aborted).toBe(true)
      expect(registry.list()).toMatchObject([{ status: 'running' }])
      expect(registry.isBusy('export')).toBe(true)
    } finally { gate.resolve(); await task; await registry.close() }
    expect(await task).toMatchObject({ category: 'validation' })
    expect(order).toEqual(['running', 'effect', 'error'])
  })

  it.each(['deadline', 'external', 'manual', 'shutdown'])('preserves invalid-commit validation while %s occurs during drain', async trigger => {
    vi.useFakeTimers()
    const gate = held<void>(), controller = new AbortController(), terminal = vi.fn()
    const registry = new OperationRegistry(), task = registry.run('export', async lease =>
      Reflect.apply(lease.commit, lease, [() => gate.promise]), { timeoutMs: 100, signal: controller.signal }).catch(error => error)
    void task.then(terminal)
    let closing: Promise<void> | undefined
    try {
      await Promise.resolve()
      const id = registry.list()[0].operationId
      if (trigger === 'deadline') await vi.advanceTimersByTimeAsync(101)
      if (trigger === 'external') controller.abort()
      if (trigger === 'manual') expect(registry.cancel(id)).toBe(false)
      if (trigger === 'shutdown') closing = registry.close()
      await Promise.resolve()
      expect(registry.list()[0].status).toBe('running')
      expect(registry.isBusy('export')).toBe(true)
      expect(terminal).not.toHaveBeenCalled()
    } finally { gate.resolve(); await task; await (closing ?? registry.close()) }
    expect(await task).toMatchObject({ category: 'validation' })
    expect(registry.list()).toMatchObject([{ status: 'error', category: 'validation' }])
  })

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
      expect(lease.operation.deadline! - lease.operation.startedAt).toBe(2000)
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
