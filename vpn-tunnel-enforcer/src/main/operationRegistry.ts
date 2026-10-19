import { randomUUID } from 'node:crypto'
import { OPERATION_DEADLINES, OPERATION_PRIORITY, type ManagedOperation, type ManagedOperationKind, type OperationOwner } from '../shared/operation'
import { IpcFault, classifyIpcError, type IpcErrorCategory } from '../shared/ipc-result'
import { currentActionMetadata, currentCorrelationId, withCorrelation } from './actionCorrelation'

export interface OperationLease {
  readonly signal: AbortSignal
  readonly operation: ManagedOperation
  assertActive(): void
  wait<T>(task: Promise<T>): Promise<T>
  /** Native consent/picker time is not application work; cancellation still drains it. */
  waitForUser<T>(task: Promise<T>): Promise<T>
  /** Final synchronous persistence and its result become terminal together.
   * All tracked I/O must have settled; no more effects may follow this call. */
  commit<T>(effect: () => T): T
}
interface RunOptions { owner?: OperationOwner; resource?: string; timeoutMs?: number; signal?: AbortSignal }
interface Entry {
  operation: ManagedOperation
  controller: AbortController
  drained: Promise<void>
  cancel(category: 'cancelled' | 'timeout'): boolean
}

/** Caller cancellation is prompt; physical effects retain their exclusive lease
 * until actual settlement. Feature code must await boundaries through the lease
 * and guard event callbacks before publishing or committing results. */
export class OperationRegistry {
  private readonly active = new Map<string, Entry>()
  private readonly history = new Map<string, ManagedOperation>()
  private closing = new AbortController()
  private closed = false
  private generation = 0
  constructor(
    private readonly observe: (operation: ManagedOperation) => void = () => {},
    private readonly committedFailure: (operation: ManagedOperation, category: IpcErrorCategory) => void = () => {}
  ) {}

  list(): ManagedOperation[] { return [...this.history.values()].map(operation => ({ ...operation })) }
  isBusy(resource: string): boolean { return this.active.has(resource) }
  cancel(operationId: string): boolean {
    const entry = [...this.active.values()].find(item => item.operation.operationId === operationId)
    if (!entry || entry.operation.status !== 'running') return false
    return entry.cancel('cancelled')
  }
  async close(): Promise<void> {
    this.closed = true
    this.generation += 1
    this.closing.abort()
    const entries = [...this.active.values()]
    for (const entry of entries) entry.cancel('cancelled')
    await Promise.all(entries.map(entry => entry.drained))
  }

  /** Only a refused quit may resume feature work, after all old effects drain. */
  resumeAdmission(): boolean {
    if (!this.closed) return true
    if (this.active.size) return false
    this.closing = new AbortController()
    this.closed = false
    return true
  }

  async run<T>(kind: ManagedOperationKind, effect: (lease: OperationLease) => Promise<T>, options: RunOptions = {}): Promise<T> {
    const timeoutMs = options.timeoutMs ?? OPERATION_DEADLINES[kind], owner = options.owner ?? 'manual'
    if (!Object.hasOwn(OPERATION_DEADLINES, kind) || !Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 2 ** 31 - 1
      || !Object.hasOwn(OPERATION_PRIORITY, owner)) throw new IpcFault('validation')
    if (options.signal?.aborted) throw new IpcFault('cancelled')
    if (this.closed) throw new IpcFault('conflict')
    const startedAt = Date.now(), expiresAt = performance.now() + timeoutMs, generation = this.generation
    const resource = options.resource ?? kind
    while (this.active.has(resource)) {
      const previous = this.active.get(resource)!
      if (previous.operation.status !== 'running' || OPERATION_PRIORITY[owner] <= OPERATION_PRIORITY[previous.operation.owner]) throw new IpcFault('conflict')
      previous.cancel('cancelled')
      await this.waitForDrain(previous.drained, expiresAt - performance.now(), options.signal)
      if (generation !== this.generation) throw new IpcFault('conflict')
    }
    if (options.signal?.aborted) throw new IpcFault('cancelled')
    if (this.closed) throw new IpcFault('conflict')
    const remainingMs = expiresAt - performance.now()
    if (remainingMs <= 0) throw new IpcFault('timeout')
    const operationId = randomUUID(), controller = new AbortController()
    const metadata = { source: currentActionMetadata()?.source ?? 'lifecycle', owner }
    let release!: () => void, rejectAbort!: (error: IpcFault) => void, abortFault: IpcFault | undefined
    const drained = new Promise<void>(done => { release = done })
    const aborted = new Promise<never>((_, reject) => { rejectAbort = reject })
    void aborted.catch(() => {})
    const effects: Promise<unknown>[] = []
    let pendingEffects = 0, committing = false, committed: { result: unknown } | undefined
    let userWaits = 0, workRemainingMs = remainingMs, workClock = performance.now()
    const entry: Entry = { controller, drained, operation: {
      version: 1, operationId, correlationId: currentCorrelationId() ?? 'op_' + operationId.replaceAll('-', ''),
      kind, owner, source: metadata.source, startedAt, deadline: startedAt + timeoutMs, status: 'running'
    }, cancel: category => {
      if (entry.operation.status !== 'running' || committing) return false
      abortFault = new IpcFault(category)
      finish(category === 'cancelled' ? 'cancelled' : 'error', category)
      controller.abort()
      rejectAbort(abortFault)
      return true
    } }
    const publish = () => withCorrelation(entry.operation.correlationId, () => {
      this.history.set(operationId, { ...entry.operation })
      // Never evict live records, including those whose native effects drain.
      if (this.history.size > 1000) for (const [id] of this.history) {
        if (![...this.active.values()].some(item => item.operation.operationId === id)) { this.history.delete(id); break }
      }
      try { this.observe({ ...entry.operation }) } catch { /* telemetry cannot strand a lease */ }
    }, metadata)
    const finish = (status: ManagedOperation['status'], category?: IpcErrorCategory) => {
      if (entry.operation.status !== 'running') return
      clearTimeout(timer)
      entry.operation = { ...entry.operation, status, ...(category ? { category } : {}) }
      publish()
    }
    const assertActive = () => {
      if (controller.signal.aborted || entry.operation.status !== 'running' || this.active.get(resource) !== entry) throw abortFault ?? new IpcFault('cancelled')
    }
    const updateDeadline = (deadline: number | null) => {
      entry.operation = { ...entry.operation, deadline }
      this.history.set(operationId, { ...entry.operation })
    }
    const lease: OperationLease = { signal: controller.signal, get operation() { return { ...entry.operation } }, assertActive,
      async wait<R>(task: Promise<R>): Promise<R> {
        pendingEffects++
        effects.push(task.then(() => { pendingEffects-- }, () => { pendingEffects-- }))
        assertActive()
        const value = await Promise.race([task, aborted])
        assertActive()
        return value
      },
      async waitForUser<R>(task: Promise<R>): Promise<R> {
        const waiting = lease.wait(task)
        if (entry.operation.status !== 'running') return waiting
        if (userWaits++ === 0) {
          workRemainingMs = Math.max(0, workRemainingMs - (performance.now() - workClock))
          if (workRemainingMs <= 0) { userWaits--; entry.cancel('timeout'); return waiting }
          clearTimeout(timer)
          updateDeadline(null)
        }
        try { return await waiting }
        finally {
          if (--userWaits === 0 && entry.operation.status === 'running') {
            workClock = performance.now()
            updateDeadline(Date.now() + workRemainingMs)
            timer = setTimeout(() => entry.cancel('timeout'), workRemainingMs)
            timer.unref?.()
          }
        }
      },
      commit<R>(effect: () => R): R {
        assertActive()
        if (pendingEffects) throw new IpcFault('conflict')
        let result: R
        committing = true
        try { result = effect() } finally { committing = false }
        if (result && (typeof result === 'object' || typeof result === 'function') && typeof (result as { then?: unknown }).then === 'function') {
          pendingEffects++
          effects.push(Promise.resolve(result).then(() => { pendingEffects-- }, () => { pendingEffects-- }))
          throw new IpcFault('validation')
        }
        committed = { result }
        finish('success')
        return result
      }
    }
    let timer = setTimeout(() => entry.cancel('timeout'), remainingMs)
    timer.unref?.()
    const onAbort = () => entry.cancel('cancelled')
    options.signal?.addEventListener('abort', onAbort, { once: true })
    this.active.set(resource, entry)
    publish()
    const work = withCorrelation(entry.operation.correlationId, async () => {
      try {
        assertActive()
        const result = await effect(lease)
        await Promise.all(effects)
        if (committed) return committed.result as T
        assertActive()
        const failed = result && typeof result === 'object' && (('success' in result && result.success === false) || ('ok' in result && result.ok === false))
        finish(failed ? 'error' : 'success')
        return result
      } catch (error) {
        if (committed) {
          try { this.committedFailure({ ...entry.operation }, classifyIpcError(error)) } catch { /* telemetry cannot reverse persistence */ }
          return committed.result as T
        }
        finish('error', classifyIpcError(error))
        controller.abort() // Abort sibling network effects on a terminal failure too.
        throw error
      } finally {
        await Promise.all(effects)
        clearTimeout(timer)
        options.signal?.removeEventListener('abort', onAbort)
        if (this.active.get(resource) === entry) this.active.delete(resource)
        release()
      }
    }, metadata)
    return Promise.race([work, aborted])
  }

  private async waitForDrain(drained: Promise<void>, timeoutMs: number, signal?: AbortSignal): Promise<void> {
    if (signal?.aborted) throw new IpcFault('cancelled')
    if (this.closed) throw new IpcFault('conflict')
    if (timeoutMs <= 0) throw new IpcFault('timeout')
    let rejectWait!: (error: IpcFault) => void
    const stopped = new Promise<never>((_, reject) => { rejectWait = reject })
    const onAbort = () => rejectWait(new IpcFault('cancelled'))
    const onClose = () => rejectWait(new IpcFault('conflict'))
    const timer = setTimeout(() => rejectWait(new IpcFault('timeout')), timeoutMs)
    timer.unref?.()
    signal?.addEventListener('abort', onAbort, { once: true })
    this.closing.signal.addEventListener('abort', onClose, { once: true })
    try { await Promise.race([drained, stopped]) }
    finally {
      clearTimeout(timer)
      signal?.removeEventListener('abort', onAbort)
      this.closing.signal.removeEventListener('abort', onClose)
    }
  }
}
