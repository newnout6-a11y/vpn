import { randomUUID } from 'node:crypto'
import { OPERATION_PRIORITY, type ConnectionOperation, type ConnectionOperationRejection, type OperationOwner } from '../shared/operation'
import type { TunnelStateMachine } from './tunnelStateMachine'
import { currentCorrelationId, currentActionMetadata, withCorrelation, type ActionMetadata } from './actionCorrelation'
import type { OperationLease } from './operationRegistry'
import { IpcFault } from '../shared/ipc-result'

/** Main startup owns baseline effects as well as the controller startup. */
export interface ConnectionStartupOwner {
  readonly signal: AbortSignal
  readonly operation: ConnectionOperation
  assertActive(): void
  retain<T>(effect: Promise<T>): Promise<T>
  wait<T>(effect: Promise<T>): Promise<T>
}
export interface RotationOwner extends ConnectionStartupOwner {
  beginRestart(): void
  /** Final synchronous selection/scheduling and the successful result are one commit. */
  complete<T extends { success: true }>(effect: () => T): T
}

interface StartOptions { owner?: OperationOwner; timeoutMs?: number; refreshSoft?: boolean }
type CleanupResult = { success: boolean; error?: string }
type Startup = {
  controller: AbortController
  completion: Promise<void>
  operation: ConnectionOperation
  metadata: ActionMetadata
  abortCategory?: 'cancelled' | 'timeout'
  terminalPublished?: boolean
  managed?: boolean
}

function rejection(category: ConnectionOperationRejection['category'], error: string, operationId?: string): ConnectionOperationRejection {
  const code = { conflict: 'OPERATION_CONFLICT', cancelled: 'OPERATION_CANCELLED', timeout: 'OPERATION_TIMEOUT' } as const
  return { success: false, error, code: code[category], category, ...(operationId ? { operationId } : {}) }
}

function failed(result: unknown): boolean {
  return !!result && typeof result === 'object' && 'success' in result && result.success === false
}

export class ConnectionLifecycle {
  private startup: Startup | null = null
  private stopping: Promise<unknown> | null = null
  private stopOperation: ConnectionOperation | null = null
  private lastOperation: ConnectionOperation | null = null
  private closed = false

  constructor(
    private readonly cancelControllerStartup: () => void,
    private readonly cleanupCancelled?: () => Promise<CleanupResult>,
    private readonly onOperation: (operation: ConnectionOperation) => void = () => {},
    private readonly stateMachine?: TunnelStateMachine
  ) {}

  get starting(): boolean { return this.startup !== null }
  get busy(): boolean { return this.closed || this.startup !== null || this.stopping !== null }
  get operation(): ConnectionOperation | null {
    const current = this.startup?.operation ?? this.stopOperation ?? this.lastOperation
    return current ? { ...current } : null
  }

  private publish(operation: ConnectionOperation, metadata: ActionMetadata, managed = false): void {
    withCorrelation(operation.correlationId, () => {
      this.lastOperation = operation
      this.stateMachine?.operationChanged(operation)
      // An observer is not allowed to strand native ownership or cleanup.
      if (!managed) try { this.onOperation({ ...operation }) } catch { /* telemetry is best effort */ }
    }, metadata)
  }

  /** Borrow the registry identity, retaining the same native lane as connect/stop.
   * The outer registry returns promptly on abort; this Promise drains actual I/O. */
  async rotate<T>(lease: OperationLease, effect: (owner: RotationOwner) => Promise<T>): Promise<T> {
    lease.assertActive()
    if (lease.operation.kind !== 'rotation' || lease.operation.owner !== 'rotation') throw new IpcFault('validation')
    if (this.startup?.operation.status === 'running' && this.cleanupCancelled
      && OPERATION_PRIORITY[lease.operation.owner] > OPERATION_PRIORITY[this.startup.operation.owner]) {
      const stopped = await lease.wait(this.stop(this.cleanupCancelled, { owner: lease.operation.owner }))
      lease.assertActive()
      if (!stopped.success) throw new IpcFault('conflict')
    }
    if (this.busy || this.stateMachine && !this.stateMachine.canRotate()) throw new IpcFault('conflict')
    let release!: () => void
    const completion = new Promise<void>(done => { release = done })
    const metadata: ActionMetadata = { source: lease.operation.source, owner: lease.operation.owner }
    const startup: Startup = { controller: new AbortController(), completion, metadata, managed: true,
      operation: { ...lease.operation, kind: 'rotation', category: undefined } }
    const effects: Promise<unknown>[] = []
    let nativeTouched = false
    let completed: { result: unknown } | undefined
    const retain = <R>(task: Promise<R>): Promise<R> => {
      effects.push(task.then(() => undefined, () => undefined))
      return lease.retain(task)
    }
    const owner: RotationOwner = {
      signal: lease.signal, get operation() { return { ...startup.operation } },
      assertActive: () => lease.assertActive(), retain,
      wait: task => {
        effects.push(task.then(() => undefined, () => undefined))
        return lease.wait(task)
      },
      beginRestart: () => { lease.assertActive(); nativeTouched = true },
      complete: finalize => {
        lease.assertActive()
        if (this.stateMachine && !this.stateMachine.canConfirmRotation()) throw new Error('Rotation confirmation missing')
        return lease.commit(() => {
          const result = finalize()
          startup.operation = { ...startup.operation, status: 'success' }
          completed = { result }
          this.publish(startup.operation, metadata, true)
          startup.terminalPublished = true
          return result
        })
      }
    }
    const onPreempt = () => { lease.cancel() }
    let cleanup: Promise<unknown> | undefined
    const onAbort = () => withCorrelation(lease.operation.correlationId, () => {
      const retained = !nativeTouched && (!this.stateMachine || this.stateMachine.confirmRetainedRotation(startup.operation.operationId).success)
      if (!startup.terminalPublished) {
        startup.abortCategory = lease.operation.category === 'timeout' ? 'timeout' : 'cancelled'
        startup.operation = { ...startup.operation, status: startup.abortCategory === 'timeout' ? 'error' : 'cancelled', category: startup.abortCategory }
        this.publish(startup.operation, metadata, true)
        startup.terminalPublished = true
      }
      if (retained) startup.controller.abort()
      else if (this.cleanupCancelled) cleanup = this.stop(this.cleanupCancelled, { owner: 'recovery' })
      else { startup.controller.abort(); try { this.cancelControllerStartup() } catch { /* physical I/O still drains */ } }
      void cleanup?.catch(() => undefined)
    }, metadata)
    this.startup = startup
    startup.controller.signal.addEventListener('abort', onPreempt, { once: true })
    lease.signal.addEventListener('abort', onAbort, { once: true })
    this.publish(startup.operation, metadata, true)
    try {
      lease.assertActive()
      const result = await effect(owner)
      if (completed) return completed.result as T
      lease.assertActive()
      if (!failed(result)) throw new Error('Rotation completion missing')
      if (!nativeTouched) this.stateMachine?.confirmRetainedRotation(startup.operation.operationId)
      startup.operation = { ...startup.operation, status: 'error' }
      return result
    } catch (error) {
      if (completed) throw error // registry retains its committed result and diagnoses the throw
      if (!startup.terminalPublished) startup.operation = { ...startup.operation, status: lease.signal.aborted ? 'cancelled' : 'error',
        category: lease.signal.aborted ? 'cancelled' : 'internal' }
      throw error
    } finally {
      await Promise.all(effects)
      lease.signal.removeEventListener('abort', onAbort)
      startup.controller.signal.removeEventListener('abort', onPreempt)
      if (!startup.terminalPublished) this.publish(startup.operation, metadata, true)
      if (this.startup === startup) this.startup = null
      release()
      // stop waits completion, so release first; registry ownership lasts through cleanup.
      await cleanup
    }
  }

  async start<T>(effect: (owner: ConnectionStartupOwner) => Promise<T>, options: StartOptions = {}): Promise<T | ConnectionOperationRejection> {
    const timeoutMs = options.timeoutMs ?? 120_000, operationOwner = options.owner ?? 'manual'
    if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 2 ** 31 - 1) throw new Error('Invalid operation timeout')
    if (this.closed || this.stopping) return rejection('conflict', 'Остановка защиты ещё выполняется — подождите')
    if (this.startup) {
      if (this.startup.operation.status !== 'running') return rejection('conflict', 'Отменённая операция ещё завершается')
      if (this.cleanupCancelled && OPERATION_PRIORITY[operationOwner] > OPERATION_PRIORITY[this.startup.operation.owner]) {
        const stopped = await this.stop(this.cleanupCancelled, { owner: operationOwner })
        if (!stopped.success) return rejection('conflict', 'Не удалось завершить отменённую операцию')
        return this.start(effect, options)
      }
      return rejection('conflict', 'Запуск защиты уже выполняется')
    }
    const snapshot = this.stateMachine?.snapshot
    // Soft refresh reapplies the selected proxy under the same exclusive lane.
    // It must never admit a second native core or overwrite an active transition.
    const softRefresh = options.refreshSoft && snapshot?.state === 'connected'
      && snapshot.mode === 'soft' && snapshot.transition === null
    if (this.stateMachine && !this.stateMachine.canStart() && !softRefresh) return rejection('conflict', 'Состояние туннеля не допускает новый запуск')
    const controller = new AbortController()
    let release!: () => void
    const completion = new Promise<void>(done => { release = done })
    const startedAt = Date.now()
    const operationId = randomUUID()
    const metadata: ActionMetadata = { source: currentActionMetadata()?.source ?? 'lifecycle', owner: operationOwner }
    const startup: Startup = { controller, completion, metadata, operation: {
      version: 1, operationId, correlationId: currentCorrelationId() ?? 'op_' + operationId.replaceAll('-', ''), kind: 'connect', owner: operationOwner,
      startedAt, deadline: startedAt + timeoutMs, status: 'running'
    } }
    this.startup = startup
    this.publish(startup.operation, startup.metadata)
    const cancellationResult = () => {
      const category = startup.abortCategory ?? 'cancelled'
      return rejection(category, category === 'timeout' ? 'Истекло время запуска защиты' : 'Запуск отменён', startup.operation.operationId)
    }
    const timer = setTimeout(() => withCorrelation(startup.operation.correlationId, () => {
      startup.abortCategory = 'timeout'
      startup.operation = { ...startup.operation, status: 'error', category: 'timeout' }
      this.publish(startup.operation, startup.metadata)
      startup.terminalPublished = true
      // Cancelling never releases a native effect. Cleanup reserves admission
      // synchronously, then waits for the actual startup completion.
      controller.abort()
      if (this.cleanupCancelled) void this.stop(this.cleanupCancelled, { owner: 'recovery' }).catch(() => undefined)
      else { try { this.cancelControllerStartup() } catch { /* startup still drains */ } }
    }, startup.metadata), timeoutMs)
    timer.unref?.()
    let onAbort!: () => void
    let failure: { error: unknown } | undefined
    const cancelled = new Promise<ConnectionOperationRejection>((resolve, reject) => {
      onAbort = () => {
        clearTimeout(timer)
        // A known failure awaiting native drain must keep its original cause.
        if (failure) reject(failure.error)
        else resolve(cancellationResult())
      }
      controller.signal.addEventListener('abort', onAbort, { once: true })
      if (controller.signal.aborted) onAbort()
    })
    const effects: Promise<unknown>[] = []
    const assertActive = () => {
      if (controller.signal.aborted || this.startup !== startup) throw new Error('Запуск отменён')
    }
    const retain = <R>(task: Promise<R>): Promise<R> => {
      // Observe rejection immediately, including effects not awaited until
      // finally. Native effects keep their owner until actual settlement.
      effects.push(task.then(() => undefined, () => undefined))
      return task
    }
    const owner: ConnectionStartupOwner = {
      signal: controller.signal, get operation() { return { ...startup.operation } }, assertActive, retain,
      async wait<R>(task: Promise<R>): Promise<R> {
        retain(task)
        assertActive()
        let onAbort!: () => void
        const cancelled = new Promise<never>((_, reject) => {
          onAbort = () => reject(new Error('Запуск отменён'))
          controller.signal.addEventListener('abort', onAbort, { once: true })
        })
        try {
          const result = await Promise.race([task, cancelled])
          assertActive()
          return result
        } finally { controller.signal.removeEventListener('abort', onAbort) }
      }
    }
    // The caller may leave on abort; this task alone releases the native lease.
    // Promise.race also observes late rejection after the caller has returned.
    const drained = withCorrelation(startup.operation.correlationId, async () => {
      try {
        assertActive()
        const result = await effect(owner)
        await Promise.all(effects)
        assertActive()
        if (!failed(result) && this.stateMachine && !this.stateMachine.canConfirmStart()) {
          // A failed confirmation must not abandon a process started by this owner.
          await this.cleanupCancelled?.()
          throw new Error('Connection confirmation missing')
        }
        startup.operation = { ...startup.operation, status: failed(result) ? 'error' : 'success' }
        return result
      } catch (error) {
        if (controller.signal.aborted) {
          const category = startup.abortCategory ?? 'cancelled'
          startup.operation = { ...startup.operation, status: category === 'timeout' ? 'error' : 'cancelled', category }
          return cancellationResult()
        }
        failure = { error }
        startup.operation = { ...startup.operation, status: 'error', category: 'internal' }
        throw error
      } finally {
        await Promise.all(effects)
        clearTimeout(timer)
        if (!startup.terminalPublished) this.publish(startup.operation, startup.metadata)
        if (this.startup === startup) this.startup = null
        release()
      }
    }, startup.metadata)
    try { return await Promise.race([drained, cancelled]) }
    finally { controller.signal.removeEventListener('abort', onAbort) }
  }

  stop<T>(effect: () => Promise<T>, options: { owner?: OperationOwner } = {}): Promise<T | ConnectionOperationRejection> {
    if (this.stopping) return this.stopping as Promise<T>
    const owner = options.owner ?? 'manual'
    const active = this.startup?.operation
    if (active && OPERATION_PRIORITY[owner] < OPERATION_PRIORITY[active.owner]) {
      return Promise.resolve(rejection('conflict', 'Операция более высокого приоритета ещё выполняется'))
    }
    const startup = this.startup
    const cancellationErrors: unknown[] = []
    const operationId = randomUUID()
    const metadata: ActionMetadata = { source: currentActionMetadata()?.source ?? 'lifecycle', owner }
    const operation: ConnectionOperation = {
      version: 1, operationId, correlationId: currentCorrelationId() ?? 'op_' + operationId.replaceAll('-', ''), owner, kind: 'disconnect',
      startedAt: Date.now(), deadline: null, status: 'running'
    }
    const stopped = Promise.resolve().then(async () => {
      if (startup) await startup.completion
      const result = await withCorrelation(operation.correlationId, effect, metadata)
      if (!failed(result) && this.stateMachine && !this.stateMachine.canConfirmStop()) throw new Error('Runtime cleanup confirmation missing')
      if (cancellationErrors.length) throw cancellationErrors[0]
      this.stopOperation = { ...operation, status: failed(result) ? 'error' : 'success' }
      return result
    }).catch(error => {
      this.stopOperation = { ...operation, status: 'error', category: 'internal' }
      throw error
    }).finally(() => {
      if (this.stopping === stopped) {
        this.publish(this.stopOperation!, metadata)
        this.stopOperation = null
        this.stopping = null
      }
    })
    // Reserve admission before signalling the controller or waiting for I/O.
    this.stopping = stopped
    this.stopOperation = operation
    this.publish(operation, metadata)
    if (startup && startup.operation.status === 'running' && !startup.abortCategory) {
      startup.abortCategory = 'cancelled'
      startup.operation = { ...startup.operation, status: 'cancelled', category: 'cancelled' }
      this.publish(startup.operation, startup.metadata, startup.managed)
      startup.terminalPublished = true
    }
    startup?.controller.abort()
    try { this.cancelControllerStartup() }
    catch (error) { cancellationErrors.push(error) }
    return stopped
  }

  async close(): Promise<void> {
    this.closed = true
    if (this.startup && this.startup.operation.status === 'running' && !this.startup.abortCategory) {
      this.startup.abortCategory = 'cancelled'
      this.startup.operation = { ...this.startup.operation, status: 'cancelled', category: 'cancelled' }
      this.publish(this.startup.operation, this.startup.metadata, this.startup.managed)
      this.startup.terminalPublished = true
    }
    this.startup?.controller.abort()
    const cancellationErrors: unknown[] = []
    try { this.cancelControllerStartup() }
    catch (error) { cancellationErrors.push(error) }
    if (this.startup) await this.startup.completion
    if (this.stopping) await this.stopping
    if (cancellationErrors.length) throw cancellationErrors[0]
  }
}
