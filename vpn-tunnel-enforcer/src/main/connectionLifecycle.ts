import { randomUUID } from 'node:crypto'
import { OPERATION_PRIORITY, type ConnectionOperation, type ConnectionOperationRejection, type OperationOwner } from '../shared/operation'
import type { TunnelStateMachine } from './tunnelStateMachine'

/** Main startup owns baseline effects as well as the controller startup. */
export interface ConnectionStartupOwner {
  readonly signal: AbortSignal
  readonly operation: ConnectionOperation
  assertActive(): void
  retain<T>(effect: Promise<T>): Promise<T>
  wait<T>(effect: Promise<T>): Promise<T>
}

interface StartOptions { owner?: OperationOwner; timeoutMs?: number; refreshSoft?: boolean }
type CleanupResult = { success: boolean; error?: string }
type Startup = {
  controller: AbortController
  completion: Promise<void>
  operation: ConnectionOperation
  abortCategory?: 'cancelled' | 'timeout'
  terminalPublished?: boolean
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

  private publish(operation: ConnectionOperation): void {
    this.lastOperation = operation
    this.stateMachine?.operationChanged(operation)
    // An observer is not allowed to strand native ownership or cleanup.
    try { this.onOperation({ ...operation }) } catch { /* telemetry is best effort */ }
  }

  async start<T>(effect: (owner: ConnectionStartupOwner) => Promise<T>, options: StartOptions = {}): Promise<T | ConnectionOperationRejection> {
    const timeoutMs = options.timeoutMs ?? 120_000, operationOwner = options.owner ?? 'manual'
    if (!Number.isInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 2 ** 31 - 1) throw new Error('Invalid operation timeout')
    if (this.closed || this.stopping) return rejection('conflict', 'Остановка защиты ещё выполняется — подождите')
    if (this.startup) {
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
    const startup: Startup = { controller, completion, operation: {
      version: 1, operationId, correlationId: 'op_' + operationId.replaceAll('-', ''), kind: 'connect', owner: operationOwner,
      startedAt, deadline: startedAt + timeoutMs, status: 'running'
    } }
    this.startup = startup
    this.publish(startup.operation)
    const timer = setTimeout(() => {
      startup.abortCategory = 'timeout'
      startup.operation = { ...startup.operation, status: 'error', category: 'timeout' }
      this.publish(startup.operation)
      startup.terminalPublished = true
      // Cancelling never releases a native effect. Cleanup reserves admission
      // synchronously, then waits for the actual startup completion.
      controller.abort()
      if (this.cleanupCancelled) void this.stop(this.cleanupCancelled, { owner: 'recovery' }).catch(() => undefined)
      else { try { this.cancelControllerStartup() } catch { /* startup still drains */ } }
    }, timeoutMs)
    timer.unref?.()
    controller.signal.addEventListener('abort', () => clearTimeout(timer), { once: true })
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
    try {
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
        return rejection(category, category === 'timeout' ? 'Истекло время запуска защиты' : 'Запуск отменён', startup.operation.operationId)
      }
      startup.operation = { ...startup.operation, status: 'error', category: 'internal' }
      throw error
    } finally {
      await Promise.all(effects)
      clearTimeout(timer)
      if (!startup.terminalPublished) this.publish(startup.operation)
      if (this.startup === startup) this.startup = null
      release()
    }
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
    const operation: ConnectionOperation = {
      version: 1, operationId, correlationId: 'op_' + operationId.replaceAll('-', ''), owner, kind: 'disconnect',
      startedAt: Date.now(), deadline: null, status: 'running'
    }
    const stopped = Promise.resolve().then(async () => {
      if (startup) await startup.completion
      const result = await effect()
      if (!failed(result) && this.stateMachine && !this.stateMachine.canConfirmStop()) throw new Error('Runtime cleanup confirmation missing')
      if (cancellationErrors.length) throw cancellationErrors[0]
      this.stopOperation = { ...operation, status: failed(result) ? 'error' : 'success' }
      return result
    }).catch(error => {
      this.stopOperation = { ...operation, status: 'error', category: 'internal' }
      throw error
    }).finally(() => {
      if (this.stopping === stopped) {
        this.publish(this.stopOperation!)
        this.stopOperation = null
        this.stopping = null
      }
    })
    // Reserve admission before signalling the controller or waiting for I/O.
    this.stopping = stopped
    this.stopOperation = operation
    this.publish(operation)
    if (startup && !startup.abortCategory) {
      startup.abortCategory = 'cancelled'
      startup.operation = { ...startup.operation, status: 'cancelled', category: 'cancelled' }
      this.publish(startup.operation)
      startup.terminalPublished = true
    }
    startup?.controller.abort()
    try { this.cancelControllerStartup() }
    catch (error) { cancellationErrors.push(error) }
    return stopped
  }

  async close(): Promise<void> {
    this.closed = true
    if (this.startup && !this.startup.abortCategory) {
      this.startup.abortCategory = 'cancelled'
      this.startup.operation = { ...this.startup.operation, status: 'cancelled', category: 'cancelled' }
      this.publish(this.startup.operation)
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
