/** Main startup owns baseline effects as well as the controller startup. */
export interface ConnectionStartupOwner {
  readonly signal: AbortSignal
  assertActive(): void
  retain<T>(effect: Promise<T>): Promise<T>
  wait<T>(effect: Promise<T>): Promise<T>
}

type RejectedConnection = { success: false; error: string }

export class ConnectionLifecycle {
  private startup: { controller: AbortController; completion: Promise<void> } | null = null
  private stopping: Promise<unknown> | null = null
  private closed = false

  constructor(private readonly cancelControllerStartup: () => void) {}

  get starting(): boolean { return this.startup !== null }

  async start<T>(effect: (owner: ConnectionStartupOwner) => Promise<T>): Promise<T | RejectedConnection> {
    if (this.closed || this.stopping) return { success: false, error: 'Остановка защиты ещё выполняется — подождите' }
    if (this.startup) return { success: false, error: 'Запуск защиты уже выполняется' }
    const controller = new AbortController()
    let release!: () => void
    const completion = new Promise<void>(done => { release = done })
    const startup = { controller, completion }
    this.startup = startup
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
      signal: controller.signal, assertActive, retain,
      async wait<R>(task: Promise<R>): Promise<R> {
        const result = await retain(task)
        assertActive()
        return result
      }
    }
    try {
      const result = await effect(owner)
      await Promise.all(effects)
      assertActive()
      return result
    } catch (error) {
      if (controller.signal.aborted) return { success: false, error: 'Запуск отменён' }
      throw error
    } finally {
      await Promise.all(effects)
      if (this.startup === startup) this.startup = null
      release()
    }
  }

  stop<T>(effect: () => Promise<T>): Promise<T> {
    if (this.stopping) return this.stopping as Promise<T>
    const startup = this.startup
    const cancellationErrors: unknown[] = []
    const stopped = Promise.resolve().then(async () => {
      if (startup) await startup.completion
      const result = await effect()
      if (cancellationErrors.length) throw cancellationErrors[0]
      return result
    }).finally(() => {
      if (this.stopping === stopped) this.stopping = null
    })
    // Reserve admission before signalling the controller or waiting for I/O.
    this.stopping = stopped
    startup?.controller.abort()
    try { this.cancelControllerStartup() }
    catch (error) { cancellationErrors.push(error) }
    return stopped
  }

  async close(): Promise<void> {
    this.closed = true
    this.startup?.controller.abort()
    const cancellationErrors: unknown[] = []
    try { this.cancelControllerStartup() }
    catch (error) { cancellationErrors.push(error) }
    if (this.startup) await this.startup.completion
    if (this.stopping) await this.stopping
    if (cancellationErrors.length) throw cancellationErrors[0]
  }
}
