// AT-07-002 / AT-08-007: client side of the native-read host. No Electron import here, so it is unit-testable
// with a fake process; nativeHost.ts wires it to Electron's utilityProcess.
import { isHostResponse, NativeHostError, type HostOp, type HostRequest } from './hostProtocol'

/** The subset of Electron's UtilityProcess the client needs. */
export interface HostProcess {
  postMessage(message: unknown): void
  on(event: 'message', listener: (message: unknown) => void): unknown
  on(event: 'exit', listener: (code: number) => void): unknown
  kill(): boolean
}

export interface HostClientOptions {
  fork: () => HostProcess
  /** Per-request timeout; a hung FFI call cannot be cancelled, so a timeout kills the host. */
  defaultTimeoutMs?: number
  /** Crash-loop breaker: this many deaths within deathWindowMs disables the host until restart. */
  maxDeaths?: number
  deathWindowMs?: number
  now?: () => number
  log?: (level: 'info' | 'warn', message: string, details?: Record<string, unknown>) => void
}

interface Pending {
  resolve: (value: unknown) => void
  reject: (error: Error) => void
  timer: ReturnType<typeof setTimeout>
  op: HostOp
  /** The process this request was sent to: a late 'exit' of an old process must not fail a newer one's requests. */
  owner: HostProcess
}

export interface HostClient {
  call<T>(op: HostOp, args?: unknown, timeoutMs?: number): Promise<T>
  /** Stops the host without counting it as a crash (application quit). */
  shutdown(): void
  status(): { running: boolean; disabled: boolean; deaths: number }
}

export function createHostClient(options: HostClientOptions): HostClient {
  const defaultTimeoutMs = options.defaultTimeoutMs ?? 10_000
  const maxDeaths = options.maxDeaths ?? 3
  const deathWindowMs = options.deathWindowMs ?? 5 * 60_000
  const now = options.now ?? Date.now
  const log = options.log ?? (() => undefined)

  let proc: HostProcess | null = null
  let nextId = 1
  let disabled = false
  let shuttingDown = false
  const deaths: number[] = []
  const pending = new Map<number, Pending>()
  /** Processes already accounted for (killed by us or exited): their later events are ignored. */
  const dead = new WeakSet<HostProcess>()

  function rejectAll(owner: HostProcess | null, reason: string): void {
    for (const [id, entry] of pending) {
      if (owner && entry.owner !== owner) continue
      clearTimeout(entry.timer)
      pending.delete(id)
      entry.reject(new NativeHostError('unavailable', reason))
    }
  }

  function recordDeath(reason: string): void {
    const at = now()
    deaths.push(at)
    while (deaths.length > 0 && at - deaths[0] > deathWindowMs) deaths.shift()
    log('warn', 'native host died', { reason, deathsInWindow: deaths.length })
    if (deaths.length >= maxDeaths && !disabled) {
      disabled = true
      log('warn', 'native host disabled for this session after repeated deaths; PowerShell is used', { deaths: deaths.length })
    }
  }

  /** Drops the current process (kill if still alive), fails every pending request, counts the death. */
  function fail(current: HostProcess, reason: string): void {
    if (dead.has(current)) return
    dead.add(current)
    if (proc === current) proc = null
    try { current.kill() } catch { /* already gone */ }
    rejectAll(current, reason)
    if (!shuttingDown) recordDeath(reason)
  }

  function ensureProcess(): HostProcess {
    if (proc) return proc
    let created: HostProcess
    try {
      created = options.fork()
    } catch (error) {
      recordDeath(`spawn failed: ${(error as Error).message}`)
      throw new NativeHostError('unavailable', `native host could not start: ${(error as Error).message}`)
    }
    proc = created
    created.on('message', message => {
      if (!isHostResponse(message)) {
        fail(created, 'malformed reply from native host')
        return
      }
      const entry = pending.get(message.id)
      if (!entry) return // late answer for a request that already timed out
      clearTimeout(entry.timer)
      pending.delete(message.id)
      if (message.ok) entry.resolve(message.value)
      else entry.reject(new NativeHostError(message.kind, message.message))
    })
    created.on('exit', code => fail(created, `native host exited (code ${code})`))
    return created
  }

  return {
    call<T>(op: HostOp, args?: unknown, timeoutMs: number = defaultTimeoutMs): Promise<T> {
      if (shuttingDown) return Promise.reject(new NativeHostError('unavailable', 'native host is shutting down'))
      if (disabled) return Promise.reject(new NativeHostError('unavailable', 'native host disabled after repeated crashes'))
      let target: HostProcess
      try {
        target = ensureProcess()
      } catch (error) {
        return Promise.reject(error)
      }
      const id = nextId++
      return new Promise<T>((resolve, reject) => {
        const timer = setTimeout(() => {
          if (!pending.has(id)) return
          fail(target, `native host request ${op} timed out after ${timeoutMs} ms`)
        }, timeoutMs)
        pending.set(id, { resolve: resolve as (value: unknown) => void, reject, timer, op, owner: target })
        const request: HostRequest = { id, op, args }
        try {
          target.postMessage(request)
        } catch (error) {
          fail(target, `native host postMessage failed: ${(error as Error).message}`)
        }
      })
    },
    shutdown(): void {
      shuttingDown = true
      const current = proc
      proc = null
      if (current) dead.add(current)
      rejectAll(null, 'native host is shutting down')
      try { current?.kill() } catch { /* already gone */ }
    },
    status() {
      return { running: proc !== null, disabled, deaths: deaths.length }
    }
  }
}
