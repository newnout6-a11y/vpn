import { spawn, type ChildProcess } from 'node:child_process'
import { logEvent } from './appLogger'

const PREFLIGHT_TIMEOUT_MS = 5000 // ТЗ-01 §1: Xray config test deadline.
const EXIT_CONFIRMATION_MS = 1000
const OUTPUT_TAIL_BYTES = 64 * 1024
type PendingPreflight = { child: ChildProcess; abort: () => void; isAborted: () => boolean; exited: Promise<void> }
const pending = new Set<PendingPreflight>()

/** Config validation owns its child until exit/close, including after timeout. */
export function runXrayConfigPreflight(exePath: string, runtimeDir: string, configPath: string, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) return Promise.reject(new Error('Xray config validation cancelled'))
  return new Promise<void>((resolve, reject) => {
    const controller = new AbortController()
    let abortError: Error | null = null
    let settled = false
    let exitObserved = false
    let child: ChildProcess
    let stdout = Buffer.alloc(0), stderr = Buffer.alloc(0)
    let truncated = false
    let confirmationTimer: ReturnType<typeof setTimeout> | undefined
    let resolveExit!: () => void
    const exited = new Promise<void>(done => { resolveExit = done })
    const releaseCaller = (error?: Error) => {
      if (settled) return
      settled = true
      clearTimeout(deadline)
      if (confirmationTimer) clearTimeout(confirmationTimer)
      signal?.removeEventListener('abort', cancel)
      if (error) reject(error)
      else resolve()
    }
    const abort = (error: Error) => {
      if (abortError) return
      abortError = error
      if (exitObserved) {
        // The child exited, but inherited stdio can keep close pending.
        child.stdout?.destroy?.()
        child.stderr?.destroy?.()
        releaseCaller(error)
        return
      }
      controller.abort()
      // AbortError means a signal was requested, not that the process exited.
      // Retain ownership if confirmation is missing; stop can retry this child.
      if (!settled) confirmationTimer = setTimeout(() => {
        logEvent('warn', 'xray', 'preflight exit not confirmed', { pendingProcesses: pending.size })
        releaseCaller(new Error('Xray config validation failed: process exit not confirmed'))
      }, EXIT_CONFIRMATION_MS)
    }
    const cancel = () => abort(new Error('Xray config validation cancelled'))
    const deadline = setTimeout(() => abort(new Error('Xray config validation timed out after 5000 ms')), PREFLIGHT_TIMEOUT_MS)
    try {
      child = spawn(exePath, ['run', '-test', '-c', configPath], {
        cwd: runtimeDir, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
        signal: controller.signal, killSignal: 'SIGKILL'
      })
    } catch (error) {
      releaseCaller(error as Error)
      return
    }
    const owned: PendingPreflight = { child, abort: cancel, isAborted: () => controller.signal.aborted, exited }
    pending.add(owned)
    const append = (previous: Buffer, chunk: Buffer | string) => {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
      if (!truncated && previous.length + bytes.length > OUTPUT_TAIL_BYTES) {
        truncated = true
        logEvent('warn', 'xray', 'stderr.truncated', { phase: 'config-preflight', limitBytes: OUTPUT_TAIL_BYTES })
      }
      if (bytes.length >= OUTPUT_TAIL_BYTES) return Buffer.from(bytes.subarray(bytes.length - OUTPUT_TAIL_BYTES))
      const keep = Math.min(previous.length, OUTPUT_TAIL_BYTES - bytes.length)
      return Buffer.concat([previous.subarray(previous.length - keep), bytes])
    }
    child.stdout?.on('data', chunk => { stdout = append(stdout, chunk) })
    child.stderr?.on('data', chunk => { stderr = append(stderr, chunk) })
    child.on('error', error => {
      if (controller.signal.aborted && error.name === 'AbortError') return
      // ENOENT/EACCES with no PID means no process was created.
      if (!child.pid) { pending.delete(owned); resolveExit() }
      releaseCaller(error)
    })
    child.once('exit', () => { exitObserved = true; pending.delete(owned); resolveExit() })
    child.once('close', code => {
      pending.delete(owned)
      resolveExit()
      if (abortError) releaseCaller(abortError)
      else if (code === 0) releaseCaller()
      else releaseCaller(new Error(`xray run -test preflight failed: ${(stderr.length ? stderr : stdout).toString('utf8').trim() || `exit code ${code}`}`))
    })
    signal?.addEventListener('abort', cancel, { once: true })
    // Covers an abort between the initial check and listener registration.
    if (signal?.aborted) cancel()
  })
}

/** Stop retries only ChildProcess handles created by this module, never names/PIDs. */
export async function stopXrayPreflights(): Promise<void> {
  const results = await Promise.allSettled([...pending].map(async owned => {
    const retry = owned.isAborted()
    owned.abort()
    if (retry && pending.has(owned)) {
      try { owned.child.kill('SIGKILL') } catch {}
    }
    let timer: ReturnType<typeof setTimeout> | undefined
    try {
      await Promise.race([owned.exited, new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error('Xray preflight process exit not confirmed')), EXIT_CONFIRMATION_MS)
      })])
    } finally { if (timer) clearTimeout(timer) }
  }))
  const failed = results.find(result => result.status === 'rejected')
  if (failed?.status === 'rejected') throw failed.reason
}
