import { spawn, type ChildProcess } from 'child_process'
import { StringDecoder } from 'string_decoder'
import { resolve } from 'path'
import { isProcessElevated } from './admin'
import { logEvent } from './appLogger'
import { RECOVERY_MAX_BYTES, recoveryWorkerScript, validateRecoveryRequest, type RecoveryRequest } from './recoveryPsProtocol'

export class RecoveryWorkerError extends Error {
  constructor(public readonly code: 'unavailable' | 'closed' | 'busy' | 'timeout' | 'exited' | 'protocol' | 'rejected', message: string) {
    super(message)
    this.name = 'RecoveryWorkerError'
  }
}
interface Job {
  id: number
  request: RecoveryRequest
  timeoutMs: number
  resolve: (value: string) => void
  reject: (error: Error) => void
  timer?: ReturnType<typeof setTimeout>
}
const MAX_FRAME_BYTES = RECOVERY_MAX_BYTES * 12 + 4096 // JSON escaping + base64; bounded even with no newline.
const MAX_QUEUE = 8

/** One command in flight; no caller completion on kill request alone (AT-02-005). */
export class RecoveryPsWorker {
  private proc: ChildProcess | null = null
  private queue: Job[] = []
  private active: Job | null = null
  private nextId = 0
  private accepting = true
  private failure: Error | null = null
  private readyResolve!: () => void
  private readyReject!: (error: Error) => void
  private closeResolve!: () => void
  private ready = new Promise<void>((resolve, reject) => { this.readyResolve = resolve; this.readyReject = reject })
  private closed = new Promise<void>(resolve => { this.closeResolve = resolve })
  private isReady = false
  private finished = false
  private startupTimer?: ReturnType<typeof setTimeout>
  private idleExitTimer?: ReturnType<typeof setTimeout>
  private exitSent = false

  constructor(public readonly programData: string, spawnProcess: typeof spawn = spawn) {
    this.ready.catch(() => undefined)
    const env = { ...process.env }
    // Do not inherit PowerShell 7 module paths into Windows PowerShell 5.1.
    for (const key of Object.keys(env)) if (key.toLowerCase() === 'psmodulepath') delete env[key]
    const decoder = new StringDecoder('utf8')
    let buffer = ''
    try {
      const proc = spawnProcess('powershell.exe', ['-NoProfile', '-NoLogo', '-NonInteractive', '-EncodedCommand',
        Buffer.from(recoveryWorkerScript(programData), 'utf16le').toString('base64')], { env, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] })
      this.proc = proc
      // Register lifetime listeners before any IO or first command.
      proc.once('error', () => {
        if (!proc.pid) this.finish(new RecoveryWorkerError('unavailable', 'Recovery worker could not be spawned'))
        else this.fail(new RecoveryWorkerError('exited', 'Recovery worker process error'))
      })
      proc.once('close', () => this.finish(this.failure ?? new RecoveryWorkerError('exited', 'Recovery worker exited')))
      proc.stdin?.on('error', () => this.fail(new RecoveryWorkerError('exited', 'Recovery worker input failed')))
      proc.stderr?.on('data', () => { /* continuously drain; payloads/paths never enter logs */ })
      proc.stdout?.on('data', (chunk: Buffer) => {
        if (this.finished || this.failure) return
        buffer += decoder.write(chunk)
        if (Buffer.byteLength(buffer, 'utf8') > MAX_FRAME_BYTES) {
          this.fail(new RecoveryWorkerError('protocol', 'Recovery worker output exceeds limit'))
          return
        }
        let end: number
        while ((end = buffer.indexOf('\n')) >= 0 && !this.failure) {
          const line = buffer.slice(0, end).replace(/^\uFEFF/, '').trim()
          buffer = buffer.slice(end + 1)
          if (line) this.receive(line)
        }
      })
      this.startupTimer = setTimeout(() => this.fail(new RecoveryWorkerError('timeout', 'Recovery worker startup timed out')), 15000)
    } catch {
      this.finish(new RecoveryWorkerError('unavailable', 'Recovery worker could not be spawned'))
    }
  }

  private receive(line: string): void {
    let response: { id: number; ok: boolean; value?: string; error?: string }
    try { response = JSON.parse(line) } catch { this.fail(new RecoveryWorkerError('protocol', 'Invalid recovery worker response')); return }
    if (!response || !Number.isSafeInteger(response.id) || typeof response.ok !== 'boolean') {
      this.fail(new RecoveryWorkerError('protocol', 'Invalid recovery worker envelope')); return
    }
    if (!this.isReady) {
      if (response.id !== 0 || !response.ok || response.value !== 'RECOVERY_WORKER_READY') {
        this.fail(new RecoveryWorkerError('protocol', 'Recovery worker readiness not confirmed')); return
      }
      clearTimeout(this.startupTimer)
      this.isReady = true
      this.readyResolve()
      return
    }
    const job = this.active
    if (!job || response.id !== job.id || (response.ok ? typeof response.value !== 'string' || Buffer.byteLength(response.value, 'utf8') > RECOVERY_MAX_BYTES * 2 : typeof response.error !== 'string')) {
      this.fail(new RecoveryWorkerError('protocol', 'Recovery worker response does not match active operation')); return
    }
    clearTimeout(job.timer)
    this.active = null
    if (response.ok) job.resolve(response.value!)
    else job.reject(new RecoveryWorkerError('rejected', response.error!.slice(0, 1024)))
    this.pump()
  }

  private finish(error: Error): void {
    if (this.finished) return
    this.finished = true
    this.failure ??= error
    this.accepting = false
    this.proc = null
    clearTimeout(this.startupTimer)
    clearTimeout(this.idleExitTimer)
    this.readyReject(error)
    if (this.active) { clearTimeout(this.active.timer); this.active.reject(error); this.active = null }
    for (const job of this.queue.splice(0)) job.reject(error)
    this.closeResolve()
  }

  private fail(error: Error): void {
    if (this.failure || this.finished) return
    this.failure = error
    this.accepting = false
    // Keep all promises owned until 'close'; .killed is not proof of exit.
    try { this.proc?.kill() } catch { /* keep ownership; a close event is still required */ }
  }

  async execute(request: RecoveryRequest, timeoutMs = 15000): Promise<string> {
    validateRecoveryRequest(request)
    const ownedRequest = { ...request }
    if (!Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000) throw new Error('Invalid recovery worker deadline')
    if (!this.accepting) throw this.failure ?? new RecoveryWorkerError('closed', 'Recovery worker admission is closed')
    await this.ready
    if (!this.accepting) throw this.failure ?? new RecoveryWorkerError('closed', 'Recovery worker admission is closed')
    if (this.queue.length + (this.active ? 1 : 0) >= MAX_QUEUE) throw new RecoveryWorkerError('busy', 'Recovery worker queue is full')
    return new Promise((resolve, reject) => {
      // Copy only validated fields so later caller mutation cannot change dispatch.
      this.queue.push({ id: ++this.nextId, request: ownedRequest, timeoutMs, resolve, reject })
      this.pump()
    })
  }

  private pump(): void {
    if (this.active || this.failure || this.finished) return
    const job = this.queue.shift()
    if (!job) {
      if (!this.accepting && !this.exitSent) {
        this.exitSent = true
        // No active command remains; idle exit can be forced without interrupting
        // native recovery. Completion still waits for the actual close event.
        this.idleExitTimer = setTimeout(() => { try { this.proc?.kill() } catch {} }, 1000)
        try { this.proc?.stdin?.end('__EXIT__\n') }
        catch { this.fail(new RecoveryWorkerError('exited', 'Recovery worker shutdown input failed')) }
      }
      return
    }
    this.active = job
    job.timer = setTimeout(() => this.fail(new RecoveryWorkerError('timeout', 'Recovery operation timed out; worker exit required')), job.timeoutMs)
    try { this.proc!.stdin!.write(JSON.stringify({ id: job.id, request: job.request }) + '\n') }
    catch { this.fail(new RecoveryWorkerError('exited', 'Recovery operation dispatch failed')) }
  }

  async stop(): Promise<void> {
    this.accepting = false
    await this.ready.catch(() => undefined)
    this.pump() // settle admitted work before terminating this process
    await this.closed
  }
  get hasExited(): boolean { return this.finished }
}

let worker: RecoveryPsWorker | null = null
let starting: Promise<RecoveryPsWorker> | null = null
let admissionClosed = false
async function getWorker(): Promise<RecoveryPsWorker> {
  if (admissionClosed) throw new RecoveryWorkerError('closed', 'Recovery shutdown has closed admission')
  if (worker?.hasExited) worker = null
  if (worker) {
    if (resolve(worker.programData).toLowerCase() !== resolve(process.env.ProgramData || 'C:\\ProgramData').toLowerCase()) throw new RecoveryWorkerError('rejected', 'Recovery ProgramData changed during worker lifetime')
    return worker
  }
  if (starting) return starting
  starting = (async () => {
    if (process.platform !== 'win32' || !(await isProcessElevated())) throw new RecoveryWorkerError('unavailable', 'Recovery worker requires elevated Windows main')
    if (admissionClosed) throw new RecoveryWorkerError('closed', 'Recovery shutdown has closed admission')
    worker = new RecoveryPsWorker(process.env.ProgramData || 'C:\\ProgramData')
    return worker
  })()
  try { return await starting } finally { starting = null }
}
export async function executeRecoveryOperation(request: RecoveryRequest, timeoutMs = 15000): Promise<string> {
  validateRecoveryRequest(request)
  if (!Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000) throw new Error('Invalid recovery worker deadline')
  const started = performance.now()
  try { return await (await getWorker()).execute(request, timeoutMs) }
  finally { logEvent('debug', 'recovery-worker', 'operation timing', { operation: request.op, durationMs: Math.round(performance.now() - started) }) }
}
export async function warmRecoveryPsWorker(): Promise<void> {
  const started = performance.now()
  try { await executeRecoveryOperation({ op: 'warmup' }) }
  catch { logEvent('warn', 'recovery-worker', 'read-only module warm-up unavailable') }
  finally { logEvent('debug', 'recovery-worker', 'warm-up timing', { durationMs: Math.round(performance.now() - started) }) }
}
export async function stopRecoveryPsWorker(): Promise<void> {
  admissionClosed = true
  if (starting) await starting.catch(() => undefined)
  await worker?.stop()
  worker = null
}
