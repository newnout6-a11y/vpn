import { isIP } from 'net'
import { ipcMain } from 'electron'
import http from 'http'
import https from 'https'
import axios from 'axios'
import { logEvent } from './appLogger'
import { redactSensitiveText } from './vpnProfiles'
import type { PublicIpEvidence, PublicIpVerdict } from '../shared/publicIp'
import { IP_SOCKET_DRAIN_MS, publicIpTransport } from './ipMonitorTransport'

export const IP_CHECK_URLS = [
  // Ordinary OS routing and certificate verification still apply; no local DNS is required.
  'https://1.1.1.1/cdn-cgi/trace',
  'https://api.ipify.org?format=json',
  'https://icanhazip.com',
  'https://api.myip.com'
]

export const noKeepAliveHttpAgent = new http.Agent({ keepAlive: false })
export const noKeepAliveHttpsAgent = new https.Agent({ keepAlive: false })
const IP_WAVE_TIMEOUT_MS = 2000
const readBudget = (timeoutMs?: number) => Number.isFinite(timeoutMs) && timeoutMs! > 0
  ? Math.min(timeoutMs!, IP_WAVE_TIMEOUT_MS) : IP_WAVE_TIMEOUT_MS
export interface PublicIpReadOptions { timeoutMs?: number; signal?: AbortSignal }
interface IpWaveOptions { timeoutMs?: number; family?: 4 | 6 }

let currentIp: string | null = null
let vpnIp: string | null = null
let isLeak = false
let intervalId: ReturnType<typeof setInterval> | null = null
let verdict: PublicIpVerdict = 'not-checked'
let ipCallbacks: ((ip: string, isLeak: boolean, evidence: PublicIpEvidence) => void)[] = []
let checkInterval = 30000 // 30 seconds
let lastSuccessAt = 0
let readGeneration = 0
interface PublicIpRead {
  owner?: () => boolean
  signal?: AbortSignal
  promise: Promise<string | null>
  controller: AbortController
  timeoutMs: number
  family?: 4 | 6
}
const publicIpReads = new Set<PublicIpRead>()
const providerBackoff = new Map<string, number>()

function cancelPublicIpReads(): void {
  readGeneration += 1
  for (const read of publicIpReads.values()) read.controller.abort()
  publicIpReads.clear()
}

// ─── suspended state ──────────────────────────────────────────────────────
// While `suppressed === true`, every public surface that could compute or emit
// a leak verdict short-circuits: no callbacks fire, currentIp is not updated,
// isLeak is not recomputed. This exists to silence the false-positive
// "ОБНАРУЖЕНА УТЕЧКА IP" event that was firing during the user-initiated
// stop-tun rollback. The TUN status flips to 'stopping' before firewall /
// adapter / DNS rollback completes (≈7-9s). During that window an in-flight
// or scheduled `checkIp()` would happily fetch the user's real public IP
// and compare it against the still-cached VPN baseline, screaming "leak"
// at the user even though the user is the one tearing the tunnel down.
// The renderer (and tunController via IPC) is expected to call
// `ipMonitor.suspend()` when the stop begins and `ipMonitor.resume()` once
// the rollback has finished or a new tunnel is established.
let suppressed = false
// A protected profile swap must keep monitoring suspended until the new
// tunnel's public IP has been explicitly adopted as the baseline. `stop()`
// calls `resume()` in its finally block, so a plain boolean was not enough:
// the monitor could wake up in the middle of the stop->start transition.
let resumeDeferred = false

// Serialise concurrent recheck(rebaseline=true) calls. Without this, two
// concurrent callers both fetch the IP, then both write vpnIp — the second
// write wins with a potentially stale value and breaks all future leak checks.
let recheckInFlight: Promise<{ ip: string | null; isLeak: boolean; vpnIp: string | null }> | null = null
let recheckOwner: (() => boolean) | undefined
let recheckOptions: PublicIpReadOptions | undefined
let recheckExpectedIp: string | undefined

let ipMonitorRecoveryCallback: ((source: string) => void) | null = null

export function setIpMonitorRecoveryCallback(cb: ((source: string) => void) | null): void {
  ipMonitorRecoveryCallback = cb
}

export async function fetchPublicIpFrom(url: string, canPublish?: () => boolean, signal?: AbortSignal,
  options: IpWaveOptions & { deferPublication?: boolean } = {}): Promise<string> {
  const started = performance.now(), providerIndex = IP_CHECK_URLS.indexOf(url)
  let outcome = 'failed', code = 'NETWORK', status: number | undefined
  const owned = publicIpTransport(), controller = new AbortController()
  const abort = () => controller.abort()
  signal?.addEventListener('abort', abort, { once: true })
  const timeout = setTimeout(() => { code = 'DEADLINE'; controller.abort() },
    Math.max(1, readBudget(options.timeoutMs) - IP_SOCKET_DRAIN_MS))
  let rejectAbort!: () => void
  const cancelled = new Promise<never>((_resolve, reject) => {
    rejectAbort = () => reject(new Error(code === 'DEADLINE' ? 'IP_DEADLINE' : 'IP_CANCELLED'))
    controller.signal.addEventListener('abort', rejectAbort, { once: true })
  })
  void cancelled.catch(() => undefined)
  try {
    if (signal?.aborted) { controller.abort(); throw new Error('IP_CANCELLED') }
    if ((providerBackoff.get(url) ?? 0) > Date.now()) { outcome = 'backoff'; throw new Error('IP provider backoff active') }
    const resp = await Promise.race([axios.get(url, {
      signal: controller.signal,
      timeout: Math.max(1, readBudget(options.timeoutMs) - IP_SOCKET_DRAIN_MS),
      proxy: false,
      maxRedirects: 0,
      maxContentLength: 4096,
      transport: owned.transport,
      family: options.family,
      responseType: 'text',
      transformResponse: (d) => d,
      headers: { Connection: 'close', 'Cache-Control': 'no-cache' },
      httpAgent: noKeepAliveHttpAgent,
      httpsAgent: noKeepAliveHttpsAgent
    }), cancelled])
    if (signal?.aborted) throw new Error('IP probe cancelled')
    const raw = typeof resp.data === 'string' ? resp.data.trim() : JSON.stringify(resp.data)
    let ip: string | null = null
    if (typeof resp.data === 'object' && resp.data !== null && !Array.isArray(resp.data)) {
      ip = (resp.data as any).ip || (resp.data as any).query || null
    }
    if (!ip && raw.startsWith('{')) {
      try {
        const parsed = JSON.parse(raw)
        ip = parsed?.ip || parsed?.query || null
      } catch {}
    }
    if (!ip) {
      // Check cloudflare cdn-cgi/trace format: ip=1.2.3.4
      const matchTrace = raw.match(/^ip=([0-9a-fA-F:.]+)/m)
      if (matchTrace) {
        ip = matchTrace[1]
      } else if (/^[0-9a-fA-F:.]+$/.test(raw)) {
        // Plain text IP (icanhazip)
        ip = raw
      }
    }
    if (ip && (isIP(ip) === 4 || isIP(ip) === 6) && (!options.family || isIP(ip) === options.family)) {
      await owned.close()
      if (controller.signal.aborted || (canPublish && !canPublish())) throw new Error('IP_CANCELLED')
      outcome = 'succeeded'
      code = 'OK'
      const current = !canPublish || canPublish()
      if (current) logEvent('debug', 'ip-monitor', 'public IP endpoint succeeded', { providerIndex })
      if (current && !options.deferPublication) publishIpHealth()
      return ip
    }
    code = options.family && ip && isIP(ip) !== options.family ? 'IP_FAMILY_MISMATCH' : 'INVALID_IP'
    throw new Error('response did not contain a valid IP')
  } catch (err: any) {
    if (controller.signal.aborted) { outcome = code === 'DEADLINE' ? 'timeout' : 'cancelled'; code = code === 'DEADLINE' ? code : 'CANCELLED' }
    else if (err?.response?.status) { status = err.response.status; code = 'HTTP_STATUS' }
    else if (['ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'ERR_TLS_CERT_ALTNAME_INVALID',
      'CERT_HAS_EXPIRED', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE'].includes(err?.code)) code = err.code
    if (!signal?.aborted && err?.response?.status === 429) {
      const retrySeconds = Number(err.response.headers?.['retry-after'])
      const delayMs = Number.isFinite(retrySeconds) && retrySeconds > 0 ? Math.min(retrySeconds * 1000, 300000) : 60000
      providerBackoff.set(url, Date.now() + delayMs)
    }
    throw err
  } finally {
    clearTimeout(timeout)
    signal?.removeEventListener('abort', abort)
    controller.signal.removeEventListener('abort', rejectAbort)
    try { await owned.close() }
    catch (error) { outcome = 'failed'; code = 'SOCKET_CLOSE_UNCONFIRMED'; throw error }
    finally {
      if (providerIndex >= 0) logEvent('debug', 'ip-monitor', 'public IP provider timing', {
        providerIndex, outcome, code, ...(status ? { status } : {}),
        ...owned.diagnostics(), durationMs: Math.round(performance.now() - started)
      })
    }
  }
}

function publishIpHealth(): void {
  lastSuccessAt = Date.now()
  try { ipMonitorRecoveryCallback?.('ipMonitor') } catch {}
}

export async function fetchPublicIp(canPublish?: () => boolean, signal?: AbortSignal, options: IpWaveOptions = {}): Promise<string | null> {
  if (signal?.aborted || (canPublish && !canPublish())) return null
  const timeoutMs = readBudget(options.timeoutMs)
  const existing = [...publicIpReads].find(read => read.owner === canPublish && read.signal === signal
    && read.timeoutMs === timeoutMs && read.family === options.family)
  if (existing) return existing.promise
  const controller = new AbortController(), generation = readGeneration
  const onAbort = () => controller.abort()
  signal?.addEventListener('abort', onAbort, { once: true })
  const isCurrent = () => generation === readGeneration && !controller.signal.aborted && (!canPublish || canPublish())
  let read!: PublicIpRead
  const promise = (async () => {
    const providers = IP_CHECK_URLS.map(url => fetchPublicIpFrom(url, isCurrent, controller.signal,
      { timeoutMs, family: options.family, deferPublication: true }))
    try {
      const ip = await Promise.any(providers)
      const current = isCurrent()
      controller.abort()
      const settled = await Promise.allSettled(providers)
      if (!current || signal?.aborted || generation !== readGeneration || (canPublish && !canPublish())
        || settled.some(result => result.status === 'rejected' && result.reason?.message === 'IP_SOCKET_CLOSE_UNCONFIRMED')) return null
      publishIpHealth()
      return ip
    } catch {
      if (isCurrent()) logEvent('warn', 'ip-monitor', 'all public IP endpoints failed')
      return null
    } finally { controller.abort(); await Promise.allSettled(providers) }
  })().finally(() => {
    signal?.removeEventListener('abort', onAbort)
    publicIpReads.delete(read)
  })
  read = { owner: canPublish, signal, promise, controller, timeoutMs, family: options.family }
  publicIpReads.add(read)
  return promise
}

function notifyCallbacks(ip: string, leak: boolean) {
  ipCallbacks.forEach(cb => cb(ip, leak, { vpnIp, verdict }))
}

function observeIp(ip: string): void {
  currentIp = ip
  // A different VPN egress (rotation, anycast, split routes) is inconclusive.
  // Actual leak alarms come from the independent physical-adapter self-test.
  isLeak = false
  verdict = vpnIp ? (ip === vpnIp ? 'passed' : 'indeterminate') : 'not-checked'
}

function startMonitoring(initialCheck = true) {
  if (intervalId) return
  // Initial check
  if (initialCheck) void checkIp()
  intervalId = setInterval(checkIp, checkInterval)
}

async function checkIp() {
  if (suppressed) return
  const generation = readGeneration
  const ip = await fetchPublicIp()
  if (suppressed || generation !== readGeneration) {
    // Drop the result on the floor — we're inside a stop-tun rollback and
    // anything we'd compute here is a false positive.
    return
  }
  const previousIp = currentIp, previousVerdict = verdict
  if (ip) observeIp(ip)
  else verdict = 'not-checked'
  if (currentIp && (currentIp !== previousIp || verdict !== previousVerdict)) notifyCallbacks(currentIp, isLeak)
}

function stopMonitoring() {
  if (intervalId) {
    clearInterval(intervalId)
    intervalId = null
  }
}

export const ipMonitor = {
  startMonitoring,
  stopMonitoring,
  setRecoveryCallback: setIpMonitorRecoveryCallback,
  getEvidence(): PublicIpEvidence { return { vpnIp, verdict } },
  invalidateVpnIpBaseline() {
    vpnIp = null
    isLeak = false
    verdict = 'not-checked'
    if (currentIp) notifyCallbacks(currentIp, false)
  },
  async getCurrentIp(canPublish?: () => boolean, signal?: AbortSignal): Promise<{ ip: string | null; isLeak: boolean; vpnIp: string | null }> {
    if (signal?.aborted || (canPublish && !canPublish())) return { ip: currentIp, isLeak, vpnIp }
    if (suppressed) {
      // Return last-known state without touching it. Never report leak while
      // suspended — see the suspended-state comment block above.
      return { ip: currentIp, isLeak: false, vpnIp }
    }
    const generation = readGeneration
    const ip = await fetchPublicIp(canPublish, signal)
    if (generation !== readGeneration) return { ip: currentIp, isLeak, vpnIp }
    if (signal?.aborted || (canPublish && !canPublish())) return { ip: currentIp, isLeak, vpnIp }
    if (suppressed) {
      // We may have been suspended while the HTTP request was in flight.
      return { ip: currentIp, isLeak: false, vpnIp }
    }
    if (ip) observeIp(ip)
    else verdict = 'not-checked'
    return { ip: currentIp, isLeak, vpnIp }
  },

  /** Probe the network during a protected transition without changing the
   * cached verdict or notifying the renderer. */
  async probeCurrentIp(): Promise<string | null> {
    return fetchPublicIp()
  },

  /**
   * Force an immediate IP re-check. When `rebaseline` is true, the freshly
   * fetched IP is treated as the new VPN baseline (clearing any stale leak
   * status). Use this after a VPN tunnel is established so the user doesn't
   * see "real IP visible" while routes are still propagating.
   *
   * Concurrent rebaseline calls are serialised — only one fetch runs at a
   * time so two callers racing to set vpnIp don't overwrite each other.
   */
  async recheck(
    rebaseline = false,
    canPublish?: () => boolean,
    expectedIp?: string,
    options?: PublicIpReadOptions
  ): Promise<{ ip: string | null; isLeak: boolean; vpnIp: string | null }> {
    if (options?.signal?.aborted || (canPublish && !canPublish())) return { ip: currentIp, isLeak, vpnIp }
    if (suppressed && !rebaseline) {
      return { ip: currentIp, isLeak: false, vpnIp }
    }
    if (rebaseline && recheckInFlight) {
      if (recheckOwner === canPublish && recheckExpectedIp === expectedIp
        && recheckOptions?.signal === options?.signal && recheckOptions?.timeoutMs === options?.timeoutMs) return recheckInFlight
      // Different sessions never share a network sample. Wait for the older
      // owner, then take a fresh sample if this caller is still current.
      const began = performance.now(), budget = readBudget(options?.timeoutMs)
      let timer: ReturnType<typeof setTimeout> | undefined, abort!: () => void
      const expired = new Promise<false>(resolve => {
        abort = () => resolve(false)
        timer = setTimeout(abort, budget)
        options?.signal?.addEventListener('abort', abort, { once: true })
      })
      let settled: boolean
      try { settled = await Promise.race([recheckInFlight.then(() => true, () => true), expired]) }
      finally { clearTimeout(timer); options?.signal?.removeEventListener('abort', abort) }
      const remainingMs = budget - (performance.now() - began)
      if (!settled || options?.signal?.aborted || remainingMs <= IP_SOCKET_DRAIN_MS) return { ip: null, isLeak, vpnIp }
      return ipMonitor.recheck(rebaseline, canPublish, expectedIp, { ...options, timeoutMs: remainingMs })
    }

    const doRecheck = async (): Promise<{ ip: string | null; isLeak: boolean; vpnIp: string | null }> => {
      const generation = readGeneration
      const family = expectedIp ? isIP(expectedIp) : 0
      const ip = await fetchPublicIp(canPublish, options?.signal, { timeoutMs: options?.timeoutMs, family: family === 4 || family === 6 ? family : undefined })
      if (generation !== readGeneration) return { ip: rebaseline ? null : currentIp, isLeak, vpnIp }
      if (options?.signal?.aborted || (canPublish && !canPublish())) return { ip: rebaseline ? null : currentIp, isLeak, vpnIp }
      if (suppressed && !rebaseline) {
        return { ip: currentIp, isLeak: false, vpnIp }
      }
      // A baseline requires a fresh successful sample. Preserve cached state
      // on provider failure, but do not present it as a successful rebaseline.
      if (!ip) {
        verdict = 'not-checked'
        if (!suppressed && currentIp) notifyCallbacks(currentIp, isLeak)
        return { ip: rebaseline ? null : currentIp, isLeak, vpnIp }
      }
      if (ip) {
        currentIp = ip
        if (rebaseline) {
          if (expectedIp && ip !== expectedIp) {
            logEvent('warn', 'ip-monitor', 'rebaseline rejected due to mismatch with expected baseline IP', {
              expectedIp: redactSensitiveText(expectedIp),
              actualIp: redactSensitiveText(ip)
            })
            verdict = 'indeterminate'
            isLeak = false
            return { ip, isLeak: false, vpnIp }
          }
          vpnIp = ip
          isLeak = false
          verdict = 'passed'
          startMonitoring(false)
        } else observeIp(ip)
        // An explicit rebaseline is the end of a protected transition. It is
        // safe to publish the clean result even while the deferred resume is
        // still held; the caller releases the monitor immediately afterwards.
        if (!suppressed || rebaseline) notifyCallbacks(ip, isLeak)
      }
      return { ip: currentIp, isLeak, vpnIp }
    }

    if (rebaseline) {
      recheckOwner = canPublish
      recheckOptions = options
      recheckExpectedIp = expectedIp
      recheckInFlight = doRecheck().finally(() => { recheckInFlight = null; recheckOwner = undefined; recheckOptions = undefined; recheckExpectedIp = undefined })
      return recheckInFlight
    }
    return doRecheck()
  },

  setVpnIp(ip: string) {
    vpnIp = ip
    isLeak = false
    verdict = currentIp === ip ? 'passed' : 'not-checked'
    startMonitoring()
  },

  clearVpnIp() {
    cancelPublicIpReads()
    vpnIp = null
    isLeak = false
    verdict = 'not-checked'
    stopMonitoring()
  },

  setCheckInterval(ms: number) {
    checkInterval = ms
    if (intervalId) {
      stopMonitoring()
      startMonitoring()
    }
  },

  onIpChange(callback: (ip: string, isLeak: boolean, evidence: PublicIpEvidence) => void) {
    ipCallbacks.push(callback)
  },

  getLastSuccessAt() {
    return lastSuccessAt
  },

  /**
   * Pause leak detection. Abort in-flight provider waves and discard late
   * results even if a provider ignores cancellation. While suspended, public
   * methods return the cached state with `isLeak=false` and notify callbacks
   * are never invoked. Idempotent.
   */
  suspend() {
    if (suppressed) return
    suppressed = true
    cancelPublicIpReads()
    logEvent('info', 'ip-monitor', 'leak detection suspended (stop-tun rollback)')
  },

  /** Hold a later resume until the caller has installed a fresh VPN baseline. */
  deferResume() {
    cancelPublicIpReads()
    resumeDeferred = true
    suppressed = true
    logEvent('info', 'ip-monitor', 'leak detection resume deferred (protected profile switch)')
  },

  releaseDeferredResume() {
    resumeDeferred = false
    if (suppressed) {
      suppressed = false
      logEvent('info', 'ip-monitor', 'deferred leak detection resume released')
    }
  },

  /**
   * Resume leak detection. Does NOT trigger an immediate re-check — the
   * caller is responsible for that (typically `ipMonitor.recheck(true)` once
   * the new tunnel is up, or simply leaving the periodic timer to fire).
   * Idempotent.
   */
  resume() {
    if (resumeDeferred) {
      logEvent('debug', 'ip-monitor', 'leak detection resume ignored while protected profile switch is active')
      return
    }
    if (!suppressed) return
    suppressed = false
    logEvent('info', 'ip-monitor', 'leak detection resumed')
  }
}

/** Called by main only after the process-wide IPC boundary is installed. */
export function registerIpMonitorIpcHandlers(): void {
  ipcMain.handle('ip-monitor:suspend', async () => { ipMonitor.suspend(); return { ok: true as const } })
  ipcMain.handle('ip-monitor:resume', async () => { ipMonitor.resume(); return { ok: true as const } })
}
