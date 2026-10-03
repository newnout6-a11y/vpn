import { isIP } from 'net'
import axios from 'axios'
import { logEvent } from './appLogger'
import type { PublicIpEvidence, PublicIpVerdict } from '../shared/publicIp'

export const IP_CHECK_URLS = [
  'https://cloudflare.com/cdn-cgi/trace',
  'https://api.ipify.org?format=json',
  'https://icanhazip.com',
  'https://api.myip.com'
]

let currentIp: string | null = null
let vpnIp: string | null = null
let isLeak = false
let intervalId: ReturnType<typeof setInterval> | null = null
let verdict: PublicIpVerdict = 'not-checked'
let ipCallbacks: ((ip: string, isLeak: boolean, evidence: PublicIpEvidence) => void)[] = []
let checkInterval = 30000 // 30 seconds
let lastSuccessAt = 0
let readGeneration = 0
const publicIpReads = new Map<(() => boolean) | undefined, { promise: Promise<string | null>; controller: AbortController }>()
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

let ipMonitorRecoveryCallback: ((source: string) => void) | null = null

export function setIpMonitorRecoveryCallback(cb: ((source: string) => void) | null): void {
  ipMonitorRecoveryCallback = cb
}

export async function fetchPublicIpFrom(url: string, canPublish?: () => boolean, signal?: AbortSignal): Promise<string> {
  try {
    if (signal?.aborted) throw new Error('IP probe cancelled')
    if ((providerBackoff.get(url) ?? 0) > Date.now()) throw new Error('IP provider backoff active')
    const resp = await axios.get(url, {
      signal,
      timeout: 10000,
      responseType: 'text',
      transformResponse: (d) => d
    })
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
    if (ip && (isIP(ip) === 4 || isIP(ip) === 6)) {
      const current = !canPublish || canPublish()
      if (current) lastSuccessAt = Date.now()
      if (current) logEvent('debug', 'ip-monitor', 'public IP endpoint succeeded', { url, ip })
      if (current && ipMonitorRecoveryCallback) {
        try {
          ipMonitorRecoveryCallback('ipMonitor')
        } catch {}
      }
      return ip
    }
    throw new Error('response did not contain a valid IP')
  } catch (err: any) {
    if (!signal?.aborted && err?.response?.status === 429) {
      const retrySeconds = Number(err.response.headers?.['retry-after'])
      const delayMs = Number.isFinite(retrySeconds) && retrySeconds > 0 ? Math.min(retrySeconds * 1000, 300000) : 60000
      providerBackoff.set(url, Date.now() + delayMs)
    }
    if (!signal?.aborted) logEvent('debug', 'ip-monitor', 'public IP endpoint failed', { url, error: err.message || String(err) })
    throw err
  }
}

export async function fetchPublicIp(canPublish?: () => boolean): Promise<string | null> {
  if (canPublish && !canPublish()) return null
  const existing = publicIpReads.get(canPublish)
  if (existing) return existing.promise
  const controller = new AbortController(), generation = readGeneration
  const isCurrent = () => generation === readGeneration && !controller.signal.aborted && (!canPublish || canPublish())
  const promise = (async () => {
    try {
      const ip = await Promise.any(IP_CHECK_URLS.map(url => fetchPublicIpFrom(url, isCurrent, controller.signal)))
      return isCurrent() ? ip : null
    } catch {
      if (isCurrent()) logEvent('warn', 'ip-monitor', 'all public IP endpoints failed')
      return null
    } finally { controller.abort() }
  })().finally(() => {
    if (publicIpReads.get(canPublish)?.controller === controller) publicIpReads.delete(canPublish)
  })
  publicIpReads.set(canPublish, { promise, controller })
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
  async getCurrentIp(canPublish?: () => boolean): Promise<{ ip: string | null; isLeak: boolean; vpnIp: string | null }> {
    if (canPublish && !canPublish()) return { ip: currentIp, isLeak, vpnIp }
    if (suppressed) {
      // Return last-known state without touching it. Never report leak while
      // suspended — see the suspended-state comment block above.
      return { ip: currentIp, isLeak: false, vpnIp }
    }
    const generation = readGeneration
    const ip = await fetchPublicIp(canPublish)
    if (generation !== readGeneration) return { ip: currentIp, isLeak, vpnIp }
    if (canPublish && !canPublish()) return { ip: currentIp, isLeak, vpnIp }
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
  async recheck(rebaseline = false, canPublish?: () => boolean): Promise<{ ip: string | null; isLeak: boolean; vpnIp: string | null }> {
    if (canPublish && !canPublish()) return { ip: currentIp, isLeak, vpnIp }
    if (suppressed && !rebaseline) {
      return { ip: currentIp, isLeak: false, vpnIp }
    }
    if (rebaseline && recheckInFlight) {
      if (recheckOwner === canPublish) return recheckInFlight
      // Different sessions never share a network sample. Wait for the older
      // owner, then take a fresh sample if this caller is still current.
      await recheckInFlight.catch(() => undefined)
      return ipMonitor.recheck(rebaseline, canPublish)
    }

    const doRecheck = async (): Promise<{ ip: string | null; isLeak: boolean; vpnIp: string | null }> => {
      const generation = readGeneration
      const ip = await fetchPublicIp(canPublish)
      if (generation !== readGeneration) return { ip: rebaseline ? null : currentIp, isLeak, vpnIp }
      if (canPublish && !canPublish()) return { ip: currentIp, isLeak, vpnIp }
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
      recheckInFlight = doRecheck().finally(() => { recheckInFlight = null; recheckOwner = undefined })
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

// ─── IPC self-registration ────────────────────────────────────────────────
// The renderer needs to flip suspend/resume the moment the TUN status
// transitions to 'stopping' (before rollback) and back when status returns
// to 'running' / 'stopped'. We can't add bridge methods to preload from
// here (file ownership), so we expose the bare ipcMain channels and rely
// on the renderer calling them through whatever bridge the orchestrator
// wires up later. The renderer also has a defense-in-depth `stoppingNow`
// flag that drops leak events client-side, so even without an IPC bridge
// the false-positive disappears.
function registerIpMonitorIpcHandlers() {
  // Avoid double-registration if this module is imported twice in tests.
  // ipcMain.handle throws on duplicate channel names.
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { ipcMain } = require('electron') as typeof import('electron')
    if (!ipcMain) return
    ipcMain.handle('ip-monitor:suspend', async () => {
      ipMonitor.suspend()
      return { ok: true }
    })
    ipcMain.handle('ip-monitor:resume', async () => {
      ipMonitor.resume()
      return { ok: true }
    })
  } catch (err) {
    logEvent('debug', 'ip-monitor', 'IPC self-registration skipped', {
      error: (err as Error)?.message
    })
  }
}

// Self-register on import when running inside the Electron main process.
// `process.type === 'browser'` is Electron's marker for the main process;
// renderer processes report 'renderer' and unit tests have no `process.type`.
if (typeof process !== 'undefined' && (process as any).type === 'browser') {
  registerIpMonitorIpcHandlers()
}
