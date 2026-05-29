import axios from 'axios'
import { logEvent } from './appLogger'

const IP_CHECK_URLS = [
  'https://api.ipify.org?format=json',
  'https://ipinfo.io/json',
  'https://api.myip.com'
]

let currentIp: string | null = null
let vpnIp: string | null = null
let isLeak = false
let intervalId: ReturnType<typeof setInterval> | null = null
let ipCallbacks: ((ip: string, isLeak: boolean) => void)[] = []
let checkInterval = 30000 // 30 seconds

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

async function fetchPublicIp(): Promise<string | null> {
  for (const url of IP_CHECK_URLS) {
    try {
      const resp = await axios.get(url, { timeout: 8000 })
      const ip = resp.data?.ip || resp.data?.query || null
      if (ip) {
        logEvent('debug', 'ip-monitor', 'public IP endpoint succeeded', { url, ip })
        return ip
      }
    } catch (err: any) {
      logEvent('debug', 'ip-monitor', 'public IP endpoint failed', { url, error: err.message || String(err) })
    }
  }
  logEvent('warn', 'ip-monitor', 'all public IP endpoints failed')
  return null
}

function notifyCallbacks(ip: string, leak: boolean) {
  ipCallbacks.forEach(cb => cb(ip, leak))
}

function startMonitoring() {
  if (intervalId) return
  // Initial check
  checkIp()
  intervalId = setInterval(checkIp, checkInterval)
}

async function checkIp() {
  const ip = await fetchPublicIp()
  if (suppressed) {
    // Drop the result on the floor — we're inside a stop-tun rollback and
    // anything we'd compute here is a false positive.
    return
  }
  if (ip && ip !== currentIp) {
    currentIp = ip

    if (vpnIp) {
      isLeak = ip !== vpnIp
    }

    notifyCallbacks(ip, isLeak)
  }
}

function stopMonitoring() {
  if (intervalId) {
    clearInterval(intervalId)
    intervalId = null
  }
}

export const ipMonitor = {
  async getCurrentIp(): Promise<{ ip: string | null; isLeak: boolean; vpnIp: string | null }> {
    if (suppressed) {
      // Return last-known state without touching it. Never report leak while
      // suspended — see the suspended-state comment block above.
      return { ip: currentIp, isLeak: false, vpnIp }
    }
    const ip = await fetchPublicIp()
    if (suppressed) {
      // We may have been suspended while the HTTP request was in flight.
      return { ip: currentIp, isLeak: false, vpnIp }
    }
    if (ip) {
      currentIp = ip
      if (vpnIp) isLeak = ip !== vpnIp
    }
    return { ip: currentIp, isLeak, vpnIp }
  },

  /**
   * Force an immediate IP re-check. When `rebaseline` is true, the freshly
   * fetched IP is treated as the new VPN baseline (clearing any stale leak
   * status). Use this after a VPN tunnel is established so the user doesn't
   * see "real IP visible" while routes are still propagating.
   */
  async recheck(rebaseline = false): Promise<{ ip: string | null; isLeak: boolean; vpnIp: string | null }> {
    if (suppressed) {
      return { ip: currentIp, isLeak: false, vpnIp }
    }
    const ip = await fetchPublicIp()
    if (suppressed) {
      return { ip: currentIp, isLeak: false, vpnIp }
    }
    if (ip) {
      currentIp = ip
      if (rebaseline) {
        vpnIp = ip
        isLeak = false
      } else if (vpnIp) {
        isLeak = ip !== vpnIp
      }
      notifyCallbacks(ip, isLeak)
    }
    return { ip: currentIp, isLeak, vpnIp }
  },

  setVpnIp(ip: string) {
    vpnIp = ip
    isLeak = false
    startMonitoring()
  },

  clearVpnIp() {
    vpnIp = null
    isLeak = false
    stopMonitoring()
  },

  setCheckInterval(ms: number) {
    checkInterval = ms
    if (intervalId) {
      stopMonitoring()
      startMonitoring()
    }
  },

  onIpChange(callback: (ip: string, isLeak: boolean) => void) {
    ipCallbacks.push(callback)
  },

  /**
   * Pause leak detection. Existing in-flight HTTP requests are allowed to
   * complete but their results are discarded. While suspended, all public
   * methods return the cached state with `isLeak=false` and notify callbacks
   * are never invoked. Idempotent.
   */
  suspend() {
    if (suppressed) return
    suppressed = true
    logEvent('info', 'ip-monitor', 'leak detection suspended (stop-tun rollback)')
  },

  /**
   * Resume leak detection. Does NOT trigger an immediate re-check — the
   * caller is responsible for that (typically `ipMonitor.recheck(true)` once
   * the new tunnel is up, or simply leaving the periodic timer to fire).
   * Idempotent.
   */
  resume() {
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
