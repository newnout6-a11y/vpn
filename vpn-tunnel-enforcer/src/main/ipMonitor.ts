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
  if (ip && ip !== currentIp) {
    const prevIp = currentIp
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
    const ip = await fetchPublicIp()
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
    const ip = await fetchPublicIp()
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
  }
}
