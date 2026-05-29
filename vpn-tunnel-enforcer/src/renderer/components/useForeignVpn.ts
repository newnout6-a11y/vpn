import { useCallback, useEffect, useState } from 'react'
import { useAppStore } from '../store'

/**
 * Polls the main process for a foreign VPN/TUN adapter (Happ, WireGuard,
 * OpenVPN, Hiddify, …) while OUR tunnel is OFF.
 *
 * Why this matters for the UI. When another VPN's TUN adapter is up, it
 * captures every TCP-connect we make for latency measurement and answers it
 * locally — even to non-routable test IPs. So all per-server pings collapse
 * to a meaningless ~1-46 ms (the RTT to the foreign tun stack, not to the
 * real servers). The user reading "AE 3 ms, Sweden 45 ms" thinks some
 * servers are great and others slow, when in reality every number is noise.
 *
 * We only poll while our own tunnel is DOWN: when it's UP, the main-process
 * `competingTunDetector` already raises a stronger, route-conflict banner,
 * and the IPC returns null in that case anyway.
 *
 * Returns the foreign adapter descriptor ("happ-tun (172.18.0.1)") or null.
 */
export function useForeignVpn(pollMs = 5000): string | null {
  const tunRunning = useAppStore(s => s.tunRunning)
  const [foreign, setForeign] = useState<string | null>(null)

  const check = useCallback(async () => {
    // While our tunnel is up the main process returns null by design; skip
    // the IPC entirely to avoid flicker and needless work.
    if (tunRunning) {
      setForeign(null)
      return
    }
    try {
      const res = await window.electronAPI.detectForeignVpn()
      setForeign(res?.foreign ?? null)
    } catch {
      // Tolerate missing IPC (older preload) — just report "no foreign VPN".
      setForeign(null)
    }
  }, [tunRunning])

  useEffect(() => {
    check()
    if (tunRunning) return
    const id = setInterval(check, pollMs)
    return () => clearInterval(id)
  }, [check, tunRunning, pollMs])

  return foreign
}

/**
 * Pull a short, human display name out of the raw adapter descriptor.
 * "happ-tun (172.18.0.1)" → "Happ". Falls back to the adapter name when we
 * don't recognise the vendor.
 */
export function foreignVpnFriendlyName(raw: string | null): string | null {
  if (!raw) return null
  const lower = raw.toLowerCase()
  if (lower.includes('happ')) return 'Happ'
  if (lower.includes('hiddify')) return 'Hiddify'
  if (lower.includes('wireguard') || /\bwg\d*\b/.test(lower)) return 'WireGuard'
  if (lower.includes('openvpn') || lower.includes('tap-windows')) return 'OpenVPN'
  if (lower.includes('xray') || lower.includes('v2ray') || lower.includes('singbox')) return 'Xray/V2Ray'
  // Strip the "(ip)" suffix for an unknown adapter so we show just the name.
  const name = raw.replace(/\s*\(.*\)\s*$/, '').trim()
  return name || raw
}
