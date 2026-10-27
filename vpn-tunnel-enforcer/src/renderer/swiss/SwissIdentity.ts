import { useEffect, useRef, useState } from 'react'
import { useAppStore } from '../store'
import { SERVER_CHANGED_EVENT } from '../nav'
import type { ServerProfile } from '../../shared/ipc-types'

/** Fired by the servers panel after a ping: detail = { id, ms } for one server, or {} after "ping all". */
export const SWISS_PING_EVENT = 'vpnte:swiss-ping'
export type SwissPingDetail = { id?: string; ms?: number | null }

// Memory only: never persisted, gone when the app closes.
let lastHomeIp: string | null = null
// Every address seen as the exit while protected; never mistaken for the home IP.
const exitIps = new Set<string>()

/**
 * The user's real address. Captured only when the connection is settled OFF
 * (no connect/disconnect/switch in flight) and the address was never seen as
 * an exit while protected, so a stale VPN IP right after disconnect is ignored.
 * A confirmed leak while protected is the real address too.
 */
export function useHomeIp(connected: boolean): string | null {
  const publicIp = useAppStore(s => s.publicIp)
  const vpnIp = useAppStore(s => s.vpnIp)
  const isLeak = useAppStore(s => s.isLeak)
  const busy = useAppStore(s => s.connectionBusy)
  const switching = useAppStore(s => s.serverSwitchingName)
  const [home, setHome] = useState<string | null>(lastHomeIp)

  useEffect(() => {
    if (vpnIp) exitIps.add(vpnIp)
    if (!publicIp) return
    if (connected && !isLeak) {
      exitIps.add(publicIp)
      return
    }
    const settledOff = !connected && !busy && !switching
    const leaking = connected && isLeak
    if ((settledOff || leaking) && publicIp !== vpnIp && !exitIps.has(publicIp)) {
      lastHomeIp = publicIp
      setHome(publicIp)
    }
  }, [publicIp, vpnIp, isLeak, busy, switching, connected])

  return home
}

/** The active server profile, kept fresh on server changes, tunnel state changes and panel pings. */
export function useActiveProfile(): ServerProfile | null {
  const tunRunning = useAppStore(s => s.tunRunning)
  const [profile, setProfile] = useState<ServerProfile | null>(null)
  const seq = useRef(0)
  useEffect(() => {
    const load = () => {
      const mine = ++seq.current
      window.electronAPI.serversGetActive()
        .then(active => { if (mine === seq.current) setProfile(active.profile ?? null) })
        .catch(() => undefined)
    }
    const onPing = (e: Event) => {
      const detail = (e as CustomEvent<SwissPingDetail>).detail ?? {}
      if (detail.id === undefined) {
        load()
        return
      }
      const ms = detail.ms ?? null
      setProfile(p => (p && p.id === detail.id ? { ...p, ping: ms } : p))
    }
    load()
    window.addEventListener(SERVER_CHANGED_EVENT, load)
    window.addEventListener(SWISS_PING_EVENT, onPing)
    return () => {
      seq.current++
      window.removeEventListener(SERVER_CHANGED_EVENT, load)
      window.removeEventListener(SWISS_PING_EVENT, onPing)
    }
  }, [tunRunning])
  return profile
}
