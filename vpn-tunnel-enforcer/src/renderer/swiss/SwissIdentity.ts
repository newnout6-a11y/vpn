import { useEffect, useState } from 'react'
import { useAppStore } from '../store'
import { SERVER_CHANGED_EVENT } from '../nav'
import type { ServerProfile } from '../../shared/ipc-types'

// Last public IP seen while protection was OFF = the user's real address.
// Memory only: never persisted, gone when the app closes.
let lastHomeIp: string | null = null

/** Real address: the current public IP while disconnected, the last one seen while connected. */
export function useHomeIp(publicIp: string | null, connected: boolean): string | null {
  if (!connected && publicIp) lastHomeIp = publicIp
  return connected ? lastHomeIp : publicIp
}

/** The active server profile, kept fresh on server changes and tunnel state changes. */
export function useActiveProfile(): ServerProfile | null {
  const tunRunning = useAppStore(s => s.tunRunning)
  const [profile, setProfile] = useState<ServerProfile | null>(null)
  useEffect(() => {
    let alive = true
    const load = () => {
      window.electronAPI.serversGetActive()
        .then(active => { if (alive) setProfile(active.profile ?? null) })
        .catch(() => undefined)
    }
    load()
    window.addEventListener(SERVER_CHANGED_EVENT, load)
    return () => {
      alive = false
      window.removeEventListener(SERVER_CHANGED_EVENT, load)
    }
  }, [tunRunning])
  return profile
}
