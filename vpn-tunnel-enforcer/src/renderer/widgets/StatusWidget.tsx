/**
 * StatusWidget — Shows connection status, current profile name, and uptime.
 * Reads tunRunning + tunStartedAt from the store and pulls the active server
 * profile from the server-picker via IPC.
 */

import React, { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { Wifi, WifiOff, Loader2 } from 'lucide-react'
import { useAppStore } from '../store'
import { SERVER_CHANGED_EVENT } from '../nav'

export interface StatusWidgetProps {
  size: 'compact' | 'expanded'
}

function formatUptime(startedAt: number | null): string {
  if (!startedAt) return '—'
  const diff = Math.max(0, Math.floor((Date.now() - startedAt) / 1000))
  const hours = Math.floor(diff / 3600)
  const minutes = Math.floor((diff % 3600) / 60)
  const seconds = diff % 60
  if (hours > 0) return `${hours}h ${minutes}m`
  if (minutes > 0) return `${minutes}m ${seconds}s`
  return `${seconds}s`
}

export const StatusWidget: React.FC<StatusWidgetProps> = ({ size }) => {
  const { t } = useTranslation()
  const tunRunning = useAppStore((s) => s.tunRunning)
  const tunStartedAt = useAppStore((s) => s.tunStartedAt)
  const detecting = useAppStore((s) => s.detecting)

  // Tick every second to update uptime display
  const [, setTick] = useState(0)
  useEffect(() => {
    if (!tunRunning || !tunStartedAt) return
    const interval = setInterval(() => setTick((t) => t + 1), 1000)
    return () => clearInterval(interval)
  }, [tunRunning, tunStartedAt])

  // Pull the active profile name from the server-picker store. We poll on a
  // slow cadence and also listen for the explicit change event so the widget
  // reflects selections made elsewhere in the UI without a page transition.
  const [profileName, setProfileName] = useState<string>(t('dashboard.noProfile'))
  useEffect(() => {
    let cancelled = false
    const refresh = async () => {
      try {
        const { profile } = await window.electronAPI.serversGetActive()
        if (cancelled) return
        setProfileName(profile?.name || t('dashboard.noProfile'))
      } catch {
        if (cancelled) return
        setProfileName(t('dashboard.noProfile'))
      }
    }
    refresh()
    const id = setInterval(refresh, 3000)
    const handler = () => refresh()
    window.addEventListener(SERVER_CHANGED_EVENT, handler)
    return () => {
      cancelled = true
      clearInterval(id)
      window.removeEventListener(SERVER_CHANGED_EVENT, handler)
    }
  }, [t])

  const status = detecting ? 'connecting' : tunRunning ? 'connected' : 'disconnected'

  const statusColor =
    status === 'connected'
      ? 'text-green-500'
      : status === 'connecting'
        ? 'text-yellow-500'
        : 'text-[var(--color-text-secondary)]'

  const statusIcon =
    status === 'connecting' ? (
      <Loader2 size={size === 'compact' ? 18 : 24} className="animate-spin text-yellow-500" />
    ) : status === 'connected' ? (
      <Wifi size={size === 'compact' ? 18 : 24} className="text-green-500" />
    ) : (
      <WifiOff size={size === 'compact' ? 18 : 24} className="text-[var(--color-text-secondary)]" />
    )

  if (size === 'compact') {
    return (
      <div className="flex items-center gap-3">
        {statusIcon}
        <div className="min-w-0 flex-1">
          <p className={`text-sm font-medium ${statusColor}`}>
            {t(`dashboard.${status}`)}
          </p>
          <p className="text-xs text-[var(--color-text-secondary)] truncate">{profileName}</p>
        </div>
        {tunRunning && (
          <span className="text-xs text-[var(--color-text-secondary)] tabular-nums">
            {formatUptime(tunStartedAt)}
          </span>
        )}
      </div>
    )
  }

  // Expanded view
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3">
        {statusIcon}
        <span className={`text-base font-semibold ${statusColor}`}>
          {t(`dashboard.${status}`)}
        </span>
      </div>
      <div className="grid grid-cols-2 gap-2 text-sm">
        <div>
          <p className="text-[var(--color-text-secondary)] text-xs">{t('dashboard.currentProfile')}</p>
          <p className="text-[var(--color-text)] font-medium truncate">{profileName}</p>
        </div>
        <div>
          <p className="text-[var(--color-text-secondary)] text-xs">{t('dashboard.uptime')}</p>
          <p className="text-[var(--color-text)] font-medium tabular-nums">
            {tunRunning ? formatUptime(tunStartedAt) : '—'}
          </p>
        </div>
      </div>
    </div>
  )
}
