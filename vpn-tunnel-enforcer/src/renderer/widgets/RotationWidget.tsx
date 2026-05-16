/**
 * RotationWidget — Shows current rotation profile and countdown to next rotation.
 * Will read from IPC later.
 */

import React, { useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { RefreshCw } from 'lucide-react'

export interface RotationWidgetProps {
  size: 'compact' | 'expanded'
}

interface RotationInfo {
  enabled: boolean
  currentProfileName: string
  nextRotationAt: number | null
  intervalMinutes: number
  order: 'sequential' | 'random'
}

function formatCountdown(targetMs: number | null): string {
  if (!targetMs) return '—'
  const diff = Math.max(0, targetMs - Date.now())
  const minutes = Math.floor(diff / 60_000)
  const seconds = Math.floor((diff % 60_000) / 1000)
  if (minutes > 60) return `${Math.floor(minutes / 60)}h ${minutes % 60}m`
  if (minutes > 0) return `${minutes}m ${seconds}s`
  return `${seconds}s`
}

export const RotationWidget: React.FC<RotationWidgetProps> = ({ size }) => {
  const { t } = useTranslation()
  const [rotation, setRotation] = useState<RotationInfo | null>(null)
  const [, setTick] = useState(0)

  // Attempt to fetch rotation config from IPC
  useEffect(() => {
    const fetchRotation = async () => {
      try {
        const api = (window as any).electronAPI
        if (api?.rotationGetConfig) {
          const config = await api.rotationGetConfig()
          if (config) {
            // Resolve current profile name from servers list
            let profileName = 'Unknown'
            if (config.profileIds?.length > 0 && api.serversList) {
              try {
                const profiles = await api.serversList()
                const currentId = config.profileIds[config.currentIndex]
                const found = profiles.find((p: any) => p.id === currentId)
                if (found) profileName = found.name
              } catch {
                // fallback
              }
            }
            setRotation({
              enabled: config.enabled,
              currentProfileName: profileName,
              nextRotationAt: config.nextRotationAt,
              intervalMinutes: config.intervalMinutes,
              order: config.order
            })
          }
        }
      } catch {
        // IPC not yet wired
      }
    }
    fetchRotation()
    const interval = setInterval(fetchRotation, 10_000)
    return () => clearInterval(interval)
  }, [])

  // Tick every second for countdown
  useEffect(() => {
    if (!rotation?.nextRotationAt) return
    const interval = setInterval(() => setTick((t) => t + 1), 1000)
    return () => clearInterval(interval)
  }, [rotation?.nextRotationAt])

  if (!rotation || !rotation.enabled) {
    if (size === 'compact') {
      return (
        <div className="flex items-center gap-3">
          <RefreshCw size={18} className="text-[var(--color-text-secondary)]" />
          <p className="text-sm text-[var(--color-text-secondary)]">
            {t('dashboard.nextRotation')}: —
          </p>
        </div>
      )
    }
    return (
      <div className="flex flex-col items-center justify-center py-4 text-[var(--color-text-secondary)]">
        <RefreshCw size={24} className="mb-2 opacity-50" />
        <p className="text-sm">Rotation disabled</p>
      </div>
    )
  }

  if (size === 'compact') {
    return (
      <div className="flex items-center gap-3">
        <RefreshCw size={18} className="text-[var(--color-accent)]" />
        <div className="min-w-0 flex-1">
          <p className="text-sm text-[var(--color-text)] truncate">
            {rotation.currentProfileName}
          </p>
          <p className="text-xs text-[var(--color-text-secondary)]">
            {t('dashboard.nextRotation')}: {formatCountdown(rotation.nextRotationAt)}
          </p>
        </div>
      </div>
    )
  }

  // Expanded view
  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <RefreshCw size={20} className="text-[var(--color-accent)]" />
        <span className="text-sm font-medium text-[var(--color-text)]">
          {t('settings.rotation')}
        </span>
      </div>
      <div className="grid grid-cols-2 gap-2">
        <div className="rounded-[var(--radius-sm)] bg-[var(--color-bg)] p-2.5 border border-[var(--color-border)]">
          <p className="text-xs text-[var(--color-text-secondary)] mb-0.5">
            {t('dashboard.currentProfile')}
          </p>
          <p className="text-sm font-medium text-[var(--color-text)] truncate">
            {rotation.currentProfileName}
          </p>
        </div>
        <div className="rounded-[var(--radius-sm)] bg-[var(--color-bg)] p-2.5 border border-[var(--color-border)]">
          <p className="text-xs text-[var(--color-text-secondary)] mb-0.5">
            {t('dashboard.nextRotation')}
          </p>
          <p className="text-sm font-medium text-[var(--color-text)] tabular-nums">
            {formatCountdown(rotation.nextRotationAt)}
          </p>
        </div>
        <div className="rounded-[var(--radius-sm)] bg-[var(--color-bg)] p-2.5 border border-[var(--color-border)]">
          <p className="text-xs text-[var(--color-text-secondary)] mb-0.5">Interval</p>
          <p className="text-sm font-medium text-[var(--color-text)]">
            {rotation.intervalMinutes} min
          </p>
        </div>
        <div className="rounded-[var(--radius-sm)] bg-[var(--color-bg)] p-2.5 border border-[var(--color-border)]">
          <p className="text-xs text-[var(--color-text-secondary)] mb-0.5">
            {t('settings.rotationOrder')}
          </p>
          <p className="text-sm font-medium text-[var(--color-text)] capitalize">
            {rotation.order}
          </p>
        </div>
      </div>
    </div>
  )
}
