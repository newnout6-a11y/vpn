/**
 * NotificationSettings — UI for configuring notification preferences.
 *
 * Features:
 * - Fetches current prefs from 'notifications:get-prefs' IPC on mount
 * - Checks Windows OS notification state and warns if disabled
 * - Toggle (MacSwitch) for each event type: vpnConnect, vpnDisconnect, leakDetected,
 *   profileRotation, scheduleTriggered, connectionError
 * - Method selector (MacSegmentedControl): System / In-app / Both
 * - Sound toggle (MacSwitch)
 * - Saves changes via 'notifications:set-prefs' IPC on each toggle change
 * - Uses MacCard, MacSwitch, MacSegmentedControl from design-system
 * - Uses i18n translations from notifications namespace
 *
 * Validates: Requirements 17.1, 17.2, 17.4, 17.5
 */

import React, { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Bell,
  Wifi,
  WifiOff,
  ShieldAlert,
  RefreshCw,
  Clock,
  AlertTriangle,
  Volume2,
} from 'lucide-react'
import { MacCard } from '../design-system/MacCard'
import { MacSwitch } from '../design-system/MacSwitch'
import { MacSegmentedControl } from '../design-system/MacSegmentedControl'
import type { NotificationPreferences } from '../../shared/ipc-types'

// ─── Event type definitions ──────────────────────────────────────────────────

type NotificationEventType =
  | 'vpnConnect'
  | 'vpnDisconnect'
  | 'leakDetected'
  | 'profileRotation'
  | 'scheduleTriggered'
  | 'connectionError'

interface EventToggleConfig {
  key: NotificationEventType
  icon: React.ReactNode
}

const EVENT_TOGGLES: EventToggleConfig[] = [
  { key: 'vpnConnect', icon: <Wifi size={16} /> },
  { key: 'vpnDisconnect', icon: <WifiOff size={16} /> },
  { key: 'leakDetected', icon: <ShieldAlert size={16} /> },
  { key: 'profileRotation', icon: <RefreshCw size={16} /> },
  { key: 'scheduleTriggered', icon: <Clock size={16} /> },
  { key: 'connectionError', icon: <AlertTriangle size={16} /> },
]

// ─── Component ───────────────────────────────────────────────────────────────

export const NotificationSettings: React.FC = () => {
  const { t } = useTranslation()
  const [prefs, setPrefs] = useState<NotificationPreferences | null>(null)
  const [osBlocked, setOsBlocked] = useState(false)

  const api = (window as any).electronAPI

  // ─── Fetch OS notification state ──────────────────────────────────────────

  const fetchOsState = useCallback(async () => {
    try {
      const state = await api.checkOsNotificationState()
      setOsBlocked(!state.osNotificationsEnabled)
    } catch {
      // IPC not yet available — assume allowed
    }
  }, [api])

  // ─── Fetch initial preferences ────────────────────────────────────────────

  const fetchPrefs = useCallback(async () => {
    try {
      const result: NotificationPreferences = await api.notificationsGetPrefs()
      setPrefs(result)
    } catch {
      // IPC not yet available
    }
  }, [api])

  useEffect(() => {
    fetchPrefs()
    fetchOsState()
  }, [fetchPrefs, fetchOsState])

  // Re-check OS state when the window regains focus (user may have fixed it
  // in Windows Settings without restarting the app).
  useEffect(() => {
    const onFocus = () => fetchOsState()
    window.addEventListener('focus', onFocus)
    return () => window.removeEventListener('focus', onFocus)
  }, [fetchOsState])

  // ─── Update preferences via IPC ───────────────────────────────────────────

  const updatePrefs = useCallback(
    async (partial: Partial<NotificationPreferences>) => {
      try {
        const updated: NotificationPreferences = await api.notificationsSetPrefs(partial)
        setPrefs(updated)
      } catch {
        // IPC error — keep local state unchanged
      }
    },
    [api]
  )

  // ─── Handlers ─────────────────────────────────────────────────────────────

  const handleEventToggle = (key: NotificationEventType, checked: boolean) => {
    updatePrefs({ [key]: checked })
  }

  const handleMethodChange = (value: string) => {
    if (value === 'system' || value === 'inapp' || value === 'both') {
      updatePrefs({ method: value })
    }
  }

  const handleSoundToggle = (checked: boolean) => {
    updatePrefs({ sound: checked })
  }

  // ─── Method options ────────────────────────────────────────────────────────

  const methodOptions = [
    { value: 'system', label: t('notifications.methodSystem') },
    { value: 'inapp', label: t('notifications.methodInapp') },
    { value: 'both', label: t('notifications.methodBoth') },
  ]

  // ─── Render ────────────────────────────────────────────────────────────────

  if (!prefs) {
    return (
      <MacCard>
        <div className="flex items-center gap-2 text-[var(--color-text-secondary)]">
          <Bell size={18} className="animate-pulse" />
          <span className="text-sm">{t('common.loading')}</span>
        </div>
      </MacCard>
    )
  }

  return (
    <MacCard className="space-y-5">
      {/* Header */}
      <div className="flex items-center gap-2">
        <Bell size={20} className="text-[var(--color-accent)]" />
        <div>
          <h3 className="text-base font-semibold text-[var(--color-text)]">
            {t('notifications.title')}
          </h3>
          <p className="text-xs text-[var(--color-text-secondary)]">
            {t('notifications.description')}
          </p>
        </div>
      </div>

      {/* OS-level warning banner */}
      {osBlocked && (
        <div className="flex items-start gap-3 p-3 rounded-[var(--radius-sm)] bg-[var(--color-warning)]/10 border border-[var(--color-warning)]/30">
          <ShieldAlert size={18} className="mt-0.5 shrink-0 text-[var(--color-warning)]" />
          <div className="space-y-2 flex-1">
            <p className="text-xs font-medium text-[var(--color-warning)]">
              {t('notifications.osBlockedWarning')}
            </p>
            <p className="text-xs text-[var(--color-text-secondary)]">
              {t('notifications.osBlockedExplanation')}
            </p>
            {prefs && (prefs.method === 'system' || prefs.method === 'both') && (
              <p className="text-xs text-[var(--color-text-secondary)]">
                {t('notifications.osBlockedHint')}
              </p>
            )}
            <div className="flex flex-wrap gap-2 pt-1">
              <button
                type="button"
                onClick={async () => {
                  try {
                    // Best-effort: the IPC may be missing on older preload
                    // builds, in which case we simply skip the reset and
                    // still re-poll OS state.
                    await api.notificationsResetOsBlock?.()
                  } catch {
                    // Handler returns a structured shape, but be defensive.
                  }
                  // Re-check immediately, then again after a beat — Windows
                  // can lag a moment in propagating registry changes back to
                  // its in-process notification state.
                  fetchOsState()
                  setTimeout(fetchOsState, 1000)
                }}
                className="text-xs font-medium px-3 py-1.5 rounded-[var(--radius-sm)] bg-[var(--color-warning)]/20 hover:bg-[var(--color-warning)]/30 text-[var(--color-warning)] transition-colors"
              >
                {t('notifications.resetWindowsBlock')}
              </button>
              <button
                type="button"
                onClick={() => api.notificationsOpenWindowsSettings?.()}
                className="text-xs font-medium px-3 py-1.5 rounded-[var(--radius-sm)] border border-[var(--color-border)] hover:bg-[var(--color-card-elevated)] transition-colors"
              >
                {t('notifications.openWindowsSettings')}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Event type toggles */}
      <div className="space-y-3">
        {EVENT_TOGGLES.map(({ key, icon }) => (
          <div
            key={key}
            className="flex items-center justify-between py-2 px-3 rounded-[var(--radius-sm)] hover:bg-[var(--color-bg)] transition-colors duration-[var(--transition-fast)]"
          >
            <div className="flex items-center gap-3">
              <span className="text-[var(--color-text-secondary)]">{icon}</span>
              <span className="text-sm text-[var(--color-text)]">
                {t(`notifications.${key}`)}
              </span>
            </div>
            <MacSwitch
              checked={prefs[key]}
              onChange={(checked) => handleEventToggle(key, checked)}
            />
          </div>
        ))}
      </div>

      {/* Delivery method selector */}
      <div className="space-y-2 pt-2 border-t border-[var(--color-border)]">
        <label className="text-sm font-medium text-[var(--color-text)]">
          {t('notifications.method')}
        </label>
        <MacSegmentedControl
          options={methodOptions}
          value={prefs.method}
          onChange={handleMethodChange}
        />
      </div>

      {/* Sound toggle */}
      <div className="flex items-center justify-between pt-2 border-t border-[var(--color-border)]">
        <div className="flex items-center gap-3">
          <Volume2 size={16} className="text-[var(--color-text-secondary)]" />
          <span className="text-sm text-[var(--color-text)]">
            {t('notifications.soundEnabled')}
          </span>
        </div>
        <MacSwitch checked={prefs.sound} onChange={handleSoundToggle} />
      </div>
    </MacCard>
  )
}
