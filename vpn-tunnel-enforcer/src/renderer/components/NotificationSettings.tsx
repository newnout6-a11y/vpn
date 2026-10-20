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
import { MacButton } from '../design-system/MacButton'
import { ipcError as canonicalIpcError, isIpcRemoteErrorData } from '../../shared/ipc-result'
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
  const { t, i18n } = useTranslation()
  const tRef = useRef(t)
  tRef.current = t
  const [prefs, setPrefs] = useState<NotificationPreferences | null>(null)
  const [osBlocked, setOsBlocked] = useState(false)
  const [osCheckError, setOsCheckError] = useState<string | null>(null)
  const [ipcError, setIpcError] = useState<string | null>(null)

  const lifetime = useRef(0)
  const osRequest = useRef(0)
  const resetTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const resetPending = useRef(false)
  const [resetting, setResetting] = useState(false)
  const api = window.electronAPI
  const visibleError = (error: unknown, fallback: string): string | null => {
    if (isIpcRemoteErrorData(error)) return error.category === 'cancelled' ? null : error.message
    return error instanceof Error ? error.message : fallback
  }

  // ─── Fetch OS notification state ──────────────────────────────────────────

  const fetchOsState = useCallback(async () => {
    const generation = lifetime.current
    const request = ++osRequest.current
    try {
      setOsCheckError(null)
      const state = await api.checkOsNotificationState()
      if (generation !== lifetime.current || request !== osRequest.current) return
      setOsBlocked(!state.osNotificationsEnabled)
    } catch (error) {
      if (generation === lifetime.current && request === osRequest.current) {
        setOsCheckError(visibleError(error, tRef.current('notifications.osCheckError')))
      }
    }
  }, [api])

  const fetchPrefs = useCallback(async () => {
    const generation = lifetime.current
    try {
      const result = await api.notificationsGetPrefs()
      if (generation === lifetime.current) setPrefs(result)
    } catch (error) {
      if (generation === lifetime.current) setIpcError(visibleError(error, tRef.current('notifications.loadError')))
    }
  }, [api])

  useEffect(() => {
    ++lifetime.current
    fetchPrefs()
    fetchOsState()
    return () => {
      ++lifetime.current
      if (resetTimer.current !== null) clearTimeout(resetTimer.current)
    }
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
      const generation = lifetime.current
      try {
        setIpcError(null)
        const updated = await api.notificationsSetPrefs(partial)
        if (generation === lifetime.current) setPrefs(updated)
      } catch (error) {
        if (generation === lifetime.current) setIpcError(visibleError(error, tRef.current('notifications.saveError')))
      }
    },
    [api]
  )

  const resetOsBlock = async () => {
    if (resetPending.current) return
    resetPending.current = true
    setResetting(true)
    const generation = lifetime.current
    ++osRequest.current // Fence reads started before the reset.
    if (resetTimer.current !== null) clearTimeout(resetTimer.current)
    try {
      setIpcError(null)
      const report = await api.notificationsResetOsBlock()
      if (generation !== lifetime.current) return
      if (report.errors.length) {
        const details = report.errors.map(item => canonicalIpcError(item.error.category, i18n.language.startsWith('en') ? 'en' : 'ru').message)
        setIpcError(`${tRef.current('notifications.resetPartial', { cleared: report.cleared.length, failed: report.errors.length })}: ${[...new Set(details)].join('; ')}`)
      }
      await fetchOsState()
      if (generation !== lifetime.current) return
      resetTimer.current = setTimeout(() => { resetTimer.current = null; void fetchOsState() }, 1000)
    } catch (error) {
      if (generation === lifetime.current) setIpcError(visibleError(error, tRef.current('notifications.resetError')))
    } finally {
      resetPending.current = false
      if (generation === lifetime.current) setResetting(false)
    }
  }

  const openWindowsSettings = async () => {
    const generation = lifetime.current
    try {
      setIpcError(null)
      await api.notificationsOpenWindowsSettings()
    } catch (error) {
      if (generation === lifetime.current) setIpcError(visibleError(error, tRef.current('notifications.openSettingsError')))
    }
  }

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
        {ipcError ? (
          <div
            role="alert"
            className="flex items-center justify-between p-3 rounded-[var(--radius-sm)] bg-red-500/10 border border-red-500/30 text-red-400 text-xs"
          >
            <div className="flex items-center gap-2">
              <AlertTriangle size={16} className="shrink-0 text-red-400" />
              <span>{ipcError}</span>
            </div>
            <MacButton
              variant="secondary"
              size="sm"
              onClick={() => {
                setIpcError(null)
                fetchPrefs()
                fetchOsState()
              }}
            >
              {t('common.retry')}
            </MacButton>
          </div>
        ) : (
          <div className="flex items-center gap-2 text-[var(--color-text-secondary)]">
            <Bell size={18} className="animate-pulse" />
            <span className="text-sm">{t('common.loading')}</span>
          </div>
        )}
      </MacCard>
    )
  }

  return (
    <MacCard className="space-y-5">
      {/* Error banner */}
      {ipcError && (
        <div
          role="alert"
          className="flex items-center justify-between p-3 rounded-[var(--radius-sm)] bg-red-500/10 border border-red-500/30 text-red-400 text-xs"
        >
          <div className="flex items-center gap-2">
            <AlertTriangle size={16} className="shrink-0 text-red-400" />
            <span>{ipcError}</span>
          </div>
          <button
            type="button"
            onClick={() => setIpcError(null)}
            className="text-red-400 hover:text-red-300 font-bold ml-2 px-1 text-sm leading-none"
            aria-label="Dismiss error"
          >
            ×
          </button>
        </div>
      )}

      {/* OS notification check error banner */}
      {osCheckError && (
        <div
          role="alert"
          className="flex items-center justify-between p-3 rounded-[var(--radius-sm)] bg-[var(--color-warning)]/10 border border-[var(--color-warning)]/30 text-[var(--color-warning)] text-xs"
        >
          <div className="flex items-center gap-2">
            <AlertTriangle size={16} className="shrink-0 text-[var(--color-warning)]" />
            <span>{osCheckError}</span>
          </div>
          <div className="flex items-center gap-2">
            <MacButton
              variant="secondary"
              size="sm"
              onClick={() => fetchOsState()}
            >
              {t('common.retry')}
            </MacButton>
            <button
              type="button"
              onClick={() => setOsCheckError(null)}
              className="text-[var(--color-warning)] hover:opacity-80 font-bold px-1 text-sm leading-none"
              aria-label="Dismiss OS error"
            >
              ×
            </button>
          </div>
        </div>
      )}

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
                onClick={() => void resetOsBlock()}
                disabled={resetting}
                className="text-xs font-medium px-3 py-1.5 rounded-[var(--radius-sm)] bg-[var(--color-warning)]/20 hover:bg-[var(--color-warning)]/30 text-[var(--color-warning)] transition-colors"
              >
                {t('notifications.resetWindowsBlock')}
              </button>
              <button
                type="button"
                onClick={() => void openWindowsSettings()}
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
