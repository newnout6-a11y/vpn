/**
 * RotationSettings — Configuration UI for automatic profile rotation.
 *
 * Features:
 * - Toggle to enable/disable rotation (MacSwitch)
 * - Interval input (5–1440 minutes) with validation
 * - Order selector (Sequential / Random) via MacSegmentedControl
 * - Profile list with checkboxes to include/exclude from rotation
 * - Calls 'rotation:set-config' IPC when settings change
 * - Shows current rotation status: current profile name, time until next rotation
 * - "Rotate Now" button that calls 'rotation:rotate-now' IPC
 * - Handles IPC errors with user feedback and state synchronization
 *
 * Validates: Requirements 9.1, 9.3, 9.5
 */

import React, { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { RefreshCw, Clock, Shuffle, TriangleAlert } from 'lucide-react'
import { MacCard } from '../design-system/MacCard'
import { MacSwitch } from '../design-system/MacSwitch'
import { MacInput } from '../design-system/MacInput'
import { MacSegmentedControl } from '../design-system/MacSegmentedControl'
import { MacButton } from '../design-system/MacButton'
import type { RotationConfig, ServerProfile } from '../../shared/ipc-types'

// ─── Helpers ─────────────────────────────────────────────────────────────────

const MIN_INTERVAL = 5
const MAX_INTERVAL = 1440

function clampInterval(value: number): number {
  if (!Number.isFinite(value)) return MIN_INTERVAL
  if (value < MIN_INTERVAL) return MIN_INTERVAL
  if (value > MAX_INTERVAL) return MAX_INTERVAL
  return value
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

// ─── Component ───────────────────────────────────────────────────────────────

export const RotationSettings: React.FC = () => {
  const { t } = useTranslation()
  const [config, setConfig] = useState<RotationConfig | null>(null)
  const [profiles, setProfiles] = useState<ServerProfile[]>([])
  const [intervalInput, setIntervalInput] = useState('')
  const [intervalError, setIntervalError] = useState<string | undefined>(undefined)
  const [ipcError, setIpcError] = useState<string | null>(null)
  const [rotating, setRotating] = useState(false)
  const [, setTick] = useState(0)
  const tickRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const api = window.electronAPI

  // ─── Fetch initial data ──────────────────────────────────────────────────

  const fetchConfig = useCallback(async () => {
    try {
      const cfg: RotationConfig = await api.rotationGetConfig()
      setConfig(cfg)
      setIntervalInput(String(cfg.intervalMinutes))
    } catch (err: any) {
      setIpcError(err?.message || 'Не удалось загрузить настройки ротации')
    }
  }, [api])

  const fetchProfiles = useCallback(async () => {
    try {
      const list: ServerProfile[] = await api.serversList()
      setProfiles(list)
    } catch (err: any) {
      setIpcError(err?.message || 'Не удалось загрузить список серверов')
    }
  }, [api])

  useEffect(() => {
    fetchConfig()
    fetchProfiles()
  }, [fetchConfig, fetchProfiles])

  // ─── Countdown tick ──────────────────────────────────────────────────────

  useEffect(() => {
    if (config?.enabled && config.nextRotationAt) {
      tickRef.current = setInterval(() => setTick((t) => t + 1), 1000)
    } else if (tickRef.current) {
      clearInterval(tickRef.current)
      tickRef.current = null
    }
    return () => {
      if (tickRef.current) clearInterval(tickRef.current)
    }
  }, [config?.enabled, config?.nextRotationAt])

  // ─── Update config via IPC ───────────────────────────────────────────────

  const updateConfig = useCallback(
    async (partial: Partial<RotationConfig>) => {
      try {
        setIpcError(null)
        const updated: RotationConfig = await api.rotationSetConfig(partial)
        setConfig(updated)
        setIntervalInput(String(updated.intervalMinutes))
      } catch (err: any) {
        setIpcError(err?.message || 'Не удалось сохранить настройки ротации')
        if (config) {
          setIntervalInput(String(config.intervalMinutes))
        }
      }
    },
    [api, config]
  )

  // ─── Handlers ────────────────────────────────────────────────────

  const handleToggleEnabled = (checked: boolean) => {
    updateConfig({ enabled: checked })
  }

  const handleIntervalChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const raw = e.target.value
    setIntervalInput(raw)

    const num = parseInt(raw, 10)
    if (!raw.trim() || isNaN(num)) {
      setIntervalError(t('settings.rotationIntervalHint'))
      return
    }
    if (num < MIN_INTERVAL || num > MAX_INTERVAL) {
      setIntervalError(t('settings.rotationIntervalHint'))
      return
    }
    setIntervalError(undefined)
  }

  const handleIntervalBlur = () => {
    const num = parseInt(intervalInput, 10)
    if (isNaN(num)) {
      const clamped = config?.intervalMinutes ?? 30
      setIntervalInput(String(clamped))
      setIntervalError(undefined)
      return
    }
    const clamped = clampInterval(num)
    setIntervalInput(String(clamped))
    setIntervalError(undefined)
    if (clamped !== config?.intervalMinutes) {
      updateConfig({ intervalMinutes: clamped })
    }
  }

  const handleOrderChange = (value: string) => {
    if (value === 'sequential' || value === 'random') {
      updateConfig({ order: value })
    }
  }

  const handleProfileToggle = (profileId: string, included: boolean) => {
    if (!config) return
    const currentIds = config.profileIds || []
    const newIds = included
      ? [...currentIds, profileId]
      : currentIds.filter((id) => id !== profileId)
    updateConfig({ profileIds: newIds })
  }

  const handleRotateNow = async () => {
    setRotating(true)
    setIpcError(null)
    try {
      const result = await api.rotationRotateNow()
      if (!result?.success) throw new Error('Не удалось переключить сервер. Проверьте доступность профилей и повторите попытку.')
      await fetchConfig()
    } catch (err: any) {
      setIpcError(err?.message || 'Не удалось выполнить ротацию')
    } finally {
      setRotating(false)
    }
  }

  // ─── Derived state ───────────────────────────────────────────────────────

  const currentProfileName = (() => {
    if (!config || config.profileIds.length === 0) return null
    const currentId = config.profileIds[config.currentIndex]
    const profile = profiles.find((p) => p.id === currentId)
    return profile?.name ?? currentId ?? null
  })()

  const orderOptions = [
    { value: 'sequential', label: t('settings.rotationSequential') },
    { value: 'random', label: t('settings.rotationRandom') },
  ]

  // ─── Render ──────────────────────────────────────────────────────────────

  if (!config) {
    return (
      <MacCard>
        {ipcError ? (
          <div
            role="alert"
            className="flex items-center justify-between p-3 rounded-[var(--radius-sm)] bg-red-500/10 border border-red-500/30 text-red-400 text-xs"
          >
            <div className="flex items-center gap-2">
              <TriangleAlert size={16} className="shrink-0 text-red-400" />
              <span>{ipcError}</span>
            </div>
            <MacButton
              variant="secondary"
              size="sm"
              onClick={() => {
                setIpcError(null)
                fetchConfig()
                fetchProfiles()
              }}
            >
              Повторить
            </MacButton>
          </div>
        ) : (
          <div className="flex items-center gap-2 text-[var(--color-text-secondary)]">
            <RefreshCw size={18} className="animate-spin" />
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
            <TriangleAlert size={16} className="shrink-0 text-red-400" />
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

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <RefreshCw size={20} className="text-[var(--color-accent)]" />
          <h3 className="text-base font-semibold text-[var(--color-text)]">
            {t('settings.rotation')}
          </h3>
        </div>
        <MacSwitch
          checked={config.enabled}
          onChange={handleToggleEnabled}
          label={t('settings.rotationEnabled')}
        />
      </div>

      {/* Status section — visible when enabled */}
      {config.enabled && (
        <div className="flex items-center gap-4 p-3 rounded-[var(--radius-sm)] bg-[var(--color-bg)] border border-[var(--color-border)]">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <Shuffle size={14} className="text-[var(--color-text-secondary)]" />
              <span className="text-xs text-[var(--color-text-secondary)]">
                {t('settings.rotationCurrentProfile')}
              </span>
            </div>
            <p className="text-sm font-medium text-[var(--color-text)] truncate">
              {currentProfileName || '—'}
            </p>
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <Clock size={14} className="text-[var(--color-text-secondary)]" />
              <span className="text-xs text-[var(--color-text-secondary)]">
                {t('settings.rotationNextIn')}
              </span>
            </div>
            <p className="text-sm font-medium text-[var(--color-text)] tabular-nums">
              {formatCountdown(config.nextRotationAt)}
            </p>
          </div>
          <MacButton
            variant="secondary"
            size="sm"
            onClick={handleRotateNow}
            loading={rotating}
            disabled={config.profileIds.length === 0}
          >
            {t('settings.rotationRotateNow')}
          </MacButton>
        </div>
      )}

      {/* Interval input */}
      <MacInput
        type="number"
        label={t('settings.rotationInterval')}
        value={intervalInput}
        onChange={handleIntervalChange}
        onBlur={handleIntervalBlur}
        min={MIN_INTERVAL}
        max={MAX_INTERVAL}
        error={intervalError}
        hint={t('settings.rotationIntervalHint')}
        disabled={!config.enabled}
      />

      {/* Order selector */}
      <div className="space-y-1.5">
        <label className="text-sm font-medium text-[var(--color-text)]">
          {t('settings.rotationOrder')}
        </label>
        <MacSegmentedControl
          options={orderOptions}
          value={config.order}
          onChange={handleOrderChange}
        />
      </div>

      {/* Profile list */}
      <div className="space-y-2">
        <label className="text-sm font-medium text-[var(--color-text)]">
          {t('settings.rotationProfiles')}
        </label>
        {profiles.length === 0 ? (
          <p className="text-sm text-[var(--color-text-secondary)] py-2">
            {t('settings.rotationNoProfiles')}
          </p>
        ) : (
          <div className="max-h-48 overflow-y-auto rounded-[var(--radius-sm)] border border-[var(--color-border)] divide-y divide-[var(--color-border)]">
            {profiles.map((profile) => {
              const included = config.profileIds.includes(profile.id)
              return (
                <label
                  key={profile.id}
                  className="flex items-center gap-3 px-3 py-2.5 cursor-pointer hover:bg-[var(--color-bg)] transition-colors duration-[var(--transition-fast)]"
                >
                  <input
                    type="checkbox"
                    checked={included}
                    onChange={(e) => handleProfileToggle(profile.id, e.target.checked)}
                    disabled={!config.enabled}
                    className="w-4 h-4 rounded border-[var(--color-border)] text-[var(--color-accent)] focus:ring-[var(--color-accent)] focus:ring-offset-0"
                  />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-[var(--color-text)] truncate">
                      {profile.name}
                    </p>
                    <p className="text-xs text-[var(--color-text-secondary)]">
                      {profile.protocol}
                      {profile.country ? ` · ${profile.country}` : ''}
                    </p>
                  </div>
                  {profile.status === 'online' && (
                    <span className="w-2 h-2 rounded-full bg-green-500 shrink-0" />
                  )}
                  {profile.status === 'offline' && (
                    <span className="w-2 h-2 rounded-full bg-red-500 shrink-0" />
                  )}
                </label>
              )
            })}
          </div>
        )}
      </div>
    </MacCard>
  )
}
