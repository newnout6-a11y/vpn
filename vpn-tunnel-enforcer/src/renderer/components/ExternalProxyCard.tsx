import { useCallback, useEffect, useRef, useState } from 'react'
import { Globe2, Loader2, Plus, RefreshCw, Square } from 'lucide-react'
import { MacCard } from '../design-system/MacCard'
import { MacButton } from '../design-system/MacButton'
import { MacSelect, type SelectOption } from '../design-system/MacSelect'
import { useAppStore } from '../store'
import { SERVER_CHANGED_EVENT } from '../nav'
import type { ExternalProxyInstanceStatus, ExternalProxyProfileRow, ExternalProxyStatus } from '../../shared/ipc-types'

const STOPPED: ExternalProxyStatus = {
  slot: 1,
  running: false,
  processRunning: false,
  ready: false,
  health: 'stopped',
  state: 'stopped',
  generation: 0,
  egressIp: null,
  latencyMs: null,
  lastCheckedAt: null,
  lastSuccessAt: null,
  egressCheckedAt: null,
  updatedAt: null,
  lastError: null,
  lastErrorAt: null,
  degradationReason: null,
  consecutiveFailures: 0,
  nextCheckAt: null,
  lastRotateReason: null,
  autoDisabled: false,
  host: '127.0.0.1',
  port: null,
  proxyUrl: null,
  profileId: null,
  profileName: null,
  country: null,
  pid: null,
  startedAt: null,
  controlHost: '127.0.0.1',
  controlPort: null,
  controlUrl: null,
  maxInstances: null,
  instances: [],
  aggregate: {
    total: 0,
    running: 0,
    ready: 0,
    healthy: 0,
    uniqueEgress: 0,
    duplicateEgress: 0,
    starting: 0,
    degraded: 0,
    quarantined: 0
  }
}

type BusyAction = 'start' | 'stop' | 'rotate' | 'stopAll'
const EXTERNAL_PROXY_CHANGED_EVENT = 'vpnte:external-proxy-changed'
export const EXTERNAL_PROXY_UNSTABLE_REFRESH_INTERVAL_MS = 3_000
export const EXTERNAL_PROXY_HEALTHY_REFRESH_INTERVAL_MS = 10_000
export const EXTERNAL_PROXY_IDLE_REFRESH_INTERVAL_MS = 10_000

export function externalProxyRefreshIntervalMs(status: ExternalProxyStatus): number {
  const runningInstances = status.instances.filter((instance) => instance.processRunning)

  if (runningInstances.length === 0) {
    return status.instances.some((instance) => instance.autoDisabled)
      ? EXTERNAL_PROXY_HEALTHY_REFRESH_INTERVAL_MS
      : EXTERNAL_PROXY_IDLE_REFRESH_INTERVAL_MS
  }

  return runningInstances.some((instance) => !instance.ready || instance.health !== 'healthy')
    ? EXTERNAL_PROXY_UNSTABLE_REFRESH_INTERVAL_MS
    : EXTERNAL_PROXY_HEALTHY_REFRESH_INTERVAL_MS
}

function renderedStatusKey(status: ExternalProxyStatus): string {
  const visibleInstances = status.instances.filter((instance) => instance.processRunning || instance.autoDisabled)
  const instanceKey = visibleInstances.map((instance) => [
    instance.slot,
    instance.processRunning,
    instance.autoDisabled,
    instance.health,
    instance.profileName,
    instance.country,
    instance.egressIp,
    instance.latencyMs,
    instance.proxyUrl,
    instance.lastError
  ].join('|')).join('||')

  return `${status.controlUrl ?? ''}::${instanceKey}`
}

function firstAvailableSlot(instances: ExternalProxyInstanceStatus[]): number {
  const occupied = new Set(instances.filter((instance) => instance.processRunning).map((instance) => instance.slot))
  let slot = 1
  while (occupied.has(slot)) slot += 1
  return slot
}

export function ExternalProxyCard() {
  const addLog = useAppStore(s => s.addLog)
  const addGlobalToast = useAppStore(s => s.addGlobalToast)

  const [status, setStatus] = useState<ExternalProxyStatus>(STOPPED)
  const [availableProfiles, setAvailableProfiles] = useState<ExternalProxyProfileRow[]>([])
  const [selectedProfileId, setSelectedProfileId] = useState('')
  const [busy, setBusy] = useState<{ slot: number | 'all'; action: BusyAction } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const statusRef = useRef(status)
  const refreshInFlightRef = useRef(false)
  const refreshVersionRef = useRef(0)
  const scheduleRefreshRef = useRef<() => void>(() => undefined)

  const instances = status.instances.filter((instance) => instance.processRunning || instance.autoDisabled)
  const processRunningCount = instances.filter((instance) => instance.processRunning).length
  const activeCountries = [...new Set(
    instances
      .filter((instance) => instance.processRunning)
      .map((instance) => instance.country)
      .filter((country): country is string => Boolean(country))
  )]
  const countrySummary = activeCountries.length <= 6
    ? activeCountries.join(', ')
    : `${activeCountries.slice(0, 6).join(', ')} +${activeCountries.length - 6}`

  const applyStatus = useCallback((next: ExternalProxyStatus) => {
    statusRef.current = next
    setStatus((current) => renderedStatusKey(current) === renderedStatusKey(next) ? current : next)
  }, [])

  const refreshStatus = useCallback(async () => {
    if (refreshInFlightRef.current) return

    refreshInFlightRef.current = true
    const refreshVersion = refreshVersionRef.current
    try {
      const [next, profiles] = await Promise.all([
        window.electronAPI.externalProxyStatus(),
        window.electronAPI.externalProxyList()
      ])
      if (refreshVersion === refreshVersionRef.current) {
        applyStatus(next ?? STOPPED)
        setAvailableProfiles(profiles)
        setSelectedProfileId((current) => {
          const canUse = (row: ExternalProxyProfileRow) => !row.active && !row.selectedForVpn
          if (profiles.some((row) => row.id === current && canUse(row))) return current
          return profiles.find(canUse)?.id ?? ''
        })
      }
    } catch {
      // Status polling is advisory. Controls surface actionable failures.
    } finally {
      refreshInFlightRef.current = false
    }
  }, [applyStatus])

  useEffect(() => {
    let pollTimer: number | null = null
    let disposed = false

    const clearScheduledRefresh = () => {
      if (pollTimer !== null) {
        window.clearTimeout(pollTimer)
        pollTimer = null
      }
    }

    const scheduleRefresh = () => {
      clearScheduledRefresh()
      if (disposed || document.hidden) return

      pollTimer = window.setTimeout(() => {
        pollTimer = null
        void refreshStatus().finally(scheduleRefresh)
      }, externalProxyRefreshIntervalMs(statusRef.current))
    }

    const refreshNow = () => {
      if (disposed || document.hidden) return
      void refreshStatus().finally(scheduleRefresh)
    }

    const handleVisibilityChange = () => {
      if (document.hidden) {
        clearScheduledRefresh()
      } else {
        refreshNow()
      }
    }

    scheduleRefreshRef.current = scheduleRefresh
    refreshNow()
    window.addEventListener(EXTERNAL_PROXY_CHANGED_EVENT, refreshNow)
    window.addEventListener(SERVER_CHANGED_EVENT, refreshNow)
    window.addEventListener('focus', refreshNow)
    document.addEventListener('visibilitychange', handleVisibilityChange)
    return () => {
      disposed = true
      clearScheduledRefresh()
      scheduleRefreshRef.current = () => undefined
      window.removeEventListener(EXTERNAL_PROXY_CHANGED_EVENT, refreshNow)
      window.removeEventListener(SERVER_CHANGED_EVENT, refreshNow)
      window.removeEventListener('focus', refreshNow)
      document.removeEventListener('visibilitychange', handleVisibilityChange)
    }
  }, [refreshStatus])

  const runAction = async (slot: number, action: BusyAction, profileId?: string) => {
    setBusy({ slot, action })
    setError(null)
    refreshVersionRef.current += 1
    try {
      const next = action === 'start'
        ? await window.electronAPI.externalProxyStart({ slot, profileId })
        : action === 'stop'
          ? await window.electronAPI.externalProxyStop(slot)
          : await window.electronAPI.externalProxyRotate(slot)
      applyStatus(next ?? STOPPED)
      void refreshStatus()
      scheduleRefreshRef.current()
      return next
    } catch (err: any) {
      const message = err?.message || String(err)
      setError(message)
      addGlobalToast('error', 'Внешний прокси: операция не выполнена', message)
      addLog('error', `Внешний прокси ${slot}: ${message}`)
      return null
    } finally {
      setBusy(null)
    }
  }

  const handleAdd = async () => {
    const selectedProfile = availableProfiles.find((profile) => profile.id === selectedProfileId)
    if (!selectedProfile) {
      setError('Выберите конкретный сервер для внешнего прокси')
      return
    }
    const slot = firstAvailableSlot(instances)

    addLog('info', `Внешний прокси ${slot}: запускаем ${selectedProfile.name}`)
    const next = await runAction(slot, 'start', selectedProfile.id)
    if (next?.processRunning) {
      addGlobalToast('success', `Внешний прокси ${slot} запущен`, next.proxyUrl ?? undefined)
      addLog('info', `Внешний прокси ${slot} запущен: ${next.proxyUrl} (${next.profileName ?? 'без имени'})`)
    }
  }

  const handleStop = async (instance: ExternalProxyInstanceStatus) => {
    addLog('info', `Внешний прокси ${instance.slot}: останавливаем`)
    const next = await runAction(instance.slot, 'stop')
    if (next) {
      addGlobalToast('info', `Внешний прокси ${instance.slot} остановлен`)
      addLog('info', `Внешний прокси ${instance.slot} остановлен`)
    }
  }

  const handleRotate = async (instance: ExternalProxyInstanceStatus) => {
    addLog('info', `Внешний прокси ${instance.slot}: меняем профиль`)
    const next = await runAction(instance.slot, 'rotate')
    if (next?.processRunning) {
      addGlobalToast('success', `Профиль прокси ${instance.slot} сменён`, next.profileName ?? undefined)
      addLog('info', `Внешний прокси ${instance.slot}: ${next.profileName ?? 'без имени'}`)
    }
  }

  const handleStopAll = async () => {
    setBusy({ slot: 'all', action: 'stopAll' })
    setError(null)
    refreshVersionRef.current += 1
    addLog('info', 'Внешние прокси: останавливаем все')
    try {
      const next = await window.electronAPI.externalProxyStopAll()
      applyStatus(next ?? STOPPED)
      scheduleRefreshRef.current()
      addGlobalToast('info', `Остановлено внешних прокси: ${processRunningCount}`)
      addLog('info', `Внешние прокси: остановлено ${processRunningCount}`)
    } catch (err: any) {
      const message = err?.message || String(err)
      setError(message)
      addGlobalToast('error', 'Не удалось остановить все внешние прокси', message)
      addLog('error', `Внешние прокси: ошибка массовой остановки: ${message}`)
    } finally {
      setBusy(null)
    }
  }

  const isBusy = busy !== null
  const profileOptions: SelectOption[] = availableProfiles.map((profile) => {
    const indicator = profile.status === 'online'
      ? 'success' as const
      : profile.status === 'offline'
        ? 'danger' as const
        : 'muted' as const
    const indicatorLabel = profile.status === 'online'
      ? 'Сервер доступен'
      : profile.status === 'offline'
        ? 'Сервер не отвечает'
        : 'Сервер не проверен'
    const assignmentLabel = profile.active
      ? 'уже в прокси'
      : profile.selectedForVpn
        ? 'текущий VPN'
        : null
    return {
      value: profile.id,
      label: [profile.name, profile.country, profile.protocol.toUpperCase(), assignmentLabel].filter(Boolean).join(' · '),
      indicator,
      indicatorLabel,
      disabled: profile.active || profile.selectedForVpn
    }
  })
  return (
    <MacCard>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wider flex items-center gap-2">
            <Globe2 className="w-4 h-4 text-[var(--color-accent)]" />
            Внешние прокси
          </h3>
          {countrySummary && (
            <p className="text-xs mt-1 text-[var(--color-text-muted)] truncate" title={activeCountries.join(', ')}>
              Страны: {countrySummary}
            </p>
          )}
          <p className="text-sm mt-1 text-[var(--color-text-secondary)]">
            Запущено: {processRunningCount}
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap justify-end">
          <MacButton
            variant="danger"
            size="sm"
            onClick={handleStopAll}
            disabled={isBusy || processRunningCount === 0}
            title="Остановить все внешние прокси"
          >
            {busy?.action === 'stopAll' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Square className="w-4 h-4" />}
            Остановить все
          </MacButton>
        </div>
      </div>

      <div className="mt-3 grid grid-cols-1 gap-2 md:grid-cols-[minmax(0,1fr)_auto] md:items-end">
        <MacSelect
          label="Сервер для нового прокси"
          options={profileOptions}
          value={selectedProfileId}
          onChange={setSelectedProfileId}
          placeholder={profileOptions.length ? 'Выберите сервер' : 'Нет доступных серверов'}
          disabled={isBusy || profileOptions.length === 0}
        />
        <MacButton
          variant="primary"
          size="sm"
          onClick={handleAdd}
          disabled={isBusy || !selectedProfileId}
          title="Запустить выбранный сервер как внешний прокси"
          className="md:min-w-32"
        >
          {busy?.action === 'start' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
          Запустить
        </MacButton>
      </div>

      {instances.length > 0 && (
        <div className="mt-3 border-y border-[var(--color-border)] divide-y divide-[var(--color-border)]">
          {instances.map((instance) => {
            const rowBusy = busy?.slot === instance.slot
            return (
              <div key={instance.slot} className="grid grid-cols-1 md:grid-cols-[minmax(0,1fr)_auto_auto] items-center gap-3 py-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-[var(--color-text)]">Прокси {instance.slot}</span>
                    <span
                      className={`inline-flex items-center gap-1.5 text-xs ${
                        instance.health === 'healthy'
                          ? 'text-[var(--color-success)]'
                          : instance.health === 'starting' || instance.health === 'rotating'
                            ? 'text-[var(--color-warning)]'
                            : 'text-[var(--color-danger)]'
                      }`}
                      title={instance.lastError ?? instance.health}
                    >
                      <span
                        className={`w-1.5 h-1.5 rounded-full ${
                          instance.health === 'healthy'
                            ? 'bg-[var(--color-success)]'
                            : instance.health === 'starting' || instance.health === 'rotating'
                              ? 'bg-[var(--color-warning)]'
                              : 'bg-[var(--color-danger)]'
                        }`}
                      />
                      {instance.autoDisabled ? 'disabled' : instance.health}
                    </span>
                  </div>
                  <p className="text-xs text-[var(--color-text-secondary)] truncate mt-0.5">
                    {instance.profileName ?? 'Без имени'}{instance.country ? `, ${instance.country}` : ''}
                  </p>
                  {instance.egressIp && (
                    <p className="text-xs text-[var(--color-text-muted)] font-mono truncate mt-0.5">
                      {instance.egressIp}{instance.latencyMs !== null ? `, ${instance.latencyMs} ms` : ''}
                    </p>
                  )}
                </div>

                <span className="text-xs font-mono text-[var(--color-text)] break-all md:text-right">
                  {instance.proxyUrl ?? '—'}
                </span>

                <div className="flex items-center gap-1 justify-start md:justify-end">
                  <MacButton
                    variant="ghost"
                    size="sm"
                    onClick={() => handleRotate(instance)}
                    disabled={isBusy}
                    aria-label={`Сменить профиль прокси ${instance.slot}`}
                    title={`Сменить профиль прокси ${instance.slot}`}
                  >
                    {rowBusy && busy?.action === 'rotate' ? <Loader2 className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
                  </MacButton>
                  <MacButton
                    variant="ghost"
                    size="sm"
                    onClick={() => handleStop(instance)}
                    disabled={isBusy}
                    aria-label={`Остановить прокси ${instance.slot}`}
                    title={`Остановить прокси ${instance.slot}`}
                  >
                    {rowBusy && busy?.action === 'stop' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Square className="w-4 h-4 text-[var(--color-danger)]" />}
                  </MacButton>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {error && <p className="text-xs text-[var(--color-danger)] mt-3 break-words">{error}</p>}

      <p className="text-xs text-[var(--color-text-muted)] font-mono mt-3">
        Control API: {status.controlUrl ?? '—'}
      </p>
    </MacCard>
  )
}
