import { useCallback, useEffect, useRef, useState } from 'react'
import { Loader2, Plus, RefreshCw, Square } from 'lucide-react'
import { cn } from '../design-system/utils'
import { MacSelect, type SelectOption } from '../design-system/MacSelect'
import { useAppStore } from '../store'
import { usePageActive } from '../hooks/usePageActive'
import { SERVER_CHANGED_EVENT } from '../nav'
import type { ExternalProxyInstanceStatus, ExternalProxyProfileRow, ExternalProxyStatus } from '../../shared/ipc-types'
import { MASCOT_EVENT, type MascotEvent } from '../swiss/useMascot'
import '../styles/swiss.css'

const nudgeMascot = (kind: MascotEvent) => window.dispatchEvent(new CustomEvent(MASCOT_EVENT, { detail: kind }))

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
  const active = usePageActive()
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
    if (!active) return
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
      refreshVersionRef.current += 1
      clearScheduledRefresh()
      scheduleRefreshRef.current = () => undefined
      window.removeEventListener(EXTERNAL_PROXY_CHANGED_EVENT, refreshNow)
      window.removeEventListener(SERVER_CHANGED_EVENT, refreshNow)
      window.removeEventListener('focus', refreshNow)
      document.removeEventListener('visibilitychange', handleVisibilityChange)
    }
  }, [active, refreshStatus])

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
    nudgeMascot('proxy-start')
    const next = await runAction(slot, 'start', selectedProfile.id)
    if (next?.processRunning) {
      addGlobalToast('success', `Внешний прокси ${slot} запущен`, next.proxyUrl ?? undefined)
      addLog('info', `Внешний прокси ${slot} запущен: ${next.proxyUrl} (${next.profileName ?? 'без имени'})`)
    }
  }

  const handleStop = async (instance: ExternalProxyInstanceStatus) => {
    addLog('info', `Внешний прокси ${instance.slot}: останавливаем`)
    nudgeMascot('proxy-stop')
    const next = await runAction(instance.slot, 'stop')
    if (next) {
      addGlobalToast('info', `Внешний прокси ${instance.slot} остановлен`)
      addLog('info', `Внешний прокси ${instance.slot} остановлен`)
    }
  }

  const handleRotate = async (instance: ExternalProxyInstanceStatus) => {
    addLog('info', `Внешний прокси ${instance.slot}: меняем профиль`)
    nudgeMascot('proxy-rotate')
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
      nudgeMascot('proxy-stop-all')
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
    // «Пломба» column of the dashboard panel row: count, picker + start, one line per proxy
    <section className="swiss-panel">
      <header className="swiss-panel-head" data-perch="proxies" data-perch-y="bottom" data-perch-scale="0.32" data-perch-fit="gap">
        <span className="swiss-label swiss-label-ink">Внешние прокси</span>
        <button type="button" className="swiss-fact-action" onClick={handleStopAll} disabled={isBusy || processRunningCount === 0} title="Остановить все внешние прокси">
          {busy?.action === 'stopAll' && <Loader2 className="mr-1 inline h-3 w-3 animate-spin" />}
          стоп все
        </button>
      </header>

      <div className="swiss-proxy-top">
        <div className="swiss-proxy-summary">
          <span className="swiss-proxy-count">{processRunningCount}</span>
          <span className="swiss-label">запущено</span>
          {countrySummary && (
            <span className="swiss-mono swiss-proxy-countries" title={activeCountries.join(', ')}>
              {countrySummary}
            </span>
          )}
        </div>
        <div className="swiss-proxy-add">
          <MacSelect
            className="swiss-proxy-select"
            size="sm"
            label="Сервер для нового прокси"
            options={profileOptions}
            value={selectedProfileId}
            onChange={setSelectedProfileId}
            placeholder={profileOptions.length ? 'Выберите сервер' : 'Нет доступных серверов'}
            disabled={isBusy || profileOptions.length === 0}
          />
          <button
            type="button"
            className="swiss-proxy-start"
            onClick={handleAdd}
            disabled={isBusy || !selectedProfileId}
            aria-label="Запустить прокси"
            title="Запустить выбранный сервер как внешний прокси"
          >
            {busy?.action === 'start' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
          </button>
        </div>
      </div>

      <div className="swiss-panel-body">
        {instances.length === 0 ? (
          <p className="swiss-empty swiss-proxy-empty">Ни одного прокси не запущено.</p>
        ) : (
          instances.map((instance) => {
            const rowBusy = busy?.slot === instance.slot
            const starting = instance.health === 'starting' || instance.health === 'rotating'
            return (
              <div key={instance.slot} className="swiss-proxy-row">
                <div className="min-w-0">
                  <div className="swiss-proxy-name">
                    <span
                      className={cn('swiss-health-dot shrink-0', starting && 'is-unknown is-wait', !starting && instance.health !== 'healthy' && 'is-offline')}
                      title={instance.lastError ?? instance.health}
                    />
                    <span className="truncate">{instance.profileName ?? 'Без имени'}</span>
                    {instance.country && <span className="swiss-mono swiss-proxy-cc">{instance.country}</span>}
                  </div>
                  <div className="swiss-mono swiss-proxy-meta" title={instance.proxyUrl ?? undefined}>
                    {instance.port ? ':' + instance.port : instance.proxyUrl ?? '—'}
                    {starting ? ' · запуск…' : instance.latencyMs !== null ? ' · ' + instance.latencyMs + ' мс' : ''}
                  </div>
                </div>
                <div className="swiss-proxy-actions">
                  <button
                    type="button"
                    className="swiss-icon-btn"
                    onClick={() => handleRotate(instance)}
                    disabled={isBusy}
                    aria-label={`Сменить профиль прокси ${instance.slot}`}
                    title={`Сменить профиль прокси ${instance.slot}`}
                  >
                    {rowBusy && busy?.action === 'rotate' ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
                  </button>
                  <button
                    type="button"
                    className="swiss-icon-btn is-danger"
                    onClick={() => handleStop(instance)}
                    disabled={isBusy}
                    aria-label={`Остановить прокси ${instance.slot}`}
                    title={`Остановить прокси ${instance.slot}`}
                  >
                    {rowBusy && busy?.action === 'stop' ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Square className="h-3.5 w-3.5" />}
                  </button>
                </div>
              </div>
            )
          })
        )}
        {error && <p className="swiss-panel-error">{error}</p>}
      </div>
    </section>
  )
}
