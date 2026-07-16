import { useCallback, useEffect, useState } from 'react'
import { Globe2, Loader2, Plus, RefreshCw, Square } from 'lucide-react'
import { MacCard } from '../design-system/MacCard'
import { MacButton } from '../design-system/MacButton'
import { useAppStore } from '../store'
import type { ExternalProxyInstanceStatus, ExternalProxyStatus } from '../../shared/ipc-types'

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
  const [busy, setBusy] = useState<{ slot: number | 'all'; action: BusyAction } | null>(null)
  const [error, setError] = useState<string | null>(null)

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

  const refreshStatus = useCallback(async () => {
    try {
      const next = await window.electronAPI.externalProxyStatus()
      setStatus(next ?? STOPPED)
    } catch {
      // Status polling is advisory. Controls surface actionable failures.
    }
  }, [])

  useEffect(() => {
    const refreshNow = () => { void refreshStatus() }
    refreshNow()
    const id = window.setInterval(refreshNow, 5000)
    window.addEventListener(EXTERNAL_PROXY_CHANGED_EVENT, refreshNow)
    return () => {
      window.clearInterval(id)
      window.removeEventListener(EXTERNAL_PROXY_CHANGED_EVENT, refreshNow)
    }
  }, [refreshStatus])

  const runAction = async (slot: number, action: BusyAction) => {
    setBusy({ slot, action })
    setError(null)
    try {
      const next = action === 'start'
        ? await window.electronAPI.externalProxyStart({ slot })
        : action === 'stop'
          ? await window.electronAPI.externalProxyStop(slot)
          : await window.electronAPI.externalProxyRotate(slot)
      setStatus(next ?? STOPPED)
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
    const slot = firstAvailableSlot(instances)

    addLog('info', `Внешний прокси ${slot}: запускаем sing-box`)
    const next = await runAction(slot, 'start')
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
    addLog('info', 'Внешние прокси: останавливаем все')
    try {
      const next = await window.electronAPI.externalProxyStopAll()
      setStatus(next ?? STOPPED)
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
          <MacButton
            variant="primary"
            size="sm"
            onClick={handleAdd}
            disabled={isBusy}
            title="Добавить внешний прокси"
          >
            {busy?.action === 'start' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
            Добавить прокси
          </MacButton>
        </div>
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
