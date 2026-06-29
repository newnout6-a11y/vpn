import { useEffect, useState } from 'react'
import { Activity, CheckCircle2, ExternalLink, Info, Loader2, MapPinOff, RotateCcw, Store, Trash2, TriangleAlert, Wrench, Zap } from 'lucide-react'
import { useAppStore } from '../store'
import { MacCard, MacButton } from '../design-system'

type RepairAction =
  | 'wsreset'
  | 'open-repair-settings'
  | 'reset-package'
  | 'reregister-package'
  | 'backup-cache'
  | 'open-region-settings'

interface PrivacyStatus {
  userDenied: boolean
  policyDisabled: boolean
  applied: boolean
  details: string[]
}

interface StoreDiagnosticItem {
  id: string
  label: string
  status: 'ok' | 'warn' | 'fail' | 'info'
  value: string
  details?: string
}

interface StoreDiagnosticResult {
  ranAt: number
  summary: 'ok' | 'warn' | 'fail' | 'info'
  items: StoreDiagnosticItem[]
}

interface SystemDiagnosticItem extends StoreDiagnosticItem {
  category: string
}

interface SystemDiagnosticResult {
  ranAt: number
  summary: 'ok' | 'warn' | 'fail' | 'info'
  items: SystemDiagnosticItem[]
}

const repairActions: { id: RepairAction; label: string; icon: any; danger?: boolean; confirm?: string }[] = [
  { id: 'wsreset', label: 'WSReset', icon: RotateCcw },
  { id: 'open-repair-settings', label: 'Repair/Reset', icon: ExternalLink },
  {
    id: 'backup-cache',
    label: 'Обновить cache',
    icon: Trash2,
    danger: true,
    confirm: 'Кэш Microsoft Store будет переименован в backup, а LocalCache создан заново. Продолжить?'
  },
  {
    id: 'reset-package',
    label: 'Reset package',
    icon: Wrench,
    danger: true,
    confirm: 'Будет выполнен Reset-AppxPackage для Microsoft Store. Продолжить?'
  },
  {
    id: 'reregister-package',
    label: 'Re-register',
    icon: Store,
    danger: true,
    confirm: 'Пакет Microsoft Store будет пере-регистрирован через AppXManifest. Продолжить?'
  },
  { id: 'open-region-settings', label: 'Регион Windows', icon: ExternalLink }
]

export function Maintenance() {
  const addLog = useAppStore(s => s.addLog)
  const updateSettings = useAppStore(s => s.updateSettings)
  const [runningAction, setRunningAction] = useState<string | null>(null)
  const [lastResult, setLastResult] = useState<string | null>(null)
  const [autoPilotRunning, setAutoPilotRunning] = useState(false)
  const [privacy, setPrivacy] = useState<PrivacyStatus | null>(null)
  const [storeDiagnostics, setStoreDiagnostics] = useState<StoreDiagnosticResult | null>(null)
  const [systemDiagnostics, setSystemDiagnostics] = useState<SystemDiagnosticResult | null>(null)

  const refreshPrivacy = async () => {
    try {
      const status = await window.electronAPI.getLocationPrivacy()
      setPrivacy(status)
      updateSettings({ locationPrivacyEnabled: Boolean(status?.applied) })
    } catch (err: any) {
      addLog('error', `Не удалось прочитать privacy status: ${err.message}`)
    }
  }

  useEffect(() => {
    refreshPrivacy()
  }, [])

  const runRepair = async (action: RepairAction, confirmText?: string) => {
    if (confirmText && !window.confirm(confirmText)) return
    setRunningAction(action)
    try {
      const result = await window.electronAPI.runStoreRepair(action)
      setLastResult(result.details ? `${result.message}: ${result.details}` : result.message)
      addLog(result.success ? 'info' : 'error', result.message)
    } catch (err: any) {
      addLog('error', `Store repair failed: ${err.message}`)
    } finally {
      setRunningAction(null)
    }
  }

  const runQuickStoreFix = async () => {
    if (!window.confirm('Будут выполнены WSReset, обновление LocalCache и re-register Microsoft Store. Продолжить?')) return
    setRunningAction('store-quick')
    const sequence: RepairAction[] = ['wsreset', 'backup-cache', 'reregister-package']
    try {
      const messages: string[] = []
      for (const action of sequence) {
        const result = await window.electronAPI.runStoreRepair(action)
        messages.push(result.message)
        addLog(result.success ? 'info' : 'error', result.message)
        if (!result.success) break
      }
      setLastResult(messages.join(' -> '))
    } catch (err: any) {
      addLog('error', `Быстрая починка Store не выполнена: ${err.message}`)
    } finally {
      setRunningAction(null)
    }
  }

  const applyNetworkBaseline = async () => {
    if (!window.confirm('Будет создан backup, затем WinHTTP/User/PAC/env proxy будут сброшены для работы через TUN. Продолжить?')) return
    setRunningAction('network-baseline')
    try {
      const result = await window.electronAPI.applyTunNetworkBaseline()
      setLastResult(result.details ? `${result.message}: ${result.details}` : result.message)
      addLog(result.success ? 'info' : 'error', result.message)
    } catch (err: any) {
      addLog('error', `Не удалось нормализовать сеть: ${err.message}`)
    } finally {
      setRunningAction(null)
    }
  }

  const rollbackNetworkBaseline = async () => {
    if (!window.confirm('Будет восстановлен последний backup WinHTTP/WinINet/env proxy. Продолжить?')) return
    setRunningAction('network-rollback')
    try {
      const result = await window.electronAPI.rollbackTunNetworkBaseline()
      setLastResult(result.details ? `${result.message}: ${result.details}` : result.message)
      addLog(result.success ? 'info' : 'error', result.message)
    } catch (err: any) {
      addLog('error', `Не удалось откатить сетевой baseline: ${err.message}`)
    } finally {
      setRunningAction(null)
    }
  }

  const runManualAutoPilot = async () => {
    setAutoPilotRunning(true)
    addLog('info', 'Запуск автопилота вручную...')
    try {
      const autoPilot = await window.electronAPI.runAutoPilot()
      const liveStore = useAppStore.getState()
      liveStore.setMode(autoPilot.mode)
      liveStore.setTunRunning(autoPilot.mode === 'hard')
      if (autoPilot.mode !== 'hard') liveStore.setVpnIp(null)
      addLog(
        autoPilot.summary === 'fail' ? 'error' : autoPilot.summary === 'warn' ? 'warn' : 'info',
        `${autoPilot.title}: ${autoPilot.message}`
      )
      if (autoPilot.steps && Array.isArray(autoPilot.steps)) {
        for (const step of autoPilot.steps) {
          const stepLevel = step.status === 'fail' ? 'error' : step.status === 'warn' ? 'warn' : 'info'
          addLog(stepLevel, `Автопилот: ${step.label}${step.after ? ` → ${step.after}` : ''}`)
        }
      }
      const toastVariant = autoPilot.summary === 'fail' ? 'error' : autoPilot.summary === 'warn' ? 'warning' : 'success'
      useAppStore.getState().addGlobalToast(toastVariant, autoPilot.title, autoPilot.message)
    } catch (err: any) {
      addLog('error', `Автопилот не сработал: ${err.message}`)
      useAppStore.getState().addGlobalToast('error', 'Автопилот', `Ошибка: ${err.message}`)
    } finally {
      setAutoPilotRunning(false)
    }
  }

  const runStoreDiagnostics = async () => {
    setRunningAction('store-diagnostics')
    addLog('info', 'Запуск глубокой диагностики Microsoft Store...')
    try {
      const result = await window.electronAPI.runStoreDiagnostics()
      setStoreDiagnostics(result)
      const message =
        result.summary === 'fail'
          ? 'найдены критичные проблемы Store'
          : result.summary === 'warn'
            ? 'найдены предупреждения Store'
            : 'критичных проблем Store не найдено'
      addLog(result.summary === 'fail' ? 'error' : result.summary === 'warn' ? 'warn' : 'info', `Store diagnostics: ${message}`)
    } catch (err: any) {
      addLog('error', `Store diagnostics failed: ${err.message}`)
    } finally {
      setRunningAction(null)
    }
  }

  const runSystemDiagnostics = async () => {
    setRunningAction('system-diagnostics')
    addLog('info', 'Full system diagnostics started...')
    try {
      const result = await window.electronAPI.runSystemDiagnostics()
      setSystemDiagnostics(result)
      const message =
        result.summary === 'fail'
          ? 'critical issues found'
          : result.summary === 'warn'
            ? 'warnings found'
            : 'no critical issues found'
      addLog(result.summary === 'fail' ? 'error' : result.summary === 'warn' ? 'warn' : 'info', `Full diagnostics: ${message}`)
    } catch (err: any) {
      addLog('error', `Full diagnostics failed: ${err.message}`)
    } finally {
      setRunningAction(null)
    }
  }

  const applyPrivacy = async () => {
    if (!window.confirm('Будет создан backup registry и отключён доступ Windows к Location API. Продолжить?')) return
    setRunningAction('privacy-apply')
    try {
      const status = await window.electronAPI.applyLocationPrivacy()
      setPrivacy(status)
      updateSettings({ locationPrivacyEnabled: Boolean(status?.applied) })
      addLog('info', 'Location privacy применён')
    } catch (err: any) {
      addLog('error', `Не удалось применить Location privacy: ${err.message}`)
    } finally {
      setRunningAction(null)
    }
  }

  const rollbackPrivacy = async () => {
    if (!window.confirm('Будет выполнен rollback последнего backup registry для Location privacy. Продолжить?')) return
    setRunningAction('privacy-rollback')
    try {
      const status = await window.electronAPI.rollbackLocationPrivacy()
      setPrivacy(status)
      updateSettings({ locationPrivacyEnabled: Boolean(status?.applied) })
      addLog('info', 'Location privacy rollback выполнен')
    } catch (err: any) {
      addLog('error', `Не удалось откатить Location privacy: ${err.message}`)
    } finally {
      setRunningAction(null)
    }
  }

  const statusClass = (status: string) => {
    if (status === 'ok') return 'text-[var(--color-success)]'
    if (status === 'warn') return 'text-[var(--color-warning)]'
    if (status === 'fail') return 'text-[var(--color-danger)]'
    return 'text-[var(--color-text-secondary)]'
  }

  const statusIcon = (status: string) => {
    if (status === 'ok') return <CheckCircle2 className="w-4 h-4 text-[var(--color-success)] flex-shrink-0" />
    if (status === 'fail') return <TriangleAlert className="w-4 h-4 text-[var(--color-danger)] flex-shrink-0" />
    if (status === 'warn') return <TriangleAlert className="w-4 h-4 text-[var(--color-warning)] flex-shrink-0" />
    return <Info className="w-4 h-4 text-[var(--color-text-secondary)] flex-shrink-0" />
  }

  const groupedSystemDiagnostics = systemDiagnostics
    ? systemDiagnostics.items.reduce<Record<string, SystemDiagnosticItem[]>>((acc, item) => {
        acc[item.category] = acc[item.category] || []
        acc[item.category].push(item)
        return acc
      }, {})
    : null
  const importantCategories = new Set(['App', 'TUN', 'Proxy', 'Network', 'Internet', 'Routing', 'Store'])
  const routingCategories = new Set(['TUN', 'Proxy', 'Network', 'Internet', 'Routing'])
  const importantSystemItems = systemDiagnostics
    ? systemDiagnostics.items.filter(item => {
        if (item.status === 'fail') return importantCategories.has(item.category)
        if (item.status === 'warn') return routingCategories.has(item.category)
        return false
      }).slice(0, 6)
    : []

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h2 className="text-2xl font-bold text-[var(--color-text)]">Починка</h2>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">Microsoft Store, регион Windows и системная геолокация</p>
      </div>

      <MacCard className="space-y-4">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-[var(--color-accent)]" />
            <h3 className="text-sm font-semibold text-[var(--color-text)] uppercase tracking-wider">Full diagnostics</h3>
          </div>
          {systemDiagnostics && (
            <span className={`text-xs font-semibold ${statusClass(systemDiagnostics.summary)}`}>
              {systemDiagnostics.summary.toUpperCase()}
            </span>
          )}
        </div>
        <MacButton
          variant="primary"
          onClick={runSystemDiagnostics}
          disabled={Boolean(runningAction)}
          className="w-full flex items-center justify-center gap-2"
        >
          {runningAction === 'system-diagnostics' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Activity className="w-4 h-4" />}
          Run full system diagnostics
        </MacButton>
        {systemDiagnostics && groupedSystemDiagnostics && (
          <div className="space-y-4">
            <p className="text-xs text-[var(--color-text-secondary)]">Last run: {new Date(systemDiagnostics.ranAt).toLocaleString()}</p>
            <div className={`rounded-lg border p-3 space-y-2 ${
              importantSystemItems.length > 0 ? 'border-[var(--color-warning)]/30 bg-[var(--color-warning)]/10' : 'border-[var(--color-success)]/30 bg-[var(--color-success)]/10'
            }`}>
              <p className={`text-sm font-semibold ${importantSystemItems.length > 0 ? 'text-[var(--color-warning)]' : 'text-[var(--color-success)]'}`}>
                Что важно сейчас
              </p>
              {importantSystemItems.length > 0 ? (
                importantSystemItems.map(item => (
                  <div key={item.id} className="text-xs text-[var(--color-text)]">
                    <span className={`font-semibold ${statusClass(item.status)}`}>{item.label}:</span> {item.value}
                    {item.details && <p className="text-[var(--color-text-secondary)] mt-0.5 break-words">{item.details}</p>}
                  </div>
                ))
              ) : (
                <p className="text-xs text-[var(--color-text)]">
                  Критичных проблем маршрута не видно. Windows-события и старые логи ниже оставлены для истории, но они не означают, что VPNTE сейчас ломает интернет.
                </p>
              )}
            </div>
            {Object.entries(groupedSystemDiagnostics).map(([category, items]) => (
              <div key={category} className="space-y-2">
                <p className="text-xs font-semibold text-[var(--color-text-secondary)] uppercase tracking-wider">{category}</p>
                {items.map(item => (
                  <div key={item.id} className="bg-[var(--color-bg)]/60 border border-[var(--color-card-elevated)]/40 rounded-lg px-3 py-2">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-2 min-w-0">
                        {statusIcon(item.status)}
                        <span className="text-sm text-[var(--color-text)] break-words">{item.label}</span>
                      </div>
                      <span className={`text-xs font-mono text-right break-words max-w-[55%] ${statusClass(item.status)}`}>{item.value}</span>
                    </div>
                    {item.details && <p className="text-xs text-[var(--color-text-secondary)] mt-1 break-words font-mono">{item.details}</p>}
                  </div>
                ))}
              </div>
            ))}
          </div>
        )}
      </MacCard>

      <MacCard className="space-y-4">
        <div className="flex items-center gap-2">
          <Store className="w-5 h-5 text-[var(--color-accent)]" />
          <h3 className="text-sm font-semibold text-[var(--color-text)] uppercase tracking-wider">Microsoft Store</h3>
        </div>
        <MacButton
          variant="secondary"
          onClick={runStoreDiagnostics}
          disabled={Boolean(runningAction)}
          className="w-full flex items-center justify-center gap-2"
        >
          {runningAction === 'store-diagnostics' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Activity className="w-4 h-4" />}
          Глубокая диагностика Store
        </MacButton>
        <MacButton
          variant="primary"
          onClick={runQuickStoreFix}
          disabled={Boolean(runningAction)}
          className="w-full flex items-center justify-center gap-2"
        >
          {runningAction === 'store-quick' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Wrench className="w-4 h-4" />}
          Быстрая починка Store
        </MacButton>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
          {repairActions.map(({ id, label, icon: Icon, danger, confirm }) => (
            <MacButton
              key={id}
              variant={danger ? 'danger' : 'secondary'}
              onClick={() => runRepair(id, confirm)}
              disabled={Boolean(runningAction)}
              className="flex items-center justify-center gap-2 text-sm"
            >
              {runningAction === id ? <Loader2 className="w-4 h-4 animate-spin" /> : <Icon className="w-4 h-4" />}
              {label}
            </MacButton>
          ))}
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <MacButton
            variant="primary"
            onClick={applyNetworkBaseline}
            disabled={Boolean(runningAction)}
            className="flex items-center justify-center gap-2"
          >
            {runningAction === 'network-baseline' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Wrench className="w-4 h-4" />}
            Нормализовать сеть для TUN
          </MacButton>
          <MacButton
            variant="secondary"
            onClick={rollbackNetworkBaseline}
            disabled={Boolean(runningAction)}
            className="flex items-center justify-center gap-2"
          >
            {runningAction === 'network-rollback' ? <Loader2 className="w-4 h-4 animate-spin" /> : <RotateCcw className="w-4 h-4" />}
            Rollback сети
          </MacButton>
        </div>

        {/* AutoPilot manual trigger */}
        <div className="pt-2 border-t border-[var(--color-card-elevated)]/40">
          <p className="text-xs text-[var(--color-text-secondary)] mb-2">
            Автопилот определяет безопасный режим подключения (TUN / внешний прокси / soft mode).
          </p>
          <MacButton
            variant="primary"
            onClick={runManualAutoPilot}
            disabled={Boolean(runningAction) || autoPilotRunning}
            className="w-full flex items-center justify-center gap-2"
          >
            {autoPilotRunning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
            {autoPilotRunning ? 'Автопилот работает...' : 'Запустить автопилот вручную'}
          </MacButton>
        </div>

        {lastResult && <p className="text-xs text-[var(--color-text-secondary)] break-words">{lastResult}</p>}
        {storeDiagnostics && (
          <div className="space-y-2">
            <div className="flex items-center justify-between gap-3">
              <p className="text-xs text-[var(--color-text-secondary)]">Последняя проверка: {new Date(storeDiagnostics.ranAt).toLocaleString()}</p>
              <span className={`text-xs font-semibold ${statusClass(storeDiagnostics.summary)}`}>
                {storeDiagnostics.summary === 'fail' ? 'Есть ошибки' : storeDiagnostics.summary === 'warn' ? 'Есть предупреждения' : 'OK'}
              </span>
            </div>
            {storeDiagnostics.items.map(item => (
              <div key={item.id} className="bg-[var(--color-bg)]/60 border border-[var(--color-card-elevated)]/40 rounded-lg px-3 py-2">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-2 min-w-0">
                    {statusIcon(item.status)}
                    <span className="text-sm text-[var(--color-text)] break-words">{item.label}</span>
                  </div>
                  <span className={`text-xs font-mono text-right break-words max-w-[55%] ${statusClass(item.status)}`}>{item.value}</span>
                </div>
                {item.details && <p className="text-xs text-[var(--color-text-secondary)] mt-1 break-words font-mono">{item.details}</p>}
              </div>
            ))}
          </div>
        )}
      </MacCard>

      <MacCard className="space-y-4">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <MapPinOff className="w-5 h-5 text-[var(--color-warning)]" />
            <h3 className="text-sm font-semibold text-[var(--color-text)] uppercase tracking-wider">Location privacy</h3>
          </div>
          <span className={`text-sm font-semibold ${privacy?.applied ? 'text-[var(--color-success)]' : 'text-[var(--color-text-secondary)]'}`}>
            {privacy?.applied ? 'Ограничено' : 'Не ограничено'}
          </span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <MacButton
            variant="primary"
            onClick={applyPrivacy}
            disabled={Boolean(runningAction)}
            className="flex items-center justify-center gap-2"
          >
            {runningAction === 'privacy-apply' ? <Loader2 className="w-4 h-4 animate-spin" /> : <MapPinOff className="w-4 h-4" />}
            Отключить Location API
          </MacButton>
          <MacButton
            variant="secondary"
            onClick={rollbackPrivacy}
            disabled={Boolean(runningAction)}
            className="flex items-center justify-center gap-2"
          >
            {runningAction === 'privacy-rollback' ? <Loader2 className="w-4 h-4 animate-spin" /> : <RotateCcw className="w-4 h-4" />}
            Rollback privacy
          </MacButton>
        </div>
        {privacy && (
          <div className="space-y-1">
            {privacy.details.map((line, index) => (
              <p key={index} className="text-xs text-[var(--color-text-secondary)] font-mono break-words">{line}</p>
            ))}
          </div>
        )}
      </MacCard>
    </div>
  )
}
