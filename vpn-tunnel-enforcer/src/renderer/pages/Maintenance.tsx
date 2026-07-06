import { useMemo } from 'react'
import { Activity, CheckCircle2, Download, Loader2, ShieldCheck, TriangleAlert, Wrench } from 'lucide-react'
import { useAppStore } from '../store'
import { MacCard, MacButton } from '../design-system'

type MaintenanceAction = 'health-check' | 'auto-repair' | 'export-zip' | 'nuclear-reset'
type HealthStatus = 'ok' | 'warn' | 'fail' | 'info'

interface DiagnosticItem {
  id: string
  label: string
  status: HealthStatus
  value: string
  details?: string
  category: string
}

interface SystemDiagnosticResult {
  ranAt: number
  summary: HealthStatus
  items: DiagnosticItem[]
}

interface FirewallRepairHealth {
  protectedTunnelActive?: boolean
  manifestPresent: boolean
  ourRuleCount: number
  stuckBlockDefault: boolean
  services: Array<{ name: string; status: string }>
  profiles: Array<{ name: string; enabled: string; defaultInbound: string; defaultOutbound: string }>
  summary: 'ok' | 'warn' | 'fail'
  message: string
  recommendedActions: string[]
}

interface RepairStep {
  id: string
  label: string
  status: 'pending' | 'running' | 'ok' | 'warn' | 'fail'
  detail?: string
}

const AUTO_REPAIR_STEPS: Array<{ id: string; label: string; run: () => Promise<any> }> = [
  {
    id: 'firewall',
    label: 'Firewall: убрать только правила VPNTE и восстановить outbound policy',
    run: () => window.electronAPI.firewallRepairVpnteRules()
  },
  {
    id: 'network-baseline',
    label: 'Windows proxy baseline: откатить WinHTTP/WinINet/env proxy из backup',
    run: () => window.electronAPI.rollbackTunNetworkBaseline()
  },
  {
    id: 'adapter-lockdown',
    label: 'Адаптеры: откатить DNS/IPv6 lockdown по manifest',
    run: () => window.electronAPI.rollbackAdapterLockdown()
  },
  {
    id: 'orphaned-dns',
    label: 'DNS: убрать осиротевший manual VPNTE DNS с физических адаптеров',
    run: () => window.electronAPI.repairOrphanedDns()
  },
  {
    id: 'runtime',
    label: 'Runtime: завершить только зависшие процессы VPNTE из tun-runtime',
    run: () => window.electronAPI.killStaleSingbox()
  }
]

function statusClass(status: HealthStatus | RepairStep['status']) {
  if (status === 'ok') return 'text-[var(--color-success)]'
  if (status === 'warn') return 'text-[var(--color-warning)]'
  if (status === 'fail') return 'text-[var(--color-danger)]'
  if (status === 'running') return 'text-[var(--color-accent)]'
  return 'text-[var(--color-text-secondary)]'
}

function statusIcon(status: HealthStatus | RepairStep['status']) {
  if (status === 'running') return <Loader2 className="w-4 h-4 animate-spin text-[var(--color-accent)] flex-shrink-0" />
  if (status === 'ok') return <CheckCircle2 className="w-4 h-4 text-[var(--color-success)] flex-shrink-0" />
  if (status === 'fail') return <TriangleAlert className="w-4 h-4 text-[var(--color-danger)] flex-shrink-0" />
  if (status === 'warn') return <TriangleAlert className="w-4 h-4 text-[var(--color-warning)] flex-shrink-0" />
  return <Activity className="w-4 h-4 text-[var(--color-text-secondary)] flex-shrink-0" />
}

function firewallBlockDefaultLabel(health: FirewallRepairHealth): string {
  if (health.protectedTunnelActive && health.summary === 'ok' && health.stuckBlockDefault) {
    return 'активная защита'
  }
  return health.stuckBlockDefault ? 'залипший Block' : 'нет'
}

function stepStatusFromResult(result: any): RepairStep['status'] {
  if (result?.success === false) return 'fail'
  if (result?.blocked === true || result?.warning === true) return 'warn'
  return 'ok'
}

function resultDetail(result: any): string {
  if (!result) return 'Готово'
  if (typeof result.message === 'string') return result.message
  if (typeof result.details === 'string') return result.details
  if (Array.isArray(result.adapters)) {
    return result.adapters.length > 0 ? `Адаптеры: ${result.adapters.join(', ')}` : 'Изменений не потребовалось'
  }
  if (typeof result.rolledBack === 'boolean') return result.rolledBack ? 'Откат выполнен' : 'Активный manifest не найден'
  return 'Готово'
}

function importantItems(systemDiagnostics: SystemDiagnosticResult | null): DiagnosticItem[] {
  if (!systemDiagnostics) return []
  const importantCategories = new Set(['App', 'TUN', 'Proxy', 'Network', 'Internet', 'Routing'])
  const routingCategories = new Set(['TUN', 'Proxy', 'Network', 'Internet', 'Routing'])
  return systemDiagnostics.items
    .filter((item) => {
      if (item.status === 'fail') return importantCategories.has(item.category)
      if (item.status === 'warn') return routingCategories.has(item.category)
      return false
    })
    .slice(0, 8)
}

function maintenanceSystemSummary(systemDiagnostics: SystemDiagnosticResult | null): HealthStatus {
  if (!systemDiagnostics) return 'info'
  const maintenanceCategories = new Set(['App', 'TUN', 'Proxy', 'Network', 'Internet', 'Routing'])
  const visibleItems = systemDiagnostics.items.filter(item => maintenanceCategories.has(item.category))
  if (visibleItems.some(item => item.status === 'fail')) return 'fail'
  if (visibleItems.some(item => item.status === 'warn')) return 'warn'
  return 'ok'
}

export function Maintenance() {
  const addLog = useAppStore(s => s.addLog)
  const lastResult = useAppStore(s => s.maintenanceLastResult)
  const setLastResult = useAppStore(s => s.setMaintenanceLastResult)
  const runningAction = useAppStore(s => s.maintenanceRunningAction) as MaintenanceAction | null
  const setRunningAction = useAppStore(s => s.setMaintenanceRunningAction)
  const systemDiagnostics = useAppStore(s => s.maintenanceSystemDiagnostics) as SystemDiagnosticResult | null
  const setSystemDiagnostics = useAppStore(s => s.setMaintenanceSystemDiagnostics)
  const firewallHealth = useAppStore(s => s.maintenanceFirewallHealth) as FirewallRepairHealth | null
  const setFirewallHealth = useAppStore(s => s.setMaintenanceFirewallHealth)
  const storedRepairSteps = useAppStore(s => s.maintenanceRepairSteps) as RepairStep[] | null
  const setStoredRepairSteps = useAppStore(s => s.setMaintenanceRepairSteps)
  const repairSteps = storedRepairSteps ?? AUTO_REPAIR_STEPS.map(step => ({ id: step.id, label: step.label, status: 'pending' as const }))

  const important = useMemo(() => importantItems(systemDiagnostics), [systemDiagnostics])
  const systemSummary = useMemo(() => maintenanceSystemSummary(systemDiagnostics), [systemDiagnostics])
  const healthSummary: HealthStatus = firewallHealth?.summary === 'fail' || systemSummary === 'fail'
    ? 'fail'
    : firewallHealth?.summary === 'warn' || systemSummary === 'warn'
      ? 'warn'
      : systemDiagnostics || firewallHealth
        ? 'ok'
        : 'info'

  const runHealthCheck = async () => {
    setRunningAction('health-check')
    addLog('info', 'Починка: запуск health-check')
    try {
      const [system, firewall] = await Promise.all([
        window.electronAPI.runSystemDiagnostics(),
        window.electronAPI.firewallRepairHealth()
      ])
      setSystemDiagnostics(system)
      setFirewallHealth(firewall)
      const visibleSystemSummary = maintenanceSystemSummary(system)
      const message = firewall.summary === 'ok' && visibleSystemSummary === 'ok'
        ? 'Критичных проблем восстановления не найдено'
        : 'Health-check завершён: есть пункты для внимания'
      setLastResult(message)
      addLog(visibleSystemSummary === 'fail' || firewall.summary === 'fail' ? 'error' : visibleSystemSummary === 'warn' || firewall.summary === 'warn' ? 'warn' : 'info', message)
      return { system, firewall }
    } catch (err: any) {
      const message = `Health-check failed: ${err?.message || err}`
      setLastResult(message)
      addLog('error', message)
      useAppStore.getState().addGlobalToast('error', 'Починка', message)
      return null
    } finally {
      setRunningAction(null)
    }
  }

  const runAutoRepair = async () => {
    if (!window.confirm('Выполнить безопасную авто-починку? Будут затронуты только VPNTE firewall rules, VPNTE network baseline, VPNTE adapter lockdown, осиротевший VPNTE DNS и процессы VPNTE runtime.')) return
    setRunningAction('auto-repair')
    setStoredRepairSteps(AUTO_REPAIR_STEPS.map(step => ({ id: step.id, label: step.label, status: 'pending' })))
    addLog('warn', 'Починка: запуск безопасной авто-починки')

    const nextSteps: RepairStep[] = AUTO_REPAIR_STEPS.map(step => ({ id: step.id, label: step.label, status: 'pending' }))
    const setStep = (id: string, patch: Partial<RepairStep>) => {
      const index = nextSteps.findIndex(step => step.id === id)
      if (index >= 0) nextSteps[index] = { ...nextSteps[index], ...patch }
      setStoredRepairSteps([...nextSteps])
    }

    try {
      for (const step of AUTO_REPAIR_STEPS) {
        setStep(step.id, { status: 'running', detail: 'Выполняется...' })
        try {
          const result = await step.run()
          const status = stepStatusFromResult(result)
          const detail = resultDetail(result)
          setStep(step.id, { status, detail })
          addLog(status === 'fail' ? 'error' : status === 'warn' ? 'warn' : 'info', `${step.label}: ${detail}`)
        } catch (err: any) {
          const detail = err?.message || String(err)
          setStep(step.id, { status: 'fail', detail })
          addLog('error', `${step.label}: ${detail}`)
        }
      }

      const [system, firewall] = await Promise.all([
        window.electronAPI.runSystemDiagnostics(),
        window.electronAPI.firewallRepairHealth()
      ])
      setSystemDiagnostics(system)
      setFirewallHealth(firewall)
      const failed = nextSteps.some(step => step.status === 'fail')
      const message = failed ? 'Авто-починка завершена с ошибками' : 'Авто-починка завершена'
      setLastResult(message)
      useAppStore.getState().addGlobalToast(failed ? 'warning' : 'success', 'Починка', message)
    } finally {
      setRunningAction(null)
    }
  }

  const exportZip = async () => {
    setRunningAction('export-zip')
    addLog('info', 'Починка: экспорт диагностики в ZIP')
    try {
      const result = await window.electronAPI.exportDiagnostics()
      if (result?.success && result.path) {
        const message = `Диагностика сохранена: ${result.path}`
        setLastResult(message)
        useAppStore.getState().addGlobalToast('success', 'Диагностика', message)
      } else if (!result?.cancelled) {
        throw new Error(result?.error || 'Экспорт не выполнен')
      }
    } catch (err: any) {
      const message = err?.message || String(err)
      setLastResult(message)
      useAppStore.getState().addGlobalToast('error', 'Диагностика', message)
    } finally {
      setRunningAction(null)
    }
  }

  const emergencyFirewallReset = async () => {
    if (!window.confirm('Аварийно сбросить Windows Firewall к настройкам по умолчанию? Это удалит ВСЕ правила Windows Firewall, включая правила других программ. Перед сбросом VPNTE сохранит .wfw backup.')) return
    setRunningAction('nuclear-reset')
    addLog('warn', 'Починка: аварийный reset Windows Firewall')
    try {
      const result = await window.electronAPI.firewallNuclearReset('RESET_WINDOWS_FIREWALL_CONFIRMED')
      setLastResult(result.message || 'Windows Firewall reset выполнен')
      setFirewallHealth(await window.electronAPI.firewallRepairHealth())
      useAppStore.getState().addGlobalToast(result.success ? 'success' : 'error', 'Firewall', result.message)
    } catch (err: any) {
      const message = err?.message || String(err)
      setLastResult(message)
      useAppStore.getState().addGlobalToast('error', 'Firewall', message)
    } finally {
      setRunningAction(null)
    }
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h2 className="text-2xl font-bold text-[var(--color-text)]">Починка</h2>
        <p className="text-sm text-[var(--color-text-secondary)] mt-1">
          Проверка и восстановление VPNTE-сети без лишних legacy-действий.
        </p>
      </div>

      <MacCard className="space-y-4">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-[var(--color-accent)]" />
            <h3 className="text-sm font-semibold text-[var(--color-text)] uppercase tracking-wider">Состояние</h3>
          </div>
          <span className={`text-xs font-semibold ${statusClass(healthSummary)}`}>
            {healthSummary === 'info' ? 'НЕ ПРОВЕРЕНО' : healthSummary.toUpperCase()}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <MacButton
            variant="primary"
            onClick={runHealthCheck}
            disabled={Boolean(runningAction)}
            className="flex items-center justify-center gap-2"
          >
            {runningAction === 'health-check' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Activity className="w-4 h-4" />}
            Проверить
          </MacButton>
          <MacButton
            variant="primary"
            onClick={runAutoRepair}
            disabled={Boolean(runningAction)}
            className="flex items-center justify-center gap-2"
          >
            {runningAction === 'auto-repair' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Wrench className="w-4 h-4" />}
            Починить
          </MacButton>
          <MacButton
            variant="secondary"
            onClick={exportZip}
            disabled={Boolean(runningAction)}
            className="flex items-center justify-center gap-2"
          >
            {runningAction === 'export-zip' ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
            ZIP
          </MacButton>
        </div>

        {lastResult && (
          <p className="text-xs text-[var(--color-text-secondary)] break-words">{lastResult}</p>
        )}
      </MacCard>

      <MacCard className="space-y-3">
        <div className="flex items-center gap-2">
          <Wrench className="w-5 h-5 text-[var(--color-warning)]" />
          <h3 className="text-sm font-semibold text-[var(--color-text)] uppercase tracking-wider">Что делает авто-починка</h3>
        </div>
        <div className="space-y-2">
          {repairSteps.map(step => (
            <div key={step.id} className="bg-[var(--color-bg)]/60 border border-[var(--color-card-elevated)]/40 rounded-lg px-3 py-2">
              <div className="flex items-start gap-2">
                {statusIcon(step.status)}
                <div className="min-w-0">
                  <p className="text-sm text-[var(--color-text)] break-words">{step.label}</p>
                  {step.detail && <p className={`text-xs mt-0.5 break-words ${statusClass(step.status)}`}>{step.detail}</p>}
                </div>
              </div>
            </div>
          ))}
        </div>
      </MacCard>

      {(firewallHealth || important.length > 0) && (
        <MacCard className="space-y-3">
          <div className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-[var(--color-accent)]" />
            <h3 className="text-sm font-semibold text-[var(--color-text)] uppercase tracking-wider">Результаты проверки</h3>
          </div>

          {firewallHealth && (
            <div className="bg-[var(--color-bg)]/60 border border-[var(--color-card-elevated)]/40 rounded-lg px-3 py-2 space-y-1">
              <div className="flex items-center justify-between gap-3">
                <span className="text-sm text-[var(--color-text)]">Firewall VPNTE</span>
                <span className={`text-xs font-semibold ${statusClass(firewallHealth.summary)}`}>{firewallHealth.summary.toUpperCase()}</span>
              </div>
              <p className="text-xs text-[var(--color-text-secondary)] break-words">{firewallHealth.message}</p>
              <p className="text-xs text-[var(--color-text-secondary)] break-words">
                VPNTE rules: {firewallHealth.ourRuleCount}; manifest: {firewallHealth.manifestPresent ? 'есть' : 'нет'}; block default: {firewallBlockDefaultLabel(firewallHealth)}
              </p>
              {firewallHealth.recommendedActions.length > 0 && (
                <p className="text-xs text-[var(--color-warning)] break-words">
                  Действия: {firewallHealth.recommendedActions.join('; ')}
                </p>
              )}
            </div>
          )}

          {important.length > 0 ? (
            important.map(item => (
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
            ))
          ) : systemDiagnostics ? (
            <p className="text-xs text-[var(--color-text-secondary)]">Критичных сетевых пунктов диагностика не показала.</p>
          ) : null}
        </MacCard>
      )}

      <MacCard className="space-y-3 border border-[var(--color-danger)]/30">
        <div className="flex items-center gap-2">
          <TriangleAlert className="w-5 h-5 text-[var(--color-danger)]" />
          <h3 className="text-sm font-semibold text-[var(--color-text)] uppercase tracking-wider">Аварийно</h3>
        </div>
        <p className="text-xs text-[var(--color-text-secondary)]">
          Полный reset Windows Firewall удаляет все firewall rules Windows. Используйте только если targeted-починка не вернула сеть.
        </p>
        <MacButton
          variant="danger"
          onClick={emergencyFirewallReset}
          disabled={Boolean(runningAction)}
          className="flex items-center justify-center gap-2"
        >
          {runningAction === 'nuclear-reset' ? <Loader2 className="w-4 h-4 animate-spin" /> : <TriangleAlert className="w-4 h-4" />}
          Reset Windows Firewall
        </MacButton>
      </MacCard>
    </div>
  )
}
