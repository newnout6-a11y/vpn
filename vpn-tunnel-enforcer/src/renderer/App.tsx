import { useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useAppStore } from './store'
import { Sidebar, type SidebarPage } from './components/Sidebar'
import { FirstRunWizard } from './components/FirstRunWizard'
import { ThemeProvider } from './providers/ThemeProvider'
import { Dashboard } from './pages/Dashboard'
import { SplitTunnel } from './pages/SplitTunnel'
import { Servers } from './pages/Servers'
import { SpeedTest } from './pages/SpeedTest'
import { TrafficHistory } from './pages/TrafficHistory'
import { Schedule } from './pages/Schedule'
import { Settings } from './pages/Settings'
import { Logs } from './pages/Logs'
import { Maintenance } from './pages/Maintenance'
import type { AppSettings, LeakCheckResult, TrafficStats } from './store'
import { NAV_EVENT, type AppPage } from './nav'

declare global {
  interface Window {
    electronAPI: {
      detectHapp: () => Promise<any>
      getPublicIp: () => Promise<{ ip: string | null; isLeak: boolean; vpnIp: string | null }>
      startTun: (proxyAddr: string, proxyType?: 'socks5' | 'http') => Promise<{ success: boolean; error?: string; warning?: string | null; vpnIp?: string | null }>
      startDirectVpn: () => Promise<{ success: boolean; error?: string; warning?: string | null; vpnIp?: string | null }>
      stopTun: () => Promise<{ success: boolean; error?: string }>
      getTunStatus: () => Promise<{ running: boolean; proxyAddr: string | null; proxyType: 'socks5' | 'http' | null; pid: number | null; warning?: string | null; startedAt?: number | null; restartAttempt?: number }>
      getTrafficStats: () => Promise<TrafficStats>
      applyAutoconfig: (targets: string[], proxyAddr: string, proxyType?: 'socks5' | 'http') => Promise<Record<string, boolean>>
      rollbackAutoconfig: (targets: string[]) => Promise<Record<string, boolean>>
      getAutoconfigStatus: () => Promise<any[]>
      getSettings: () => Promise<AppSettings>
      saveSettings: (settings: Partial<AppSettings>) => Promise<AppSettings>
      inspectVpnInput: (input: string) => Promise<{ count: number; protocols: Record<string, number>; profiles: Array<{ index: number; name: string; protocol: string }>; fetched: boolean; source: string }>
      setLoginItem: (openAtLogin: boolean) => Promise<AppSettings>
      runLeakCheck: (options?: { proxyAddr?: string; proxyType?: 'socks5' | 'http' }) => Promise<LeakCheckResult>
      runStoreRepair: (action: string) => Promise<{ success: boolean; message: string; details?: string }>
      runStoreDiagnostics: () => Promise<any>
      runSystemDiagnostics: () => Promise<any>
      getRoutingPlan: () => Promise<any>
      applyBrowserLeakProtection: () => Promise<any>
      rollbackBrowserLeakProtection: () => Promise<any>
      runAutoPilot: () => Promise<any>
      logRenderer: (level: 'debug' | 'info' | 'warn' | 'error', message: string) => Promise<any>
      getFullLogs: () => Promise<any>
      clearAppLog: () => Promise<any>
      applyTunNetworkBaseline: () => Promise<any>
      rollbackTunNetworkBaseline: () => Promise<any>
      disableFirewallKillSwitch: () => Promise<{ success: boolean; message: string }>
      getFirewallKillSwitchStatus: () => Promise<{ active: boolean }>
      getLocationPrivacy: () => Promise<any>
      applyLocationPrivacy: () => Promise<any>
      rollbackLocationPrivacy: () => Promise<any>
      openTunLogFolder: () => Promise<string>
      openLogFolder: () => Promise<string>
      exportDiagnostics: () => Promise<{ success: boolean; path?: string; error?: string; cancelled?: boolean }>
      runLeakSelfTest: () => Promise<LeakSelfTestResult>
      openSnapshotsFolder: () => Promise<{ success: boolean; path?: string; error?: string }>
      // Split Tunneling
      splitTunnelGetApps: () => Promise<import('../shared/ipc-types').SplitTunnelApp[]>
      splitTunnelSetRule: (appId: string, rule: 'vpn' | 'direct' | 'none') => Promise<void>
      splitTunnelAddApp: (exePath: string) => Promise<import('../shared/ipc-types').SplitTunnelApp>
      splitTunnelRemoveApp: (appId: string) => Promise<void>
      // Server Picker
      serversList: () => Promise<import('../shared/ipc-types').ServerProfile[]>
      serversSelect: (id: string) => Promise<void>
      serversGetActive: () => Promise<{ profile: import('../shared/ipc-types').ServerProfile | null; activeId: string | null }>
      serversPingAll: () => Promise<import('../shared/ipc-types').ServerProfile[]>
      serversPingOne: (host: string, port: number) => Promise<number | null>
      serversAdd: (input: string) => Promise<import('../shared/ipc-types').ServerProfile[]>
      serversRemove: (id: string) => Promise<void>
      serversExportKey: (id: string) => Promise<
        | { ok: true; uri: string; name: string; protocol: string }
        | { ok: false; reason: string; protocol?: string }
      >
      serversExportKeyToFile: (id: string) => Promise<
        | { ok: true; path: string; uri: string; name: string; protocol: string }
        | { ok: false; cancelled: true }
        | { ok: false; reason: string; protocol?: string; error?: string }
      >
      serverProbe: (host: string, knownPort?: number) => Promise<any>
      // Kill-Switch
      killSwitchGetLevel: () => Promise<import('../shared/ipc-types').KillSwitchLevel>
      killSwitchSetLevel: (level: import('../shared/ipc-types').KillSwitchLevel) => Promise<any>
      killSwitchGetExceptions: () => Promise<import('../shared/ipc-types').KillSwitchException[]>
      killSwitchAddException: (exception: Omit<import('../shared/ipc-types').KillSwitchException, 'id'>) => Promise<import('../shared/ipc-types').KillSwitchException>
      killSwitchRemoveException: (id: string) => Promise<any>
      killSwitchBrowseApp: () => Promise<{ path: string; name: string } | null>
      onIpChanged: (callback: (data: { ip: string; isLeak: boolean }) => void) => () => void
      onTunStatusChanged: (callback: (status: string) => void) => () => void
      onTrafficStats: (callback: (stats: TrafficStats) => void) => () => void
      onLeakDetected: (callback: (result: LeakSelfTestResult) => void) => () => void
      onMainError: (callback: (data: { code: string; message: string }) => void) => () => void
      // Speed Test
      speedTestRun: () => Promise<import('../shared/ipc-types').SpeedTestResult>
      speedTestHistory: () => Promise<import('../shared/ipc-types').SpeedTestResult[]>
      onSpeedTestProgress: (callback: (data: { percent: number; phase: string }) => void) => () => void
      // DNS Profiles
      dnsList: () => Promise<import('../shared/ipc-types').DnsProfile[]>
      dnsCreate: (profile: { name: string; primary: string; secondary: string; type: 'plain' | 'doh' | 'dot' }) => Promise<import('../shared/ipc-types').DnsProfile>
      dnsDelete: (id: string) => Promise<void>
      dnsSelect: (id: string) => Promise<void>
      dnsValidate: (address: string) => Promise<{ valid: boolean; type: 'plain' | 'doh' | 'dot'; error?: string }>
      // Connection History
      connectionHistoryList: () => Promise<import('../shared/ipc-types').ConnectionLogEntry[]>
      connectionHistoryFilter: (filters: any) => Promise<import('../shared/ipc-types').ConnectionLogEntry[]>
      connectionHistoryStats: (period: 'day' | 'week' | 'month') => Promise<{ totalTimeMs: number; totalBytesDown: number; totalBytesUp: number; entryCount: number }>
      connectionHistoryExportCsv: () => Promise<string>
      connectionHistoryExportJson: () => Promise<string>
      // Traffic History
      trafficHistoryList: (vpnIp?: string) => Promise<Array<{ domain: string; firstSeen: number; lastSeen: number; count: number; vpnIp: string | null }>>
      trafficHistoryClear: () => Promise<{ success: boolean }>
      // Domain Routing
      domainRoutingList: () => Promise<import('../shared/ipc-types').DomainRule[]>
      domainRoutingAdd: (rule: { pattern: string; action: 'vpn' | 'direct' | 'block'; priority: number }) => Promise<import('../shared/ipc-types').DomainRule>
      domainRoutingUpdate: (id: string, patch: Partial<import('../shared/ipc-types').DomainRule>) => Promise<import('../shared/ipc-types').DomainRule>
      domainRoutingDelete: (id: string) => Promise<void>
      domainRoutingReorder: (ids: string[]) => Promise<import('../shared/ipc-types').DomainRule[]>
      domainRoutingImport: (filePath: string) => Promise<import('../shared/ipc-types').DomainRule[]>
      domainRoutingResetHits: () => Promise<void>
      domainRoutingBrowseFile: () => Promise<string | null>
      // Scheduler
      schedulerList: () => Promise<import('../shared/ipc-types').ScheduleEntry[]>
      schedulerCreate: (entry: Omit<import('../shared/ipc-types').ScheduleEntry, 'id'>) => Promise<import('../shared/ipc-types').ScheduleEntry>
      schedulerUpdate: (id: string, patch: Partial<import('../shared/ipc-types').ScheduleEntry>) => Promise<import('../shared/ipc-types').ScheduleEntry>
      schedulerDelete: (id: string) => Promise<void>
      schedulerNextEvent: () => Promise<{ type: 'start' | 'stop'; at: number; schedule: import('../shared/ipc-types').ScheduleEntry } | null>
      // Profile Rotation
      rotationGetConfig: () => Promise<import('../shared/ipc-types').RotationConfig>
      rotationSetConfig: (config: Partial<import('../shared/ipc-types').RotationConfig>) => Promise<import('../shared/ipc-types').RotationConfig>
      rotationRotateNow: () => Promise<{ success: boolean; newProfile: string }>
      // Config Import/Export
      configExport: () => Promise<{ success: boolean; path?: string; error?: string }>
      configBrowseImport: () => Promise<string | null>
      configImport: (filePath: string) => Promise<{ success: boolean; sections: string[]; conflicts: string[]; error?: string }>
      configImportApply: (filePath: string, sections: string[], conflictResolution: 'replace' | 'merge') => Promise<{ success: boolean; error?: string }>
      // Notification Preferences
      notificationsGetPrefs: () => Promise<import('../shared/ipc-types').NotificationPreferences>
      notificationsSetPrefs: (prefs: Partial<import('../shared/ipc-types').NotificationPreferences>) => Promise<import('../shared/ipc-types').NotificationPreferences>
      // Theme
      themeGetActive: () => Promise<import('../shared/ipc-types').ThemeConfig>
      themeList: () => Promise<import('../shared/ipc-types').ThemeConfig[]>
      themeSetActive: (id: string) => Promise<void>
      onThemeChanged: (callback: (theme: import('../shared/ipc-types').ThemeConfig) => void) => () => void
      // i18n
      i18nGetLocale: () => Promise<string>
      i18nSetLocale: (locale: string) => Promise<void>
      // Widgets
      getWidgetLayout: () => Promise<import('../shared/ipc-types').WidgetLayout[]>
      setWidgetLayout: (layout: import('../shared/ipc-types').WidgetLayout[]) => Promise<void>
    }
  }
}

export interface LeakSelfTestAdapter {
  alias: string
  ipv4: string | null
  publicIpViaThisAdapter: string | null
  curlExitCode: number | null
  curlStderrTail: string | null
}
export interface LeakSelfTestResult {
  ts: number
  physicalAdapterReached: boolean
  publicIpMismatch: boolean
  defaultRoutePublicIp: string | null
  perAdapter: LeakSelfTestAdapter[]
  summary: string
}

type Page = SidebarPage | 'maintenance'

import { useState } from 'react'

function proxyFromOverride(settings: AppSettings) {
  const raw = settings.proxyOverride.trim()
  const separator = raw.lastIndexOf(':')
  if (separator <= 0 || separator === raw.length - 1) return null
  const host = raw.slice(0, separator).trim()
  const port = parseInt(raw.slice(separator + 1), 10)
  if (!host || !Number.isInteger(port) || port <= 0 || port > 65535) return null
  return { host, port, type: settings.proxyType, verified: true, publicIpViaProxy: null }
}

export default function App() {
  const [page, setPage] = useState<Page>('dashboard')
  const addLog = useAppStore(s => s.addLog)

  // Listen for IPC events
  useEffect(() => {
    const unsubIp = window.electronAPI.onIpChanged(({ ip, isLeak }) => {
      useAppStore.getState().setPublicIp(ip, isLeak)
      if (isLeak) {
        addLog('error', `ОБНАРУЖЕНА УТЕЧКА IP! Текущий: ${ip}`)
      } else {
        addLog('info', `Публичный IP: ${ip}`)
      }
    })

    const unsubTun = window.electronAPI.onTunStatusChanged((status) => {
      const store = useAppStore.getState()
      // 'proxy-down' means TUN is still up but upstream proxy is unreachable — we keep
      // tunRunning=true so the kill-switch state is reflected (traffic blocked, not leaked).
      // 'killswitch-active' means sing-box died unexpectedly, TUN is gone, but the
      // firewall kill-switch is still blocking outbound traffic on the physical adapter.
      // 'restarting:N/M' is fired by the auto-restart loop while we wait between
      // attempts — TUN is down but we expect it to come back without user action.
      const isRestarting = status.startsWith('restarting:')
      const tunUp = status === 'running' || status === 'proxy-down'
      store.setTunRunning(tunUp)
      store.setRestarting(isRestarting ? status.slice('restarting:'.length) : null)
      if (!tunUp && !isRestarting && store.mode === 'hard') store.setMode('off')
      if (status === 'running') {
        addLog('info', 'Защита включена — весь трафик идёт через VPN.')
      } else if (status === 'stopped') {
        addLog('info', 'Защита выключена. Трафик идёт по обычному маршруту.')
      } else if (status === 'proxy-down') {
        addLog('warn', 'VPN-сервер не отвечает — трафик заблокирован для безопасности. Проверьте ваш VPN-клиент (Happ).')
      } else if (status === 'killswitch-active') {
        addLog('error', 'sing-box упал. Файрвол блокирует весь трафик, пока вы не перезапустите защиту.')
      } else if (isRestarting) {
        const [n, total] = status.slice('restarting:'.length).split('/')
        addLog('warn', `Авто-перезапуск защиты (попытка ${n} из ${total})…`)
      } else {
        addLog('info', `Статус TUN: ${status}`)
      }
      // Refresh kill-switch state after every TUN transition so the Dashboard
      // banner reflects reality without polling.
      window.electronAPI.getFirewallKillSwitchStatus()
        .then(({ active }) => store.setFirewallKillSwitchActive(active))
        .catch(() => undefined)
      // Pull the fresh startedAt from main so the uptime pill is correct.
      window.electronAPI.getTunStatus()
        .then((s) => store.setTunStartedAt(s.startedAt ?? null))
        .catch(() => undefined)
    })

    const unsubTraffic = window.electronAPI.onTrafficStats((stats) => {
      useAppStore.getState().setTrafficStats(stats)
    })

    const unsubLeak = window.electronAPI.onLeakDetected((result) => {
      const store = useAppStore.getState()
      store.setLeakSelfTestResult(result)
      addLog('error', `УТЕЧКА: ${result.summary}`)
    })

    const unsubMainErr = window.electronAPI.onMainError(({ code, message }) => {
      const store = useAppStore.getState()
      store.setLastMainError({ code, message, ts: Date.now() })
      addLog('error', `Ошибка main-процесса (поймана хэндлером, app не упал): ${code} — ${message}`)
    })

    return () => {
      unsubIp()
      unsubTun()
      unsubTraffic()
      unsubLeak()
      unsubMainErr()
    }
  }, [addLog])

  // Initial detection
  useEffect(() => {
    async function init() {
      const store = useAppStore.getState()
      store.setDetecting(true)

      let settings = store.settings
      try {
        settings = await window.electronAPI.getSettings()
        store.setSettings(settings)
      } catch (err: any) {
        addLog('warn', `Не удалось загрузить настройки: ${err.message}`)
      }

      const manualProxy = settings.connectionMode === 'directVpn' ? null : proxyFromOverride(settings)
      if (settings.connectionMode === 'directVpn') {
        store.setProxy(null)
        addLog('info', 'Режим Direct VPN: Happ не используется.')
      } else if (manualProxy) {
        store.setProxy(manualProxy)
        addLog('info', `Используется ручной прокси: ${manualProxy.host}:${manualProxy.port} (${manualProxy.type})`)
      } else {
        addLog('info', 'Поиск прокси Happ...')

        try {
          const proxy = await window.electronAPI.detectHapp()
          if (proxy) {
            store.setProxy(proxy)
            addLog('info', `Прокси Happ найдено: ${proxy.host}:${proxy.port} (${proxy.type})`)
          } else {
            addLog('warn', 'Прокси Happ не найдено автоматически')
          }
        } catch (err: any) {
          addLog('error', `Ошибка поиска: ${err.message}`)
        }
      }

      if (settings.autoPilotEnabled && settings.connectionMode !== 'directVpn') {
        try {
          addLog('info', 'Автопилот маршрута включен: приложение само выберет безопасный режим.')
          const autoPilot = await window.electronAPI.runAutoPilot()
          store.setMode(autoPilot.mode)
          store.setTunRunning(autoPilot.mode === 'hard')
          if (autoPilot.mode !== 'hard') store.setVpnIp(null)
          addLog(
            autoPilot.summary === 'fail' ? 'error' : autoPilot.summary === 'warn' ? 'warn' : 'info',
            `${autoPilot.title}: ${autoPilot.message}`
          )
        } catch (err: any) {
          addLog('error', `Автопилот маршрута не сработал: ${err.message}`)
        }
      } else {
        try {
          const plan = await window.electronAPI.getRoutingPlan()
          if (plan.recommendedMode === 'external') store.setMode('external')
          addLog(plan.status === 'broken' || plan.status === 'blocked' ? 'warn' : 'info', `План маршрута: ${plan.title}`)
        } catch (err: any) {
          addLog('warn', `Не удалось построить план маршрута: ${err.message}`)
        }
      }

      try {
        const ipInfo = await window.electronAPI.getPublicIp()
        store.setPublicIp(ipInfo.ip, ipInfo.isLeak)
        if (ipInfo.ip) addLog('info', `Текущий публичный IP: ${ipInfo.ip}`)
      } catch (err: any) {
        addLog('error', `Ошибка проверки IP: ${err.message}`)
      }

      try {
        const tunStatus = await window.electronAPI.getTunStatus()
        store.setTunRunning(tunStatus.running)
        store.setTunStartedAt(tunStatus.startedAt ?? null)
        if (tunStatus.running) store.setMode('hard')
        else if (useAppStore.getState().mode === 'hard' && settings.autoPilotEnabled) store.setMode('off')
      } catch { /* */ }

      try {
        const traffic = await window.electronAPI.getTrafficStats()
        store.setTrafficStats(traffic)
      } catch { /* */ }

      try {
        const ks = await window.electronAPI.getFirewallKillSwitchStatus()
        store.setFirewallKillSwitchActive(ks.active)
      } catch { /* */ }

      try {
        const targets = await window.electronAPI.getAutoconfigStatus()
        if (targets.length > 0) {
          const current = store.autoconfigTargets
          store.setAutoconfigTargets(current.map(t => {
            const found = targets.find((x: any) => x.id === t.id)
            return { ...t, applied: found?.applied ?? false }
          }))
        }
      } catch { /* */ }

      try {
        const privacy = await window.electronAPI.getLocationPrivacy()
        store.updateSettings({ locationPrivacyEnabled: Boolean(privacy?.applied) })
      } catch { /* */ }

      store.setDetecting(false)
    }
    init()
  }, [])

  // Periodic auto-recheck of the Happ proxy. If the user closes/reopens Happ,
  // it can come back on a different port (Happ rotates ports between launches
  // sometimes). We re-detect every 90s and silently update the store. The
  // recheck is skipped while the user has a manual proxyOverride set, while
  // TUN is up (changing the address mid-flight would be confusing), and
  // while we're inside the auto-restart loop.
  useEffect(() => {
    const interval = setInterval(async () => {
      const state = useAppStore.getState()
      if (state.tunRunning) return
      if (state.restartingProgress !== null) return
      if (state.settings.connectionMode === 'directVpn') return
      if (state.settings.proxyOverride.trim()) return
      try {
        const fresh = await window.electronAPI.detectHapp()
        if (!fresh) return
        const current = useAppStore.getState().proxy
        const changed =
          !current ||
          current.host !== fresh.host ||
          current.port !== fresh.port ||
          current.type !== fresh.type
        if (changed) {
          useAppStore.getState().setProxy(fresh)
          addLog('info', `Happ переехал — обновили адрес: ${fresh.host}:${fresh.port} (${fresh.type})`)
        }
      } catch {
        // Stay quiet: Happ может быть просто выключен.
      }
    }, 90000)
    return () => clearInterval(interval)
  }, [addLog])

  // Listen for navigation requests from deep components (e.g. inline links
  // in cards/modals). They dispatch a CustomEvent that we translate into a
  // setPage call here so the rest of the app doesn't need to know about the
  // page state machine.
  useEffect(() => {
    const handler = (e: Event) => {
      const target = (e as CustomEvent<AppPage>).detail
      if (target) setPage(target as Page)
    }
    window.addEventListener(NAV_EVENT, handler)
    return () => window.removeEventListener(NAV_EVENT, handler)
  }, [])

  const settings = useAppStore(s => s.settings)
  const updateSettings = useAppStore(s => s.updateSettings)
  // Force-redirect away from advanced-only pages if the user disables advancedMode
  // while sitting on one of them.
  useEffect(() => {
    if (!settings.advancedMode && page === 'maintenance') {
      setPage('dashboard')
    }
  }, [settings.advancedMode, page])

  const renderPage = () => {
    switch (page) {
      case 'dashboard': return <Dashboard />
      case 'apps': return <SplitTunnel />
      case 'servers': return <Servers />
      case 'speedtest': return <SpeedTest />
      case 'trafficHistory': return <TrafficHistory />
      case 'schedule': return <Schedule />
      case 'maintenance':
        return settings.advancedMode ? <Maintenance /> : <Dashboard />
      case 'settings': return <Settings />
      case 'logs': return <Logs />
    }
  }

  const handleWizardComplete = async () => {
    try {
      const saved = await window.electronAPI.saveSettings({ firstRunComplete: true })
      useAppStore.getState().setSettings(saved)
    } catch (err: any) {
      addLog('error', `Не удалось сохранить настройки: ${err.message}`)
      updateSettings({ firstRunComplete: true })
    }
  }

  return (
    <ThemeProvider>
      <div className="flex h-screen">
        <Sidebar currentPage={page} onNavigate={setPage} />
        <AnimatePresence mode="wait">
          <motion.main
            key={page}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -8 }}
            transition={{ duration: 0.18, ease: [0.4, 0, 0.2, 1] }}
            className="flex-1 overflow-y-auto p-6 tabular"
          >
            {renderPage()}
          </motion.main>
        </AnimatePresence>
        {!settings.firstRunComplete && (
          <FirstRunWizard onComplete={handleWizardComplete} onSkip={handleWizardComplete} />
        )}
      </div>
    </ThemeProvider>
  )
}
