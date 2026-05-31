import { useEffect, useState } from 'react'
import { CheckCircle2, Clock, Download, Globe, Loader2, Lock, Power, RefreshCw, ShieldAlert, ShieldCheck, ShieldOff, TriangleAlert, Upload } from 'lucide-react'
import { useAppStore } from '../store'
import { SERVER_CHANGED_EVENT } from '../nav'

// Format an elapsed-ms duration as a short Russian string. Used by the uptime
// pill on the protected hero.
function formatUptime(ms: number): string {
  const totalSec = Math.max(0, Math.floor(ms / 1000))
  const hours = Math.floor(totalSec / 3600)
  const minutes = Math.floor((totalSec % 3600) / 60)
  const seconds = totalSec % 60
  if (hours > 0) return `${hours} ч ${minutes} мин`
  if (minutes > 0) return `${minutes} мин ${seconds} с`
  return `${seconds} с`
}

function formatSpeed(bytesPerSecond: number): string {
  const bits = Math.max(0, bytesPerSecond * 8)
  if (bits < 1_000_000) return `${Math.round(bits / 1_000)} Kbps`
  return `${(bits / 1_000_000).toFixed(bits < 10_000_000 ? 1 : 0)} Mbps`
}

function formatBytes(bytes: number): string {
  const value = Math.max(0, bytes)
  if (value < 1024) return `${Math.round(value)} B`
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KB`
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MB`
  return `${(value / 1024 ** 3).toFixed(2)} GB`
}

/**
 * Single hero block at the top of the Dashboard. Replaces the old combination
 * of ModeSwitch + IpCard + ProxyCard with one obvious "what's the state and
 * what should I do" surface.
 *
 * The component decides one of five visual states:
 *   - "protected"     : TUN running, no leak — green hero, primary action = "Выключить".
 *   - "starting"      : TUN start in flight — neutral hero, spinner.
 *   - "stopping"      : TUN stop in flight — neutral hero, spinner.
 *   - "leaking"       : Status reports we have a public IP that's not the VPN IP.
 *   - "killswitch"    : sing-box dead but firewall rules still block traffic.
 *   - "off"           : Default — primary action = "Включить защиту".
 *
 * Advanced details (manual proxy, mode switch) live behind a collapsible
 * "Расширенные настройки" reveal that's only available if the global
 * advancedMode flag is on.
 */

type Phase =
  | 'protected'
  | 'starting'
  | 'stopping'
  | 'restarting'
  | 'leaking'
  | 'killswitch-engaged'
  | 'proxy-down'
  | 'no-proxy'
  | 'off'

function pickPhase(args: {
  busy: 'starting' | 'stopping' | null
  tunRunning: boolean
  isLeak: boolean
  killswitchActive: boolean
  proxy: ReturnType<typeof useAppStore.getState>['proxy']
  hasDirectVpn: boolean
  proxyDown: boolean
  restartingProgress: string | null
}): Phase {
  if (args.busy === 'starting') return 'starting'
  if (args.busy === 'stopping') return 'stopping'
  // The auto-restart loop has higher priority than killswitch-engaged: while
  // the timer is ticking we want to communicate "Перезапускаем…" rather
  // than "Файрвол блокирует".
  if (args.restartingProgress) return 'restarting'
  if (args.killswitchActive && !args.tunRunning) return 'killswitch-engaged'
  if (args.tunRunning && args.proxyDown) return 'proxy-down'
  if (args.isLeak) return 'leaking'
  if (args.tunRunning) return 'protected'
  if (!args.proxy && !args.hasDirectVpn) return 'no-proxy'
  return 'off'
}

interface PhaseUI {
  badge: string
  badgeIcon: JSX.Element
  badgeColor: string
  bgClass: string
  borderClass: string
  title: string
  subtitle: string
  primaryLabel: string
  primaryAction: 'start' | 'stop' | 'unlock' | 'detect' | 'noop'
  primaryColor: 'success' | 'danger' | 'warning' | 'accent'
  showSpinner: boolean
}

function uiForPhase(phase: Phase, vpnIp: string | null, proxyAddr: string | null, restartingProgress: string | null): PhaseUI {
  switch (phase) {
    case 'protected':
      return {
        badge: 'Защищён',
        badgeIcon: <ShieldCheck className="w-5 h-5" />,
        badgeColor: 'text-success',
        bgClass: 'bg-success/10',
        borderClass: 'border-success/40',
        title: 'Весь трафик идёт через VPN',
        subtitle: vpnIp
          ? `Внешний IP: ${vpnIp}. DNS, UDP и обычный TCP — всё через туннель.`
          : 'DNS, UDP и обычный TCP — всё через туннель.',
        primaryLabel: 'Выключить защиту',
        primaryAction: 'stop',
        primaryColor: 'danger',
        showSpinner: false
      }
    case 'starting':
      return {
        badge: 'Запускаем…',
        badgeIcon: <Loader2 className="w-5 h-5 animate-spin" />,
        badgeColor: 'text-accent',
        bgClass: 'bg-accent/10',
        borderClass: 'border-accent/40',
        title: 'Включаем защиту…',
        subtitle: 'Поднимаем TUN, ставим правила файрвола, перенаправляем трафик в VPN.',
        primaryLabel: 'Запускается…',
        primaryAction: 'noop',
        primaryColor: 'accent',
        showSpinner: true
      }
    case 'stopping':
      return {
        badge: 'Останавливаем…',
        badgeIcon: <Loader2 className="w-5 h-5 animate-spin" />,
        badgeColor: 'text-accent',
        bgClass: 'bg-accent/10',
        borderClass: 'border-accent/40',
        title: 'Выключаем защиту…',
        subtitle: 'Сворачиваем TUN, снимаем правила файрвола, возвращаем обычный маршрут.',
        primaryLabel: 'Останавливается…',
        primaryAction: 'noop',
        primaryColor: 'accent',
        showSpinner: true
      }
    case 'restarting': {
      const progress = restartingProgress ?? '?/?'
      return {
        badge: `Перезапуск ${progress}`,
        badgeIcon: <RefreshCw className="w-5 h-5 animate-spin" />,
        badgeColor: 'text-warning',
        bgClass: 'bg-warning/10',
        borderClass: 'border-warning/40',
        title: 'Восстанавливаем защиту…',
        subtitle:
          'sing-box упал, но мы пробуем запустить его заново. Файрвол продолжает блокировать трафик, чтобы не было утечки IP.',
        primaryLabel: 'Перезапускается…',
        primaryAction: 'noop',
        primaryColor: 'warning',
        showSpinner: true
      }
    }
    case 'leaking':
      return {
        badge: 'Утечка IP',
        badgeIcon: <TriangleAlert className="w-5 h-5" />,
        badgeColor: 'text-danger',
        bgClass: 'bg-danger/10',
        borderClass: 'border-danger/40',
        title: 'Виден ваш реальный IP',
        subtitle: vpnIp
          ? `Сейчас наружу уходит ${vpnIp}, но похоже это не IP VPN. Проверьте VPN-клиент.`
          : 'Сейчас наружу уходит ваш реальный IP. Включите защиту или проверьте VPN.',
        primaryLabel: 'Включить защиту',
        primaryAction: 'start',
        primaryColor: 'success',
        showSpinner: false
      }
    case 'killswitch-engaged':
      return {
        badge: 'Файрвол блокирует',
        badgeIcon: <Lock className="w-5 h-5" />,
        badgeColor: 'text-warning',
        bgClass: 'bg-warning/10',
        borderClass: 'border-warning/40',
        title: 'VPN отключён, файрвол блокирует трафик',
        subtitle:
          'sing-box не работает, но правила Windows Firewall не дают трафику утечь мимо туннеля. Перезапуск сначала снимет старую блокировку, затем включит её заново.',
        primaryLabel: 'Снять блокировку и перезапустить',
        primaryAction: 'start',
        primaryColor: 'success',
        showSpinner: false
      }
    case 'proxy-down':
      return {
        badge: 'VPN-сервер недоступен',
        badgeIcon: <ShieldAlert className="w-5 h-5" />,
        badgeColor: 'text-warning',
        bgClass: 'bg-warning/10',
        borderClass: 'border-warning/40',
        title: 'TUN работает, но прокси не отвечает',
        subtitle:
          'Трафик заблокирован в туннеле — реальный IP не утечёт. Проверьте, что VPN-клиент (Happ) запущен и работает.',
        primaryLabel: 'Выключить защиту',
        primaryAction: 'stop',
        primaryColor: 'danger',
        showSpinner: false
      }
    case 'no-proxy':
      return {
        badge: 'Не найден прокси',
        badgeIcon: <Globe className="w-5 h-5" />,
        badgeColor: 'text-gray-400',
        bgClass: 'bg-surface-light',
        borderClass: 'border-surface-lighter/50',
        title: 'Запустите VPN-клиент',
        subtitle:
          'Не нашли локальный прокси (Happ). Запустите Happ в режиме Proxy либо введите адрес вручную в Настройках.',
        primaryLabel: 'Поискать ещё раз',
        primaryAction: 'detect',
        primaryColor: 'accent',
        showSpinner: false
      }
    default:
      return {
        badge: 'Защита выключена',
        badgeIcon: <ShieldOff className="w-5 h-5" />,
        badgeColor: 'text-gray-400',
        bgClass: 'bg-surface-light',
        borderClass: 'border-surface-lighter/50',
        title: 'Защита выключена',
        subtitle: proxyAddr
          ? `Готовы поднять туннель через ${proxyAddr}. Один клик — и весь трафик пойдёт через VPN.`
          : 'Готовы поднять туннель. Один клик — и весь трафик пойдёт через VPN.',
        primaryLabel: 'Включить защиту',
        primaryAction: 'start',
        primaryColor: 'success',
        showSpinner: false
      }
  }
}

export function HeroStatus() {
  const tunRunning = useAppStore((s) => s.tunRunning)
  const tunStartedAt = useAppStore((s) => s.tunStartedAt)
  const restartingProgress = useAppStore((s) => s.restartingProgress)
  const isLeak = useAppStore((s) => s.isLeak)
  const proxy = useAppStore((s) => s.proxy)
  const settings = useAppStore((s) => s.settings)
  const vpnIp = useAppStore((s) => s.vpnIp)
  const publicIp = useAppStore((s) => s.publicIp)
  const firewallKillSwitchActive = useAppStore((s) => s.firewallKillSwitchActive)
  const traffic = useAppStore((s) => s.traffic)
  const setMode = useAppStore((s) => s.setMode)
  const setTunRunning = useAppStore((s) => s.setTunRunning)
  const setVpnIp = useAppStore((s) => s.setVpnIp)
  const setPublicIp = useAppStore((s) => s.setPublicIp)
  const setProxy = useAppStore((s) => s.setProxy)
  const setDetecting = useAppStore((s) => s.setDetecting)
  const setSettings = useAppStore((s) => s.setSettings)
  const setFirewallKillSwitchActive = useAppStore((s) => s.setFirewallKillSwitchActive)
  const addLog = useAppStore((s) => s.addLog)

  // Connect/disconnect transition lives in the GLOBAL store so it survives
  // this component unmounting on a tab switch mid-connect. Local useState here
  // used to be lost on unmount → the power button re-enabled → a second click
  // double-started the tunnel and broke routing. The store vocabulary is
  // connecting/disconnecting; the hero phases call it starting/stopping.
  const connectionBusy = useAppStore((s) => s.connectionBusy)
  const setConnectionBusy = useAppStore((s) => s.setConnectionBusy)
  const busy: 'starting' | 'stopping' | null =
    connectionBusy === 'connecting' ? 'starting'
      : connectionBusy === 'disconnecting' ? 'stopping'
        : null
  const [proxyDown, setProxyDown] = useState(false)
  const [hasActiveServer, setHasActiveServer] = useState(false)

  // Track whether the user has at least one server profile selected. Polled
  // because the selection is owned by the main process (server-picker store)
  // and reaches this component through IPC, not through the global store.
  // We also listen for explicit change events so picks reflect instantly
  // (e.g. from the right-hand quick picker on the dashboard).
  useEffect(() => {
    let cancelled = false
    const refresh = async () => {
      try {
        const { profile } = await window.electronAPI.serversGetActive()
        if (!cancelled) setHasActiveServer(Boolean(profile))
      } catch {
        if (!cancelled) setHasActiveServer(false)
      }
    }
    refresh()
    const id = setInterval(refresh, 3000)
    const handler = () => refresh()
    window.addEventListener(SERVER_CHANGED_EVENT, handler)
    return () => {
      cancelled = true
      clearInterval(id)
      window.removeEventListener(SERVER_CHANGED_EVENT, handler)
    }
  }, [])

  const directVpnReady =
    settings.connectionMode === 'directVpn' &&
    (hasActiveServer || settings.directVpnInput.trim().length > 0)
  const proxyAddr = settings.connectionMode === 'directVpn'
    ? ''
    : settings.proxyOverride.trim() || (proxy ? `${proxy.host}:${proxy.port}` : '')
  const proxyType = (settings.proxyOverride.trim() ? settings.proxyType : proxy?.type) ?? 'socks5'

  // proxy-down is signalled via the same TUN status stream the App.tsx handler
  // already listens to; we mirror it here through a tiny side-channel on the
  // store so we don't have to plumb another piece of state.
  useEffect(() => {
    const unsub = window.electronAPI.onTunStatusChanged?.((status) => {
      setProxyDown(status === 'proxy-down')
      if (status === 'running' || status === 'stopped' || status === 'killswitch-active') {
        setProxyDown(false)
      }
    })
    return () => unsub?.()
  }, [])

  const phase = pickPhase({
    busy,
    tunRunning,
    isLeak,
    killswitchActive: firewallKillSwitchActive,
    proxy,
    hasDirectVpn: directVpnReady,
    proxyDown,
    restartingProgress
  })
  const ui = uiForPhase(
    phase,
    vpnIp || publicIp,
    settings.connectionMode === 'directVpn' ? 'Direct VPN' : proxyAddr || null,
    restartingProgress
  )

  // Tick once a second so the uptime label refreshes naturally without us
  // having to wire it through the IPC stream. Cheap — only re-renders this
  // component, and only while protected.
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!tunRunning || !tunStartedAt) return
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [tunRunning, tunStartedAt])

  const handleDetect = async () => {
    setDetecting(true)
    addLog('info', 'Ищем локальный прокси (Happ)…')
    try {
      const result = await window.electronAPI.detectHapp()
      if (result) {
        setProxy(result)
        addLog('info', `Прокси найден: ${result.host}:${result.port} (${result.type})`)
      } else {
        addLog('warn', 'Прокси не найден. Запустите Happ или введите адрес вручную в Настройках.')
      }
    } catch (err: any) {
      addLog('error', `Не удалось проверить прокси: ${err.message}`)
    } finally {
      setDetecting(false)
    }
  }

  const handleStart = async () => {
    if (connectionBusy) return
    const restartingFromKillSwitch = firewallKillSwitchActive && !tunRunning
    const refreshKillSwitchState = () => {
      window.electronAPI.getFirewallKillSwitchStatus()
        .then(({ active }) => setFirewallKillSwitchActive(active))
        .catch(() => undefined)
    }

    if (settings.connectionMode === 'directVpn') {
      if (!hasActiveServer && !settings.directVpnInput.trim()) {
        addLog('error', 'Сначала выберите сервер в разделе «Серверы».')
        return
      }
      setConnectionBusy('connecting')
      addLog('info', restartingFromKillSwitch
        ? 'Снимаем старую блокировку и перезапускаем Direct VPN…'
        : 'Включаем защиту…')
      try {
        const saved = await window.electronAPI.saveSettings(settings)
        setSettings(saved)
        const result = await window.electronAPI.startDirectVpn()
        if (result.success) {
          setMode('hard')
          setTunRunning(true)
          if (result.vpnIp) {
            setVpnIp(result.vpnIp)
            setPublicIp(result.vpnIp, false)
          }
          addLog('info', 'Защита включена — Happ больше не участвует в маршруте.')
          if (result.warning) addLog('warn', result.warning)
        } else {
          addLog('error', `Не удалось включить Direct VPN: ${result.error || 'неизвестная ошибка'}`)
        }
      } catch (err: any) {
        addLog('error', `Ошибка запуска Direct VPN: ${err.message}`)
      } finally {
        refreshKillSwitchState()
        setConnectionBusy(null)
      }
      return
    }

    if (!proxyAddr) {
      await handleDetect()
      return
    }
    setConnectionBusy('connecting')
    addLog('info', restartingFromKillSwitch
      ? 'Снимаем старую блокировку и перезапускаем защиту…'
      : 'Включаем защиту…')
    try {
      const result = await window.electronAPI.startTun(proxyAddr, proxyType)
      if (result.success) {
        setMode('hard')
        setTunRunning(true)
        if (result.vpnIp) {
          setVpnIp(result.vpnIp)
          setPublicIp(result.vpnIp, false)
        }
        addLog('info', 'Защита включена — весь трафик идёт через VPN.')
        if (result.warning) addLog('warn', result.warning)
      } else {
        addLog('error', `Не удалось включить защиту: ${result.error || 'неизвестная ошибка'}`)
      }
    } catch (err: any) {
      addLog('error', `Ошибка запуска: ${err.message}`)
    } finally {
      refreshKillSwitchState()
      setConnectionBusy(null)
    }
  }

  const handleStop = async () => {
    if (connectionBusy) return
    setConnectionBusy('disconnecting')
    addLog('info', 'Выключаем защиту…')
    try {
      const result = await window.electronAPI.stopTun()
      if (result.success) {
        setMode('off')
        setTunRunning(false)
        setVpnIp(null)
        addLog('info', 'Защита выключена. Возвращаем обычный маршрут.')
      } else {
        addLog('error', `Не удалось выключить защиту: ${result.error || 'неизвестная ошибка'}`)
      }
    } catch (err: any) {
      addLog('error', `Ошибка остановки: ${err.message}`)
    } finally {
      setConnectionBusy(null)
    }
  }

  const handlePrimary = () => {
    if (ui.primaryAction === 'start') return handleStart()
    if (ui.primaryAction === 'stop') return handleStop()
    if (ui.primaryAction === 'detect') return handleDetect()
    return undefined
  }

  const buttonClass = (() => {
    const base = 'w-full sm:w-auto px-6 py-3 rounded-xl text-base font-bold transition-all flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed'
    if (ui.primaryColor === 'success') return `${base} bg-success text-black hover:bg-success/90`
    if (ui.primaryColor === 'danger') return `${base} bg-danger/90 text-white hover:bg-danger`
    if (ui.primaryColor === 'warning') return `${base} bg-warning text-black hover:bg-warning/90`
    return `${base} bg-accent text-white hover:bg-accent/90`
  })()

  return (
    <section
      className={`rounded-2xl border ${ui.borderClass} ${ui.bgClass} p-6 space-y-4 transition-colors`}
      aria-live="polite"
    >
      <div className="flex items-center gap-2">
        <span className={`flex items-center gap-2 text-xs font-bold uppercase tracking-wider ${ui.badgeColor}`}>
          {ui.badgeIcon}
          {ui.badge}
        </span>
      </div>

      <div className="space-y-1">
        <h2 className="text-2xl font-bold text-gray-100 leading-tight">{ui.title}</h2>
        <p className="text-sm text-gray-400 leading-relaxed">{ui.subtitle}</p>
      </div>

      <div className="flex flex-col sm:flex-row sm:items-center gap-3 pt-1">
        <button
          onClick={handlePrimary}
          disabled={ui.primaryAction === 'noop' || busy !== null}
          className={buttonClass}
        >
          {ui.showSpinner ? <Loader2 className="w-5 h-5 animate-spin" /> : <Power className="w-5 h-5" />}
          {ui.primaryLabel}
        </button>

        {/* Compact status chips */}
        <div className="flex flex-wrap gap-2 text-xs">
          {settings.connectionMode === 'directVpn' && (
            <span className="flex items-center gap-1.5 rounded-full bg-bg/60 border border-border px-3 py-1.5 text-gray-400">
              <Globe className="w-3.5 h-3.5 text-accent" />
              Direct VPN: <span className="font-mono">sing-box</span>
            </span>
          )}
          {settings.connectionMode !== 'directVpn' && proxyAddr && (
            <span className="flex items-center gap-1.5 rounded-full bg-bg/60 border border-border px-3 py-1.5 text-gray-400">
              <Globe className="w-3.5 h-3.5 text-accent" />
              Прокси: <span className="font-mono">{proxyAddr}</span>
              <span className="opacity-60">({proxyType.toUpperCase()})</span>
            </span>
          )}
          {firewallKillSwitchActive && tunRunning && (
            <span className="flex items-center gap-1.5 rounded-full bg-success/15 px-3 py-1.5 text-success">
              <Lock className="w-3.5 h-3.5" />
              Файрвол kill-switch активен
            </span>
          )}
          {publicIp && tunRunning && !isLeak && (
            <span className="flex items-center gap-1.5 rounded-full bg-success/10 px-3 py-1.5 text-success">
              <CheckCircle2 className="w-3.5 h-3.5" />
              Внешний IP: <span className="font-mono">{publicIp}</span>
            </span>
          )}
          {tunRunning && (
            <>
              <span className="flex items-center gap-1.5 rounded-full bg-bg/60 border border-border px-3 py-1.5 text-gray-400">
                <Download className="w-3.5 h-3.5 text-success" />
                ↓ <span className="font-mono">{formatSpeed(traffic.downloadBps)}</span>
              </span>
              <span className="flex items-center gap-1.5 rounded-full bg-bg/60 border border-border px-3 py-1.5 text-gray-400">
                <Upload className="w-3.5 h-3.5 text-accent" />
                ↑ <span className="font-mono">{formatSpeed(traffic.uploadBps)}</span>
              </span>
              <span className="flex items-center gap-1.5 rounded-full bg-bg/60 border border-border px-3 py-1.5 text-gray-400">
                Сессия: <span className="font-mono">↓ {formatBytes(traffic.sessionDownloadBytes)} / ↑ {formatBytes(traffic.sessionUploadBytes)}</span>
              </span>
            </>
          )}
          {tunRunning && tunStartedAt && (
            <span className="flex items-center gap-1.5 rounded-full bg-bg/60 border border-border px-3 py-1.5 text-gray-400">
              <Clock className="w-3.5 h-3.5 text-accent" />
              Аптайм: <span className="font-mono">{formatUptime(now - tunStartedAt)}</span>
            </span>
          )}
        </div>
      </div>
    </section>
  )
}
