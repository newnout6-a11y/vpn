import { useCallback, useEffect, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { motion } from 'framer-motion'
import { PageTip } from '../components/PageTip'
import { MacCard } from '../design-system/MacCard'
import { MacToast, ToastData } from '../design-system/MacToast'
import { useAppStore } from '../store'
import { DiagnosticsCard } from '../components/DiagnosticsCard'
import { BrowserIpCard } from '../components/BrowserIpCard'
import { ProfileSelectorInline } from '../components/ProfileSelectorInline'
import { ForeignVpnBanner } from '../components/ForeignVpnBanner'
import { DashboardSide } from '../components/DashboardSide'
import {
  CheckCircle2,
  Clock,
  Download,
  Info,
  Loader2,
  Lock,
  Power,
  Radar,
  ShieldOff,
  TriangleAlert,
  Upload
} from 'lucide-react'

// ─── Helpers ────────────────────────────────────────────────────────────────

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

let toastIdCounter = 0
function nextToastId(): string {
  return `toast-${++toastIdCounter}-${Date.now()}`
}

function countryFlag(country: string | null): string {
  if (!country) return ''
  const map: Record<string, string> = {
    'Poland': '🇵🇱', 'Norway': '🇳🇴', 'Latvia': '🇱🇻', 'Sweden': '🇸🇪',
    'Germany': '🇩🇪', 'Kazakhstan': '🇰🇿', 'Japan': '🇯🇵', 'United States': '🇺🇸',
    'Russia': '🇷🇺', 'Netherlands': '🇳🇱', 'France': '🇫🇷', 'United Kingdom': '🇬🇧',
    'Finland': '🇫🇮', 'Estonia': '🇪🇪', 'Lithuania': '🇱🇹', 'Czechia': '🇨🇿',
    'Czech Republic': '🇨🇿', 'Switzerland': '🇨🇭', 'Austria': '🇦🇹', 'Italy': '🇮🇹',
    'Spain': '🇪🇸', 'Canada': '🇨🇦', 'Singapore': '🇸🇬', 'Hong Kong': '🇭🇰',
    'South Korea': '🇰🇷', 'Korea': '🇰🇷', 'Turkey': '🇹🇷', 'Ukraine': '🇺🇦',
    'Belarus': '🇧🇾', 'Romania': '🇷🇴', 'Bulgaria': '🇧🇬', 'Hungary': '🇭🇺',
    'Slovakia': '🇸🇰', 'Greece': '🇬🇷', 'Portugal': '🇵🇹', 'Belgium': '🇧🇪',
    'Denmark': '🇩🇰', 'Ireland': '🇮🇪', 'Australia': '🇦🇺', 'New Zealand': '🇳🇿',
    'India': '🇮🇳', 'Brazil': '🇧🇷', 'Argentina': '🇦🇷', 'Mexico': '🇲🇽',
    'Chile': '🇨🇱', 'South Africa': '🇿🇦', 'Israel': '🇮🇱', 'UAE': '🇦🇪',
    'United Arab Emirates': '🇦🇪'
  }
  return map[country] || '🌐'
}

// ─── Dashboard Component ────────────────────────────────────────────────────

export function Dashboard() {
  const { t } = useTranslation()

  // Store state
  const tunRunning = useAppStore(s => s.tunRunning)
  const tunStartedAt = useAppStore(s => s.tunStartedAt)
  const proxy = useAppStore(s => s.proxy)
  const settings = useAppStore(s => s.settings)
  const publicIp = useAppStore(s => s.publicIp)
  const vpnIp = useAppStore(s => s.vpnIp)
  const isLeak = useAppStore(s => s.isLeak)
  const traffic = useAppStore(s => s.traffic)
  const firewallKillSwitchActive = useAppStore(s => s.firewallKillSwitchActive)
  const routingHealth = useAppStore(s => s.routingHealth)
  const leakChecks = useAppStore(s => s.leakChecks)
  const restartingProgress = useAppStore(s => s.restartingProgress)

  // Store actions
  const setMode = useAppStore(s => s.setMode)
  const setTunRunning = useAppStore(s => s.setTunRunning)
  const setVpnIp = useAppStore(s => s.setVpnIp)
  const setPublicIp = useAppStore(s => s.setPublicIp)
  const setSettings = useAppStore(s => s.setSettings)
  const setFirewallKillSwitchActive = useAppStore(s => s.setFirewallKillSwitchActive)
  const setLeakChecks = useAppStore(s => s.setLeakChecks)
  const addLog = useAppStore(s => s.addLog)

  // Connect/disconnect transition lives in the GLOBAL store so it survives
  // this component unmounting when the user switches tabs mid-connect. (Local
  // useState here used to be lost on unmount → button re-enabled → double
  // start → broken routing.)
  const connectionBusy = useAppStore(s => s.connectionBusy)
  const setConnectionBusy = useAppStore(s => s.setConnectionBusy)
  const connecting = connectionBusy === 'connecting'
  const disconnecting = connectionBusy === 'disconnecting'

  // Local state
  const [toasts, setToasts] = useState<ToastData[]>([])
  const [checking, setChecking] = useState(false)
  const [disengaging, setDisengaging] = useState(false)
  const [nuclearResetting, setNuclearResetting] = useState(false)
  const [ipGeo, setIpGeo] = useState<{ country: string | null; city: string | null }>({ country: null, city: null })

  // Uptime ticker
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!tunRunning || !tunStartedAt) return
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [tunRunning, tunStartedAt])

  // Fetch country/city for the current public IP via ipapi.co
  useEffect(() => {
    if (!publicIp || isLeak || !tunRunning) {
      setIpGeo({ country: null, city: null })
      return
    }
    let cancelled = false
    ;(async () => {
      try {
        const resp = await fetch(`https://ipapi.co/${publicIp}/json/`)
        if (!resp.ok) return
        const data = await resp.json()
        if (!cancelled && data && !data.error) {
          setIpGeo({
            country: data.country_name || null,
            city: data.city || null
          })
        }
      } catch {
        // silent — chip will just show IP without country
      }
    })()
    return () => { cancelled = true }
  }, [publicIp, isLeak, tunRunning])

  // ─── Toast management ───────────────────────────────────────────────────

  const showToast = useCallback((variant: ToastData['variant'], title: string, description?: string) => {
    const id = nextToastId()
    setToasts(prev => [...prev, { id, variant, title, description }])
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id))
    }, 5000)
  }, [])

  const dismissToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  // ─── Connection logic ───────────────────────────────────────────────────

  const isBusy = connecting || disconnecting
  const isConnected = tunRunning

  const proxyAddr = settings.connectionMode === 'directVpn'
    ? ''
    : settings.proxyOverride.trim() || (proxy ? `${proxy.host}:${proxy.port}` : '')
  const proxyType = (settings.proxyOverride.trim() ? settings.proxyType : proxy?.type) ?? 'socks5'

  const handleConnect = async () => {
    // Re-entry guard. `connectionBusy` lives in the global store, so even if
    // the Dashboard was unmounted/remounted on a tab switch mid-connect, a
    // second click here is rejected while the first transition is still in
    // flight. Without this the user could double-start the tunnel (main does
    // guard it, but the UI used to still allow the click and then "broke").
    if (connectionBusy) return
    setConnectionBusy('connecting')
    addLog('info', t('dashboard.connecting'))

    const refreshKillSwitchState = () => {
      window.electronAPI.getFirewallKillSwitchStatus()
        .then(({ active }) => setFirewallKillSwitchActive(active))
        .catch(() => undefined)
    }

    try {
      if (settings.connectionMode === 'directVpn') {
        const active = await window.electronAPI.serversGetActive()
        if (!active.profile && !settings.directVpnInput.trim()) {
          showToast('error', t('dashboard.connectionError'), 'No server selected')
          addLog('error', 'Сначала выберите сервер в разделе «Серверы».')
          return
        }
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
          addLog('info', 'Защита включена — Direct VPN.')
          if (result.warning) addLog('warn', result.warning)
          // Refresh public IP a bit later so the leak banner clears once
          // the tunnel routes have settled.
          setTimeout(async () => {
            try {
              const ipInfo = await window.electronAPI.getPublicIp()
              setPublicIp(ipInfo.ip, ipInfo.isLeak)
            } catch {}
          }, 2000)
        } else {
          const errorMsg = result.error || 'Unknown error'
          showToast('error', t('dashboard.connectionError'), errorMsg)
          addLog('error', `Не удалось включить Direct VPN: ${errorMsg}`)
        }
      } else {
        if (!proxyAddr) {
          showToast('error', t('dashboard.connectionError'), 'No proxy available')
          addLog('error', 'Прокси не найден. Запустите Happ или введите адрес вручную.')
          return
        }
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
          // Refresh public IP a bit later so the leak banner clears once
          // the tunnel routes have settled.
          setTimeout(async () => {
            try {
              const ipInfo = await window.electronAPI.getPublicIp()
              setPublicIp(ipInfo.ip, ipInfo.isLeak)
            } catch {}
          }, 2000)
        } else {
          const errorMsg = result.error || 'Unknown error'
          showToast('error', t('dashboard.connectionError'), errorMsg)
          addLog('error', `Не удалось включить защиту: ${errorMsg}`)
        }
      }
    } catch (err: any) {
      const errorMsg = err.message || 'Unknown error'
      showToast('error', t('dashboard.connectionError'), errorMsg)
      addLog('error', `Ошибка запуска: ${errorMsg}`)
    } finally {
      refreshKillSwitchState()
      setConnectionBusy(null)
    }
  }

  const handleDisconnect = async () => {
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
        const errorMsg = result.error || 'Unknown error'
        showToast('error', t('dashboard.connectionError'), errorMsg)
        addLog('error', `Не удалось выключить защиту: ${errorMsg}`)
      }
    } catch (err: any) {
      const errorMsg = err.message || 'Unknown error'
      showToast('error', t('dashboard.connectionError'), errorMsg)
      addLog('error', `Ошибка остановки: ${errorMsg}`)
    } finally {
      setConnectionBusy(null)
    }
  }

  const handleToggleChange = (checked: boolean) => {
    if (checked) {
      handleConnect()
    } else {
      handleDisconnect()
    }
  }

  // ─── Kill-switch disengage ──────────────────────────────────────────────

  const showKillSwitchBanner = firewallKillSwitchActive && !tunRunning
  const competingTun = useAppStore(s => s.competingTun)

  const handleDisengageKillSwitch = async () => {
    setDisengaging(true)
    try {
      const result = await window.electronAPI.disableFirewallKillSwitch()
      if (result.success) {
        setFirewallKillSwitchActive(false)
        // `skipped:true` means main found nothing to disable — kill-switch was
        // already off (typical: user clicks the banner just after the auto-
        // rollback fired on TUN stop). Don't pretend the user "did" anything,
        // just close the banner silently.
        if (!result.skipped) {
          addLog('warn', `Файрвол kill-switch снят вручную: ${result.message}`)
        }
      } else {
        addLog('error', `Не удалось снять kill-switch: ${result.message}`)
      }
    } catch (err: any) {
      addLog('error', `Ошибка снятия kill-switch: ${err.message}`)
    } finally {
      setDisengaging(false)
    }
  }

  // Last-resort recovery for a wedged firewall (e.g. disable-kill-switch
  // succeeded but DefaultOutboundAction stayed Block, or third-party rules
  // still block all outbound). Wipes Windows Firewall to defaults.
  const handleNuclearFirewallReset = async () => {
    setNuclearResetting(true)
    try {
      const result = await window.electronAPI.firewallNuclearReset()
      if (result.success) {
        setFirewallKillSwitchActive(false)
        showToast('info', 'Firewall сброшен', result.message)
        addLog('warn', `Полный сброс firewall: ${result.message}`)
      } else {
        showToast('error', 'Не удалось сбросить firewall', result.message)
        addLog('error', `Полный сброс firewall не удался: ${result.message}`)
      }
    } catch (err: any) {
      showToast('error', 'Ошибка сброса firewall', err.message || String(err))
      addLog('error', `Ошибка сброса firewall: ${err.message}`)
    } finally {
      setNuclearResetting(false)
    }
  }

  // ─── Route diagnostics ─────────────────────────────────────────────────

  const runDiagnostics = async () => {
    const addr = settings.proxyOverride.trim() || (proxy ? `${proxy.host}:${proxy.port}` : '')
    setChecking(true)
    addLog('info', 'Проверяем маршрут — куда сейчас идёт трафик…')
    try {
      const result = await window.electronAPI.runLeakCheck({
        proxyAddr: addr || undefined,
        proxyType: settings.proxyOverride.trim() ? settings.proxyType : proxy?.type ?? settings.proxyType
      })
      setLeakChecks(result)
      const message =
        result.summary === 'ok'
          ? 'Утечек не найдено — всё через VPN.'
          : result.summary === 'fail'
            ? 'Найдена критичная проблема маршрутизации.'
            : 'Есть предупреждения, посмотрите детали ниже.'
      addLog(result.summary === 'fail' ? 'error' : result.summary === 'warn' ? 'warn' : 'info', `Проверка маршрута: ${message}`)
    } catch (err: any) {
      addLog('error', `Проверка не выполнена: ${err.message}`)
    } finally {
      setChecking(false)
    }
  }

  const statusClass = (status: string) => {
    if (status === 'ok') return 'text-[var(--color-success)]'
    if (status === 'warn') return 'text-[var(--color-warning)]'
    if (status === 'fail') return 'text-[var(--color-danger)]'
    return 'text-[var(--color-text-secondary)]'
  }

  const statusIcon = (status: string) => {
    if (status === 'ok') return <CheckCircle2 className="w-4 h-4 text-[var(--color-success)]" />
    if (status === 'fail') return <TriangleAlert className="w-4 h-4 text-[var(--color-danger)]" />
    if (status === 'warn') return <TriangleAlert className="w-4 h-4 text-[var(--color-warning)]" />
    return <Info className="w-4 h-4 text-[var(--color-text-secondary)]" />
  }

  // ─── Status label ──────────────────────────────────────────────────────

  const statusLabel = (() => {
    if (connecting) return t('dashboard.connecting')
    if (disconnecting) return t('dashboard.connecting')
    if (restartingProgress) return `Перезапуск ${restartingProgress}`
    if (isConnected) return t('dashboard.connected')
    return t('dashboard.disconnected')
  })()

  const statusColor = (() => {
    if (connecting || disconnecting || restartingProgress) return 'text-[var(--color-warning)]'
    if (isConnected) return 'text-[var(--color-success)]'
    return 'text-[var(--color-text-secondary)]'
  })()

  // ─── Render ────────────────────────────────────────────────────────────

  return (
    /*
     * Two-column layout:
     *   • Default (narrow / windowed mode): single column, behaves like before.
     *   • xl breakpoint and up (≥1280px viewport): companion column appears
     *     on the right with a quick server picker, live traffic graph, and
     *     a recent-sites mini-panel.
     *
     * The right column is `sticky` so it stays in view as the user scrolls
     * the long primary column (kill-switch banner → toggle → leak → diagnostics).
     */
    <div className="grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_320px] xl:gap-6 items-start">
      <div className="space-y-6 max-w-3xl xl:max-w-none">
        {/* Onboarding tip */}
        <PageTip tipKey="dashboard">{t('tips.dashboard')}</PageTip>

      {/* Toast notifications */}
      <MacToast toasts={toasts} onDismiss={dismissToast} position="top-right" />

      {/* Top-of-page kill-switch alert — shown when sing-box is dead but the
          firewall still blocks outbound traffic. Made deliberately loud and
          above-the-fold so users don't miss it when their browser stops
          working. The smaller informational banner with both action buttons
          still appears further down. */}
      {competingTun && tunRunning && (
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-[var(--radius-md)] border border-[var(--color-warning)]/60 bg-[var(--color-warning)]/10 p-4"
          role="alert"
          aria-live="polite"
        >
          <p className="text-sm font-semibold text-[var(--color-warning)]">
            Обнаружен второй VPN/TUN: {competingTun}
          </p>
          <p className="text-xs text-[var(--color-text-secondary)] mt-1">
            Два туннеля одновременно ломают DNS и интернет. Оставьте включённым только один — выключите либо нашу защиту, либо сторонний клиент (Happ TUN, WireGuard, OpenVPN и т.п.).
          </p>
        </motion.div>
      )}
      {showKillSwitchBanner && (
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-[var(--radius-md)] border-2 border-[var(--color-danger)]/60 bg-[var(--color-danger)]/15 p-5 shadow-[0_0_30px_rgba(255,69,58,0.25)]"
          role="alert"
          aria-live="assertive"
        >
          <div className="flex items-start gap-4">
            <Lock className="w-8 h-8 text-[var(--color-danger)] flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <p className="text-lg font-bold text-[var(--color-danger)]">
                Интернет заблокирован файрволом
              </p>
              <p className="text-sm text-[var(--color-danger)]/90 mt-1">
                VPN отключён, но Windows Firewall всё ещё блокирует трафик чтобы предотвратить утечку IP.
                Сайты не будут открываться, пока вы не снимете блокировку или не включите защиту заново.
              </p>
              <div className="flex flex-wrap gap-2 mt-3">
                <button
                  onClick={handleDisengageKillSwitch}
                  disabled={disengaging || nuclearResetting}
                  className="text-sm font-medium flex items-center gap-2 px-4 py-2 rounded-[var(--radius-sm)] bg-[var(--color-danger)] text-white hover:bg-[var(--color-danger)]/90 transition-colors duration-[var(--transition-fast)] disabled:opacity-50"
                >
                  {disengaging ? <Loader2 className="w-4 h-4 animate-spin" /> : <ShieldOff className="w-4 h-4" />}
                  Снять блокировку
                </button>
                <button
                  onClick={handleNuclearFirewallReset}
                  disabled={disengaging || nuclearResetting}
                  className="text-sm font-medium flex items-center gap-2 px-4 py-2 rounded-[var(--radius-sm)] border border-[var(--color-danger)] text-[var(--color-danger)] hover:bg-[var(--color-danger)]/10 transition-colors duration-[var(--transition-fast)] disabled:opacity-50"
                  title="Сбрасывает все правила Windows Firewall к заводским"
                >
                  {nuclearResetting ? <Loader2 className="w-4 h-4 animate-spin" /> : <TriangleAlert className="w-4 h-4" />}
                  Сбросить firewall (если интернет не работает)
                </button>
              </div>
            </div>
          </div>
        </motion.div>
      )}

      {/* Main VPN Toggle Card */}
      <MacCard className="flex flex-col items-center justify-center py-10 gap-6">
        <h2 className="text-lg font-semibold text-[var(--color-text)]">
          {t('dashboard.vpnToggle')}
        </h2>

        {/* Large circular power button */}
        <motion.button
          onClick={() => handleToggleChange(!isConnected)}
          disabled={isBusy}
          whileHover={!isBusy ? { scale: 1.03 } : {}}
          whileTap={!isBusy ? { scale: 0.97 } : {}}
          aria-label={statusLabel}
          className={`
            relative w-36 h-36 rounded-full flex items-center justify-center
            transition-all duration-300 ease-out
            ${isConnected
              ? 'bg-[var(--color-success)] shadow-[0_0_60px_rgba(52,199,89,0.4)]'
              : 'bg-[var(--color-accent)] shadow-[0_0_30px_rgba(0,122,255,0.2)]'
            }
            ${isBusy ? 'opacity-70 cursor-wait' : 'cursor-pointer'}
          `}
        >
          {isConnected && (
            <motion.div
              className="absolute inset-0 rounded-full bg-[var(--color-success)]"
              animate={{ scale: [1, 1.15, 1], opacity: [0.5, 0, 0.5] }}
              transition={{ duration: 2, repeat: Infinity, ease: 'easeOut' }}
            />
          )}
          <div className="relative z-10">
            {isBusy ? (
              <Loader2 size={56} className="text-white animate-spin" />
            ) : (
              <Power size={56} className="text-white" strokeWidth={2.5} />
            )}
          </div>
        </motion.button>

        {/* Status text */}
        <p className={`text-sm font-medium ${statusColor}`}>
          {statusLabel}
        </p>

        {/* Profile selector card */}
        <div className="w-full max-w-md space-y-2">
          <ForeignVpnBanner />
          <ProfileSelectorInline />
        </div>

        {/* Connection info chips */}
        {isConnected && (
          <div className="flex flex-wrap items-center justify-center gap-2 text-xs">
            {publicIp && !isLeak && (
              <span className="flex items-center gap-1.5 rounded-full bg-[var(--color-success)]/10 px-3 py-1.5 text-[var(--color-success)]">
                <CheckCircle2 className="w-3.5 h-3.5" />
                {ipGeo.country && (
                  <span className="text-base leading-none">{countryFlag(ipGeo.country)}</span>
                )}
                <span className="font-mono">{publicIp}</span>
                {ipGeo.country && (
                  <span className="opacity-80">
                    — {ipGeo.country}{ipGeo.city ? `, ${ipGeo.city}` : ''}
                  </span>
                )}
              </span>
            )}
            <span className="flex items-center gap-1.5 rounded-full bg-[var(--color-bg)] px-3 py-1.5 text-[var(--color-text-secondary)]">
              <Download className="w-3.5 h-3.5 text-[var(--color-success)]" />
              ↓ <span className="font-mono">{formatSpeed(traffic.downloadBps)}</span>
            </span>
            <span className="flex items-center gap-1.5 rounded-full bg-[var(--color-bg)] px-3 py-1.5 text-[var(--color-text-secondary)]">
              <Upload className="w-3.5 h-3.5 text-[var(--color-accent)]" />
              ↑ <span className="font-mono">{formatSpeed(traffic.uploadBps)}</span>
            </span>
            {tunStartedAt && (
              <span className="flex items-center gap-1.5 rounded-full bg-[var(--color-bg)] px-3 py-1.5 text-[var(--color-text-secondary)]">
                <Clock className="w-3.5 h-3.5 text-[var(--color-accent)]" />
                {formatUptime(now - tunStartedAt)}
              </span>
            )}
            <span className="flex items-center gap-1.5 rounded-full bg-[var(--color-bg)] px-3 py-1.5 text-[var(--color-text-secondary)]">
              {t('dashboard.trafficDown')}: <span className="font-mono">{formatBytes(traffic.sessionDownloadBytes)}</span>
              {' / '}
              {t('dashboard.trafficUp')}: <span className="font-mono">{formatBytes(traffic.sessionUploadBytes)}</span>
            </span>
          </div>
        )}
      </MacCard>

      {/* Leak warning banner */}
      {isLeak && (
        <MacCard className="!border-[var(--color-danger)]/40 !bg-[var(--color-danger)]/10">
          <div className="flex items-center gap-3">
            <ShieldOff className="w-6 h-6 text-[var(--color-danger)] flex-shrink-0" />
            <div>
              <p className="text-sm font-bold text-[var(--color-danger)]">Виден ваш реальный IP</p>
              <p className="text-xs text-[var(--color-danger)]/80">
                Включите защиту или проверьте VPN-клиент. Если защита уже включена — возможно, VPN-сервер не работает.
              </p>
            </div>
          </div>
        </MacCard>
      )}

      <BrowserIpCard />

      {/* Firewall kill-switch banner */}
      {showKillSwitchBanner && (
        <MacCard className="!border-[var(--color-warning)]/40 !bg-[var(--color-warning)]/10">
          <div className="flex items-start gap-3">
            <Lock className="w-6 h-6 text-[var(--color-warning)] flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <p className="text-sm font-bold text-[var(--color-warning)]">VPN отключён, файрвол блокирует трафик</p>
              <p className="text-xs text-[var(--color-warning)]/90 mt-1">
                sing-box не работает, но правила Windows Firewall защищают от утечки IP. Включите защиту заново
                чтобы вернуть интернет через VPN, либо снимите блокировку вручную.
              </p>
              <div className="flex flex-wrap gap-2 mt-2">
                <button
                  onClick={handleDisengageKillSwitch}
                  disabled={disengaging || nuclearResetting}
                  className="text-xs flex items-center gap-2 px-3 py-1.5 rounded-[var(--radius-sm)] bg-[var(--color-warning)]/20 text-[var(--color-warning)] hover:bg-[var(--color-warning)]/30 transition-colors duration-[var(--transition-fast)] disabled:opacity-50"
                >
                  {disengaging ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldOff className="w-3.5 h-3.5" />}
                  Снять блокировку вручную
                </button>
                <button
                  onClick={handleNuclearFirewallReset}
                  disabled={disengaging || nuclearResetting}
                  className="text-xs flex items-center gap-2 px-3 py-1.5 rounded-[var(--radius-sm)] border border-[var(--color-warning)]/40 text-[var(--color-warning)] hover:bg-[var(--color-warning)]/10 transition-colors duration-[var(--transition-fast)] disabled:opacity-50"
                  title="Полностью сбросить Windows Firewall к настройкам по умолчанию"
                >
                  {nuclearResetting ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <TriangleAlert className="w-3.5 h-3.5" />}
                  Сбросить firewall (если интернет не работает)
                </button>
              </div>
            </div>
          </div>
        </MacCard>
      )}

      {/* Route diagnostics card */}
      <MacCard>
        <div className="flex items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-[var(--color-text-secondary)] uppercase tracking-wider">
              Проверка маршрута
            </h3>
            <p className={`text-sm mt-1 ${statusClass(routingHealth.summary)}`}>
              {routingHealth.message}
            </p>
          </div>
          <button
            onClick={runDiagnostics}
            disabled={checking}
            className="flex items-center gap-2 text-sm px-4 py-2 rounded-[var(--radius-sm)] bg-[var(--color-accent)]/10 text-[var(--color-accent)] hover:bg-[var(--color-accent)]/20 transition-colors duration-[var(--transition-fast)] disabled:opacity-50"
          >
            {checking ? <Loader2 className="w-4 h-4 animate-spin" /> : <Radar className="w-4 h-4" />}
            Проверить
          </button>
        </div>
        {leakChecks && (
          <div className="space-y-2 mt-4">
            {leakChecks.items.map(item => (
              <div key={item.id} className="bg-[var(--color-bg)] border border-[var(--color-border)] rounded-[var(--radius-sm)] px-3 py-2">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-center gap-2">
                    {statusIcon(item.status)}
                    <span className="text-sm text-[var(--color-text)]">{item.label}</span>
                  </div>
                  <span className={`text-xs font-mono text-right ${statusClass(item.status)}`}>{item.value}</span>
                </div>
                {item.details && <p className="text-xs text-[var(--color-text-secondary)] mt-1 break-words">{item.details}</p>}
              </div>
            ))}
          </div>
        )}
      </MacCard>

      {/* Diagnostics card */}
      <DiagnosticsCard />
      </div>

      {/* Right-hand companion column. Hidden on narrower windows via the
          parent grid template (no `xl:` size on the right tracks). The
          column itself sticks to the top of the viewport as the user
          scrolls through the primary column. */}
      <aside className="hidden xl:block sticky top-6 self-start max-h-[calc(100vh-3rem)] overflow-y-auto pr-1">
        <DashboardSide />
      </aside>
    </div>
  )
}
