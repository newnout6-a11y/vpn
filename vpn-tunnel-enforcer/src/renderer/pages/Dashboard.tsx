import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'
import { tunnelStartedMessageKey } from '../tunnelMessages'
import { motion } from 'framer-motion'
import { MacCard } from '../design-system/MacCard'
import { MacToast, ToastData } from '../design-system/MacToast'
import { useAppStore } from '../store'
import { ForeignVpnBanner } from '../components/ForeignVpnBanner'
import { usePageActive } from '../hooks/usePageActive'
import { CountryFlagIcon } from '../components/CountryFlagIcon'
import { FitWord } from '../swiss/FitWord'
import { SwissFactsStrip } from '../swiss/SwissFactsStrip'
import { SwissProgress } from '../swiss/SwissProgress'
import { SwissPanels } from '../swiss/SwissPanels'
import { deriveSwissState } from '../swiss/swissState'
import { useActiveProfile, useHomeIp } from '../swiss/SwissIdentity'
import { SwissMascot, type SwissPhase } from '../swiss/SwissMascot'
import { MASCOT_EVENT } from '../swiss/useMascot'
import '../styles/swiss.css'
import { cn } from '../design-system/utils'
import { isIpcRemoteErrorData } from '../../shared/ipc-result'
import { ArrowRight, Loader2, Lock, ShieldOff, Square, TriangleAlert } from 'lucide-react'

// ─── Helpers ────────────────────────────────────────────────────────────────

function formatUptime(ms: number): string {
  const totalSec = Math.max(0, Math.floor(ms / 1000))
  const pad = (n: number) => String(n).padStart(2, '0')
  return pad(Math.floor(totalSec / 3600)) + ':' + pad(Math.floor((totalSec % 3600) / 60)) + ':' + pad(totalSec % 60)
}

function UptimeLabel({ startedAt }: { startedAt: number }) {
  const { t } = useTranslation()
  const active = usePageActive()
  const [now, setNow] = useState(() => Date.now())

  useEffect(() => {
    if (!active) return
    const updateNow = () => setNow(Date.now())
    const id = window.setInterval(() => {
      if (!document.hidden) updateNow()
    }, 1000)

    updateNow()
    document.addEventListener('visibilitychange', updateNow)
    return () => {
      window.clearInterval(id)
      document.removeEventListener('visibilitychange', updateNow)
    }
  }, [active, startedAt])

  return <span className="swiss-uptime">{'· ' + formatUptime(now - startedAt) + ' ' + t('dashboard.swissInTunnel')}</span>
}

let toastIdCounter = 0
// Like the global busy flag, this generation must survive a Dashboard remount.
// Cancellation on another tab invalidates callbacks from the old component.
const connectionTransitionSeq = { current: 0 }
function nextToastId(): string {
  return `toast-${++toastIdCounter}-${Date.now()}`
}

// ─── Dashboard Component ────────────────────────────────────────────────────

interface DashboardProps {
  suppressFirewallBannerUntil?: number
}

export function Dashboard({ suppressFirewallBannerUntil = 0 }: DashboardProps) {
  const { t } = useTranslation()

  // Store state
  const tunRunning = useAppStore(s => s.tunRunning)
  const tunnelSnapshot = useAppStore(s => s.tunnelSnapshot)
  const proxyDown = useAppStore(s => s.proxyDown)
  const tunStartedAt = useAppStore(s => s.tunStartedAt)
  const proxy = useAppStore(s => s.proxy)
  const settings = useAppStore(s => s.settings)
  const publicIp = useAppStore(s => s.publicIp)
  const vpnIp = useAppStore(s => s.vpnIp)
  const isLeak = useAppStore(s => s.isLeak)
  const publicIpVerdict = useAppStore(s => s.publicIpVerdict)
  const traffic = useAppStore(s => s.traffic)
  const firewallStatus = useAppStore(s => s.firewallKillSwitchStatus)
  const restartingProgress = useAppStore(s => s.restartingProgress)
  const serverSwitchingName = useAppStore(s => s.serverSwitchingName)

  // Store actions
  const setMode = useAppStore(s => s.setMode)
  const setTunRunning = useAppStore(s => s.setTunRunning)
  const setVpnIp = useAppStore(s => s.setVpnIp)
  const setPublicIp = useAppStore(s => s.setPublicIp)
  const setSettings = useAppStore(s => s.setSettings)
  const refreshFirewallStatus = useAppStore(s => s.refreshFirewallKillSwitchStatus)
  const setLeakChecks = useAppStore(s => s.setLeakChecks)
  const addLog = useAppStore(s => s.addLog)

  // Connect/disconnect transition lives in the GLOBAL store so it survives
  // this component unmounting when the user switches tabs mid-connect. (Local
  // useState here used to be lost on unmount → button re-enabled → double
  // start → broken routing.)
  const connectionBusy = useAppStore(s => s.connectionBusy)
  const cancelling = useAppStore(s => s.connectionCancelling)
  const setConnectionBusy = useAppStore(s => s.setConnectionBusy)
  const connecting = connectionBusy === 'connecting'
  const disconnecting = connectionBusy === 'disconnecting'
  const isServerSwitching = Boolean(serverSwitchingName)

  // Local state
  const [toasts, setToasts] = useState<ToastData[]>([])
  const [checking, setChecking] = useState(false)
  const [disengaging, setDisengaging] = useState(false)
  const [nuclearResetting, setNuclearResetting] = useState(false)
  const [ipGeo, setIpGeo] = useState<{ country: string | null; city: string | null }>({ country: null, city: null })
  const [confirmDisconnect, setConfirmDisconnect] = useState(false)
  const [ipCopied, setIpCopied] = useState(false)

  // Fetch country/city for the current public IP via ipapi.co
  // Only after VPN IP is confirmed — avoids geolocating the user's real IP.
  // Skipped entirely when disableGeoLookup is ON (privacy setting).
  useEffect(() => {
    if (!publicIp || isLeak || publicIpVerdict !== 'passed' || !tunRunning || !vpnIp || settings?.disableGeoLookup) {
      setIpGeo({ country: null, city: null })
      return
    }
    let cancelled = false
    const controller = new AbortController()
    ;(async () => {
      let country: string | null = null
      let city: string | null = null
      try {
        const resp = await fetch(`https://ipapi.co/${publicIp}/json/`, { signal: controller.signal })
        if (resp.ok) {
          const data = await resp.json().catch(() => null)
          if (data && !data.error) {
            country = data.country_name || null
            city = data.city || null
          }
        }
      } catch {}

      if (!country && !controller.signal.aborted) {
        try {
          const alt = await fetch(`https://ipwho.is/${encodeURIComponent(publicIp)}`, { signal: controller.signal })
          if (alt.ok) {
            const data = await alt.json().catch(() => null)
            if (data && data.success !== false) {
              country = data.country || null
              city = data.city || null
            }
          }
        } catch {}
      }

      if (!cancelled && (country || city)) {
        setIpGeo({ country, city })
        if (country) {
          window.electronAPI.serversVerifyActiveCountry(publicIp).catch(() => undefined)
        }
      }
    })()
    return () => {
      cancelled = true
      controller.abort()
    }
  }, [publicIp, isLeak, publicIpVerdict, tunRunning, vpnIp, settings?.disableGeoLookup])

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
  const circleBusy = isBusy || isServerSwitching
  // Soft mode is "connected" without a TUN: the UI mode flag ('soft') is set
  // when the env autoconfig is applied and cleared on disconnect.
  const uiMode = useAppStore(s => s.mode)
  const isSoftConnected =
    uiMode === 'soft' && settings.connectionMode !== 'directVpn'
  const isConnected = tunnelSnapshot
    ? tunnelSnapshot.state === 'connected' && tunnelSnapshot.transition === null : tunRunning || isSoftConnected
  const hasConnectionResources = tunnelSnapshot ? tunnelSnapshot.cleanupRequired : isConnected

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
    if (useAppStore.getState().connectionBusy || useAppStore.getState().serverSwitchingName) return
    const transitionSeq = ++connectionTransitionSeq.current
    setConnectionBusy('connecting')
    addLog('info', t('dashboard.connecting'))

    // Safety timeout: if the IPC never resolves (main process hung), clear
    // the busy state after 30s so the power button is not stuck spinning.
    const busyTimeout = setTimeout(() => {
      if (transitionSeq === connectionTransitionSeq.current) {
        setConnectionBusy(null)
        addLog('warn', 'Превышено время ожидания запуска. Попробуйте снова.')
      }
    }, 30000)

    const refreshKillSwitchState = () => {
      void refreshFirewallStatus()
    }

    try {
      if (settings.connectionMode === 'directVpn') {
        const active = await window.electronAPI.serversGetActive()
        if (transitionSeq !== connectionTransitionSeq.current) return
        if (!active.profile && !settings.directVpnInput.trim()) {
          showToast('error', t('dashboard.connectionError'), 'No server selected')
          addLog('error', 'Сначала выберите сервер в разделе «Серверы».')
          return
        }
        const saved = await window.electronAPI.saveSettings(settings)
        if (transitionSeq !== connectionTransitionSeq.current) return
        setSettings(saved)
        const result = await window.electronAPI.startDirectVpn()
        if (transitionSeq !== connectionTransitionSeq.current) return
        if (result.success) {
          setMode('hard')
          setTunRunning(true)
          if (result.vpnIp && (!useAppStore.getState().tunnelSnapshot ||
              useAppStore.getState().tunnelSnapshot?.state === 'connected' && !useAppStore.getState().tunnelSnapshot?.transition)) {
            setVpnIp(result.vpnIp)
            setPublicIp(result.vpnIp, false)
          }
          addLog('info', t(tunnelStartedMessageKey(saved.smartRuSplit)))
          if (result.warning) addLog('warn', result.warning)
        } else {
          const errorMsg = result.error || 'Unknown error'
          showToast('error', t('dashboard.connectionError'), errorMsg)
          addLog('error', `Не удалось включить Direct VPN: ${errorMsg}`)
        }
      } else if (settings.routingMode === 'soft') {
        // Soft mode (chosen in the first-run wizard): no TUN at all. Point
        // apps at the local proxy through the env autoconfig (setx
        // HTTP_PROXY/HTTPS_PROXY/ALL_PROXY) — this is the whole difference
        // from Hard, which tunnels everything at the routing layer.
        if (!proxyAddr) {
          showToast('error', t('dashboard.connectionError'), 'No proxy available')
          addLog('error', 'Прокси не найден. Запустите Happ или введите адрес вручную.')
          return
        }
        const saved = await window.electronAPI.saveSettings(settings)
        if (transitionSeq !== connectionTransitionSeq.current) return
        setSettings(saved)
        const result = await window.electronAPI.startSoftProtection(proxyAddr, proxyType)
        if (transitionSeq !== connectionTransitionSeq.current) return
        if (result.success) {
          setMode('soft')
          setTunRunning(false)
          setVpnIp(null)
          addLog('info', 'Soft-режим включён: приложения настроены на VPN-прокси (env autoconfig).')
        } else {
          const errorMsg = result.error || 'Не удалось применить env autoconfig'
          showToast('error', t('dashboard.connectionError'), errorMsg)
          addLog('error', `Не удалось включить Soft-режим: ${errorMsg}`)
        }
      } else {
        if (!proxyAddr) {
          showToast('error', t('dashboard.connectionError'), 'No proxy available')
          addLog('error', 'Прокси не найден. Запустите Happ или введите адрес вручную.')
          return
        }
        const saved = await window.electronAPI.saveSettings(settings)
        if (transitionSeq !== connectionTransitionSeq.current) return
        setSettings(saved)
        const result = await window.electronAPI.startTun(proxyAddr, proxyType)
        if (transitionSeq !== connectionTransitionSeq.current) return
        if (result.success) {
          setMode('hard')
          setTunRunning(true)
          if (result.vpnIp && (!useAppStore.getState().tunnelSnapshot ||
              useAppStore.getState().tunnelSnapshot?.state === 'connected' && !useAppStore.getState().tunnelSnapshot?.transition)) {
            setVpnIp(result.vpnIp)
            setPublicIp(result.vpnIp, false)
          }
          addLog('info', t(tunnelStartedMessageKey(saved.smartRuSplit)))
          if (result.warning) addLog('warn', result.warning)
        } else {
          const errorMsg = result.error || 'Unknown error'
          showToast('error', t('dashboard.connectionError'), errorMsg)
          addLog('error', `Не удалось включить защиту: ${errorMsg}`)
        }
      }
    } catch (err: any) {
      if (transitionSeq !== connectionTransitionSeq.current) return
      const errorMsg = err.message || 'Unknown error'
      showToast('error', t('dashboard.connectionError'), errorMsg)
      addLog('error', `Ошибка запуска: ${errorMsg}`)
    } finally {
      clearTimeout(busyTimeout)
      refreshKillSwitchState()
      if (transitionSeq === connectionTransitionSeq.current) {
        setConnectionBusy(null)
      }
    }
  }

  const handleDisconnect = async () => {
    if (connectionBusy) return
    const transitionSeq = ++connectionTransitionSeq.current
    setConnectionBusy('disconnecting')
    addLog('info', 'Выключаем защиту…')

    const busyTimeout = setTimeout(() => {
      if (transitionSeq === connectionTransitionSeq.current) {
        setConnectionBusy(null)
        addLog('warn', 'Превышено время ожидания остановки. Попробуйте снова.')
      }
    }, 30000)

    try {
      // The main connection owner also drains/rolls back Soft env changes.
      const result = await window.electronAPI.stopTun()
      if (transitionSeq !== connectionTransitionSeq.current) return
      if (result.success) {
        setMode('off')
        setTunRunning(false)
        setVpnIp(null)
        useAppStore.getState().resetConnectionState()
        addLog('info', 'Защита выключена. Возвращаем обычный маршрут.')
        if (result.warning) {
          showToast('warning', 'Защита выключена с предупреждениями', result.warning)
          addLog('warn', `Предупреждение при отключении: ${result.warning}`)
        }
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
      clearTimeout(busyTimeout)
      if (transitionSeq === connectionTransitionSeq.current) {
        setConnectionBusy(null)
      }
    }
  }

  const handleCancelTransition = async () => {
    if (!circleBusy || useAppStore.getState().connectionCancelling) return
    connectionTransitionSeq.current++
    useAppStore.getState().setConnectionCancelling(true)
    setConfirmDisconnect(false)
    const cancellationTarget = isServerSwitching ? 'смену сервера' : 'подключение'
    let switchCancellationRequested = false
    addLog('warn', `Отменяем ${cancellationTarget}…`)
    try {
      if (isServerSwitching) {
        await window.electronAPI.serversCancelSwitch()
        useAppStore.getState().acknowledgeServerSwitchCancellation()
        switchCancellationRequested = true
        addLog('info', t('dashboard.serverSwitchCancellationRequested'))
      } else {
        const result = await window.electronAPI.cancelTun()
        if (result.success) {
          setMode('off')
          setTunRunning(false)
          setVpnIp(null)
          useAppStore.getState().resetConnectionState()
          if (result.warning) {
            showToast('warning', t('dashboard.cancelledWithWarnings'), result.warning)
            addLog('warn', `Отмена завершилась с предупреждением: ${result.warning}`)
          } else {
            showToast('info', t('dashboard.connectionCancelled'))
            addLog('info', t('dashboard.connectionCancelled'))
          }
        } else {
          const errorMsg = result.error || t('dashboard.cancelFailed')
          showToast('error', t('dashboard.cancelFailed'), errorMsg)
          addLog('error', `Не удалось отменить подключение: ${errorMsg}`)
        }
      }
    } catch (err: any) {
      showToast('error', t('dashboard.cancelFailed'), err?.message || String(err))
      addLog('error', `Не удалось отменить ${cancellationTarget}: ${err?.message || String(err)}`)
    } finally {
      // These IPCs only acknowledge the request. The selection owner releases
      // cancellation after restart/rollback has actually completed.
      if (!switchCancellationRequested || !useAppStore.getState().serverSwitchingName) {
        useAppStore.getState().setConnectionCancelling(false)
        setConnectionBusy(null)
      }
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

  const visibleLeak = isLeak && !isServerSwitching
  const showKillSwitchBanner =
    firewallStatus.state !== 'inactive' &&
    firewallStatus.reason !== 'checking' &&
    !tunRunning &&
    !isServerSwitching &&
    !connecting &&
    !disconnecting &&
    !restartingProgress &&
    Date.now() >= suppressFirewallBannerUntil
  const competingTun = useAppStore(s => s.competingTun)

  const handleDisengageKillSwitch = async () => {
    setDisengaging(true)
    useAppStore.getState().invalidateFirewallKillSwitchStatus()
    try {
      const result = await window.electronAPI.disableFirewallKillSwitch()
      if (result.success) {
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
      void refreshFirewallStatus()
      setDisengaging(false)
    }
  }

  // Last-resort recovery for a wedged firewall (e.g. disable-kill-switch
  // succeeded but DefaultOutboundAction stayed Block, or third-party rules
  // still block all outbound). Wipes Windows Firewall to defaults.
  const handleNuclearFirewallReset = async () => {
    const confirmed = window.confirm(
      'Полностью сбросить Windows Firewall к настройкам по умолчанию? Это удалит ВСЕ правила firewall, включая правила других приложений.'
    )
    if (!confirmed) return
    setNuclearResetting(true)
    useAppStore.getState().invalidateFirewallKillSwitchStatus()
    try {
      const result = await window.electronAPI.firewallNuclearReset('RESET_WINDOWS_FIREWALL_CONFIRMED')
      if (result.success) {
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
      void refreshFirewallStatus()
      setNuclearResetting(false)
    }
  }

  // ─── Route diagnostics ─────────────────────────────────────────────────

  const runDiagnostics = async () => {
    const addr = settings.proxyOverride.trim() || (proxy ? `${proxy.host}:${proxy.port}` : '')
    setChecking(true)
    addLog('info', t('dashboard.routeCheckStart'))
    try {
      const result = await window.electronAPI.runLeakCheck({
        proxyAddr: addr || undefined,
        proxyType: settings.proxyOverride.trim() ? settings.proxyType : proxy?.type ?? settings.proxyType
      })
      setLeakChecks(result)
      // The dashboard shows only the verdict; the journal keeps which checks need attention
      for (const item of result.items) {
        if (item.status === 'warn' || item.status === 'fail') addLog(item.status === 'fail' ? 'error' : 'warn', item.label + ': ' + item.value)
      }
      const message =
        result.summary === 'ok'
          ? t('dashboard.routeCheckOk')
          : result.summary === 'fail'
            ? t('dashboard.routeCheckFail')
            : t('dashboard.routeCheckWarn')
      addLog(result.summary === 'fail' ? 'error' : result.summary === 'warn' ? 'warn' : 'info', t('dashboard.routeCheckResult', { message }))
    } catch (err: unknown) {
      // No verdict from this run: drop the previous one so nothing presents it as current
      setLeakChecks(null)
      const message = isIpcRemoteErrorData(err) || err instanceof Error ? err.message : String(err)
      addLog('error', t('dashboard.routeCheckFailed', { message }))
    } finally {
      setChecking(false)
    }
  }

  // ─── Status label ──────────────────────────────────────────────────────

  const isProxyActuallyDown = proxyDown && (!traffic?.running || ((traffic.smoothedDownloadBps || traffic.downloadBps) <= 1024 && (traffic.smoothedUploadBps || traffic.uploadBps) <= 1024))

  const statusLabel = (() => {
    if (cancelling) return t('dashboard.cancelling')
    if (isServerSwitching) return t('dashboard.switchingServer', { name: serverSwitchingName })
    if (connecting) return t('dashboard.connecting')
    if (disconnecting) return t('dashboard.disconnecting', 'Отключение...')
    if (restartingProgress) return `Перезапуск ${restartingProgress}`
    if (tunnelSnapshot?.state === 'blocked') return t('dashboard.tunnelBlocked')
    if (tunnelSnapshot?.state === 'unknown') return t('dashboard.tunnelUnknown')
    if (tunnelSnapshot?.state === 'error') return t('dashboard.tunnelError')
    if (isConnected && isProxyActuallyDown) return 'Сервер не отвечает — трафик заблокирован'
    if (isConnected) return t('dashboard.connected')
    return t('dashboard.disconnected')
  })()

  // ─── «Пломба» redesign: one big Latin status word + slab state ─────────

  // Secure only when connected, healthy and the exit IP is verified. The words
  // are deliberately Latin in every locale (heavy Cyrillic caps read poorly at
  // this size); they still live in en/ru.json.
  const swissState = deriveSwissState({
    cancelling,
    switching: isServerSwitching,
    connecting,
    disconnecting,
    restarting: Boolean(restartingProgress),
    connected: Boolean(isConnected),
    leak: visibleLeak,
    tunnelState: tunnelSnapshot?.state ?? null,
    proxyDown: Boolean(isProxyActuallyDown),
    degraded: tunnelSnapshot?.health === 'degraded' || Boolean(competingTun),
    verdict: publicIpVerdict ?? null
  })
  const swissWordKeys = {
    cancel: 'dashboard.swissWordCancel',
    switch: 'dashboard.swissWordSwitch',
    linking: 'dashboard.swissWordLinking',
    closing: 'dashboard.swissWordClosing',
    restart: 'dashboard.swissWordRestart',
    leak: 'dashboard.swissWordLeak',
    alert: 'dashboard.swissWordAlert',
    blocked: 'dashboard.swissWordBlocked',
    degraded: 'dashboard.swissWordDegraded',
    verify: 'dashboard.swissWordVerify',
    secure: 'dashboard.swissWordSecure',
    exposed: 'dashboard.swissWordExposed'
  } as const
  const swissWord = t(swissWordKeys[swissState])
  const swissBusy = circleBusy || cancelling || Boolean(restartingProgress)
  const swissAlert = swissState === 'leak' || swissState === 'alert' || swissState === 'blocked' || swissState === 'degraded'
  const swissOn = swissState === 'secure'
  // 'verify' = a live tunnel waiting for its IP check, not a transition: the mascot
  // must not treat a recheck as reconnecting.
  const swissPhase: SwissPhase = swissOn || swissState === 'verify' ? 'on' : swissAlert ? 'alert' : swissBusy ? 'connecting' : 'off'
  const nudgeMascot = (kind: 'hover-in' | 'hover-out') => {
    window.dispatchEvent(new CustomEvent(MASCOT_EVENT, { detail: kind }))
  }

  // «Пломба» identity column: what sites see, the real address, the active node
  const homeIp = useHomeIp(Boolean(isConnected))
  const activeProfile = useActiveProfile()
  const realHidden = Boolean(isConnected) && !visibleLeak
  const copyIp = async () => {
    if (!publicIp) return
    try {
      await navigator.clipboard.writeText(publicIp)
      setIpCopied(true)
      window.setTimeout(() => setIpCopied(false), 1300)
    } catch {
      // Clipboard unavailable: no false "copied" feedback
    }
  }
  const nodePing = activeProfile ? activeProfile.ping ?? activeProfile.healthLatencyMs ?? null : null
  const nodeHealth = activeProfile ? activeProfile.healthStatus ?? activeProfile.status : undefined
  const nodeMeta = activeProfile
    ? [activeProfile.protocol ? activeProfile.protocol.toUpperCase() : '', nodePing !== null ? nodePing + ' ' + t('dashboard.swissMs') : nodeHealth === 'offline' ? t('dashboard.swissOffline') : t('dashboard.swissUnchecked')].filter(Boolean).join(' · ')
    : ''
  // Ctrl/Cmd+Enter presses the power button: same confirm/cancel rules as a click
  const powerRef = useRef<HTMLButtonElement>(null)
  const pageActive = usePageActive()
  useEffect(() => {
    if (!pageActive) return
    const onKey = (e: KeyboardEvent) => {
      if (!(e.ctrlKey || e.metaKey) || e.key !== 'Enter' || e.repeat) return
      const target = e.target as HTMLElement | null
      if (target && (target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName))) return
      // A focused control keeps its own Ctrl+Enter (e.g. «Отмена» in the confirm), dialogs own the keyboard
      if (target && target !== powerRef.current && target.closest('button, a, [role="dialog"], [aria-modal="true"]')) return
      // The first-run wizard covers the dashboard: no VPN toggling underneath it
      if (!useAppStore.getState().settings.firstRunComplete) return
      const button = powerRef.current
      if (!button || button.disabled) return
      e.preventDefault()
      button.click()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [pageActive])

  // ─── Render ────────────────────────────────────────────────────────────

  return (
    /* «Пломба» dashboard: facts strip → status slab → panel row (traffic · servers · journal). */
    <div className="c-swiss swiss-skin">
      <div className="space-y-6">
      {/* Toast notifications */}
      <MacToast toasts={toasts} onDismiss={dismissToast} position="top-right" />

      {restartingProgress && (
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="rounded-[var(--radius-md)] border-2 border-[var(--color-warning)]/60 bg-[var(--color-warning)]/10 p-4 shadow-[0_0_20px_rgba(255,165,0,0.15)]"
          role="alert"
        >
          <div className="flex items-center gap-3">
            <Loader2 className="w-6 h-6 text-[var(--color-warning)] animate-spin flex-shrink-0" />
            <div>
              <p className="text-sm font-bold text-[var(--color-warning)]">
                VPN соединение потеряно — авто-перезапуск {restartingProgress}
              </p>
              <p className="text-xs text-[var(--color-warning)]/80 mt-0.5">
                Пытаемся восстановить подключение автоматически. Если не получится — включите защиту вручную.
              </p>
            </div>
          </div>
        </motion.div>
      )}
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
                {t(firewallStatus.state === 'verified' ? 'dashboard.firewallVerifiedTitle' : 'dashboard.firewallUnknownTitle')}
              </p>
              <p className="text-sm text-[var(--color-danger)]/90 mt-1">
                {t(firewallStatus.state === 'verified' ? 'dashboard.firewallVerifiedBody' : 'dashboard.firewallUnknownBody')}
              </p>
              <div className="flex flex-wrap gap-2 mt-3">
                <button
                  onClick={() => void refreshFirewallStatus()}
                  disabled={firewallStatus.reason === 'checking' || disengaging || nuclearResetting}
                  aria-busy={firewallStatus.reason === 'checking'}
                  className="text-sm font-medium px-4 py-2 rounded-[var(--radius-sm)] border border-[var(--color-danger)] text-[var(--color-danger)] hover:bg-[var(--color-danger)]/10 transition-colors duration-[var(--transition-fast)] disabled:opacity-50"
                >
                  {t(firewallStatus.reason === 'checking' ? 'dashboard.firewallChecking' : 'dashboard.firewallRecheck')}
                </button>
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

      {/* Leak warning banner */}
      {visibleLeak && (
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

      <ForeignVpnBanner />

      {/* «Пломба» facts strip: mode · Smart RU · kill-switch · leaks */}
      <SwissFactsStrip onCheckLeaks={runDiagnostics} checking={checking} />

      {/* Main VPN Toggle Card — «Пломба» status slab */}
      <section className={cn('c-swiss swiss-slab', swissOn && 'is-on', swissAlert && 'is-alert')}>
        <div className="swiss-slab-main">
          {swissBusy && <div className="swiss-stripes" aria-hidden="true" />}
          {/* Heading for screen readers; the slab itself carries no visible label */}
          <h2 className="sr-only">{t('dashboard.vpnToggle')}</h2>
          <div className="swiss-word-row relative">
            <FitWord key={swissWord} text={swissWord} busyDot={swissBusy} />
            {/* The mascot's home perch; SwissMascot draws him on top of it */}
            <div className="swiss-home" data-perch="home" data-perch-y="bottom" data-perch-scale="0.8" aria-hidden="true" />
          </div>
          <div className="swiss-caption-row relative">
        {/* During cancellation the button shows the label; keep live status for screen readers. */}
        <p className={cancelling ? 'sr-only' : 'swiss-caption'} role="status" aria-live="polite">
          {statusLabel}
        </p>
        {isConnected && !swissBusy && tunStartedAt && <UptimeLabel startedAt={tunStartedAt} />}
          </div>
        </div>

        <div className="swiss-slab-side">
          <div className="swiss-identity">
            <div>
              <div className="swiss-label">{t('dashboard.swissSitesSee')}</div>
              {publicIp ? (
                <button type="button" className="swiss-ip" onClick={() => void copyIp()} title={t('dashboard.swissCopy')}>
                  <span key={publicIp} className="roll">{publicIp}</span>
                  <span className={cn('swiss-ip-copy', ipCopied && 'is-copied')}>{ipCopied ? t('dashboard.swissCopied') : t('dashboard.swissCopy')}</span>
                </button>
              ) : (
                <div className="swiss-ip is-dim">—</div>
              )}
              <div
                className={cn('swiss-sub', Boolean(publicIp) && visibleLeak && 'is-alert')}
                data-perch="ip"
                data-perch-y="bottom"
                data-perch-x="1"
                data-perch-scale="0.24"
                data-perch-fit="gap"
              >
                {publicIp && visibleLeak ? (
                  <span>{'— ' + t('dashboard.swissIpLeak')}</span>
                ) : publicIp && isConnected && (publicIpVerdict === 'indeterminate' || publicIpVerdict === 'not-checked') ? (
                  <span>{'— ' + (publicIpVerdict === 'indeterminate' ? t('dashboard.ipChangedUnverified') : t('dashboard.ipNotChecked'))}</span>
                ) : publicIp && isConnected && publicIpVerdict === 'passed' && ipGeo.country ? (
                  <>
                    <CountryFlagIcon country={ipGeo.country} size={14} />
                    <span>{ipGeo.country + (ipGeo.city ? ', ' + ipGeo.city : '')}</span>
                  </>
                ) : publicIp && isConnected && publicIpVerdict === 'passed' ? (
                  <span>{t('dashboard.swissViaVpn')}</span>
                ) : isConnected ? (
                  <span>{t('dashboard.swissIpDetecting')}</span>
                ) : (
                  <span>{t('dashboard.swissIpYourIsp')}</span>
                )}
              </div>
            </div>
            <div>
              <div className="swiss-label">{t('dashboard.swissRealAddress')}</div>
              <div className={cn('swiss-real', realHidden && Boolean(homeIp) && 'is-hidden')}>{homeIp ?? '—'}</div>
              {!realHidden && <div className="swiss-sub is-alert">{t('dashboard.swissExposedToAll')}</div>}
            </div>
            <div>
              <div className="swiss-label">{t('dashboard.swissNode')}</div>
              {activeProfile ? (
                <>
                  <div className="swiss-node">
                    {activeProfile.country ? <CountryFlagIcon country={activeProfile.country} size={14} /> : null}
                    <span className="truncate">{activeProfile.name}</span>
                  </div>
                  {nodeMeta && <div className="swiss-sub">{nodeMeta}</div>}
                </>
              ) : (
                <div className="swiss-node is-dim">{t('dashboard.swissNoServer')}</div>
              )}
            </div>
          </div>

          {(confirmDisconnect || connecting || isServerSwitching || cancelling) && (
            <div className="swiss-transient">
              {/* Disconnect confirmation */}
              {confirmDisconnect && (
                <motion.div
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="flex flex-col gap-2"
                >
                  <p className="swiss-confirm-text">
                    {t('dashboard.disconnectConfirmation')}
                  </p>
                  <div className="swiss-confirm-actions">
                    <button
                      onClick={() => { setConfirmDisconnect(false); handleToggleChange(false) }}
                      className="swiss-confirm-yes"
                    >
                      {t('dashboard.confirmDisconnect')}
                    </button>
                    <button
                      onClick={() => setConfirmDisconnect(false)}
                      className="swiss-confirm-no"
                    >
                      {t('dashboard.cancelDisconnect')}
                    </button>
                  </div>
                </motion.div>
              )}

              {(connecting || isServerSwitching || cancelling) && (
                <button
                  type="button"
                  onClick={handleCancelTransition}
                  disabled={cancelling}
                  aria-busy={cancelling}
                  className="swiss-cancel-btn"
                >
                  {cancelling ? <Loader2 size={13} className="animate-spin" /> : <Square size={13} />}
                  {cancelling ? t('dashboard.cancelling') : isServerSwitching ? t('dashboard.cancelServerSwitch') : t('dashboard.cancelConnection')}
                </button>
              )}
            </div>
          )}

          <motion.button
            ref={powerRef}
            onClick={() => {
              if (hasConnectionResources && !confirmDisconnect && !isBusy) {
                setConfirmDisconnect(true)
                // Auto-cancel confirmation after 3s
                setTimeout(() => setConfirmDisconnect(false), 3000)
                return
              }
              setConfirmDisconnect(false)
              handleToggleChange(!hasConnectionResources)
            }}
            disabled={circleBusy}
            whileHover={!circleBusy ? { scale: 1.01 } : {}}
            whileTap={!circleBusy ? { scale: 0.99 } : {}}
            aria-label={statusLabel}
            animate={isServerSwitching && !cancelling ? { scale: [1, 1.025, 1] } : { scale: 1 }}
            transition={isServerSwitching && !cancelling ? { duration: 1.2, repeat: Infinity, ease: 'easeInOut' } : { duration: 0.2 }}
            className={cn('swiss-power', cancelling ? 'is-cancel' : isServerSwitching ? 'is-busy' : isConnected && 'is-on', circleBusy && 'is-wait')}
            title={hasConnectionResources ? t('dashboard.swissDisable') : t('dashboard.swissEnable')}
            onMouseEnter={() => nudgeMascot('hover-in')}
            onMouseLeave={() => nudgeMascot('hover-out')}
            data-perch="toggle"
            data-perch-y="bottom"
            data-perch-x="0.6"
            data-perch-scale="0.48"
            data-perch-fit="gap"
          >
            {isServerSwitching && !cancelling && (
              <>
                <motion.div
                  className="absolute inset-0 border-2 border-[var(--signal)]"
                  animate={{ scale: [0.95, 1.18, 0.95], opacity: [0.65, 0.08, 0.65] }}
                  transition={{ duration: 1.35, repeat: Infinity, ease: 'easeOut' }}
                />
              </>
            )}
            {isConnected && !isServerSwitching && !cancelling && (
              <motion.div
                className="absolute inset-0 bg-[var(--signal)]"
                initial={{ scale: 1, opacity: 0.35 }}
                animate={{ scale: 1.12, opacity: 0 }}
                transition={{ duration: 0.6, ease: 'easeOut' }}
              />
            )}
            <div className="swiss-power-content">
              <span className="truncate">{swissBusy ? statusLabel : hasConnectionResources ? t('dashboard.swissDisable') : t('dashboard.swissEnable')}</span>
              {circleBusy ? (
                <Loader2 size={20} className="shrink-0 animate-spin" />
              ) : (
                <ArrowRight size={20} className="swiss-power-arrow shrink-0" strokeWidth={2.5} />
              )}
            </div>
          </motion.button>
        </div>

        <SwissProgress operation={tunnelSnapshot?.operation ?? null} busy={swissBusy} />
        <SwissMascot phase={swissPhase} />
      </section>

      {/* Traffic · servers · journal: the panel row under the slab */}
      <SwissPanels />
      </div>
    </div>
  )
}
