import { app, BrowserWindow, dialog, ipcMain, Tray, shell, session, type IpcMainInvokeEvent } from 'electron'
import { exec as execCb } from 'child_process'
import { promisify } from 'util'
import { join } from 'path'
import { happDetector } from './happDetector'
import { tunController, detectForeignTun } from './tunController'
import { classifyNavigation } from './navigationPolicy'
import { ipMonitor } from './ipMonitor'
import { autoconfig } from './autoconfig'
import { createTray, updateTrayState, type TrayStatus } from './tray'
import { settingsStore } from './settings'
import { runLeakCheck } from './leakDiagnostics'
import { runStoreRepair, type StoreRepairAction } from './storeRepair'
import { runStoreDiagnostics } from './storeDiagnostics'
import { applyLocationPrivacy, getLocationPrivacyStatus, rollbackLocationPrivacy } from './locationPrivacy'
import {
  applyTunNetworkBaseline,
  isBaselineApplied,
  rollbackTunNetworkBaseline,
  rollbackTunNetworkBaselineIfApplied
} from './systemNetwork'
import {
  disableKillSwitchIfActive,
  isKillSwitchActive,
  nuclearFirewallReset,
  recoverStaleKillSwitch
} from './firewallKillSwitch'
import {
  isPhysicalAdapterLockdownApplied,
  repairOrphanedPhysicalAdapterDns,
  rollbackPhysicalAdapterLockdownIfApplied
} from './physicalAdapterLockdown'
import { relaunchElevatedIfNeeded } from './admin'
import { clearAppLog, getFullLogs, logEvent, openLogFolder, type AppLogLevel } from './appLogger'
import { runSystemDiagnostics } from './systemDiagnostics'
import { getRoutingPlan } from './connectionPlanner'
import { runAutoPilot } from './autoPilot'
import { notify, setInAppFallbackCallback } from './notifications'
import { exportDiagnosticsZip } from './diagnosticsExport'
import { captureSnapshot, getSnapshotsDir, startPeriodicSnapshots, stopPeriodicSnapshots } from './systemSnapshot'
import { runLeakSelfTest, startPeriodicLeakTest, stopPeriodicLeakTest, setLeakDetectedCallback, startNetworkChangeWatcher, stopNetworkChangeWatcher } from './leakSelfTest'
import { trafficMonitor, type TrafficStats } from './trafficMonitor'
import { applyBrowserLeakProtection, rollbackBrowserLeakProtection } from './browserHardening'
import { resolveVpnProfile, resolveVpnProfiles, redactSensitiveConfig, type VpnProfile } from './vpnProfiles'

// ─── V2 Feature Modules ──────────────────────────────────────────────────────
import { registerSplitTunnelHandlers } from './splitTunneling'
import { registerServerPickerHandlers, serverPicker } from './serverPicker'
import { registerServerGroupsHandlers } from './serverGroups'
import { registerServerProbeIpcHandlers } from './serverProbe'
import { registerUrlAvailabilityHandlers } from './urlAvailability'
import { registerSpeedTestHandlers } from './speedTest'
import { registerKillSwitchIpc, granularKillSwitch } from './granularKillSwitch'
import { registerRotationHandlers, initProfileRotation } from './profileRotation'
import { registerSchedulerIpcHandlers, schedulerService } from './scheduler'
import { registerConnectionHistoryIpcHandlers, connectionHistoryService } from './connectionHistory'
import { registerTrafficHistoryIpcHandlers } from './trafficHistory'
import { registerDnsHandlers, initDnsProfiles } from './dnsProfiles'
import { registerDomainRoutingIpcHandlers } from './domainRouting'
import { registerConfigManagerIpcHandlers } from './configManager'
import { registerNotificationPrefsIpcHandlers } from './notificationPrefs'
import { registerI18nIpcHandlers } from './i18n'
import { registerThemeIpcHandlers } from './themeManager'
import { registerWidgetLayoutIpcHandlers } from './widgetLayout'

const exec = promisify(execCb)

let mainWindow: BrowserWindow | null = null
let tray: Tray | null = null
let isQuitting = false
let shutdownInProgress = false
let latestPublicIp: string | null = null
let latestTraffic: TrafficStats = trafficMonitor.getCurrentStats()
let latestTrayStatus: TrayStatus = 'off'
let latestTrayProxyAddr: string | null = null
let latestKillSwitchActive = false
let latestRestartingProgress: string | null = null

// Connection history tracking. We open a "current connection" record when
// startProtection / startDirectVpnProtection succeeds, and close it on stop or
// on a status change to a terminal state. `stopInProgress` guards against
// double-recording when the user-initiated stop also triggers a status-change
// event.
let currentConnectionStart: number | null = null
let currentConnectionProfile: { id: string; name: string; mode: 'hard' | 'soft' | 'direct' } | null = null
let stopInProgress = false

// Global guards against uncaught exceptions / rejections in the main process.
// Without these, a stray ECONNRESET on a stale TCP socket (axios connection
// dropped mid-stream, telemetry probe killed by the firewall, etc.) shows the
// big white "A JavaScript error occurred in the main process" modal and
// effectively wedges the app — even though the error is recoverable. Here we
// just log it and keep going. We deliberately do NOT swallow the error
// silently: it goes through `logEvent` so it shows up in app log + diagnostics
// ZIP, and it's surfaced to the renderer so the user can see "что-то пошло не
// так" without losing the whole app.
function installCrashGuards(): void {
  // Common, mostly-recoverable network-layer errors that shouldn't crash the
  // app even once. ECONNRESET happens when the peer (proxy/AV/firewall) tears
  // down a half-open TCP socket. EPIPE is similar for write side. ENOTFOUND /
  // EAI_AGAIN come from DNS while TUN is restarting.
  const benignNetCodes = new Set(['ECONNRESET', 'EPIPE', 'ENOTFOUND', 'EAI_AGAIN', 'ETIMEDOUT', 'ECONNABORTED'])

  process.on('uncaughtException', (err: NodeJS.ErrnoException) => {
    const isBenignNet = err && err.code !== undefined && benignNetCodes.has(err.code)
    logEvent(isBenignNet ? 'warn' : 'error', 'app', 'uncaughtException — keeping app alive', {
      code: err?.code,
      message: err?.message,
      stack: err?.stack
    })
    if (mainWindow && !mainWindow.isDestroyed()) {
      try {
        mainWindow.webContents.send('main-error', {
          code: err?.code ?? 'UNKNOWN',
          message: err?.message ?? String(err)
        })
      } catch {
        // If even the IPC send throws, swallow it — there's nothing meaningful to do.
      }
    }
  })

  process.on('unhandledRejection', (reason: any) => {
    const code = reason?.code
    const isBenignNet = typeof code === 'string' && benignNetCodes.has(code)
    logEvent(isBenignNet ? 'warn' : 'error', 'app', 'unhandledRejection — keeping app alive', {
      code,
      message: reason?.message ?? String(reason),
      stack: reason?.stack
    })
  })
}
installCrashGuards()

// ─── Windows AppUserModelID ─────────────────────────────────────────────────
//
// Must be set BEFORE app.whenReady() so every Notification object created in
// this process is tagged with this AUMID. Without it, Electron picks an
// unstable auto-generated id, which means:
//   - Windows can't find us in Settings → Notifications (no stable identity).
//   - The "Don't show notifications" registry block ends up keyed to a random
//     id that survives across builds (or, conversely, the user's intentional
//     allow gets lost when the id rolls).
//   - Toasts may show but never appear in Action Center history because the
//     OS can't correlate them with a registered Start Menu shortcut.
//
// Keep this string in sync with electron-builder.yml `appId` and with the
// `candidateModelIds()` list in src/main/notifications.ts — those three
// places must agree or the registry-based block check / clear will miss.
export const APP_USER_MODEL_ID = 'com.vpntunnelenforcer.app'
if (process.platform === 'win32') {
  app.setAppUserModelId(APP_USER_MODEL_ID)
}

// ─── Single-instance lock ────────────────────────────────────────────────────
//
// A VPN enforcer must never run as two instances. Both would manage the SAME
// kill-switch manifest, TUN adapter and adapter-lockdown manifest. The most
// dangerous race: instance B's startup stale-recovery could roll back instance
// A's LIVE kill-switch / adapter lockdown, opening a real IP-leak window while
// A still believes its tunnel is protected. They'd also double-register IPC,
// fight over the tray, and issue conflicting start/stop.
//
// requestSingleInstanceLock() returns false in the second process; we quit it
// immediately. The first process gets a 'second-instance' event and focuses
// its existing window so the user sees the running app instead of nothing.
//
// Skipped in dev (ELECTRON_RENDERER_URL set) so hot-reload / multiple dev
// launches aren't blocked.
if (app.isPackaged && !app.requestSingleInstanceLock()) {
  // We are the second instance. Do NOT run any cleanup/recovery — that would
  // touch the first instance's live firewall/adapter state. Just exit hard.
  app.exit(0)
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore()
      if (!mainWindow.isVisible()) mainWindow.show()
      mainWindow.focus()
    }
  })
}

function getIconPath() {
  if (process.env.ELECTRON_RENDERER_URL) {
    return join(__dirname, '../../resources/icon.ico')
  }
  return join(process.resourcesPath, 'icon.ico')
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 900,
    height: 680,
    minWidth: 800,
    minHeight: 600,
    show: false,
    frame: true,
    autoHideMenuBar: true,
    icon: getIconPath(),
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      contextIsolation: true,
      nodeIntegration: false
    },
    backgroundColor: '#1e1e2e'
  })

  mainWindow.on('ready-to-show', () => {
    mainWindow!.show()
  })

  mainWindow.on('close', (e) => {
    // Quitting through tray menu / app.quit() — let it close immediately.
    if (isQuitting) return

    const tunRunning = tunController.getStatus().running
    const minimizeToTray = settingsStore.get().minimizeToTray

    // Common case: tunnel idle. Either send to tray (if user wants that) or
    // proceed with the regular close flow that triggers before-quit cleanup.
    if (!tunRunning) {
      if (!minimizeToTray) return
      e.preventDefault()
      mainWindow!.hide()
      return
    }

    // VPN is running. Closing the window now would trigger an asynchronous
    // shutdown sequence (tunController.stop → kill-switch rollback → adapter
    // lockdown rollback → DNS repair) which takes 5–15s, during which the
    // app looks "dead" and the user might pull the plug or relaunch — both
    // leave Windows in a half-cleaned-up state. So we prompt explicitly.
    e.preventDefault()
    const choices = minimizeToTray
      ? ['Свернуть в трей', 'Отключить и закрыть', 'Отмена']
      : ['Отключить и закрыть', 'Отмена']
    const trayIdx = minimizeToTray ? 0 : -1
    const stopIdx = minimizeToTray ? 1 : 0
    const cancelIdx = choices.length - 1

    void dialog.showMessageBox(mainWindow!, {
      type: 'question',
      title: 'Защита включена',
      message: 'VPN сейчас активен.',
      detail: minimizeToTray
        ? 'Окно можно свернуть в трей — защита продолжит работать в фоне. Или полностью отключить защиту и закрыть приложение (это безопасно откатит все сетевые настройки, занимает несколько секунд).'
        : 'Чтобы корректно завершить работу, нужно сначала отключить защиту: мы вернём DNS, IPv6 и правила брандмауэра в исходное состояние. Это займёт несколько секунд.',
      buttons: choices,
      defaultId: trayIdx >= 0 ? trayIdx : stopIdx,
      cancelId: cancelIdx,
      noLink: true
    }).then(async ({ response }) => {
      if (response === cancelIdx) return
      if (trayIdx >= 0 && response === trayIdx) {
        mainWindow!.hide()
        return
      }
      // "Отключить и закрыть": stop the tunnel synchronously, then quit.
      // The renderer is still mounted at this point so we can show progress
      // through the tray balloon and the in-window overlay (the renderer is
      // also notified via 'app:shutting-down' so it can disable controls).
      isQuitting = true
      try {
        mainWindow?.webContents.send('app:shutting-down')
      } catch {
        /* renderer may already be gone */
      }
      try {
        await stopProtection()
      } catch (err) {
        logEvent('warn', 'app', 'stopProtection during user-initiated close failed', err)
      }
      app.quit()
    }).catch(() => {
      /* Dialog itself failed (rare). Leave window as-is rather than risk
         a half-closed state. */
    })
  })

  const loadRenderer = () => {
    if (process.env.ELECTRON_RENDERER_URL) {
      mainWindow!.loadURL(process.env.ELECTRON_RENDERER_URL).catch(() => {
        setTimeout(loadRenderer, 1000)
      })
    } else {
      mainWindow!.loadFile(join(__dirname, '../renderer/index.html'))
    }
  }
  loadRenderer()

  hardenWebContents(mainWindow.webContents)
}

/**
 * Lock down a BrowserWindow's webContents against the classic Electron
 * navigation-hijack class of bugs. Two attack vectors matter here:
 *
 *   1. Attacker-controlled URLs reaching the renderer. The biggest one is
 *      `webPageUrl`, which we read verbatim from a subscription's
 *      `profile-web-page-url` HTTP header (vpnProfiles.ts) — i.e. the VPN
 *      provider, not the user, controls it. The Servers page renders it as a
 *      `<a target="_blank">`. Without a guard, a malicious panel could point
 *      it at a `file://`, an arbitrary `https://` phishing page that loads
 *      INSIDE our trusted window (same chromium, our preload), or a custom
 *      scheme that launches another program.
 *   2. Any in-app `window.open` / link click that would otherwise spawn a
 *      child BrowserWindow with default (unhardened) webPreferences.
 *
 * The actual decision lives in the pure, tested `classifyNavigation`.
 */
function hardenWebContents(contents: Electron.WebContents): void {
  const devUrl = process.env.ELECTRON_RENDERER_URL

  // Hand http(s) links to the OS browser; reject everything else. Never let a
  // renderer-triggered open create a new in-app window.
  contents.setWindowOpenHandler(({ url }) => {
    if (classifyNavigation(url, devUrl) === 'open-external') {
      shell.openExternal(url).catch(err =>
        logEvent('warn', 'security', 'openExternal failed', { url, err: String(err) })
      )
    } else {
      logEvent('warn', 'security', 'blocked window.open', { url })
    }
    return { action: 'deny' }
  })

  // Cancel any attempt to navigate the main window away from our own origin.
  contents.on('will-navigate', (event, url) => {
    const verdict = classifyNavigation(url, devUrl)
    if (verdict === 'allow-internal') return
    event.preventDefault()
    logEvent('warn', 'security', 'blocked in-app navigation', { url, verdict })
    if (verdict === 'open-external') {
      shell.openExternal(url).catch(() => undefined)
    }
  })

  // Defence-in-depth: never allow <webview> embeds (we don't use them).
  contents.on('will-attach-webview', (event) => {
    event.preventDefault()
    logEvent('warn', 'security', 'blocked webview attach')
  })
}

function compactForLog(value: unknown): string {
  try {
    const raw = JSON.stringify(redactSensitiveConfig(value))
    if (!raw) return ''
    return raw.length > 2000 ? `${raw.slice(0, 2000)}...<truncated>` : raw
  } catch {
    return String(value)
  }
}

function handleLogged<T>(
  channel: string,
  listener: (event: IpcMainInvokeEvent, ...args: any[]) => Promise<T> | T
) {
  ipcMain.handle(channel, async (event, ...args) => {
    const started = Date.now()
    logEvent('debug', 'ipc', `${channel} started`, { args: compactForLog(args) })
    try {
      const result = await listener(event, ...args)
      logEvent('debug', 'ipc', `${channel} finished`, {
        ms: Date.now() - started,
        result: compactForLog(result)
      })
      return result
    } catch (err) {
      logEvent('error', 'ipc', `${channel} failed`, err)
      throw err
    }
  })
}

// Crash recovery: if a previous session applied the network baseline but never rolled it
// back (process killed, BSOD, force-quit), the user's HKCU\Internet Settings + env proxy
// vars stay wiped forever. On startup, if no sing-box is left running, restore them.
async function recoverStaleBaseline(): Promise<void> {
  if (process.platform !== 'win32') return
  if (!(await isBaselineApplied())) return
  try {
    const { stdout } = await exec('tasklist /FI "IMAGENAME eq vpnte-sing-box.exe" /FO CSV /NH', {
      windowsHide: true,
      timeout: 5000,
      encoding: 'utf8'
    })
    if (String(stdout).toLowerCase().includes('vpnte-sing-box.exe')) {
      logEvent('info', 'app', 'baseline marker found and sing-box is still running — keeping baseline')
      return
    }
  } catch {
    // fall through to rollback
  }
  logEvent('warn', 'app', 'stale baseline detected on startup (sing-box not running) — rolling back')
  await rollbackTunNetworkBaselineIfApplied('crash recovery on startup').catch(err =>
    logEvent('warn', 'app', 'crash-recovery rollback failed', err)
  )
}

function refreshTrayState(patch: {
  status?: TrayStatus
  publicIp?: string | null
  proxyAddr?: string | null
  traffic?: TrafficStats
  killSwitchActive?: boolean
  restartingProgress?: string | null
} = {}): void {
  if (patch.status) latestTrayStatus = patch.status
  if (patch.publicIp !== undefined) latestPublicIp = patch.publicIp
  if (patch.traffic) latestTraffic = patch.traffic
  if (patch.killSwitchActive !== undefined) latestKillSwitchActive = patch.killSwitchActive
  if (patch.restartingProgress !== undefined) latestRestartingProgress = patch.restartingProgress

  const tunStatus = tunController.getStatus()
  const settings = settingsStore.get()
  if (patch.proxyAddr !== undefined) {
    latestTrayProxyAddr = patch.proxyAddr
  } else {
    latestTrayProxyAddr = tunStatus.proxyAddr || settings.proxyOverride.trim() || latestTrayProxyAddr
  }

  if (!tray) return
  updateTrayState(tray, {
    status: latestTrayStatus,
    publicIp: latestPublicIp,
    proxyAddr: latestTrayProxyAddr,
    downloadBps: latestTraffic.downloadBps,
    uploadBps: latestTraffic.uploadBps,
    tunRunning: tunStatus.running,
    firewallKillSwitchActive: latestKillSwitchActive,
    restartingProgress: latestRestartingProgress
  })
}

async function clearStaleKillSwitchBeforeStart(context: string): Promise<{ success: boolean; error?: string }> {
  if (tunController.getStatus().running) return { success: true }
  if (!(await isKillSwitchActive())) return { success: true }

  logEvent('info', 'firewall-killswitch', `restart preflight: clearing stale kill-switch before ${context}`)
  const result = await disableKillSwitchIfActive(`restart preflight: ${context}`)
  refreshTrayState({ killSwitchActive: await isKillSwitchActive().catch(() => false) })
  if (!result.success) {
    return {
      success: false,
      error: `Не удалось снять старую блокировку перед перезапуском: ${result.message}`
    }
  }
  return { success: true }
}

function trayStatusFromTunStatus(status: string): TrayStatus {
  if (status === 'running') return 'protected'
  if (status === 'proxy-down') return 'proxy-down'
  if (status === 'killswitch-active') return 'killswitch'
  if (status.startsWith('restarting:')) return 'restarting'
  return 'off'
}

async function resolveProxyForTrayStart(): Promise<{ proxyAddr: string; proxyType: 'socks5' | 'http' } | null> {
  const settings = settingsStore.get()
  const override = settings.proxyOverride.trim()
  if (override) return { proxyAddr: override, proxyType: settings.proxyType }
  const detected = await happDetector.detect()
  if (!detected) return null
  return { proxyAddr: `${detected.host}:${detected.port}`, proxyType: detected.type }
}

async function startProtection(proxyAddr: string, proxyType?: 'socks5' | 'http'): Promise<{ success: boolean; error?: string; warning?: string | null; vpnIp?: string | null }> {
  // Snapshot BEFORE we change anything. This is the baseline state that
  // support/diagnostics will compare against.
  captureSnapshot('tun-pre-start').catch(() => undefined)

  const staleKillSwitch = await clearStaleKillSwitchBeforeStart('local proxy start')
  if (!staleKillSwitch.success) return { success: false, error: staleKillSwitch.error }

  const plan = await getRoutingPlan()
  if (!plan.canStartHard) {
    return {
      success: false,
      error: `${plan.title}. ${plan.explanation} ${plan.after}`
    }
  }

  let baselineWarning: string | null = null
  if (settingsStore.get().autoNetworkBaseline) {
    const baseline = await applyTunNetworkBaseline()
    if (!baseline.success) {
      baselineWarning = `Не удалось применить сетевой baseline: ${baseline.message}`
    }
  }

  const result = await tunController.start({
    proxyAddr,
    proxyType: proxyType ?? 'socks5',
    enableFirewallKillSwitch: settingsStore.get().firewallKillSwitch,
    enableAdapterLockdown: settingsStore.get().strictAdapterLockdown,
    publicWifiCompatibility: settingsStore.get().publicWifiCompatibility,
    stealthMode: settingsStore.get().stealthMode
  })
  if (!result.success) {
    // TUN failed to start. If we wiped the user's proxy settings to prepare for it,
    // restore them now so we don't leave the system worse than we found it. The
    // kill-switch is dropped by tunController itself in this path — see start().
    await rollbackTunNetworkBaselineIfApplied('start-tun failed').catch(err =>
      logEvent('warn', 'app', 'rollback after start-tun failure failed', err)
    )
    captureSnapshot('tun-start-failed').catch(() => undefined)
    return result
  }

  const ipInfo = await ipMonitor.getCurrentIp()
  if (ipInfo.ip) {
    ipMonitor.setVpnIp(ipInfo.ip)
    try {
      mainWindow?.webContents.send('ip-changed', { ip: ipInfo.ip, isLeak: false })
    } catch {}
  }
  refreshTrayState({ status: 'protected', publicIp: ipInfo.ip ?? latestPublicIp, proxyAddr })

  // Open a connection-history record. Closed by stopProtection() or by the
  // tunController.onStatusChange handler if the tunnel dies on its own.
  currentConnectionStart = Date.now()
  currentConnectionProfile = {
    id: 'local-proxy',
    name: `Proxy ${proxyAddr}`,
    mode: 'hard'
  }

  // Schedule a follow-up IP recheck after the tunnel is fully ready. The first
  // check above can race with route propagation, leaving `isLeak` stale on the
  // renderer until the periodic monitor catches up. Re-baselining the VPN IP
  // 2.5s later ensures the leak banner clears once routes settle.
  setTimeout(() => {
    ipMonitor.recheck(true).catch(() => undefined)
  }, 2500)

  // Snapshot AFTER everything is applied (TUN up, kill-switch up,
  // adapter lockdown up). Then start the periodic snapshot timer +
  // periodic leak self-test so we keep collecting data for support.
  captureSnapshot('tun-post-start').catch(() => undefined)
  startPeriodicSnapshots(60_000)
  startPeriodicLeakTest(30_000)
  // Watch for network changes (Wi-Fi flap, Ethernet plug, IP renew). On
  // any change, fire an event-driven leak check after a short grace so
  // the new interface has time to come up.
  startNetworkChangeWatcher()

  return {
    ...result,
    warning: [baselineWarning, result.warning].filter(Boolean).join(' | ') || null,
    vpnIp: ipInfo.ip ?? null
  }
}

async function startDirectVpnProtection(): Promise<{ success: boolean; error?: string; warning?: string | null; vpnIp?: string | null }> {
  captureSnapshot('tun-pre-start').catch(() => undefined)

  const staleKillSwitch = await clearStaleKillSwitchBeforeStart('Direct VPN start')
  if (!staleKillSwitch.success) return { success: false, error: staleKillSwitch.error }

  const settings = settingsStore.get()

  // V2: server-picker store is the single source of truth. Pull the active
  // profile from there. If its outbound was lost (older builds saved
  // profiles without it) we try to recover from the legacy
  // directVpnCachedProfiles list at runtime.
  let profile: VpnProfile | undefined
  const activeServer = serverPicker.getActiveProfile()
  if (activeServer) {
    let outbound = activeServer.outbound
    if (!outbound || typeof outbound !== 'object') {
      const legacy = Array.isArray(settings.directVpnCachedProfiles)
        ? settings.directVpnCachedProfiles
        : []
      const fallback = legacy.find((p: any) =>
        p?.outbound?.server === activeServer.server &&
        Number(p?.outbound?.server_port || 0) === activeServer.port
      ) || legacy.find((p: any) => p?.name === activeServer.name && p?.outbound)
      if (fallback?.outbound) {
        outbound = fallback.outbound as Record<string, any>
        logEvent('info', 'tun', 'recovered outbound from legacy cache for active picker profile', {
          name: activeServer.name,
          server: activeServer.server
        })
      }
    }
    if (outbound && typeof outbound === 'object') {
      profile = {
        name: activeServer.name,
        protocol: activeServer.protocol as VpnProfile['protocol'],
        outbound
      }
      logEvent('info', 'tun', 'using server-picker active profile', {
        id: activeServer.id,
        protocol: activeServer.protocol,
        name: activeServer.name
      })
    } else {
      captureSnapshot('tun-start-failed').catch(() => undefined)
      return {
        success: false,
        error: 'У выбранного сервера нет конфигурации (outbound пуст). Удалите его в разделе «Серверы» и добавьте подписку заново.'
      }
    }
  } else if (settings.directVpnInput.trim()) {
    try {
      profile = await resolveVpnProfile(settings.directVpnInput, settings.directVpnSelectedIndex, {
        proxyAddr: settings.proxyOverride,
        proxyType: settings.proxyType
      })
      logEvent('info', 'tun', 'using legacy directVpnInput fallback (no server-picker profile)', {
        protocol: profile.protocol,
        name: profile.name
      })
    } catch (err: any) {
      captureSnapshot('tun-start-failed').catch(() => undefined)
      return { success: false, error: err?.message || String(err) }
    }
  } else {
    captureSnapshot('tun-start-failed').catch(() => undefined)
    return {
      success: false,
      error: 'Нет выбранного сервера. Откройте раздел "Серверы" и добавьте подписку или ключ.'
    }
  }

  let baselineWarning: string | null = null
  if (settings.autoNetworkBaseline) {
    const baseline = await applyTunNetworkBaseline()
    if (!baseline.success) {
      baselineWarning = `Не удалось применить сетевой baseline: ${baseline.message}`
    }
  }

  logEvent('info', 'tun', 'direct VPN profile selected', {
    protocol: profile.protocol,
    name: profile.name
  })

  const result = await tunController.start({
    mode: 'directVpn',
    vpnProfile: profile,
    proxyType: 'socks5',
    enableFirewallKillSwitch: settings.firewallKillSwitch,
    enableAdapterLockdown: settings.strictAdapterLockdown,
    publicWifiCompatibility: settings.publicWifiCompatibility,
    stealthMode: settings.stealthMode
  })
  if (!result.success) {
    await rollbackTunNetworkBaselineIfApplied('direct-vpn start failed').catch(err =>
      logEvent('warn', 'app', 'rollback after direct-vpn start failure failed', err)
    )
    captureSnapshot('tun-start-failed').catch(() => undefined)
    return result
  }

  const ipInfo = await ipMonitor.getCurrentIp()
  if (ipInfo.ip) {
    ipMonitor.setVpnIp(ipInfo.ip)
    try {
      mainWindow?.webContents.send('ip-changed', { ip: ipInfo.ip, isLeak: false })
    } catch {}
  }
  refreshTrayState({ status: 'protected', publicIp: ipInfo.ip ?? latestPublicIp, proxyAddr: profile.name })

  // Open a connection-history record (Direct VPN variant).
  currentConnectionStart = Date.now()
  currentConnectionProfile = {
    id: profile.name || 'direct-vpn',
    name: profile.name || 'Direct VPN',
    mode: 'direct'
  }

  // Schedule a follow-up IP recheck after the tunnel is fully ready (see
  // matching comment in `startProtection`).
  setTimeout(() => {
    ipMonitor.recheck(true).catch(() => undefined)
  }, 2500)

  captureSnapshot('tun-post-start').catch(() => undefined)
  startPeriodicSnapshots(60_000)
  startPeriodicLeakTest(30_000)
  // Same network-change watcher as in startProtection — direct-vpn mode
  // benefits equally from event-driven leak checks on Wi-Fi flap.
  startNetworkChangeWatcher()

  return {
    ...result,
    warning: [baselineWarning, result.warning].filter(Boolean).join(' | ') || null,
    vpnIp: ipInfo.ip ?? null
  }
}

async function stopProtection(): Promise<{ success: boolean; error?: string }> {
  // Record the connection BEFORE we stop, so traffic counters are still valid.
  // `stopInProgress` ensures the status-change handler doesn't double-record
  // when tunController emits 'stopped' as a result of the call below.
  stopInProgress = true
  if (currentConnectionStart && currentConnectionProfile) {
    const traffic = trafficMonitor.getCurrentStats()
    try {
      connectionHistoryService.addEntry({
        startedAt: currentConnectionStart,
        endedAt: Date.now(),
        profileName: currentConnectionProfile.name,
        profileId: currentConnectionProfile.id,
        mode: currentConnectionProfile.mode,
        bytesDown: traffic.sessionDownloadBytes ?? 0,
        bytesUp: traffic.sessionUploadBytes ?? 0,
        disconnectReason: 'user'
      })
    } catch (err) {
      logEvent('warn', 'app', 'failed to record connection history', err)
    }
    currentConnectionStart = null
    currentConnectionProfile = null
  }

  stopPeriodicSnapshots()
  stopPeriodicLeakTest()
  stopNetworkChangeWatcher()
  const result = await tunController.stop()
  ipMonitor.clearVpnIp()
  trafficMonitor.stop()
  await repairOrphanedPhysicalAdapterDns('post-stop safety repair').catch(err =>
    logEvent('warn', 'phys-lockdown', 'post-stop orphaned DNS repair failed', err)
  )

  // Auto-rollback Windows location-privacy if we (or the user) had it
  // applied for the duration of the VPN session. Without this, geolocation
  // stays disabled across reboots and the user wonders why Maps/Weather
  // can't find them. We always check status (not just our settings flag)
  // because the user might have applied it manually in Maintenance.
  try {
    const status = await getLocationPrivacyStatus()
    if (status.applied) {
      const rolled = await rollbackLocationPrivacy()
      settingsStore.save({ locationPrivacyEnabled: rolled.applied })
      logEvent('info', 'tun', 'rolled back location privacy on VPN stop', {
        wasApplied: true,
        nowApplied: rolled.applied
      })
    }
  } catch (err) {
    logEvent('warn', 'tun', 'location privacy rollback on stop failed', err)
  }

  refreshTrayState({ status: 'off', restartingProgress: null })
  captureSnapshot('tun-post-stop').catch(() => undefined)
  stopInProgress = false
  return result
}

async function startProtectionFromTray(): Promise<void> {
  if (settingsStore.get().connectionMode === 'directVpn') {
    refreshTrayState({ status: 'starting' })
    const result = await startDirectVpnProtection()
    if (!result.success) {
      notify('error', 'Не удалось включить защиту', result.error || 'Неизвестная ошибка', 'connectionError')
      refreshTrayState({ status: 'off' })
    }
    return
  }

  const resolved = await resolveProxyForTrayStart()
  if (!resolved) {
    notify('error', 'Прокси не найден', 'Запустите VPN-клиент в режиме Proxy или задайте адрес вручную в настройках.', 'connectionError')
    mainWindow?.show()
    return
  }
  refreshTrayState({ proxyAddr: resolved.proxyAddr })
  const result = await startProtection(resolved.proxyAddr, resolved.proxyType)
  if (!result.success) {
    notify('error', 'Не удалось включить защиту', result.error || 'Неизвестная ошибка', 'connectionError')
  }
}

async function runTrayDiagnostics(): Promise<void> {
  const tunStatus = tunController.getStatus()
  const settings = settingsStore.get()
  const proxyAddr = tunStatus.proxyAddr || settings.proxyOverride.trim() || undefined
  const result = await runLeakCheck({
    proxyAddr,
    proxyType: tunStatus.proxyType || settings.proxyType,
    tunRunning: tunStatus.running,
    connectionMode: tunStatus.mode ?? settings.connectionMode,
    smartRuSplit: settings.smartRuSplit === true
  })
  const message =
    result.summary === 'ok'
      ? 'Утечек не найдено.'
      : result.summary === 'fail'
        ? 'Найдена критичная проблема маршрутизации.'
        : 'Есть предупреждения, откройте приложение для деталей.'
  notify(result.summary === 'fail' ? 'error' : result.summary === 'warn' ? 'warn' : 'info', 'Проверка маршрута', message)
  mainWindow?.show()
}

async function quitFromTray(): Promise<void> {
  mainWindow?.removeAllListeners('close')
  mainWindow?.close()
  app.quit()
}

app.whenReady().then(async () => {
  logEvent('info', 'app', 'application ready', {
    version: app.getVersion(),
    packaged: app.isPackaged,
    userData: app.getPath('userData')
  })

  // Content-Security-Policy for the renderer. We ship a fully self-contained
  // bundle (no external CDNs), so a strict policy costs us nothing and shuts
  // the door on injected-script / data-exfil vectors if any renderer input is
  // ever mishandled. 'unsafe-inline' for style is required by our CSS-in-JS
  // (design tokens injected as inline <style>); script stays locked to 'self'.
  // connect-src allows https/wss because the renderer talks to ip-api / ipify
  // and the dev server uses ws for HMR.
  if (app.isPackaged) {
    const csp = [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: https:",
      "font-src 'self' data:",
      "connect-src 'self' https: wss:",
      "object-src 'none'",
      "base-uri 'self'",
      "frame-ancestors 'none'",
      "form-action 'none'"
    ].join('; ')
    session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
      callback({
        responseHeaders: {
          ...details.responseHeaders,
          'Content-Security-Policy': [csp]
        }
      })
    })
  }

  if (app.isPackaged && await relaunchElevatedIfNeeded()) {
    logEvent('info', 'app', 'relaunching elevated')
    app.quit()
    return
  }

  await recoverStaleBaseline()
  await recoverStaleKillSwitch(async () => {
    try {
      const { stdout } = await exec('tasklist /FI "IMAGENAME eq vpnte-sing-box.exe" /FO CSV /NH', {
        windowsHide: true,
        timeout: 5000,
        encoding: 'utf8'
      })
      return String(stdout).toLowerCase().includes('vpnte-sing-box.exe')
    } catch {
      return false
    }
  })

  // Same crash-recovery story for the physical-adapter lockdown: if a previous
  // run left IPv6 disabled / DNS overridden on real adapters, the user is now
  // looking at a half-broken network and there's no sing-box to enforce
  // anything. Roll back to whatever we snapshotted.
  if (await isPhysicalAdapterLockdownApplied()) {
    let singboxRunning = false
    try {
      const { stdout } = await exec('tasklist /FI "IMAGENAME eq vpnte-sing-box.exe" /FO CSV /NH', {
        windowsHide: true,
        timeout: 5000,
        encoding: 'utf8'
      })
      singboxRunning = String(stdout).toLowerCase().includes('vpnte-sing-box.exe')
    } catch {
      // If tasklist fails we assume sing-box is not running and roll back.
    }
    if (!singboxRunning) {
      logEvent('warn', 'phys-lockdown', 'recovering stale adapter lockdown — sing-box not running')
      try {
        await rollbackPhysicalAdapterLockdownIfApplied('startup recovery — sing-box not running')
      } catch (err) {
        logEvent('warn', 'phys-lockdown', 'startup rollback failed', err)
      }
    }
  }
  await repairOrphanedPhysicalAdapterDns('startup orphaned DNS repair')
    .catch(err => logEvent('warn', 'phys-lockdown', 'startup orphaned DNS repair failed', err))

  const initialSettings = settingsStore.get()
  settingsStore.syncLoginItem()
  ipMonitor.setCheckInterval(initialSettings.checkInterval)

  createWindow()
  tray = createTray(mainWindow!, {
    onStart: startProtectionFromTray,
    onStop: stopProtection,
    onRunDiagnostics: runTrayDiagnostics,
    onOpenLogs: openLogFolder,
    onQuit: quitFromTray
  })
  refreshTrayState()
  isKillSwitchActive()
    .then(active => refreshTrayState({ killSwitchActive: active, status: active && !tunController.getStatus().running ? 'killswitch' : latestTrayStatus }))
    .catch(() => undefined)

  // In-app notification fallback. When `notify()` cannot deliver a Windows
  // toast (Windows blocks the AUMID, or Notification.isSupported() === false
  // on this platform), it calls this callback so the renderer can surface
  // the message in-app instead of silently dropping it. This is what keeps
  // notifications working after a user has clicked "Don't show notifications"
  // on the Windows toast — until they hit "Reset Windows block" in Settings,
  // at which point real toasts come back.
  setInAppFallbackCallback((level, title, body) => {
    try {
      mainWindow?.webContents.send('inapp-notification', { level, title, body, ts: Date.now() })
    } catch {
      // Window may be torn down (close-on-quit race). Nothing to recover from.
    }
  })

  // Capture a snapshot of the system state on every app launch — gives us a
  // "what does the network look like before the user clicks anything" record
  // for free, in case they later report "doesn't work" without ever clicking.
  captureSnapshot('app-start').catch(() => undefined)

  // When the periodic leak self-test (started at TUN start) detects a leak,
  // bubble that to the renderer so the UI can show a giant red banner, AND
  // fire a Windows toast. Two distinct toast paths so the user can tell at a
  // glance whether it's a physical-adapter leak (most severe — egress IP
  // bypasses the VPN entirely) or a DNS-side leak (resolver path egresses
  // somewhere unexpected). If physical-adapter fires AND dns-leak fires,
  // we prefer the physical-adapter toast — it's strictly more severe.
  setLeakDetectedCallback((r) => {
    try {
      mainWindow?.webContents.send('leak-detected', r)
    } catch {}
    try {
      if (r.physicalAdapterReached) {
        notify('warn', 'УТЕЧКА обнаружена', r.summary, 'leakDetected')
      } else if ((r as any).dnsLeakDetected) {
        notify('warn', 'УТЕЧКА DNS', r.summary, 'leakDetected')
      }
    } catch {}
  })

  // IPC handlers
  handleLogged('detect-happ', async () => {
    return happDetector.detect()
  })

  handleLogged('get-public-ip', async () => {
    return ipMonitor.getCurrentIp()
  })

  handleLogged('recheck-public-ip', async (_e, rebaseline?: boolean) => {
    return ipMonitor.recheck(rebaseline === true)
  })

  handleLogged('start-tun', async (_e, proxyAddr: string, proxyType?: 'socks5' | 'http') => {
    return startProtection(proxyAddr, proxyType)
  })

  handleLogged('start-direct-vpn', async () => {
    return startDirectVpnProtection()
  })

  handleLogged('stop-tun', async () => {
    return stopProtection()
  })

  handleLogged('get-tun-status', async () => {
    return tunController.getStatus()
  })

  handleLogged('get-traffic-stats', async () => {
    return trafficMonitor.getCurrentStats()
  })

  handleLogged('apply-autoconfig', async (_e, targets: string[], proxyAddr: string, proxyType?: 'socks5' | 'http') => {
    return autoconfig.apply(targets, proxyAddr, proxyType ?? settingsStore.get().proxyType)
  })

  handleLogged('rollback-autoconfig', async (_e, targets: string[]) => {
    return autoconfig.rollback(targets)
  })

  handleLogged('get-autoconfig-status', async () => {
    return autoconfig.getStatus()
  })

  handleLogged('get-settings', async () => {
    return settingsStore.get()
  })

  handleLogged('save-settings', async (_e, settings) => {
    const previous = settingsStore.get()
    const saved = settingsStore.save(settings)
    ipMonitor.setCheckInterval(saved.checkInterval)

    // Apply changes that affect the running tunnel/firewall.

    // 1. firewallKillSwitch toggled OFF → must disengage active rules so the
    //    user gets internet back even without restarting VPN.
    if (previous.firewallKillSwitch && !saved.firewallKillSwitch) {
      try {
        await disableKillSwitchIfActive('user disabled firewall kill-switch in Settings')
        // Also sync the granular level so they stay aligned.
        if (granularKillSwitch.getLevel() !== 'off') {
          await granularKillSwitch.setLevel('off')
        }
      } catch (err) {
        logEvent('warn', 'app', 'failed to disengage kill-switch on settings save', err)
      }
    }

    // 2. firewallKillSwitch toggled ON while VPN is running → engage now so
    //    the user doesn't have to reconnect.
    if (!previous.firewallKillSwitch && saved.firewallKillSwitch && tunController.getStatus().running) {
      try {
        if (granularKillSwitch.getLevel() === 'off') {
          await granularKillSwitch.setLevel('standard')
        }
        // applyPolicy() is called by setLevel; nothing else needed.
      } catch (err) {
        logEvent('warn', 'app', 'failed to engage kill-switch on settings save', err)
      }
    }

    return saved
  })

  handleLogged('inspect-vpn-input', async (_e, input: string) => {
    const settings = settingsStore.get()
    const resolved = await resolveVpnProfiles(input, {
      proxyAddr: settings.proxyOverride,
      proxyType: settings.proxyType
    })
    const protocols: Record<string, number> = {}
    for (const profile of resolved.profiles) {
      protocols[profile.protocol] = (protocols[profile.protocol] || 0) + 1
    }
    // Only overwrite the cached profile list when the new probe actually
    // produced something — otherwise a typo or a not-yet-supported share
    // link (e.g. Happ encrypted subscription) would silently wipe the
    // user's previously-imported servers. We always update the input
    // text and last-checked timestamp so the UI shows what was inspected.
    if (resolved.profiles.length > 0) {
      settingsStore.save({
        directVpnInput: input,
        directVpnCachedInput: input.trim(),
        directVpnCachedSource: resolved.source,
        directVpnCachedAt: Date.now(),
        directVpnCachedProfiles: resolved.profiles
      })
    } else {
      settingsStore.save({
        directVpnInput: input,
        directVpnCachedAt: Date.now()
      })
    }
    return {
      count: resolved.profiles.length,
      protocols,
      profiles: resolved.profiles.map((profile, index) => ({ index, name: profile.name, protocol: profile.protocol })),
      fetched: resolved.fetched,
      source: resolved.source
    }
  })

  handleLogged('set-login-item', async (_e, openAtLogin: boolean) => {
    return settingsStore.setLoginItem(openAtLogin)
  })

  handleLogged('run-leak-check', async (_e, options?: { proxyAddr?: string; proxyType?: 'socks5' | 'http' }) => {
    const tunStatus = tunController.getStatus()
    const settings = settingsStore.get()
    return runLeakCheck({
      proxyAddr: options?.proxyAddr ?? tunStatus.proxyAddr ?? undefined,
      proxyType: options?.proxyType ?? tunStatus.proxyType ?? settingsStore.get().proxyType,
      tunRunning: tunStatus.running,
      connectionMode: tunStatus.mode ?? settings.connectionMode,
      smartRuSplit: settings.smartRuSplit === true
    })
  })

  handleLogged('run-store-repair', async (_e, action: StoreRepairAction) => {
    return runStoreRepair(action)
  })

  handleLogged('run-store-diagnostics', async () => {
    return runStoreDiagnostics()
  })

  handleLogged('run-system-diagnostics', async () => {
    return runSystemDiagnostics()
  })

  handleLogged('get-routing-plan', async () => {
    return getRoutingPlan()
  })

  handleLogged('apply-browser-leak-protection', async () => {
    return applyBrowserLeakProtection()
  })

  handleLogged('rollback-browser-leak-protection', async () => {
    return rollbackBrowserLeakProtection()
  })

  handleLogged('run-auto-pilot', async () => {
    return runAutoPilot()
  })

  handleLogged('renderer-log', async (_e, level: AppLogLevel, message: string) => {
    const safeLevel: AppLogLevel = ['debug', 'info', 'warn', 'error'].includes(level) ? level : 'info'
    logEvent(safeLevel, 'renderer', message)
    return { success: true }
  })

  handleLogged('get-full-logs', async () => {
    return getFullLogs()
  })

  handleLogged('clear-app-log', async () => {
    await clearAppLog()
    logEvent('info', 'app', 'app log cleared')
    return { success: true }
  })

  handleLogged('apply-tun-network-baseline', async () => {
    return applyTunNetworkBaseline()
  })

  handleLogged('rollback-tun-network-baseline', async () => {
    return rollbackTunNetworkBaseline()
  })

  // Manual override: snip the firewall kill-switch even if sing-box hasn't been
  // restarted. Used by the Dashboard banner that appears when sing-box died and
  // left the rules in place — the user can either restart TUN or, as a last
  // resort, drop the kill-switch and accept the leak window themselves.
  handleLogged('disable-firewall-kill-switch', async () => {
    return tunController.disableFirewallKillSwitch('manual override from UI')
  })

  handleLogged('get-firewall-kill-switch-status', async () => {
    return { active: await isKillSwitchActive() }
  })

  // Detect another active VPN/TUN adapter (Happ, WireGuard, OpenVPN, …) that
  // would intercept our latency probes. When such an adapter is up, every
  // TCP-connect we make is answered locally by ITS tun stack — even to
  // non-routable test IPs — so per-server pings become meaningless (the
  // "1-46 ms на всех серверах" the user saw was Happ's happ-tun answering).
  // The renderer polls this while OUR tunnel is OFF to warn the user that
  // ping numbers can't be trusted until they close the other VPN. When our
  // tunnel is ON, competingTunDetector already raises a stronger banner, so
  // we return null here to avoid a duplicate warning.
  handleLogged('system:detect-foreign-vpn', async () => {
    if (tunController.getStatus().running) return { foreign: null }
    return { foreign: detectForeignTun() }
  })

  // Nuclear option for stuck firewalls: reset Windows Firewall to defaults if
  // even disable-firewall-kill-switch can't restore connectivity (e.g. the user
  // accumulated other rules or DefaultOutboundAction got stuck on Block).
  handleLogged('firewall:nuclear-reset', async () => {
    return nuclearFirewallReset()
  })

  handleLogged('get-location-privacy', async () => {
    return getLocationPrivacyStatus()
  })

  handleLogged('apply-location-privacy', async () => {
    const status = await applyLocationPrivacy()
    settingsStore.save({ locationPrivacyEnabled: status.applied })
    return status
  })

  handleLogged('rollback-location-privacy', async () => {
    const status = await rollbackLocationPrivacy()
    settingsStore.save({ locationPrivacyEnabled: status.applied })
    return status
  })

  handleLogged('open-tun-log-folder', async () => {
    const folder = join(app.getPath('userData'), 'tun-runtime')
    await shell.openPath(folder)
    return folder
  })

  handleLogged('open-log-folder', async () => {
    return openLogFolder()
  })

  handleLogged('export-diagnostics', async () => {
    // User-driven export. Take a fresh snapshot first so it's the most
    // recent thing in the ZIP — then call the existing exporter.
    await captureSnapshot('manual').catch(() => undefined)
    return exportDiagnosticsZip()
  })

  handleLogged('run-leak-self-test', async () => {
    const result = await runLeakSelfTest()
    if (result.physicalAdapterReached || result.publicIpMismatch) {
      // Always snapshot when we see a leak — that's exactly the moment we
      // want frozen for support.
      captureSnapshot('leak-detected').catch(() => undefined)
    }
    return result
  })

  // Routing self-test: prove the VPN/direct split is real by comparing the
  // egress IP through proxy-out (VPN) vs direct-out, and — when smart RU split
  // is on — that RU hosts egress with the real IP.
  handleLogged('run-routing-self-test', async () => {
    const { runRoutingSelfTest } = await import('./routingSelfTest')
    return runRoutingSelfTest()
  })

  handleLogged('open-snapshots-folder', async () => {
    const dir = getSnapshotsDir()
    try {
      // Ensure the directory exists before opening — on first launch the user
      // might click this before any snapshot has been written.
      const { mkdir } = await import('fs/promises')
      await mkdir(dir, { recursive: true })
      const { shell } = await import('electron')
      const result = await shell.openPath(dir)
      // openPath returns '' on success, error message on failure.
      if (result) return { success: false, error: result, path: dir }
      return { success: true, path: dir }
    } catch (err) {
      return { success: false, error: (err as Error).message }
    }
  })

  // ─── V2 Feature Module Registration ──────────────────────────────────────────
  // Order: infrastructure (settings already loaded above) → i18n/theme → feature services → widgets

  // Infrastructure services
  registerI18nIpcHandlers()
  registerThemeIpcHandlers()

  // Feature services
  registerSplitTunnelHandlers()
  registerServerPickerHandlers()
  registerServerGroupsHandlers()
  // Migrate legacy directVpnCachedProfiles → server-picker store on first run.
  // No-op for fresh installs and for users already on the new store.
  serverPicker.migrateLegacyDirectVpnProfiles()
  // Backfill `outbound` on picker entries that were saved by older builds
  // before the field existed. No-op when nothing needs fixing.
  serverPicker.backfillMissingOutbounds()
  // Assign every dangling picker profile to a default group, so the new
  // groups-aware UI never has to deal with ungrouped entries from older
  // versions of the app. Idempotent.
  serverPicker.migrateProfilesIntoGroups()

  // Repair installs shattered by the old SNI-suffix splitter: fold bogus
  // camouflage-domain "subscription" groups (no sourceUrl) back into the
  // single "Ручные ключи" bucket. Idempotent — no-op once cleaned.
  serverPicker.consolidateBogusSniGroups()
  // Backfill missing `sourceUri` on profiles that were imported by older
  // builds before we tracked subscription URLs. Lets the smart-group
  // classifier re-bin previously-orphaned keys on the next migration pass.
  // Idempotent — safe to run on every startup.
  serverPicker.backfillProfileSourceUris()

  // One-time wipe of stale stored ping/status/lastChecked. Earlier builds
  // (pre-D6.5) stamped tunnel-RTT onto the active profile during connected
  // pingAll sweeps, leaving fake "~2 ms" values that survived disconnect.
  // We clear them on startup so the user starts every session from a clean
  // baseline; the next offline pingAll repopulates with real numbers.
  serverPicker.clearStaleStoredPings()
  // Fire-and-forget background geolocation pass for any profile that doesn't
  // already have a country tag. This makes country labels appear on the
  // dashboard without the user having to ping every server manually.
  void serverPicker.geolocateAll().catch(() => undefined)
  registerServerProbeIpcHandlers()
  registerUrlAvailabilityHandlers()
  registerSpeedTestHandlers()
  registerKillSwitchIpc()
  registerRotationHandlers()
  registerSchedulerIpcHandlers()
  registerConnectionHistoryIpcHandlers()
  registerTrafficHistoryIpcHandlers()
  registerDnsHandlers()
  registerDomainRoutingIpcHandlers()
  registerConfigManagerIpcHandlers()
  registerNotificationPrefsIpcHandlers()

  // Widget layout (depends on feature services being registered)
  registerWidgetLayoutIpcHandlers()

  // Initialize services that need startup logic
  const singboxExePath = app.isPackaged
    ? join(process.resourcesPath, 'sing-box.exe')
    : join(app.getAppPath(), 'resources', 'sing-box.exe')
  granularKillSwitch.init(singboxExePath)
  initDnsProfiles()
  initProfileRotation()
  schedulerService.init({
    onConnect: (schedule) => {
      logEvent('info', 'scheduler', `schedule "${schedule.name}" triggered connect`, { profileId: schedule.profileId, mode: schedule.mode })
      if (schedule.mode === 'direct') {
        startDirectVpnProtection().catch(err =>
          logEvent('error', 'scheduler', 'scheduled direct VPN start failed', err)
        )
      } else {
        resolveProxyForTrayStart().then(resolved => {
          if (!resolved) {
            logEvent('warn', 'scheduler', 'scheduled connect failed: no proxy found')
            return
          }
          startProtection(resolved.proxyAddr, resolved.proxyType).catch(err =>
            logEvent('error', 'scheduler', 'scheduled start failed', err)
          )
        })
      }
    },
    onDisconnect: (schedule) => {
      logEvent('info', 'scheduler', `schedule "${schedule.name}" triggered disconnect`)
      stopProtection().catch(err =>
        logEvent('error', 'scheduler', 'scheduled stop failed', err)
      )
    }
  })

  logEvent('info', 'app', 'V2 feature modules registered and initialized')

  // Push events from main → renderer
  trafficMonitor.onStatsChange((stats) => {
    latestTraffic = stats
    try {
      mainWindow?.webContents.send('traffic-stats', stats)
    } catch {}
    refreshTrayState({ traffic: stats })
  })

  ipMonitor.onIpChange((ip: string, isLeak: boolean) => {
    latestPublicIp = ip
    mainWindow?.webContents.send('ip-changed', { ip, isLeak })
    refreshTrayState({ status: isLeak ? 'leak' : tunController.getStatus().running ? 'protected' : 'off', publicIp: ip })
    if (isLeak) {
      notify('error', 'Виден ваш реальный IP', `Текущий публичный IP: ${ip}. Включите защиту или проверьте VPN-клиент.`, 'leakDetected')
    }
  })

  tunController.onStatusChange((status: string) => {
    mainWindow?.webContents.send('tun-status-changed', status)
    const isRestarting = status.startsWith('restarting:')
    if (status === 'running' || status === 'proxy-down') {
      trafficMonitor.start()
    } else {
      trafficMonitor.stop()
    }

    // Record connection-history entry on terminal/error transitions if we
    // weren't already in the user-initiated stop path. `crash` for kill-switch
    // (sing-box died and left firewall rules), otherwise `error` — the
    // tunController emits 'stopped' on internal failures too.
    if (
      (status === 'killswitch-active' || status === 'stopped') &&
      currentConnectionStart &&
      currentConnectionProfile &&
      !stopInProgress
    ) {
      const reason: 'crash' | 'error' = status === 'killswitch-active' ? 'crash' : 'error'
      const traffic = trafficMonitor.getCurrentStats()
      try {
        connectionHistoryService.addEntry({
          startedAt: currentConnectionStart,
          endedAt: Date.now(),
          profileName: currentConnectionProfile.name,
          profileId: currentConnectionProfile.id,
          mode: currentConnectionProfile.mode,
          bytesDown: traffic.sessionDownloadBytes ?? 0,
          bytesUp: traffic.sessionUploadBytes ?? 0,
          disconnectReason: reason
        })
      } catch (err) {
        logEvent('warn', 'app', 'failed to record connection history (status-change)', err)
      }
      currentConnectionStart = null
      currentConnectionProfile = null
    }

    refreshTrayState({
      status: trayStatusFromTunStatus(status),
      proxyAddr: tunController.getStatus().proxyAddr,
      restartingProgress: isRestarting ? status.slice('restarting:'.length) : null
    })
    isKillSwitchActive()
      .then(active => refreshTrayState({ killSwitchActive: active }))
      .catch(() => undefined)
  })

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
    else mainWindow?.show()
  })
})

// Coordinated shutdown: stop TUN, roll back any global system-proxy edits we made, and
// roll back the soft-mode env-proxy autoconfig. Without this, closing the app could
// leave the user with no VPN AND no original proxy settings — the "breaks global
// settings" failure mode this PR addresses.
async function performShutdownCleanup(reason: string): Promise<void> {
  if (shutdownInProgress) return
  shutdownInProgress = true
  logEvent('info', 'app', `shutdown cleanup started: ${reason}`)

  try {
    if (tunController.getStatus().running) {
      await tunController.stop()
    }
  } catch (err) {
    logEvent('warn', 'app', 'tunController.stop during shutdown failed', err)
  }

  try {
    await rollbackTunNetworkBaselineIfApplied(`shutdown: ${reason}`)
  } catch (err) {
    logEvent('warn', 'app', 'baseline rollback during shutdown failed', err)
  }

  try {
    // Always disengage the firewall kill-switch on app exit. Leaving it in
    // place would lock the user out of the internet between sessions.
    await disableKillSwitchIfActive(`shutdown: ${reason}`)
  } catch (err) {
    logEvent('warn', 'app', 'kill-switch disable during shutdown failed', err)
  }

  try {
    // Same for the adapter lockdown: never leave IPv6 disabled / DNS overridden
    // across sessions. tunController.stop() already does this, but a forced
    // shutdown path (no Stop button click) needs it as a backstop.
    await rollbackPhysicalAdapterLockdownIfApplied(`shutdown: ${reason}`)
  } catch (err) {
    logEvent('warn', 'app', 'adapter lockdown rollback during shutdown failed', err)
  }

  try {
    await repairOrphanedPhysicalAdapterDns(`shutdown: ${reason}`)
  } catch (err) {
    logEvent('warn', 'app', 'orphaned DNS repair during shutdown failed', err)
  }

  try {
    const status = await autoconfig.getStatus()
    const envApplied = status.find(t => t.id === 'env')?.applied
    if (envApplied) {
      logEvent('info', 'app', 'rolling back env autoconfig (setx HTTP_PROXY) on shutdown')
      await autoconfig.rollback(['env'])
    }
  } catch (err) {
    logEvent('warn', 'app', 'env autoconfig rollback during shutdown failed', err)
  }
}

app.on('before-quit', async (event) => {
  if (shutdownInProgress) return
  isQuitting = true
  logEvent('info', 'app', 'before quit')
  event.preventDefault()
  await performShutdownCleanup('before-quit')
  app.exit(0)
})

app.on('window-all-closed', async () => {
  if (process.platform !== 'darwin') {
    logEvent('info', 'app', 'all windows closed')
    await performShutdownCleanup('window-all-closed')
    app.quit()
  }
})
