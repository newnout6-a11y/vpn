import { app, dialog } from 'electron'
import Store from 'electron-store'
import { copyFileSync, existsSync } from 'fs'
import { join } from 'path'
import { execElevated } from './admin'
import { domainEnrichmentService } from './domainEnrichment'
import { readBootRecoveryReport } from './recoveryManifest'
import {
  decryptJsonSecret,
  decryptSecret,
  encryptJsonSecret,
  encryptSecret,
  isSecretEncryptionAvailable,
  isSecretRef,
  type SecretRef
} from './secretStorage'

export interface AppSettings {
  connectionMode: 'localProxy' | 'directVpn'
  // Routing preference chosen in the first-run wizard / Settings:
  // 'hard' = full TUN tunnel (start-tun), 'soft' = no TUN, apps are pointed
  // at the local proxy via env autoconfig (setx HTTP_PROXY …). Distinct from
  // connectionMode, which only picks the upstream (Happ proxy vs direct VPN
  // server) — hard and soft used to collapse into the same start-tun path.
  routingMode: 'hard' | 'soft'
  proxyOverride: string
  proxyType: 'socks5' | 'http'
  bootstrapRouteMode: 'auto' | 'direct' | 'localProxy'
  directVpnInput: string
  directVpnSelectedIndex: number
  directVpnCachedInput: string
  directVpnCachedSource: string
  directVpnCachedAt: number | null
  directVpnCachedProfiles: Array<{
    name: string
    protocol: string
    outbound: Record<string, any>
  }>
  checkInterval: number
  autoStart: boolean
  autoPilotEnabled: boolean
  minimizeToTray: boolean
  locationPrivacyEnabled: boolean
  domainEnrichmentEnabled: boolean
  autoNetworkBaseline: boolean
  firewallKillSwitch: boolean
  // When false, the renderer hides the advanced/destructive maintenance and
  // network-tuning options. The Apps page remains a normal visible workflow.
  advancedMode: boolean
  // Flips to true after the first-run wizard completes (or the user dismisses
  // it). Until then the wizard overlay is shown.
  firstRunComplete: boolean
  // Автоперезапуск sing-box при крахе (PR #6 фича). On by default — most
  // "упал" cases (transient AV interference, OOM) recover with one retry
  // before we hand the user a banner.
  autoRestartOnCrash: boolean
  // Show Windows toast notifications on state changes (TUN up/down, leak,
  // kill-switch engaged). On by default.
  desktopNotifications: boolean
  // Public/captive Wi-Fi compatibility: do not rewrite physical adapter DNS
  // and use a safer TUN MTU for hotspot-like networks. Captive portals often
  // decide "no internet" if Wi-Fi DNS is forced to the TUN resolver before
  // the portal is authorized, and mobile/public networks often blackhole
  // larger TLS packets during PMTU discovery.
  publicWifiCompatibility: boolean
  // Hard adapter lockdown: while TUN is up, disable IPv6 + force IPv4 DNS to
  // the TUN resolver on every physical (Wired/Wireless) adapter. Catches
  // leaks the firewall kill-switch alone misses (DNS-over-HTTPS bypassing
  // NRPT, IPv6 default-route preference, etc.). On by default — it's
  // invasive but reverted on stop, and without it real-world users still see
  // their original ISP IP in some apps.
  strictAdapterLockdown: boolean
  // Disable app-controlled third-party IP geolocation lookups. When ON, the
  // app does not send current VPN/server IPs to ipapi.co, geojs.io,
  // ipwho.is, ipinfo.*, or iplocation.net. External websites the user opens
  // can still geolocate the IP they see.
  disableGeoLookup: boolean
  // Packet-level diagnostics capture. Keeps a rolling OS packet trace while
  // VPN protection is active so exported diagnostics can be inspected down to
  // drops, resets, timings and packet payload boundaries.
  deepTrafficInspectionEnabled: boolean
  deepTrafficInspectionMaxSizeMb: number
  deepTrafficInspectionRetainSessions: number
  // Anti-DPI / "stealth" mode against ISP-level traffic-shaping (TSPU and
  // similar). When ON we apply a bundle of mitigations that reduce VPN
  // signature visibility:
  //   1. Lower TUN MTU to 1280 so XTLS/Reality payload sizes drift away
  //      from the values DPI signature databases pattern-match.
  //   2. Enable TLS ClientHello fragmentation in the proxy outbound (only
  //      for non-Reality outbounds — Reality embeds auth in ClientHello and
  //      breaks if fragmented).
  // Note: the auto-failover watchdog runs unconditionally (regardless of
  // stealthMode) — it is always active for safety.
  // Safe to leave ON outside of restrictive networks too — costs ~5% extra
  // bandwidth from MTU overhead and a handful of extra TLS roundtrips.
  stealthMode: boolean
  adaptiveBypassEnabled: boolean
  adaptiveBypassServerFallback: boolean
  // Smart RU split-routing. When ON, RU-hosted destinations and narrow
  // government/map domain sets egress with the user's real IP via direct-out,
  // while everything else goes through the VPN. The signal is not a naive
  // ".ru" domain check: we use geoip-ru plus narrow geosite-category-gov-ru
  // / maps suffix rules, and deliberately avoid broad category-ru.
  // Off by default — it's an opt-in routing policy, and when off the tunnel
  // behaves exactly as before (everything through proxy-out).
  smartRuSplit: boolean
  // Optional sub-toggle: also send online maps (Yandex/2GIS/Google Maps tiles)
  // direct so they resolve to the user's real location. Only meaningful when
  // smartRuSplit is ON ("карты по желанию").
  smartRuMapsDirect: boolean
  // Smart-RU rule-set source. `bundled` keeps the current safe app-shipped
  // files; `managed` prefers an app-owned cache under userData and falls back
  // to bundled files when the cache is incomplete.
  smartRuRuleSetMode: 'bundled' | 'managed'
  // Background refresh for the managed rule-set cache.
  smartRuRuleSetAutoUpdate: boolean
  // Try to use the configured proxy override for managed rule-set downloads.
  smartRuRuleSetUseProxy: boolean
  // Managed rule-set refresh cadence.
  smartRuRuleSetUpdateIntervalHours: number
  // Proxy engine for upstream tunnel:
  // 'auto': xray for REALITY inbounds, sing-box for everything else
  // 'sing-box': force sing-box
  // 'xray': force xray for supported protocols
  proxyEngine: 'auto' | 'sing-box' | 'xray'
}

const defaults: AppSettings = {
  connectionMode: 'localProxy',
  routingMode: 'hard',
  proxyOverride: '',
  proxyType: 'socks5',
  bootstrapRouteMode: 'auto',
  directVpnInput: '',
  directVpnSelectedIndex: 0,
  directVpnCachedInput: '',
  directVpnCachedSource: '',
  directVpnCachedAt: null,
  directVpnCachedProfiles: [],
  checkInterval: 30000,
  disableGeoLookup: false,
  autoStart: false,
  autoPilotEnabled: true,
  minimizeToTray: true,
  locationPrivacyEnabled: false,
  domainEnrichmentEnabled: false,
  // Off by default — wiping HKCU\Internet Settings + WinHTTP + env proxies is destructive
  // and not actually required for TUN to capture traffic at the routing layer. Users who
  // need to fix UWP/Store traffic capture can opt in via Settings → "Auto baseline".
  autoNetworkBaseline: false,
  // Off by default: Windows Firewall block rules can also block the VPN core
  // process on public Wi-Fi, which looks exactly like "DNS/internet died".
  firewallKillSwitch: false,
  advancedMode: false,
  firstRunComplete: false,
  autoRestartOnCrash: true,
  desktopNotifications: true,
  publicWifiCompatibility: true,
  strictAdapterLockdown: true,
  deepTrafficInspectionEnabled: false,
  deepTrafficInspectionMaxSizeMb: 512,
  deepTrafficInspectionRetainSessions: 3,
  stealthMode: false,
  adaptiveBypassEnabled: true,
  adaptiveBypassServerFallback: true,
  smartRuSplit: false,
  smartRuMapsDirect: false,
  smartRuRuleSetMode: 'bundled',
  smartRuRuleSetAutoUpdate: true,
  smartRuRuleSetUseProxy: true,
  smartRuRuleSetUpdateIntervalHours: 24,
  proxyEngine: 'auto'
}

type PersistedAppSettings = Omit<
  AppSettings,
  'directVpnInput' | 'directVpnCachedInput' | 'directVpnCachedSource' | 'directVpnCachedProfiles'
> & {
  directVpnInput: string | SecretRef
  directVpnCachedInput: string | SecretRef
  directVpnCachedSource: string | SecretRef
  directVpnCachedProfiles: AppSettings['directVpnCachedProfiles'] | SecretRef
}

const store = new Store<{ settings: PersistedAppSettings | AppSettings; schemaVersion: number; migration?: unknown }>({
  name: 'settings',
  defaults: { settings: defaults, schemaVersion: 1 }
})

function hasPlaintextSettingsSecrets(value: PersistedAppSettings | AppSettings): boolean {
  return Boolean(
    (typeof value.directVpnInput === 'string' && value.directVpnInput) ||
    (typeof value.directVpnCachedInput === 'string' && value.directVpnCachedInput) ||
    (typeof value.directVpnCachedSource === 'string' && value.directVpnCachedSource) ||
    (Array.isArray(value.directVpnCachedProfiles) && value.directVpnCachedProfiles.length > 0)
  )
}

function decodePersistedSettings(value: PersistedAppSettings | AppSettings): AppSettings {
  return {
    ...value,
    directVpnInput: isSecretRef(value.directVpnInput) ? decryptSecret(value.directVpnInput) : value.directVpnInput,
    directVpnCachedInput: isSecretRef(value.directVpnCachedInput) ? decryptSecret(value.directVpnCachedInput) : value.directVpnCachedInput,
    directVpnCachedSource: isSecretRef(value.directVpnCachedSource) ? decryptSecret(value.directVpnCachedSource) : value.directVpnCachedSource,
    directVpnCachedProfiles: isSecretRef(value.directVpnCachedProfiles)
      ? decryptJsonSecret<AppSettings['directVpnCachedProfiles']>(value.directVpnCachedProfiles)
      : value.directVpnCachedProfiles
  }
}

function encodeSettings(value: AppSettings): PersistedAppSettings {
  return {
    ...value,
    directVpnInput: value.directVpnInput ? encryptSecret(value.directVpnInput) : '',
    directVpnCachedInput: value.directVpnCachedInput ? encryptSecret(value.directVpnCachedInput) : '',
    directVpnCachedSource: value.directVpnCachedSource ? encryptSecret(value.directVpnCachedSource) : '',
    directVpnCachedProfiles: value.directVpnCachedProfiles.length > 0
      ? encryptJsonSecret(value.directVpnCachedProfiles)
      : []
  }
}

function readSettingsWithMigration(): AppSettings {
  const persisted = store.get('settings')
  const decoded = decodePersistedSettings(persisted)
  if (!hasPlaintextSettingsSecrets(persisted)) return decoded
  if (!isSecretEncryptionAvailable()) {
    throw new Error('Settings migration requires Windows secure storage; plaintext data was left unchanged')
  }

  const backupPath = `${store.path}.pre-safe-storage-v1.bak`
  if (existsSync(store.path) && !existsSync(backupPath)) copyFileSync(store.path, backupPath)
  store.store = {
    settings: encodeSettings(decoded),
    schemaVersion: 1,
    migration: {
      id: 'safe-storage-v1',
      completedAt: Date.now()
    }
  }
  return decoded
}

function persistSettings(value: AppSettings): void {
  const containsSecrets = Boolean(
    value.directVpnInput ||
    value.directVpnCachedInput ||
    value.directVpnCachedSource ||
    value.directVpnCachedProfiles.length
  )
  if (containsSecrets && !isSecretEncryptionAvailable()) {
    throw new Error('Secure storage is unavailable; settings containing VPN secrets were not written')
  }
  store.set('settings', encodeSettings(value))
  store.set('schemaVersion', 1)
}

function normalizeSettings(input: Partial<AppSettings> | undefined): AppSettings {
  const merged = { ...defaults, ...(input ?? {}) }
  const cachedProfiles = Array.isArray(merged.directVpnCachedProfiles)
    ? merged.directVpnCachedProfiles
        .filter((profile: any) => profile && typeof profile === 'object' && profile.outbound && typeof profile.outbound === 'object')
        .map((profile: any) => ({
          name: typeof profile.name === 'string' && profile.name.trim() ? profile.name.trim() : 'VPN',
          protocol: typeof profile.protocol === 'string' && profile.protocol.trim() ? profile.protocol.trim() : String(profile.outbound?.type || 'sing-box'),
          outbound: profile.outbound
        }))
    : []
  return {
    connectionMode: merged.connectionMode === 'directVpn' ? 'directVpn' : 'localProxy',
    routingMode: merged.routingMode === 'soft' ? 'soft' : 'hard',
    proxyOverride: typeof merged.proxyOverride === 'string' ? merged.proxyOverride.trim() : '',
    proxyType: merged.proxyType === 'http' ? 'http' : 'socks5',
    bootstrapRouteMode: merged.bootstrapRouteMode === 'direct' || merged.bootstrapRouteMode === 'localProxy'
      ? merged.bootstrapRouteMode
      : 'auto',
    directVpnInput: typeof merged.directVpnInput === 'string' ? merged.directVpnInput.trim() : '',
    directVpnSelectedIndex: Math.max(0, Math.floor(Number(merged.directVpnSelectedIndex) || 0)),
    directVpnCachedInput: typeof merged.directVpnCachedInput === 'string' ? merged.directVpnCachedInput.trim() : '',
    directVpnCachedSource: typeof merged.directVpnCachedSource === 'string' ? merged.directVpnCachedSource.trim() : '',
    directVpnCachedAt: Number.isFinite(Number(merged.directVpnCachedAt)) ? Number(merged.directVpnCachedAt) : null,
    directVpnCachedProfiles: cachedProfiles,
    checkInterval: Math.min(300000, Math.max(5000, Number(merged.checkInterval) || defaults.checkInterval)),
    autoStart: Boolean(merged.autoStart),
    autoPilotEnabled: merged.autoPilotEnabled !== false,
    minimizeToTray: Boolean(merged.minimizeToTray),
    locationPrivacyEnabled: Boolean(merged.locationPrivacyEnabled),
    domainEnrichmentEnabled: Boolean(merged.domainEnrichmentEnabled),
    autoNetworkBaseline: Boolean(merged.autoNetworkBaseline),
    // Security-sensitive and invasive: absent/malformed input never opts the
    // user into a system-wide firewall block.
    firewallKillSwitch: merged.firewallKillSwitch === true,
    advancedMode: Boolean(merged.advancedMode),
    firstRunComplete: Boolean(merged.firstRunComplete),
    autoRestartOnCrash: merged.autoRestartOnCrash !== false,
    desktopNotifications: merged.desktopNotifications !== false,
    publicWifiCompatibility: merged.publicWifiCompatibility !== false,
    strictAdapterLockdown: merged.strictAdapterLockdown !== false,
    // `=== true`, not `!== false`, unlike the flags above. Those all default to
    // true, so "anything but an explicit false means on" matches their default.
    // This one defaults to false (see defaults above) and turning it on starts
    // writing packet captures to disk, so an absent or malformed value must
    // resolve to OFF. `!== false` only held because `merged` pre-fills from
    // defaults; an explicit undefined arriving via saveSettings would have
    // silently enabled forensics.
    deepTrafficInspectionEnabled: merged.deepTrafficInspectionEnabled === true,
    deepTrafficInspectionMaxSizeMb: Math.min(
      2048,
      Math.max(128, Math.floor(Number(merged.deepTrafficInspectionMaxSizeMb) || defaults.deepTrafficInspectionMaxSizeMb))
    ),
    deepTrafficInspectionRetainSessions: Math.min(
      10,
      Math.max(1, Math.floor(Number(merged.deepTrafficInspectionRetainSessions) || defaults.deepTrafficInspectionRetainSessions))
    ),
    // stealthMode is OFF by default — its mitigations (smaller MTU, TLS
    // fragmentation) cost a few % bandwidth and extra round-trips, only
    // worth paying on networks that actively shape VPN traffic. Without
    // this line the field was silently dropped on every save/load, so
    // the existing UI toggle had no effect.
    stealthMode: Boolean(merged.stealthMode),
    adaptiveBypassEnabled: merged.adaptiveBypassEnabled !== false,
    adaptiveBypassServerFallback: merged.adaptiveBypassServerFallback !== false,
    disableGeoLookup: Boolean(merged.disableGeoLookup),
    smartRuSplit: Boolean(merged.smartRuSplit),
    smartRuMapsDirect: Boolean(merged.smartRuMapsDirect),
    smartRuRuleSetMode: merged.smartRuRuleSetMode === 'managed' ? 'managed' : 'bundled',
    smartRuRuleSetAutoUpdate: merged.smartRuRuleSetAutoUpdate !== false,
    smartRuRuleSetUseProxy: merged.smartRuRuleSetUseProxy !== false,
    smartRuRuleSetUpdateIntervalHours: Math.min(
      720,
      Math.max(1, Math.floor(Number(merged.smartRuRuleSetUpdateIntervalHours) || defaults.smartRuRuleSetUpdateIntervalHours))
    ),
    proxyEngine: merged.proxyEngine === 'sing-box' || merged.proxyEngine === 'xray'
      ? merged.proxyEngine
      : 'auto'
  }
}

let bootRecoveryTaskEnsured = false
let bootRecoveryStatus: { status: 'not-checked' | 'verified' | 'failed'; message: string } = {
  status: 'not-checked', message: 'Boot Recovery task has not been verified'
}
export function getBootRecoveryRegistrationStatus() { return { ...bootRecoveryStatus } }

export function getBootRecoveryScriptPath(packaged = app.isPackaged): string {
  return packaged
    ? join(process.resourcesPath, 'vpnte-recover.ps1')
    : join(process.cwd(), 'resources', 'vpnte-recover.ps1')
}

export function buildBootRecoveryTaskCommand(recoverScript: string): string {
  const script = `& '${recoverScript.replace(/'/g, "''")}' -RegisterTask`
  return `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ${Buffer.from(script, 'utf16le').toString('base64')}`
}

function applyLoginItem(autoStart: boolean, options: { ensureBootRecovery?: boolean } = {}) {
  if (process.platform === 'win32' && app.isPackaged) {
    const taskName = 'VPN Tunnel Enforcer'
    const exe = `\\"${process.execPath.replace(/"/g, '\\"')}\\"`
    app.setLoginItemSettings({ openAtLogin: false })

    const command = autoStart
      ? `schtasks /Create /TN "${taskName}" /SC ONLOGON /RL HIGHEST /TR "${exe}" /F`
      : `schtasks /Delete /TN "${taskName}" /F`

    execElevated(command, { timeout: 15000 }).catch(() => undefined)

    if (options.ensureBootRecovery && !bootRecoveryTaskEnsured) {
      // Reserve immediately so multiple settings operations in the same tick
      // cannot race and register the task twice. A failure clears the flag and
      // permits a later retry.
      bootRecoveryTaskEnsured = true
      // Register boot-time recovery task once per app process. It is
      // independent of autoStart and restores network settings if a crash or
      // BSOD left firewall/DNS state pinned.
      const recoverTask = buildBootRecoveryTaskCommand(getBootRecoveryScriptPath(true))
      void execElevated(recoverTask, { timeout: 30000 })
        .then(async ({ stdout }) => {
          if (!String(stdout).split(/\r?\n/).includes('RECOVERY_TASK_VERIFIED')) throw new Error('Boot Recovery read-back marker missing')
          bootRecoveryStatus = { status: 'verified', message: 'SYSTEM startup trigger, action and principal verified' }
          const report = await readBootRecoveryReport()
          if (report && report.status !== 'restored') {
            await dialog.showMessageBox({ type: 'warning', title: 'VPNTE: Boot Recovery',
              message: report.status === 'strict-retained' ? 'Строгая блокировка сохранена после перезагрузки.' : 'Восстановление сети после перезагрузки не завершено.',
              detail: 'Защита не подтверждена. Проверьте результат Boot Recovery в системной диагностике.', buttons: ['OK'] })
          }
        })
        .catch(() => {
          bootRecoveryTaskEnsured = false
          bootRecoveryStatus = { status: 'failed', message: 'Boot Recovery registration or trusted report verification failed' }
          console.error('[settings] Boot Recovery verification failed; recovery is not confirmed')
          void dialog.showMessageBox({ type: 'error', title: 'VPNTE: Boot Recovery',
            message: 'Задача восстановления сети не подтверждена. Автовосстановление после перезагрузки не гарантировано.',
            detail: 'Проверьте системную диагностику и установку приложения с правами администратора.', buttons: ['OK'] }).catch(() => undefined)
        })
    }

    return
  }

  app.setLoginItemSettings({
    openAtLogin: autoStart,
    path: process.execPath,
    args: []
  })
}

export const settingsStore = {
  get(): AppSettings {
    return normalizeSettings(readSettingsWithMigration())
  },

  save(partial: Partial<AppSettings>): AppSettings {
    const previous = normalizeSettings(readSettingsWithMigration())
    const settings = normalizeSettings({ ...previous, ...partial })
    persistSettings(settings)
    if (!settings.domainEnrichmentEnabled && previous.domainEnrichmentEnabled) {
      domainEnrichmentService.setEnabled(false)
    }
    if (settings.autoStart !== previous.autoStart) {
      applyLoginItem(settings.autoStart, { ensureBootRecovery: true })
    }
    return settings
  },

  setLoginItem(openAtLogin: boolean): AppSettings {
    const settings = normalizeSettings({ ...normalizeSettings(readSettingsWithMigration()), autoStart: openAtLogin })
    persistSettings(settings)
    applyLoginItem(settings.autoStart, { ensureBootRecovery: true })
    return settings
  },

  syncLoginItem() {
    applyLoginItem(this.get().autoStart, { ensureBootRecovery: true })
  }
}
