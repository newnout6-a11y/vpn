import { app } from 'electron'
import Store from 'electron-store'
import { join } from 'path'
import { execElevated } from './admin'

export interface AppSettings {
  connectionMode: 'localProxy' | 'directVpn'
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
  // app does not send current VPN/server IPs to ipapi.co, ip-api.com,
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
}

const defaults: AppSettings = {
  connectionMode: 'localProxy',
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
  smartRuSplit: false,
  smartRuMapsDirect: false,
  smartRuRuleSetMode: 'bundled',
  smartRuRuleSetAutoUpdate: true,
  smartRuRuleSetUseProxy: true,
  smartRuRuleSetUpdateIntervalHours: 24
}

const store = new Store<{ settings: AppSettings }>({
  name: 'settings',
  defaults: { settings: defaults }
})

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
    autoNetworkBaseline: Boolean(merged.autoNetworkBaseline),
    firewallKillSwitch: merged.firewallKillSwitch !== false,
    advancedMode: Boolean(merged.advancedMode),
    firstRunComplete: Boolean(merged.firstRunComplete),
    autoRestartOnCrash: merged.autoRestartOnCrash !== false,
    desktopNotifications: merged.desktopNotifications !== false,
    publicWifiCompatibility: merged.publicWifiCompatibility !== false,
    strictAdapterLockdown: merged.strictAdapterLockdown !== false,
    deepTrafficInspectionEnabled: merged.deepTrafficInspectionEnabled !== false,
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
    disableGeoLookup: Boolean(merged.disableGeoLookup),
    smartRuSplit: Boolean(merged.smartRuSplit),
    smartRuMapsDirect: Boolean(merged.smartRuMapsDirect),
    smartRuRuleSetMode: merged.smartRuRuleSetMode === 'managed' ? 'managed' : 'bundled',
    smartRuRuleSetAutoUpdate: merged.smartRuRuleSetAutoUpdate !== false,
    smartRuRuleSetUseProxy: merged.smartRuRuleSetUseProxy !== false,
    smartRuRuleSetUpdateIntervalHours: Math.min(
      720,
      Math.max(1, Math.floor(Number(merged.smartRuRuleSetUpdateIntervalHours) || defaults.smartRuRuleSetUpdateIntervalHours))
    )
  }
}

let bootRecoveryTaskEnsured = false

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
      bootRecoveryTaskEnsured = true
      // Register boot-time recovery task once per app process. It is
      // independent of autoStart and restores network settings if a crash or
      // BSOD left firewall/DNS state pinned.
      const recoverScript = join(app.isPackaged ? process.resourcesPath : process.cwd(), 'resources', 'vpnte-recover.ps1')
      const recoverCmd = `powershell -NoProfile -ExecutionPolicy Bypass -File "${recoverScript}"`
      const recoverTask = `schtasks /Create /TN "VPNTE Boot Recovery" /SC ONSTART /RU SYSTEM /RP "" /TR "${recoverCmd}" /F`
      execElevated(recoverTask, { timeout: 15000 }).catch(() => undefined)
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
    return normalizeSettings(store.get('settings'))
  },

  save(partial: Partial<AppSettings>): AppSettings {
    const previous = normalizeSettings(store.get('settings'))
    const settings = normalizeSettings({ ...previous, ...partial })
    store.set('settings', settings)
    if (settings.autoStart !== previous.autoStart) {
      applyLoginItem(settings.autoStart, { ensureBootRecovery: true })
    }
    return settings
  },

  setLoginItem(openAtLogin: boolean): AppSettings {
    const settings = normalizeSettings({ ...normalizeSettings(store.get('settings')), autoStart: openAtLogin })
    store.set('settings', settings)
    applyLoginItem(settings.autoStart, { ensureBootRecovery: true })
    return settings
  },

  syncLoginItem() {
    applyLoginItem(this.get().autoStart, { ensureBootRecovery: true })
  }
}
