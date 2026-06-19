import { app } from 'electron'
import Store from 'electron-store'
import { execElevated } from './admin'

export interface AppSettings {
  routingMode: 'compatible'
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
  // When false, the renderer hides every advanced/destructive option:
  // Maintenance page, Apps autoconfig page, autoNetworkBaseline toggle,
  // proxyOverride field, mode picker. Default is false so a fresh user only
  // sees the big "вкл./выкл. защиты" hero on Dashboard.
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
  //   3. Activate the auto-failover watchdog: if the active server starts
  //      timing out (3+ consecutive TLS pings fail within 2 minutes), the
  //      next picker profile is selected and the tunnel is restarted.
  // Safe to leave ON outside of restrictive networks too — costs ~5% extra
  // bandwidth from MTU overhead and a handful of extra TLS roundtrips.
  stealthMode: boolean
  // Smart RU split-routing. When ON, Russian destinations (banks, gov
  // portals, shops, local services) egress with the user's REAL IP via
  // direct-out, while everything else goes through the VPN — so foreign
  // sites see the VPN location and RU sites that geo-fence/whitelist RU IPs
  // keep working. The signal is NOT a naive ".ru domain" check: we use
  // sing-box geoip-ru (route by destination IP country) + geosite-category-ru
  // / category-gov-ru rule-sets (curated RU domain lists that cover .com/.рф
  // properties too), maintained upstream and refreshed via cache_file.
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
  routingMode: 'compatible',
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
  deepTrafficInspectionEnabled: true,
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
    routingMode: 'compatible',
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

function applyLoginItem(autoStart: boolean) {
  if (process.platform === 'win32' && app.isPackaged) {
    const taskName = 'VPN Tunnel Enforcer'
    const exe = `\\"${process.execPath.replace(/"/g, '\\"')}\\"`
    app.setLoginItemSettings({ openAtLogin: false })

    const command = autoStart
      ? `schtasks /Create /TN "${taskName}" /SC ONLOGON /RL HIGHEST /TR "${exe}" /F`
      : `schtasks /Delete /TN "${taskName}" /F`

    execElevated(command, { timeout: 15000 }).catch(() => undefined)
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
    const settings = normalizeSettings({ ...normalizeSettings(store.get('settings')), ...partial })
    store.set('settings', settings)
    applyLoginItem(settings.autoStart)
    return settings
  },

  setLoginItem(openAtLogin: boolean): AppSettings {
    const settings = normalizeSettings({ ...normalizeSettings(store.get('settings')), autoStart: openAtLogin })
    store.set('settings', settings)
    applyLoginItem(settings.autoStart)
    return settings
  },

  syncLoginItem() {
    applyLoginItem(this.get().autoStart)
  }
}
