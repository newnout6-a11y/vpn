import { app } from 'electron'
import Store from 'electron-store'
import { execElevated } from './admin'

export interface AppSettings {
  routingMode: 'compatible'
  connectionMode: 'localProxy' | 'directVpn'
  proxyOverride: string
  proxyType: 'socks5' | 'http'
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
  // Public/captive Wi-Fi compatibility: do not rewrite physical adapter DNS.
  // Captive portals often decide "no internet" if Wi-Fi DNS is forced to the
  // TUN resolver before the portal is authorized.
  publicWifiCompatibility: boolean
  // Hard adapter lockdown: while TUN is up, disable IPv6 + force IPv4 DNS to
  // the TUN resolver on every physical (Wired/Wireless) adapter. Catches
  // leaks the firewall kill-switch alone misses (DNS-over-HTTPS bypassing
  // NRPT, IPv6 default-route preference, etc.). On by default — it's
  // invasive but reverted on stop, and without it real-world users still see
  // their original ISP IP in some apps.
  strictAdapterLockdown: boolean
}

const defaults: AppSettings = {
  routingMode: 'compatible',
  connectionMode: 'localProxy',
  proxyOverride: '',
  proxyType: 'socks5',
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
  strictAdapterLockdown: true
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
    strictAdapterLockdown: merged.strictAdapterLockdown !== false
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
