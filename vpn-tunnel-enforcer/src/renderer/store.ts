import { create } from 'zustand'

/**
 * State Management Architecture Decision (Task 21.3)
 *
 * The design document specifies Zustand slices for: connection, splitTunnel, servers,
 * schedule, dns, routing, theme, i18n, widgets, notifications, speedTest, rotation, killSwitch.
 *
 * After implementation, the following architecture was adopted instead:
 *
 * 1. **Connection state (this store)** — Shared across Dashboard, Sidebar, widgets, and Settings.
 *    Contains: tunRunning, tunStartedAt, publicIp, isLeak, vpnIp, proxy, detecting,
 *    firewallKillSwitchActive, traffic, settings, logs, etc.
 *
 * 2. **Theme** — Managed by ThemeProvider (React Context) in providers/ThemeProvider.tsx.
 *    Applies CSS custom properties and listens for system theme changes via IPC.
 *
 * 3. **i18n** — Managed by react-i18next. No Zustand slice needed.
 *
 * 4. **Feature-specific state** (splitTunnel, servers, schedule, dns, routing, widgets,
 *    notifications, speedTest, rotation, killSwitch) — Each page/component manages its own
 *    state locally via useState + IPC calls to the main process. This is intentional:
 *    - Data is always fresh from the source of truth (main process)
 *    - No stale cache issues
 *    - Features are self-contained and don't need cross-component state sharing
 *    - Simpler mental model: component mounts → fetches data → displays it
 *
 * Separate Zustand slices were deemed unnecessary because the IPC-first pattern
 * provides better data freshness guarantees and the features don't share state
 * across unrelated components.
 */

export type Mode = 'off' | 'soft' | 'hard' | 'external'

export interface ProxyInfo {
  host: string
  port: number
  type: 'socks5' | 'http'
  verified: boolean
  publicIpViaProxy: string | null
}

export interface AutoconfigTarget {
  id: string
  name: string
  applied: boolean
  enabled: boolean
}

export interface LogEntry {
  timestamp: number
  level: 'info' | 'warn' | 'error'
  message: string
}

function persistRendererLog(level: LogEntry['level'], message: string) {
  try {
    const api = typeof window !== 'undefined' ? window.electronAPI : null
    if (api?.logRenderer) void api.logRenderer(level, message)
  } catch {
    // Logging must never break UI state updates.
  }
}

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
  advancedMode: boolean
  firstRunComplete: boolean
  autoRestartOnCrash: boolean
  desktopNotifications: boolean
  publicWifiCompatibility: boolean
  strictAdapterLockdown: boolean
  deepTrafficInspectionEnabled: boolean
  deepTrafficInspectionMaxSizeMb: number
  deepTrafficInspectionRetainSessions: number
  // Anti-DPI / TSPU bypass mode. When true the main process lowers TUN
  // MTU and adds TLS ClientHello fragmentation to non-Reality outbounds
  // to make the encrypted flow harder to fingerprint.
  stealthMode: boolean
  disableGeoLookup: boolean
  // Smart RU split-routing: RU destinations (geoip-ru + curated geosite)
  // egress direct with the real IP; everything else via VPN.
  smartRuSplit: boolean
  // Optional: route online maps direct for real-location results.
  smartRuMapsDirect: boolean
  smartRuRuleSetMode: 'bundled' | 'managed'
  smartRuRuleSetAutoUpdate: boolean
  smartRuRuleSetUseProxy: boolean
  smartRuRuleSetUpdateIntervalHours: number
}

export interface LeakCheckItem {
  id: string
  label: string
  status: 'ok' | 'warn' | 'fail' | 'info'
  value: string
  details?: string
}

export interface LeakCheckResult {
  ranAt: number
  summary: 'ok' | 'warn' | 'fail' | 'info'
  items: LeakCheckItem[]
}

export interface RoutingHealth {
  lastCheck: number | null
  summary: LeakCheckResult['summary'] | 'unknown'
  message: string
}

export interface TrafficStats {
  ts: number
  running: boolean
  adapterName: string
  adapterFound: boolean
  downloadBps: number
  uploadBps: number
  totalDownloadBytes: number
  totalUploadBytes: number
  sessionDownloadBytes: number
  sessionUploadBytes: number
  peakDownloadBps: number
  peakUploadBps: number
  startedAt: number | null
}

export interface BrowserIpCheck {
  ranAt: number
  summary: 'ok' | 'warn' | 'fail' | 'info'
  browserIpv4: string | null
  browserIpv6: string | null
  nodeIp: string | null
  browserMatchesNode: boolean | null
  webRtcPublicIps: string[]
  webRtcLocalIps: string[]
  webRtcMdnsCount: number
  webRtcError: string | null
  details: string[]
}

const emptyTrafficStats: TrafficStats = {
  ts: Date.now(),
  running: false,
  adapterName: 'Ethernet 5',
  adapterFound: false,
  downloadBps: 0,
  uploadBps: 0,
  totalDownloadBytes: 0,
  totalUploadBytes: 0,
  sessionDownloadBytes: 0,
  sessionUploadBytes: 0,
  peakDownloadBps: 0,
  peakUploadBps: 0,
  startedAt: null
}

interface AppState {
  mode: Mode
  publicIp: string | null
  isLeak: boolean
  vpnIp: string | null
  proxy: ProxyInfo | null
  detecting: boolean
  tunRunning: boolean  // Wall-clock ms when the current TUN run started (or null when not running).
  // Used by the hero card to show "Защищено • 12 минут".
  tunStartedAt: number | null
  // When non-null we are inside the auto-restart loop. Format is "N/M" where
  // N is the current attempt and M is the max number of retries.
  restartingProgress: string | null

  // In-flight connect/disconnect transition. Lives in the GLOBAL store (not
  // local component state) so it survives the Dashboard/Hero unmounting when
  // the user switches tabs mid-connect — otherwise the busy state was lost on
  // return, the power button re-enabled, and a second click double-started the
  // tunnel and broke routing. null = idle.
  connectionBusy: 'connecting' | 'disconnecting' | null
  // True iff the firewall kill-switch rules are currently installed. Used to
  // drive the Dashboard banner that appears when sing-box died but the rules
  // are still in place — the user has to either restart TUN or manually drop
  // the rules.
  firewallKillSwitchActive: boolean
  // Name+IP of a foreign VPN/TUN adapter that appeared while our tunnel is
  // running (e.g. user flipped Happ to TUN mode mid-session). null when the
  // runtime watchdog sees a clean state. Drives a Dashboard banner so the
  // user understands why DNS suddenly flapped.
  competingTun: string | null
  autoconfigTargets: AutoconfigTarget[]
  routingHealth: RoutingHealth
  leakChecks: LeakCheckResult | null
  traffic: TrafficStats
  browserIpCheck: BrowserIpCheck | null
  logs: LogEntry[]
  settings: AppSettings

  setMode: (mode: Mode) => void
  setPublicIp: (ip: string | null, isLeak: boolean) => void
  setVpnIp: (ip: string | null) => void
  setProxy: (proxy: ProxyInfo | null) => void
  setDetecting: (d: boolean) => void
  setTunRunning: (r: boolean) => void
  setTunStartedAt: (ts: number | null) => void
  setRestarting: (progress: string | null) => void
  setConnectionBusy: (busy: 'connecting' | 'disconnecting' | null) => void
  setFirewallKillSwitchActive: (active: boolean) => void
  setCompetingTun: (name: string | null) => void
  proxyDown: boolean
  setProxyDown: (v: boolean) => void
  setAutoconfigTargets: (targets: AutoconfigTarget[]) => void
  setLeakChecks: (checks: LeakCheckResult | null) => void
  setTrafficStats: (stats: TrafficStats) => void
  setBrowserIpCheck: (check: BrowserIpCheck | null) => void
  resetConnectionState: () => void
  addLog: (level: LogEntry['level'], message: string) => void
  setSettings: (s: AppSettings) => void
  updateSettings: (s: Partial<AppSettings>) => void

  // Result of the active leak self-test (curl-bound to physical adapter).
  // null = never run yet.
  leakSelfTestResult: LeakSelfTestResultClient | null
  setLeakSelfTestResult: (r: LeakSelfTestResultClient | null) => void
  // Last uncaught error caught by main process and forwarded for display.
  // We don't crash on these any more — but we surface them so the user knows
  // something happened.
  lastMainError: { code: string; message: string; ts: number } | null
  setLastMainError: (e: { code: string; message: string; ts: number } | null) => void

  // Persists the diagnostic export state across tab changes
  exportingDiagnostics: boolean
  setExportingDiagnostics: (e: boolean) => void

  // Maintenance page state — persisted in global store so results survive
  // tab switches (component unmount/remount).
  maintenanceLastResult: string | null
  setMaintenanceLastResult: (r: string | null) => void
  maintenanceRunningAction: string | null
  setMaintenanceRunningAction: (a: string | null) => void
  maintenanceStoreDiagnostics: any | null
  setMaintenanceStoreDiagnostics: (r: any | null) => void
  maintenanceSystemDiagnostics: any | null
  setMaintenanceSystemDiagnostics: (r: any | null) => void
  maintenancePrivacy: any | null
  setMaintenancePrivacy: (p: any | null) => void

  // Global toast notifications — visible on all pages
  globalToasts: GlobalToast[]
  addGlobalToast: (variant: GlobalToast['variant'], title: string, description?: string) => void
  dismissGlobalToast: (id: string) => void
}

export interface GlobalToast {
  id: string
  variant: 'success' | 'error' | 'warning' | 'info'
  title: string
  description?: string
  ts: number
}

export interface LeakSelfTestResultClient {
  ts: number
  physicalAdapterReached: boolean
  publicIpMismatch: boolean
  defaultRoutePublicIp: string | null
  dnsLeakDetected?: boolean
  dnsLeakDetail?: string
  perAdapter: Array<{
    alias: string
    ipv4: string | null
    publicIpViaThisAdapter: string | null
    curlExitCode: number | null
    curlStderrTail: string | null
  }>
  summary: string
}

export const useAppStore = create<AppState>((set) => ({
  mode: 'off',
  publicIp: null,
  isLeak: false,
  vpnIp: null,
  proxy: null,
  detecting: false,
  tunRunning: false,
  tunStartedAt: null,
  restartingProgress: null,
  connectionBusy: null,
  firewallKillSwitchActive: false,
  competingTun: null,
  proxyDown: false,
  leakSelfTestResult: null,
  lastMainError: null,
  exportingDiagnostics: false,
  autoconfigTargets: [
    { id: 'android-studio', name: 'Android Studio', applied: false, enabled: true },
    { id: 'gradle', name: 'Gradle', applied: false, enabled: true },
    { id: 'env', name: 'Environment Variables', applied: false, enabled: true },
    { id: 'git', name: 'Git', applied: false, enabled: true }
  ],
  routingHealth: {
    lastCheck: null,
    summary: 'unknown',
    message: 'Диагностика ещё не запускалась'
  },
  leakChecks: null,
  traffic: emptyTrafficStats,
  browserIpCheck: null,
  logs: [],
  settings: {
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
    autoNetworkBaseline: false,
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
    disableGeoLookup: false,
    smartRuSplit: false,
    smartRuMapsDirect: false,
    smartRuRuleSetMode: 'bundled',
    smartRuRuleSetAutoUpdate: true,
    smartRuRuleSetUseProxy: true,
    smartRuRuleSetUpdateIntervalHours: 24
  },

  setMode: (mode) => set({ mode }),
  setPublicIp: (ip, isLeak) => set({ publicIp: ip, isLeak }),
  setVpnIp: (ip) => set({ vpnIp: ip }),
  setProxy: (proxy) => set({ proxy }),
  setDetecting: (d) => set({ detecting: d }),
  setTunRunning: (r) => set((state) => ({
    tunRunning: r,
    // Reset the restart progress as soon as the run becomes healthy again.
    restartingProgress: r ? null : state.restartingProgress
  })),
  setTunStartedAt: (ts) => set({ tunStartedAt: ts }),
  setRestarting: (progress) => set({ restartingProgress: progress }),
  setConnectionBusy: (busy) => set({ connectionBusy: busy }),
  setFirewallKillSwitchActive: (active) => set({ firewallKillSwitchActive: active }),
  setCompetingTun: (name) => set({ competingTun: name }),
  setProxyDown: (v) => set({ proxyDown: v }),
  setAutoconfigTargets: (targets) => set({ autoconfigTargets: targets }),
  setLeakChecks: (checks) => set({
    leakChecks: checks,
    routingHealth: checks
      ? {
          lastCheck: checks.ranAt,
          summary: checks.summary,
          message:
            checks.summary === 'ok'
              ? 'Критичных утечек не найдено'
              : checks.summary === 'fail'
                ? 'Есть критичная проблема маршрутизации'
                : 'Есть предупреждения, проверьте детали'
        }
      : { lastCheck: null, summary: 'unknown', message: 'Диагностика ещё не запускалась' }
  }),
  setTrafficStats: (traffic) => set({ traffic }),
  setBrowserIpCheck: (browserIpCheck) => set({ browserIpCheck }),
  // Reset all connection-related state — called on crash/killswitch/disconnect
  // to prevent stale data from misleading the user.
  resetConnectionState: () => set({
    vpnIp: null,
    publicIp: null,
    isLeak: false,
    proxyDown: false,
    leakSelfTestResult: null,
    leakChecks: null,
    ipGeo: { country: null, city: null },
    traffic: { downloadBps: 0, uploadBps: 0, running: false, connectedAt: null, peakDownloadBps: 0, peakUploadBps: 0 },
    browserIpCheck: null,
  }),
  addLog: (level, message) => {
    persistRendererLog(level, message)
    set((s) => ({
      logs: [...s.logs.slice(-500), { timestamp: Date.now(), level, message }]
    }))
  },
  setSettings: (settings) => set({ settings }),
  updateSettings: (partial) => set((s) => ({
    settings: { ...s.settings, ...partial }
  })),
  setLeakSelfTestResult: (r) => set({ leakSelfTestResult: r }),
  setLastMainError: (e) => set({ lastMainError: e }),
  setExportingDiagnostics: (e) => set({ exportingDiagnostics: e }),
  maintenanceLastResult: null,
  setMaintenanceLastResult: (r) => set({ maintenanceLastResult: r }),
  maintenanceRunningAction: null,
  setMaintenanceRunningAction: (a) => set({ maintenanceRunningAction: a }),
  maintenanceStoreDiagnostics: null,
  setMaintenanceStoreDiagnostics: (r) => set({ maintenanceStoreDiagnostics: r }),
  maintenanceSystemDiagnostics: null,
  setMaintenanceSystemDiagnostics: (r) => set({ maintenanceSystemDiagnostics: r }),
  maintenancePrivacy: null,
  setMaintenancePrivacy: (p) => set({ maintenancePrivacy: p }),
  globalToasts: [],
  addGlobalToast: (variant, title, description) => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`
    set((s) => ({
      globalToasts: [...s.globalToasts, { id, variant, title, description, ts: Date.now() }]
    }))
    setTimeout(() => {
      set((s) => ({ globalToasts: s.globalToasts.filter(t => t.id !== id) }))
    }, 4000)
  },
  dismissGlobalToast: (id) => set((s) => ({ globalToasts: s.globalToasts.filter(t => t.id !== id) }))
}))
