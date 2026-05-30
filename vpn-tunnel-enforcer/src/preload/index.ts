import { contextBridge, ipcRenderer } from 'electron'

export interface ElectronAPI {
  detectHapp: () => Promise<any>
  getPublicIp: () => Promise<{ ip: string | null; isLeak: boolean; vpnIp: string | null }>
  recheckPublicIp: (rebaseline?: boolean) => Promise<{ ip: string | null; isLeak: boolean; vpnIp: string | null }>
  startTun: (proxyAddr: string, proxyType?: 'socks5' | 'http') => Promise<{ success: boolean; error?: string; warning?: string | null; vpnIp?: string | null }>
  startDirectVpn: () => Promise<{ success: boolean; error?: string; warning?: string | null; vpnIp?: string | null }>
  stopTun: () => Promise<{ success: boolean; error?: string }>
  getTunStatus: () => Promise<{ running: boolean; proxyAddr: string | null; proxyType: 'socks5' | 'http' | null; pid: number | null; warning?: string | null; startedAt?: number | null; restartAttempt?: number }>
  getTrafficStats: () => Promise<TrafficStats>
  applyAutoconfig: (targets: string[], proxyAddr: string, proxyType?: 'socks5' | 'http') => Promise<Record<string, boolean>>
  rollbackAutoconfig: (targets: string[]) => Promise<Record<string, boolean>>
  getAutoconfigStatus: () => Promise<any[]>
  getSettings: () => Promise<any>
  saveSettings: (settings: any) => Promise<any>
  inspectVpnInput: (input: string) => Promise<{ count: number; protocols: Record<string, number>; profiles: Array<{ index: number; name: string; protocol: string }>; fetched: boolean; source: string }>
  setLoginItem: (openAtLogin: boolean) => Promise<any>
  runLeakCheck: (options?: { proxyAddr?: string; proxyType?: 'socks5' | 'http' }) => Promise<any>
  runStoreRepair: (action: string) => Promise<any>
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
  firewallNuclearReset: () => Promise<{ success: boolean; message: string }>
  detectForeignVpn: () => Promise<{ foreign: string | null }>
  getLocationPrivacy: () => Promise<any>
  applyLocationPrivacy: () => Promise<any>
  rollbackLocationPrivacy: () => Promise<any>
  openTunLogFolder: () => Promise<string>
  openLogFolder: () => Promise<string>
  exportDiagnostics: () => Promise<{ success: boolean; path?: string; error?: string; cancelled?: boolean }>
  runLeakSelfTest: () => Promise<LeakSelfTestResult>
  openSnapshotsFolder: () => Promise<{ success: boolean; path?: string; error?: string }>
  // Config Import/Export
  configExport: () => Promise<{ success: boolean; path?: string; error?: string }>
  configBrowseImport: () => Promise<string | null>
  configImport: (filePath: string) => Promise<{ success: boolean; sections: string[]; conflicts: string[]; error?: string }>
  configImportApply: (filePath: string, sections: string[], conflictResolution: 'replace' | 'merge') => Promise<{ success: boolean; error?: string }>
  // Split Tunneling
  splitTunnelGetApps: () => Promise<any[]>
  splitTunnelSetRule: (appId: string, rule: 'vpn' | 'direct' | 'none') => Promise<void>
  splitTunnelAddApp: (exePath: string) => Promise<any>
  splitTunnelAddProcess: (name: string) => Promise<any>
  splitTunnelRemoveApp: (appId: string) => Promise<void>
  // Server Picker
  serversList: () => Promise<any[]>
  serversSelect: (id: string) => Promise<void>
  serversGetActive: () => Promise<{ profile: any | null; activeId: string | null }>
  serversPingAll: () => Promise<any[]>
  serversPingOne: (host: string, port: number) => Promise<number | null>
  serversAdd: (input: string) => Promise<any[]>
  serversAddToGroup: (input: string, groupId: string | null) => Promise<any[]>
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
  serversExportAllKeysToFile: () => Promise<
    | { ok: true; path: string; total: number; exported: number; skipped: number }
    | { ok: false; cancelled: true }
    | { ok: false; reason: string; error?: string }
  >
  // Server Groups — origin tracking and post-trial-aware refresh.
  groupsList: () => Promise<any[]>
  groupsGet: (id: string) => Promise<any | null>
  groupsRename: (id: string, name: string) => Promise<any | null>
  groupsDelete: (id: string, deleteServers: boolean) => Promise<{ ok: boolean }>
  groupsRefresh: (id: string) => Promise<
    | { ok: true; group: any; addedCount: number; updatedCount: number; removedCount: number }
    | { ok: false; error: string }
  >
  groupsCheckHealth: (id: string) => Promise<
    | { ok: true; results: Array<{ profileId: string; online: boolean; latencyMs: number | null; reason?: string }> }
    | { ok: false; error: string }
  >
  serverProbe: (host: string, knownPort?: number) => Promise<any>
  urlAvailabilityCheck: (url: string) => Promise<any>
  urlAvailabilityHistory: () => Promise<any[]>
  urlAvailabilityClearHistory: () => Promise<void>
  // Scheduler
  schedulerList: () => Promise<any[]>
  schedulerCreate: (entry: any) => Promise<any>
  schedulerUpdate: (id: string, patch: any) => Promise<any>
  schedulerDelete: (id: string) => Promise<void>
  schedulerNextEvent: () => Promise<any>
  // Profile Rotation
  rotationGetConfig: () => Promise<any>
  rotationSetConfig: (config: any) => Promise<any>
  rotationRotateNow: () => Promise<{ success: boolean; newProfile: string }>
  // Kill-Switch
  killSwitchGetLevel: () => Promise<any>
  killSwitchSetLevel: (level: 'off' | 'standard' | 'strict') => Promise<any>
  killSwitchGetExceptions: () => Promise<any[]>
  killSwitchAddException: (exception: { type: 'app' | 'ip'; value: string; label: string }) => Promise<any>
  killSwitchRemoveException: (id: string) => Promise<any>
  killSwitchBrowseApp: () => Promise<{ path: string; name: string } | null>
  // DNS Profiles
  dnsList: () => Promise<any[]>
  dnsCreate: (profile: { name: string; primary: string; secondary: string; type: 'plain' | 'doh' | 'dot' }) => Promise<any>
  dnsDelete: (id: string) => Promise<void>
  dnsSelect: (id: string) => Promise<void>
  dnsValidate: (address: string) => Promise<{ valid: boolean; type: 'plain' | 'doh' | 'dot'; error?: string }>
  // Domain Routing
  domainRoutingList: () => Promise<any[]>
  domainRoutingAdd: (rule: { pattern: string; action: 'vpn' | 'direct' | 'block'; priority: number }) => Promise<any>
  domainRoutingUpdate: (id: string, patch: any) => Promise<any>
  domainRoutingDelete: (id: string) => Promise<void>
  domainRoutingReorder: (ids: string[]) => Promise<any[]>
  domainRoutingImport: (filePath: string) => Promise<any[]>
  domainRoutingResetHits: () => Promise<void>
  domainRoutingBrowseFile: () => Promise<string | null>
  // Connection History
  connectionHistoryList: () => Promise<any[]>
  connectionHistoryFilter: (filters: any) => Promise<any[]>
  connectionHistoryStats: (period: 'day' | 'week' | 'month') => Promise<any>
  connectionHistoryExportCsv: () => Promise<string>
  connectionHistoryExportJson: () => Promise<string>
  // Traffic History
  trafficHistoryList: (vpnIp?: string) => Promise<any[]>
  trafficHistoryClear: () => Promise<{ success: boolean }>
  // Notification Preferences
  notificationsGetPrefs: () => Promise<any>
  notificationsSetPrefs: (prefs: any) => Promise<any>
  checkOsNotificationState: () => Promise<{ osNotificationsEnabled: boolean; appUserModelId: string | null }>
  notificationsResetOsBlock: () => Promise<{ ok: true; cleared: string[]; errors: string[] } | { ok: false; error: string }>
  notificationsOpenWindowsSettings: () => Promise<{ ok: true } | { ok: false; error: string }>
  onInAppNotification: (callback: (data: { level: 'info' | 'warn' | 'error'; title: string; body: string; ts: number }) => void) => () => void
  // ip-monitor suspend/resume — leak detection guard during stop-tun rollback.
  ipMonitorSuspend: () => Promise<{ ok: true } | undefined>
  ipMonitorResume: () => Promise<{ ok: true } | undefined>
  // i18n
  i18nGetLocale: () => Promise<string>
  i18nSetLocale: (locale: string) => Promise<void>
  i18nGetSystemLocale: () => Promise<string>
  // Theme
  themeList: () => Promise<any[]>
  themeGetActive: () => Promise<any>
  themeSetActive: (id: string) => Promise<void>
  themeCreate: (theme: any) => Promise<any>
  themeDelete: (id: string) => Promise<void>
  onThemeChanged: (callback: (theme: any) => void) => () => void
  // Speed Test
  speedTestRun: () => Promise<any>
  speedTestHistory: () => Promise<any[]>
  onSpeedTestProgress: (callback: (data: { percent: number; phase: string }) => void) => () => void
  // Widgets
  getWidgetLayout: () => Promise<any[]>
  setWidgetLayout: (layout: any[]) => Promise<void>
  // Event listeners
  onIpChanged: (callback: (data: { ip: string; isLeak: boolean }) => void) => () => void
  onTunStatusChanged: (callback: (status: string) => void) => () => void
  onTrafficStats: (callback: (stats: TrafficStats) => void) => () => void
  onLeakDetected: (callback: (result: LeakSelfTestResult) => void) => () => void
  onMainError: (callback: (data: { code: string; message: string }) => void) => () => void
  // Fires when the user chose "Отключить и закрыть" from the close-confirm
  // dialog and the main process is winding the tunnel down. The renderer
  // should disable controls and surface a "Выключаем защиту…" overlay so the
  // user doesn't keep clicking buttons that won't be honoured.
  onAppShuttingDown: (callback: () => void) => () => void
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

contextBridge.exposeInMainWorld('electronAPI', {
  detectHapp: () => ipcRenderer.invoke('detect-happ'),
  getPublicIp: () => ipcRenderer.invoke('get-public-ip'),
  recheckPublicIp: (rebaseline?: boolean) => ipcRenderer.invoke('recheck-public-ip', rebaseline === true),
  startTun: (proxyAddr: string, proxyType?: 'socks5' | 'http') => ipcRenderer.invoke('start-tun', proxyAddr, proxyType),
  startDirectVpn: () => ipcRenderer.invoke('start-direct-vpn'),
  stopTun: () => ipcRenderer.invoke('stop-tun'),
  getTunStatus: () => ipcRenderer.invoke('get-tun-status'),
  getTrafficStats: () => ipcRenderer.invoke('get-traffic-stats'),
  applyAutoconfig: (targets: string[], proxyAddr: string, proxyType?: 'socks5' | 'http') => ipcRenderer.invoke('apply-autoconfig', targets, proxyAddr, proxyType),
  rollbackAutoconfig: (targets: string[]) => ipcRenderer.invoke('rollback-autoconfig', targets),
  getAutoconfigStatus: () => ipcRenderer.invoke('get-autoconfig-status'),
  getSettings: () => ipcRenderer.invoke('get-settings'),
  saveSettings: (settings: any) => ipcRenderer.invoke('save-settings', settings),
  inspectVpnInput: (input: string) => ipcRenderer.invoke('inspect-vpn-input', input),
  setLoginItem: (openAtLogin: boolean) => ipcRenderer.invoke('set-login-item', openAtLogin),
  runLeakCheck: (options?: { proxyAddr?: string; proxyType?: 'socks5' | 'http' }) => ipcRenderer.invoke('run-leak-check', options),
  runStoreRepair: (action: string) => ipcRenderer.invoke('run-store-repair', action),
  runStoreDiagnostics: () => ipcRenderer.invoke('run-store-diagnostics'),
  runSystemDiagnostics: () => ipcRenderer.invoke('run-system-diagnostics'),
  getRoutingPlan: () => ipcRenderer.invoke('get-routing-plan'),
  applyBrowserLeakProtection: () => ipcRenderer.invoke('apply-browser-leak-protection'),
  rollbackBrowserLeakProtection: () => ipcRenderer.invoke('rollback-browser-leak-protection'),
  runAutoPilot: () => ipcRenderer.invoke('run-auto-pilot'),
  logRenderer: (level: 'debug' | 'info' | 'warn' | 'error', message: string) => ipcRenderer.invoke('renderer-log', level, message),
  getFullLogs: () => ipcRenderer.invoke('get-full-logs'),
  clearAppLog: () => ipcRenderer.invoke('clear-app-log'),
  applyTunNetworkBaseline: () => ipcRenderer.invoke('apply-tun-network-baseline'),
  rollbackTunNetworkBaseline: () => ipcRenderer.invoke('rollback-tun-network-baseline'),
  disableFirewallKillSwitch: () => ipcRenderer.invoke('disable-firewall-kill-switch'),
  getFirewallKillSwitchStatus: () => ipcRenderer.invoke('get-firewall-kill-switch-status'),
  firewallNuclearReset: () => ipcRenderer.invoke('firewall:nuclear-reset'),
  detectForeignVpn: () => ipcRenderer.invoke('system:detect-foreign-vpn'),
  getLocationPrivacy: () => ipcRenderer.invoke('get-location-privacy'),
  applyLocationPrivacy: () => ipcRenderer.invoke('apply-location-privacy'),
  rollbackLocationPrivacy: () => ipcRenderer.invoke('rollback-location-privacy'),
  openTunLogFolder: () => ipcRenderer.invoke('open-tun-log-folder'),
  openLogFolder: () => ipcRenderer.invoke('open-log-folder'),
  exportDiagnostics: () => ipcRenderer.invoke('export-diagnostics'),
  runLeakSelfTest: () => ipcRenderer.invoke('run-leak-self-test'),
  openSnapshotsFolder: () => ipcRenderer.invoke('open-snapshots-folder'),
  // Split Tunneling
  splitTunnelGetApps: () => ipcRenderer.invoke('split-tunnel:get-apps'),
  splitTunnelSetRule: (appId: string, rule: 'vpn' | 'direct' | 'none') => ipcRenderer.invoke('split-tunnel:set-rule', appId, rule),
  splitTunnelAddApp: (exePath: string) => ipcRenderer.invoke('split-tunnel:add-app', exePath),
  splitTunnelAddProcess: (name: string) => ipcRenderer.invoke('split-tunnel:add-process', name),
  splitTunnelRemoveApp: (appId: string) => ipcRenderer.invoke('split-tunnel:remove-app', appId),
  // Server Picker
  serversList: () => ipcRenderer.invoke('servers:list'),
  serversSelect: (id: string) => ipcRenderer.invoke('servers:select', id),
  serversGetActive: () => ipcRenderer.invoke('servers:get-active'),
  serversPingAll: () => ipcRenderer.invoke('servers:ping-all'),
  serversPingOne: (host: string, port: number) => ipcRenderer.invoke('servers:ping-one', host, port),
  serversAdd: (input: string) => ipcRenderer.invoke('servers:add', input),
  serversAddToGroup: (input: string, groupId: string | null) => ipcRenderer.invoke('servers:add-to-group', input, groupId),
  serversRemove: (id: string) => ipcRenderer.invoke('servers:remove', id),
  serversExportKey: (id: string) => ipcRenderer.invoke('servers:export-key', id),
  serversExportKeyToFile: (id: string) => ipcRenderer.invoke('servers:export-key-file', id),
  serversExportAllKeysToFile: () => ipcRenderer.invoke('servers:export-all-keys-file'),
  // Server Groups — origin tracking and post-trial-aware refresh.
  groupsList: () => ipcRenderer.invoke('groups:list'),
  groupsGet: (id: string) => ipcRenderer.invoke('groups:get', id),
  groupsRename: (id: string, name: string) => ipcRenderer.invoke('groups:rename', id, name),
  groupsDelete: (id: string, deleteServers: boolean) => ipcRenderer.invoke('groups:delete', id, deleteServers),
  groupsRefresh: (id: string) => ipcRenderer.invoke('groups:refresh', id),
  groupsCheckHealth: (id: string) => ipcRenderer.invoke('groups:check-health', id),
  serverProbe: (host: string, knownPort?: number) => ipcRenderer.invoke('server:probe', host, knownPort),
  // URL Availability — paste a link, get verdict + diagnostics for both
  // the tunnel path and the direct path (clash-direct-out when VPN is on).
  urlAvailabilityCheck: (url: string) => ipcRenderer.invoke('url-availability:check', url),
  urlAvailabilityHistory: () => ipcRenderer.invoke('url-availability:history'),
  urlAvailabilityClearHistory: () => ipcRenderer.invoke('url-availability:clear-history'),
  // Scheduler
  schedulerList: () => ipcRenderer.invoke('scheduler:list'),
  schedulerCreate: (entry: any) => ipcRenderer.invoke('scheduler:create', entry),
  schedulerUpdate: (id: string, patch: any) => ipcRenderer.invoke('scheduler:update', id, patch),
  schedulerDelete: (id: string) => ipcRenderer.invoke('scheduler:delete', id),
  schedulerNextEvent: () => ipcRenderer.invoke('scheduler:next-event'),
  // Kill-Switch
  killSwitchGetLevel: () => ipcRenderer.invoke('kill-switch:get-level'),
  killSwitchSetLevel: (level: 'off' | 'standard' | 'strict') => ipcRenderer.invoke('kill-switch:set-level', level),
  killSwitchGetExceptions: () => ipcRenderer.invoke('kill-switch:get-exceptions'),
  killSwitchAddException: (exception: { type: 'app' | 'ip'; value: string; label: string }) => ipcRenderer.invoke('kill-switch:add-exception', exception),
  killSwitchRemoveException: (id: string) => ipcRenderer.invoke('kill-switch:remove-exception', id),
  killSwitchBrowseApp: () => ipcRenderer.invoke('kill-switch:browse-app'),
  // Profile Rotation
  rotationGetConfig: () => ipcRenderer.invoke('rotation:get-config'),
  rotationSetConfig: (config: any) => ipcRenderer.invoke('rotation:set-config', config),
  rotationRotateNow: () => ipcRenderer.invoke('rotation:rotate-now'),
  // DNS Profiles
  dnsList: () => ipcRenderer.invoke('dns:list'),
  dnsCreate: (profile: { name: string; primary: string; secondary: string; type: 'plain' | 'doh' | 'dot' }) => ipcRenderer.invoke('dns:create', profile),
  dnsDelete: (id: string) => ipcRenderer.invoke('dns:delete', id),
  dnsSelect: (id: string) => ipcRenderer.invoke('dns:select', id),
  dnsValidate: (address: string) => ipcRenderer.invoke('dns:validate', address),
  // Domain Routing
  domainRoutingList: () => ipcRenderer.invoke('domain-routing:list'),
  domainRoutingAdd: (rule: { pattern: string; action: 'vpn' | 'direct' | 'block'; priority: number }) => ipcRenderer.invoke('domain-routing:add', rule),
  domainRoutingUpdate: (id: string, patch: any) => ipcRenderer.invoke('domain-routing:update', id, patch),
  domainRoutingDelete: (id: string) => ipcRenderer.invoke('domain-routing:delete', id),
  domainRoutingReorder: (ids: string[]) => ipcRenderer.invoke('domain-routing:reorder', ids),
  domainRoutingImport: (filePath: string) => ipcRenderer.invoke('domain-routing:import', filePath),
  domainRoutingResetHits: () => ipcRenderer.invoke('domain-routing:reset-hits'),
  domainRoutingBrowseFile: () => ipcRenderer.invoke('domain-routing:browse-file'),
  // Connection History
  connectionHistoryList: () => ipcRenderer.invoke('connection-history:list'),
  connectionHistoryFilter: (filters: any) => ipcRenderer.invoke('connection-history:filter', filters),
  connectionHistoryStats: (period: 'day' | 'week' | 'month') => ipcRenderer.invoke('connection-history:stats', period),
  connectionHistoryExportCsv: () => ipcRenderer.invoke('connection-history:export-csv'),
  connectionHistoryExportJson: () => ipcRenderer.invoke('connection-history:export-json'),
  // Traffic History
  trafficHistoryList: (vpnIp?: string) => ipcRenderer.invoke('traffic-history:list', vpnIp),
  trafficHistoryClear: () => ipcRenderer.invoke('traffic-history:clear'),
  // Config Import/Export
  configExport: () => ipcRenderer.invoke('config:export'),
  configBrowseImport: () => ipcRenderer.invoke('config:browse-import'),
  configImport: (filePath: string) => ipcRenderer.invoke('config:import', filePath),
  configImportApply: (filePath: string, sections: string[], conflictResolution: 'replace' | 'merge') => ipcRenderer.invoke('config:import-apply', filePath, sections, conflictResolution),
  // Notification Preferences
  notificationsGetPrefs: () => ipcRenderer.invoke('notifications:get-prefs'),
  notificationsSetPrefs: (prefs: any) => ipcRenderer.invoke('notifications:set-prefs', prefs),
  checkOsNotificationState: () => ipcRenderer.invoke('notifications:check-os-state'),
  // Clear the Windows-side notification block (registry "Enabled = 0" set
  // when the user clicked "Don't show notifications" on a toast). Returns
  // a structured ok/error shape — never throws.
  notificationsResetOsBlock: () => ipcRenderer.invoke('notifications:reset-os-block'),
  notificationsOpenWindowsSettings: () => ipcRenderer.invoke('notifications:open-windows-settings'),
  // In-app notification fallback: fired when notify() can't deliver an OS
  // toast (Windows blocks us, or platform unsupported). Returns an
  // unsubscribe handle.
  onInAppNotification: (callback: (data: { level: 'info' | 'warn' | 'error'; title: string; body: string; ts: number }) => void) => {
    const handler = (_event: any, data: { level: 'info' | 'warn' | 'error'; title: string; body: string; ts: number }) => callback(data)
    ipcRenderer.on('inapp-notification', handler)
    return () => ipcRenderer.removeListener('inapp-notification', handler)
  },
  // ip-monitor suspend/resume bridge — main self-registers these on
  // process.type==='browser'. Renderer flips them when TUN status moves
  // to 'stopping'/'stopped' to silence false-positive leak events.
  ipMonitorSuspend: () => ipcRenderer.invoke('ip-monitor:suspend'),
  ipMonitorResume: () => ipcRenderer.invoke('ip-monitor:resume'),
  // i18n
  i18nGetLocale: () => ipcRenderer.invoke('i18n:get-locale'),
  i18nSetLocale: (locale: string) => ipcRenderer.invoke('i18n:set-locale', locale),
  i18nGetSystemLocale: () => ipcRenderer.invoke('i18n:get-system-locale'),
  // Theme
  themeList: () => ipcRenderer.invoke('theme:list'),
  themeGetActive: () => ipcRenderer.invoke('theme:get-active'),
  themeSetActive: (id: string) => ipcRenderer.invoke('theme:set-active', id),
  themeCreate: (theme: any) => ipcRenderer.invoke('theme:create', theme),
  themeDelete: (id: string) => ipcRenderer.invoke('theme:delete', id),
  onThemeChanged: (callback: (theme: any) => void) => {
    const handler = (_event: any, theme: any) => callback(theme)
    ipcRenderer.on('theme-changed', handler)
    return () => ipcRenderer.removeListener('theme-changed', handler)
  },
  // Speed Test
  speedTestRun: () => ipcRenderer.invoke('speed-test:run'),
  speedTestHistory: () => ipcRenderer.invoke('speed-test:history'),
  onSpeedTestProgress: (callback: (data: { percent: number; phase: string }) => void) => {
    const handler = (_event: any, data: { percent: number; phase: string }) => callback(data)
    ipcRenderer.on('speed-test:progress', handler)
    return () => ipcRenderer.removeListener('speed-test:progress', handler)
  },
  // Widgets
  getWidgetLayout: () => ipcRenderer.invoke('widgets:get-layout'),
  setWidgetLayout: (layout: any[]) => ipcRenderer.invoke('widgets:set-layout', layout),
  // Event listeners
  onIpChanged: (callback: (data: { ip: string; isLeak: boolean }) => void) => {
    const handler = (_event: any, data: { ip: string; isLeak: boolean }) => callback(data)
    ipcRenderer.on('ip-changed', handler)
    return () => ipcRenderer.removeListener('ip-changed', handler)
  },
  onTunStatusChanged: (callback: (status: string) => void) => {
    const handler = (_event: any, status: string) => callback(status)
    ipcRenderer.on('tun-status-changed', handler)
    return () => ipcRenderer.removeListener('tun-status-changed', handler)
  },
  onTrafficStats: (callback: (stats: TrafficStats) => void) => {
    const handler = (_event: any, stats: TrafficStats) => callback(stats)
    ipcRenderer.on('traffic-stats', handler)
    return () => ipcRenderer.removeListener('traffic-stats', handler)
  },
  onLeakDetected: (callback: (result: LeakSelfTestResult) => void) => {
    const handler = (_event: any, result: LeakSelfTestResult) => callback(result)
    ipcRenderer.on('leak-detected', handler)
    return () => ipcRenderer.removeListener('leak-detected', handler)
  },
  onMainError: (callback: (data: { code: string; message: string }) => void) => {
    const handler = (_event: any, data: { code: string; message: string }) => callback(data)
    ipcRenderer.on('main-error', handler)
    return () => ipcRenderer.removeListener('main-error', handler)
  },
  onAppShuttingDown: (callback: () => void) => {
    const handler = () => callback()
    ipcRenderer.on('app:shutting-down', handler)
    return () => ipcRenderer.removeListener('app:shutting-down', handler)
  }
})
