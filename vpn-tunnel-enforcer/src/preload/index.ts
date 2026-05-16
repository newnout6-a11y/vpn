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
  splitTunnelRemoveApp: (appId: string) => Promise<void>
  // Server Picker
  serversList: () => Promise<any[]>
  serversSelect: (id: string) => Promise<void>
  serversGetActive: () => Promise<{ profile: any | null; activeId: string | null }>
  serversPingAll: () => Promise<any[]>
  serversPingOne: (host: string, port: number) => Promise<number | null>
  serversAdd: (input: string) => Promise<any[]>
  serversRemove: (id: string) => Promise<void>
  serverProbe: (host: string, knownPort?: number) => Promise<any>
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
  splitTunnelRemoveApp: (appId: string) => ipcRenderer.invoke('split-tunnel:remove-app', appId),
  // Server Picker
  serversList: () => ipcRenderer.invoke('servers:list'),
  serversSelect: (id: string) => ipcRenderer.invoke('servers:select', id),
  serversGetActive: () => ipcRenderer.invoke('servers:get-active'),
  serversPingAll: () => ipcRenderer.invoke('servers:ping-all'),
  serversPingOne: (host: string, port: number) => ipcRenderer.invoke('servers:ping-one', host, port),
  serversAdd: (input: string) => ipcRenderer.invoke('servers:add', input),
  serversRemove: (id: string) => ipcRenderer.invoke('servers:remove', id),
  serverProbe: (host: string, knownPort?: number) => ipcRenderer.invoke('server:probe', host, knownPort),
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
  }
})
