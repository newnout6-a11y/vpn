import { contextBridge, ipcRenderer } from 'electron'
import type { ClientDevice, ExternalProxyBatchStartResult, ExternalProxyStartOptions, ExternalProxyStatus, ExternalProxyProfileRow } from '../shared/ipc-types'

export interface ElectronAPI {
  detectHapp: () => Promise<any>
  getPublicIp: () => Promise<{ ip: string | null; isLeak: boolean; vpnIp: string | null }>
  recheckPublicIp: (rebaseline?: boolean) => Promise<{ ip: string | null; isLeak: boolean; vpnIp: string | null }>
  startTun: (proxyAddr: string, proxyType?: 'socks5' | 'http') => Promise<{ success: boolean; error?: string; warning?: string | null; vpnIp?: string | null }>
  startDirectVpn: () => Promise<{ success: boolean; error?: string; warning?: string | null; vpnIp?: string | null }>
  stopTun: () => Promise<{ success: boolean; error?: string; warning?: string }>
  getTunStatus: () => Promise<{ running: boolean; proxyAddr: string | null; proxyType: 'socks5' | 'http' | null; pid: number | null; warning?: string | null; startedAt?: number | null; restartAttempt?: number }>
  getTrafficStats: () => Promise<TrafficStats>
  applyAutoconfig: (targets: string[], proxyAddr: string, proxyType?: 'socks5' | 'http') => Promise<Record<string, boolean>>
  rollbackAutoconfig: (targets: string[]) => Promise<Record<string, boolean>>
  getAutoconfigStatus: () => Promise<any[]>
  getSettings: () => Promise<any>
  saveSettings: (settings: any) => Promise<any>
  adaptiveBypassGetStatus: () => Promise<any>
  adaptiveBypassRetry: () => Promise<any>
  adaptiveBypassResetLearning: () => Promise<any>
  smartRouteRuleSetsGetState: () => Promise<any>
  smartRouteRuleSetsRefresh: (force?: boolean) => Promise<any>
  inspectVpnInput: (input: string) => Promise<{ count: number; protocols: Record<string, number>; profiles: Array<{ index: number; name: string; protocol: string }>; fetched: boolean; source: string }>
  setLoginItem: (openAtLogin: boolean) => Promise<any>
  runLeakCheck: (options?: { proxyAddr?: string; proxyType?: 'socks5' | 'http' }) => Promise<any>
  runSystemDiagnostics: () => Promise<any>
  getRoutingPlan: () => Promise<any>
  applyBrowserLeakProtection: () => Promise<any>
  rollbackBrowserLeakProtection: () => Promise<any>
  runAutoPilot: () => Promise<any>
  repairOrphanedDns: () => Promise<any>
  rollbackAdapterLockdown: () => Promise<any>
  killStaleSingbox: () => Promise<{ success: boolean; message: string }>
  logRenderer: (level: 'debug' | 'info' | 'warn' | 'error', message: string) => Promise<any>
  getFullLogs: () => Promise<any>
  clearAppLog: () => Promise<any>
  clearDiagnosticArtifacts: () => Promise<{ success: boolean; message: string; cleared: string[] }>
  rollbackTunNetworkBaseline: () => Promise<any>
  disableFirewallKillSwitch: () => Promise<{ success: boolean; message: string }>
  getFirewallKillSwitchStatus: () => Promise<{ active: boolean }>
  firewallNuclearReset: (confirmationToken: string) => Promise<{ success: boolean; message: string }>
  firewallRepairHealth: () => Promise<any>
  firewallRepairVpnteRules: () => Promise<any>
  detectForeignVpn: () => Promise<{ foreign: string | null }>
  getLocationPrivacy: () => Promise<any>
  applyLocationPrivacy: () => Promise<any>
  rollbackLocationPrivacy: () => Promise<any>
  openTunLogFolder: () => Promise<string>
  openLogFolder: () => Promise<string>
  exportDiagnostics: () => Promise<{ success: boolean; path?: string; error?: string; cancelled?: boolean }>
  runLeakSelfTest: () => Promise<LeakSelfTestResult>
  runRoutingSelfTest: () => Promise<{
    ranAt: number
    tunnelActive: boolean
    vpnIp: string | null
    directIp: string | null
    splitWorks: boolean
    smartRu: { enabled: boolean; ruHostIp: string | null; ruGoesDirect: boolean | null }
    verdict: 'ok' | 'partial' | 'leak' | 'tunnel-off' | 'inconclusive'
    message: string
  }>
  openSnapshotsFolder: () => Promise<{ success: boolean; path?: string; error?: string }>
  getTrafficForensicsStatus: () => Promise<any>
  restartTrafficForensics: () => Promise<any>
  // Config Import/Export
  configExport: () => Promise<{ success: boolean; path?: string; error?: string }>
  configBrowseImport: () => Promise<string | null>
  configImport: (filePath: string) => Promise<{ success: boolean; sections: string[]; conflicts: string[]; error?: string }>
  configImportApply: (filePath: string, sections: string[], conflictResolution: 'replace' | 'merge') => Promise<{ success: boolean; error?: string }>
  // Split Tunneling
  splitTunnelGetApps: () => Promise<any[]>
  splitTunnelGetConfig: () => Promise<any>
  splitTunnelSetRule: (appId: string, rule: 'vpn' | 'direct' | 'none') => Promise<void>
  splitTunnelAddApp: (exePath: string) => Promise<any>
  splitTunnelAddProcess: (name: string) => Promise<any>
  splitTunnelRemoveApp: (appId: string) => Promise<void>
  // Server Picker
  serversList: () => Promise<any[]>
  serversSelect: (id: string) => Promise<void>
  serversGetActive: () => Promise<{ profile: any | null; activeId: string | null }>
  serversPingAll: () => Promise<any[]>
  serversResolveIps: () => Promise<any[]>
  serversPingOne: (host: string, port: number) => Promise<number | null>
  serversVerifyActiveCountry: (ip: string) => Promise<
    | { ok: true; country: string; profile: any }
    | { ok: false; reason: string; country?: string }
  >
  serversVerifyCountry: (id: string) => Promise<
    | { ok: true; country: string; profile: any }
    | { ok: false; reason: string; country?: string }
  >
  serversAdd: (input: string, options?: { clientDevice?: ClientDevice }) => Promise<any[]>
  serversAddToGroup: (input: string, groupId: string | null, options?: { clientDevice?: ClientDevice }) => Promise<any[]>
  serversSetClientDevice: (id: string, clientDevice: ClientDevice) => Promise<any>
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
    | { ok: false; reason: string; error?: string; total?: number; skipped?: number }
  >
  serversExportAllProxiesToFile: () => Promise<
    | { ok: true; path: string; total: number; exported: number; skipped: number }
    | { ok: false; cancelled: true }
    | { ok: false; reason: string; error?: string; total?: number; skipped?: number }
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
  dnsUpdate: (id: string, patch: any) => Promise<any>
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
  domainRoutingBrowseFile: () => Promise<string | null>
  // Connection History
  connectionHistoryList: () => Promise<any[]>
  connectionHistoryFilter: (filters: any) => Promise<any[]>
  connectionHistoryStats: (period: 'day' | 'week' | 'month') => Promise<any>
  connectionHistoryExportCsv: () => Promise<string>
  connectionHistoryExportJson: () => Promise<string>
  connectionHistoryClear: () => Promise<{ success: boolean }>
  // Traffic History
  trafficHistoryList: (vpnIp?: string, scheduleEnrichment?: boolean) => Promise<any[]>
  trafficHistoryClear: () => Promise<{ success: boolean }>
  onTrafficHistoryUpdated: (callback: () => void) => () => void
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
  // External Proxy
  externalProxyStatus: (slot?: number) => Promise<ExternalProxyStatus>
  externalProxyStart: (options?: ExternalProxyStartOptions) => Promise<ExternalProxyStatus>
  externalProxyStartProfiles: (profileIds: string[]) => Promise<ExternalProxyBatchStartResult>
  externalProxyStop: (slot?: number) => Promise<ExternalProxyStatus>
  externalProxyStopAll: () => Promise<ExternalProxyStatus>
  externalProxyList: (country?: string) => Promise<ExternalProxyProfileRow[]>
  externalProxyRotate: (slot?: number) => Promise<ExternalProxyStatus>
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
  dnsLeakDetected?: boolean
  dnsLeakDetail?: string
}

const MAX_TEXT_ARG_CHARS = 4096
const MAX_VPN_INPUT_CHARS = 256 * 1024
const MAX_OBJECT_JSON_CHARS = 256 * 1024
const MAX_STRING_ARRAY_ITEMS = 500
const MAX_EXTERNAL_PROXY_SLOTS = 65535 - 17990 + 1
const MAX_EXTERNAL_PROXY_BATCH_PROFILE_IDS = 65_535

function assertString(value: unknown, name: string, maxChars = MAX_TEXT_ARG_CHARS): string {
  if (typeof value !== 'string') throw new TypeError(`${name} must be a string`)
  if (value.length > maxChars) throw new RangeError(`${name} is too large`)
  return value
}

function assertOptionalString(value: unknown, name: string, maxChars = MAX_TEXT_ARG_CHARS): string | undefined {
  if (value === undefined || value === null) return undefined
  return assertString(value, name, maxChars)
}

function assertNullableString(value: unknown, name: string, maxChars = MAX_TEXT_ARG_CHARS): string | null {
  if (value === null) return null
  return assertString(value, name, maxChars)
}

function assertBoolean(value: unknown, name: string): boolean {
  if (typeof value !== 'boolean') throw new TypeError(`${name} must be a boolean`)
  return value
}

function assertOptionalBoolean(value: unknown, name: string): boolean | undefined {
  if (value === undefined || value === null) return undefined
  return assertBoolean(value, name)
}

function assertEnum<T extends string>(value: unknown, allowed: readonly T[], name: string): T {
  if (typeof value !== 'string' || !allowed.includes(value as T)) {
    throw new TypeError(`${name} is invalid`)
  }
  return value as T
}

function assertPort(value: unknown, name: string): number | undefined {
  if (value === undefined || value === null) return undefined
  const port = Number(value)
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new TypeError(`${name} must be a valid TCP port`)
  return port
}

function assertRequiredPort(value: unknown, name: string): number {
  const port = assertPort(value, name)
  if (port === undefined) throw new TypeError(`${name} must be a valid TCP port`)
  return port
}

function assertExternalProxySlot(value: unknown): number | undefined {
  if (value === undefined || value === null) return undefined
  const slot = Number(value)
  if (!Number.isInteger(slot) || slot < 1 || slot > MAX_EXTERNAL_PROXY_SLOTS) {
    throw new RangeError(`slot must be between 1 and ${MAX_EXTERNAL_PROXY_SLOTS}`)
  }
  return slot
}

function assertExternalProxyStartOptions(value: unknown): ExternalProxyStartOptions | undefined {
  const options = assertOptionalPlainObject<Record<string, unknown>>(value, 'options')
  if (!options) return undefined
  return {
    slot: assertExternalProxySlot(options.slot),
    country: assertOptionalString(options.country, 'options.country'),
    profileId: assertOptionalString(options.profileId, 'options.profileId'),
    port: assertPort(options.port, 'options.port')
  }
}

function assertStringArray(value: unknown, name: string, maxItems = MAX_STRING_ARRAY_ITEMS): string[] {
  if (!Array.isArray(value)) throw new TypeError(`${name} must be an array`)
  if (value.length > maxItems) throw new RangeError(`${name} has too many items`)
  return value.map((item, index) => assertString(item, `${name}[${index}]`))
}

function assertPlainObject<T extends Record<string, any>>(value: unknown, name: string, maxJsonChars = MAX_OBJECT_JSON_CHARS): T {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new TypeError(`${name} must be an object`)
  const json = JSON.stringify(value)
  if (json.length > maxJsonChars) throw new RangeError(`${name} is too large`)
  return value as T
}

function assertOptionalPlainObject<T extends Record<string, any>>(value: unknown, name: string, maxJsonChars = MAX_OBJECT_JSON_CHARS): T | undefined {
  if (value === undefined || value === null) return undefined
  return assertPlainObject<T>(value, name, maxJsonChars)
}

function assertClientDevice(value: unknown): ClientDevice {
  return assertEnum(value, ['pc', 'android', 'ios', 'mac'] as const, 'clientDevice')
}

function assertClientDeviceOptions(value: unknown): { clientDevice?: ClientDevice } | undefined {
  const options = assertOptionalPlainObject<{ clientDevice?: ClientDevice }>(value, 'options')
  if (!options) return undefined
  return options.clientDevice === undefined ? {} : { clientDevice: assertClientDevice(options.clientDevice) }
}

function assertLeakOptions(value: unknown): { proxyAddr?: string; proxyType?: 'socks5' | 'http' } | undefined {
  const options = assertOptionalPlainObject<{ proxyAddr?: unknown; proxyType?: unknown }>(value, 'options')
  if (!options) return undefined
  return {
    proxyAddr: assertOptionalString(options.proxyAddr, 'options.proxyAddr'),
    proxyType: options.proxyType === undefined ? undefined : assertEnum(options.proxyType, ['socks5', 'http'] as const, 'options.proxyType')
  }
}

contextBridge.exposeInMainWorld('electronAPI', {
  detectHapp: () => ipcRenderer.invoke('detect-happ'),
  getPublicIp: () => ipcRenderer.invoke('get-public-ip'),
  recheckPublicIp: (rebaseline?: boolean) => ipcRenderer.invoke('recheck-public-ip', assertOptionalBoolean(rebaseline, 'rebaseline') === true),
  startTun: (proxyAddr: string, proxyType?: 'socks5' | 'http') =>
    ipcRenderer.invoke('start-tun', assertString(proxyAddr, 'proxyAddr'), proxyType === undefined ? undefined : assertEnum(proxyType, ['socks5', 'http'] as const, 'proxyType')),
  startDirectVpn: () => ipcRenderer.invoke('start-direct-vpn'),
  stopTun: () => ipcRenderer.invoke('stop-tun'),
  getTunStatus: () => ipcRenderer.invoke('get-tun-status'),
  getTrafficStats: () => ipcRenderer.invoke('get-traffic-stats'),
  applyAutoconfig: (targets: string[], proxyAddr: string, proxyType?: 'socks5' | 'http') =>
    ipcRenderer.invoke('apply-autoconfig', assertStringArray(targets, 'targets'), assertString(proxyAddr, 'proxyAddr'), proxyType === undefined ? undefined : assertEnum(proxyType, ['socks5', 'http'] as const, 'proxyType')),
  rollbackAutoconfig: (targets: string[]) => ipcRenderer.invoke('rollback-autoconfig', assertStringArray(targets, 'targets')),
  getAutoconfigStatus: () => ipcRenderer.invoke('get-autoconfig-status'),
  getSettings: () => ipcRenderer.invoke('get-settings'),
  saveSettings: (settings: any) => ipcRenderer.invoke('save-settings', assertPlainObject(settings, 'settings')),
  adaptiveBypassGetStatus: () => ipcRenderer.invoke('adaptive-bypass:get-status'),
  adaptiveBypassRetry: () => ipcRenderer.invoke('adaptive-bypass:retry'),
  adaptiveBypassResetLearning: () => ipcRenderer.invoke('adaptive-bypass:reset-learning'),
  smartRouteRuleSetsGetState: () => ipcRenderer.invoke('smart-route:rule-sets-state'),
  smartRouteRuleSetsRefresh: (force?: boolean) => ipcRenderer.invoke('smart-route:rule-sets-refresh', assertOptionalBoolean(force, 'force') === true),
  inspectVpnInput: (input: string) => ipcRenderer.invoke('inspect-vpn-input', assertString(input, 'input', MAX_VPN_INPUT_CHARS)),
  setLoginItem: (openAtLogin: boolean) => ipcRenderer.invoke('set-login-item', assertBoolean(openAtLogin, 'openAtLogin')),
  runLeakCheck: (options?: { proxyAddr?: string; proxyType?: 'socks5' | 'http' }) => ipcRenderer.invoke('run-leak-check', assertLeakOptions(options)),
  runSystemDiagnostics: () => ipcRenderer.invoke('run-system-diagnostics'),
  getRoutingPlan: () => ipcRenderer.invoke('get-routing-plan'),
  applyBrowserLeakProtection: () => ipcRenderer.invoke('apply-browser-leak-protection'),
  rollbackBrowserLeakProtection: () => ipcRenderer.invoke('rollback-browser-leak-protection'),
  runAutoPilot: () => ipcRenderer.invoke('run-auto-pilot'),
  repairOrphanedDns: () => ipcRenderer.invoke('network:repair-orphaned-dns'),
  rollbackAdapterLockdown: () => ipcRenderer.invoke('network:rollback-adapter-lockdown'),
  killStaleSingbox: () => ipcRenderer.invoke('tun:kill-stale-singbox'),
  logRenderer: (level: 'debug' | 'info' | 'warn' | 'error', message: string) =>
    ipcRenderer.invoke('renderer-log', assertEnum(level, ['debug', 'info', 'warn', 'error'] as const, 'level'), assertString(message, 'message', 16 * 1024)),
  getFullLogs: () => ipcRenderer.invoke('get-full-logs'),
  clearAppLog: () => ipcRenderer.invoke('clear-app-log'),
  clearDiagnosticArtifacts: () => ipcRenderer.invoke('clear-diagnostic-artifacts'),
  rollbackTunNetworkBaseline: () => ipcRenderer.invoke('rollback-tun-network-baseline'),
  disableFirewallKillSwitch: () => ipcRenderer.invoke('disable-firewall-kill-switch'),
  getFirewallKillSwitchStatus: () => ipcRenderer.invoke('get-firewall-kill-switch-status'),
  firewallNuclearReset: (confirmationToken: string) => ipcRenderer.invoke('firewall:nuclear-reset', assertString(confirmationToken, 'confirmationToken', 80)),
  firewallRepairHealth: () => ipcRenderer.invoke('firewall:repair-health'),
  firewallRepairVpnteRules: () => ipcRenderer.invoke('firewall:repair-vpnte-rules'),
  detectForeignVpn: () => ipcRenderer.invoke('system:detect-foreign-vpn'),
  getLocationPrivacy: () => ipcRenderer.invoke('get-location-privacy'),
  applyLocationPrivacy: () => ipcRenderer.invoke('apply-location-privacy'),
  rollbackLocationPrivacy: () => ipcRenderer.invoke('rollback-location-privacy'),
  openTunLogFolder: () => ipcRenderer.invoke('open-tun-log-folder'),
  openLogFolder: () => ipcRenderer.invoke('open-log-folder'),
  exportDiagnostics: () => ipcRenderer.invoke('export-diagnostics'),
  runLeakSelfTest: () => ipcRenderer.invoke('run-leak-self-test'),
  runRoutingSelfTest: () => ipcRenderer.invoke('run-routing-self-test'),
  openSnapshotsFolder: () => ipcRenderer.invoke('open-snapshots-folder'),
  getTrafficForensicsStatus: () => ipcRenderer.invoke('get-traffic-forensics-status'),
  restartTrafficForensics: () => ipcRenderer.invoke('restart-traffic-forensics'),
  // Split Tunneling
  splitTunnelGetApps: () => ipcRenderer.invoke('split-tunnel:get-apps'),
  splitTunnelGetConfig: () => ipcRenderer.invoke('split-tunnel:get-config'),
  splitTunnelSetRule: (appId: string, rule: 'vpn' | 'direct' | 'none') =>
    ipcRenderer.invoke('split-tunnel:set-rule', assertString(appId, 'appId'), assertEnum(rule, ['vpn', 'direct', 'none'] as const, 'rule')),
  splitTunnelAddApp: (exePath: string) => ipcRenderer.invoke('split-tunnel:add-app', assertString(exePath, 'exePath')),
  splitTunnelAddProcess: (name: string) => ipcRenderer.invoke('split-tunnel:add-process', assertString(name, 'name')),
  splitTunnelRemoveApp: (appId: string) => ipcRenderer.invoke('split-tunnel:remove-app', assertString(appId, 'appId')),
  // Server Picker
  serversList: () => ipcRenderer.invoke('servers:list'),
  serversSelect: (id: string) => ipcRenderer.invoke('servers:select', assertString(id, 'id')),
  serversGetActive: () => ipcRenderer.invoke('servers:get-active'),
  serversPingAll: () => ipcRenderer.invoke('servers:ping-all'),
  serversResolveIps: () => ipcRenderer.invoke('servers:resolve-ips'),
  serversPingOne: (host: string, port: number) => ipcRenderer.invoke('servers:ping-one', assertString(host, 'host'), assertRequiredPort(port, 'port')),
  serversVerifyActiveCountry: (ip: string) => ipcRenderer.invoke('servers:verify-active-country', assertString(ip, 'ip')),
  serversVerifyCountry: (id: string) => ipcRenderer.invoke('servers:verify-country', assertString(id, 'id')),
  serversAdd: (input: string, options?: { clientDevice?: ClientDevice }) => ipcRenderer.invoke('servers:add', assertString(input, 'input', MAX_VPN_INPUT_CHARS), assertClientDeviceOptions(options)),
  serversAddToGroup: (input: string, groupId: string | null, options?: { clientDevice?: ClientDevice }) =>
    ipcRenderer.invoke('servers:add-to-group', assertString(input, 'input', MAX_VPN_INPUT_CHARS), assertNullableString(groupId, 'groupId'), assertClientDeviceOptions(options)),
  serversSetClientDevice: (id: string, clientDevice: ClientDevice) => ipcRenderer.invoke('servers:set-client-device', assertString(id, 'id'), assertClientDevice(clientDevice)),
  serversRemove: (id: string) => ipcRenderer.invoke('servers:remove', assertString(id, 'id')),
  serversExportKey: (id: string) => ipcRenderer.invoke('servers:export-key', assertString(id, 'id')),
  serversExportKeyToFile: (id: string) => ipcRenderer.invoke('servers:export-key-file', assertString(id, 'id')),
  serversExportAllKeysToFile: () => ipcRenderer.invoke('servers:export-all-keys-file'),
  serversExportAllProxiesToFile: () => ipcRenderer.invoke('servers:export-all-proxies-file'),
  // Server Groups — origin tracking and post-trial-aware refresh.
  groupsList: () => ipcRenderer.invoke('groups:list'),
  groupsGet: (id: string) => ipcRenderer.invoke('groups:get', assertString(id, 'id')),
  groupsRename: (id: string, name: string) => ipcRenderer.invoke('groups:rename', assertString(id, 'id'), assertString(name, 'name')),
  groupsDelete: (id: string, deleteServers: boolean) => ipcRenderer.invoke('groups:delete', assertString(id, 'id'), assertBoolean(deleteServers, 'deleteServers')),
  groupsRefresh: (id: string) => ipcRenderer.invoke('groups:refresh', assertString(id, 'id')),
  groupsCheckHealth: (id: string) => ipcRenderer.invoke('groups:check-health', assertString(id, 'id')),
  serverProbe: (host: string, knownPort?: number) => ipcRenderer.invoke('server:probe', assertString(host, 'host'), assertPort(knownPort, 'knownPort')),
  // URL Availability — paste a link, get verdict + diagnostics for both
  // the tunnel path and the direct path (clash-direct-out when VPN is on).
  urlAvailabilityCheck: (url: string) => ipcRenderer.invoke('url-availability:check', assertString(url, 'url', MAX_VPN_INPUT_CHARS)),
  urlAvailabilityHistory: () => ipcRenderer.invoke('url-availability:history'),
  urlAvailabilityClearHistory: () => ipcRenderer.invoke('url-availability:clear-history'),
  // Scheduler
  schedulerList: () => ipcRenderer.invoke('scheduler:list'),
  schedulerCreate: (entry: any) => ipcRenderer.invoke('scheduler:create', assertPlainObject(entry, 'entry')),
  schedulerUpdate: (id: string, patch: any) => ipcRenderer.invoke('scheduler:update', assertString(id, 'id'), assertPlainObject(patch, 'patch')),
  schedulerDelete: (id: string) => ipcRenderer.invoke('scheduler:delete', assertString(id, 'id')),
  schedulerNextEvent: () => ipcRenderer.invoke('scheduler:next-event'),
  // Kill-Switch
  killSwitchGetLevel: () => ipcRenderer.invoke('kill-switch:get-level'),
  killSwitchSetLevel: (level: 'off' | 'standard' | 'strict') => ipcRenderer.invoke('kill-switch:set-level', assertEnum(level, ['off', 'standard', 'strict'] as const, 'level')),
  killSwitchGetExceptions: () => ipcRenderer.invoke('kill-switch:get-exceptions'),
  killSwitchAddException: (exception: { type: 'app' | 'ip'; value: string; label: string }) => ipcRenderer.invoke('kill-switch:add-exception', assertPlainObject(exception, 'exception')),
  killSwitchRemoveException: (id: string) => ipcRenderer.invoke('kill-switch:remove-exception', assertString(id, 'id')),
  killSwitchBrowseApp: () => ipcRenderer.invoke('kill-switch:browse-app'),
  // Profile Rotation
  rotationGetConfig: () => ipcRenderer.invoke('rotation:get-config'),
  rotationSetConfig: (config: any) => ipcRenderer.invoke('rotation:set-config', assertPlainObject(config, 'config')),
  rotationRotateNow: () => ipcRenderer.invoke('rotation:rotate-now'),
  // DNS Profiles
  dnsList: () => ipcRenderer.invoke('dns:list'),
  dnsCreate: (profile: { name: string; primary: string; secondary: string; type: 'plain' | 'doh' | 'dot' }) => ipcRenderer.invoke('dns:create', assertPlainObject(profile, 'profile')),
  dnsUpdate: (id: string, patch: any) => ipcRenderer.invoke('dns:update', assertString(id, 'id'), assertPlainObject(patch, 'patch')),
  dnsDelete: (id: string) => ipcRenderer.invoke('dns:delete', assertString(id, 'id')),
  dnsSelect: (id: string) => ipcRenderer.invoke('dns:select', assertString(id, 'id')),
  dnsValidate: (address: string) => ipcRenderer.invoke('dns:validate', assertString(address, 'address')),
  // Domain Routing
  domainRoutingList: () => ipcRenderer.invoke('domain-routing:list'),
  domainRoutingAdd: (rule: { pattern: string; action: 'vpn' | 'direct' | 'block'; priority: number }) => ipcRenderer.invoke('domain-routing:add', assertPlainObject(rule, 'rule')),
  domainRoutingUpdate: (id: string, patch: any) => ipcRenderer.invoke('domain-routing:update', assertString(id, 'id'), assertPlainObject(patch, 'patch')),
  domainRoutingDelete: (id: string) => ipcRenderer.invoke('domain-routing:delete', assertString(id, 'id')),
  domainRoutingReorder: (ids: string[]) => ipcRenderer.invoke('domain-routing:reorder', assertStringArray(ids, 'ids')),
  domainRoutingImport: (filePath: string) => ipcRenderer.invoke('domain-routing:import', assertString(filePath, 'filePath')),
  domainRoutingBrowseFile: () => ipcRenderer.invoke('domain-routing:browse-file'),
  // Connection History
  connectionHistoryList: () => ipcRenderer.invoke('connection-history:list'),
  connectionHistoryFilter: (filters: any) => ipcRenderer.invoke('connection-history:filter', assertPlainObject(filters, 'filters')),
  connectionHistoryStats: (period: 'day' | 'week' | 'month') => ipcRenderer.invoke('connection-history:stats', assertEnum(period, ['day', 'week', 'month'] as const, 'period')),
  connectionHistoryExportCsv: () => ipcRenderer.invoke('connection-history:export-csv'),
  connectionHistoryExportJson: () => ipcRenderer.invoke('connection-history:export-json'),
  connectionHistoryClear: () => ipcRenderer.invoke('connection-history:clear'),
  // Traffic History
  trafficHistoryList: (vpnIp?: string, scheduleEnrichment?: boolean) => ipcRenderer.invoke(
    'traffic-history:list',
    assertOptionalString(vpnIp, 'vpnIp'),
    assertOptionalBoolean(scheduleEnrichment, 'scheduleEnrichment') === true
  ),
  trafficHistoryClear: () => ipcRenderer.invoke('traffic-history:clear'),
  onTrafficHistoryUpdated: (callback: () => void) => {
    const listener = () => callback()
    ipcRenderer.on('traffic-history:enrichment-updated', listener)
    return () => ipcRenderer.removeListener('traffic-history:enrichment-updated', listener)
  },
  // Config Import/Export
  configExport: () => ipcRenderer.invoke('config:export'),
  configBrowseImport: () => ipcRenderer.invoke('config:browse-import'),
  configImport: (filePath: string) => ipcRenderer.invoke('config:import', assertString(filePath, 'filePath')),
  configImportApply: (filePath: string, sections: string[], conflictResolution: 'replace' | 'merge') =>
    ipcRenderer.invoke('config:import-apply', assertString(filePath, 'filePath'), assertStringArray(sections, 'sections'), assertEnum(conflictResolution, ['replace', 'merge'] as const, 'conflictResolution')),
  // Notification Preferences
  notificationsGetPrefs: () => ipcRenderer.invoke('notifications:get-prefs'),
  notificationsSetPrefs: (prefs: any) => ipcRenderer.invoke('notifications:set-prefs', assertPlainObject(prefs, 'prefs')),
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
  i18nSetLocale: (locale: string) => ipcRenderer.invoke('i18n:set-locale', assertString(locale, 'locale')),
  i18nGetSystemLocale: () => ipcRenderer.invoke('i18n:get-system-locale'),
  // Theme
  themeList: () => ipcRenderer.invoke('theme:list'),
  themeGetActive: () => ipcRenderer.invoke('theme:get-active'),
  themeSetActive: (id: string) => ipcRenderer.invoke('theme:set-active', assertString(id, 'id')),
  themeCreate: (theme: any) => ipcRenderer.invoke('theme:create', assertPlainObject(theme, 'theme')),
  themeDelete: (id: string) => ipcRenderer.invoke('theme:delete', assertString(id, 'id')),
  onThemeChanged: (callback: (theme: any) => void) => {
    const handler = (_event: any, theme: any) => callback(theme)
    ipcRenderer.on('theme-changed', handler)
    return () => ipcRenderer.removeListener('theme-changed', handler)
  },
  onServerActiveChanged: (callback: (data: { profileId: string; profileName: string; nextProfileId?: string }) => void) => {
    const handler = (_event: any, data: any) => callback(data)
    ipcRenderer.on('server-active-changed', handler)
    return () => ipcRenderer.removeListener('server-active-changed', handler)
  },
  onKillSwitchTrafficBlocked: (callback: (data: { reason: string; steps?: string[] }) => void) => {
    const handler = (_event: any, data: any) => callback(data)
    ipcRenderer.on('kill-switch:traffic-blocked', handler)
    return () => ipcRenderer.removeListener('kill-switch:traffic-blocked', handler)
  },
  onI18nLocaleChanged: (callback: (locale: string) => void) => {
    const handler = (_event: any, locale: string) => callback(locale)
    ipcRenderer.on('i18n:locale-changed', handler)
    return () => ipcRenderer.removeListener('i18n:locale-changed', handler)
  },
  // Speed Test
  speedTestRun: () => ipcRenderer.invoke('speed-test:run'),
  speedTestHistory: () => ipcRenderer.invoke('speed-test:history'),
  onSpeedTestProgress: (callback: (data: { percent: number; phase: string }) => void) => {
    const handler = (_event: any, data: { percent: number; phase: string }) => callback(data)
    ipcRenderer.on('speed-test:progress', handler)
    return () => ipcRenderer.removeListener('speed-test:progress', handler)
  },
  // External Proxy
  externalProxyStatus: (slot?: number) => ipcRenderer.invoke('external-proxy:status', assertExternalProxySlot(slot)),
  externalProxyStart: (options?: ExternalProxyStartOptions) => ipcRenderer.invoke('external-proxy:start', assertExternalProxyStartOptions(options)),
  externalProxyStartProfiles: (profileIds: string[]) => ipcRenderer.invoke(
    'external-proxy:start-profiles',
    assertStringArray(profileIds, 'profileIds', MAX_EXTERNAL_PROXY_BATCH_PROFILE_IDS)
  ),
  externalProxyStop: (slot?: number) => ipcRenderer.invoke('external-proxy:stop', assertExternalProxySlot(slot)),
  externalProxyStopAll: () => ipcRenderer.invoke('external-proxy:stop-all'),
  externalProxyList: (country?: string) => ipcRenderer.invoke('external-proxy:list', assertOptionalString(country, 'country')),
  externalProxyRotate: (slot?: number) => ipcRenderer.invoke('external-proxy:rotate', assertExternalProxySlot(slot)),
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
