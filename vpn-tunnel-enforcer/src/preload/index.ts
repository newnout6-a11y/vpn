import type { PublicIpInfo } from '../shared/publicIp'
import { contextBridge, ipcRenderer } from 'electron'
import { assertIpcRequest, type IpcChannel, type IpcRequest, type IpcResponse } from '../shared/ipc-contract'
import { unwrapIpcResult, IpcRemoteError, ipcError, type IpcErrorLocale } from '../shared/ipc-result'
import type {
  ClientDevice,
  ExternalProxyStartOptions,
  LiveCheckProgress,
  LiveServerBatchCheckOptions,
  LiveServerBatchCheckProgress,
  LiveServerBatchCheckResult,
  LiveServerCheckOptions
} from '../shared/ipc-types'

import type { ElectronAPI, TrafficStats, LeakSelfTestResult } from '../shared/electron-api'
export type { ElectronAPI, TrafficStats, LeakSelfTestAdapter, LeakSelfTestResult } from '../shared/electron-api'

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

function assertInteger(value: unknown, name: string): number {
  if (!Number.isInteger(value)) throw new TypeError(`${name} must be an integer`)
  return value as number
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

function assertLiveCheckOptions(value: unknown): LiveServerCheckOptions {
  const options = assertPlainObject<Record<string, unknown>>(value, 'options')
  const mode = options.mode !== undefined ? assertEnum(options.mode, ['basic', 'extended'] as const, 'options.mode') : undefined
  return {
    requestId: assertOptionalString(options.requestId, 'options.requestId'),
    profileId: assertOptionalString(options.profileId, 'options.profileId'),
    host: assertOptionalString(options.host, 'options.host'),
    port: assertPort(options.port, 'options.port'),
    mode
  }
}

let ipcLocale: IpcErrorLocale = typeof navigator !== 'undefined' && navigator.language?.startsWith('ru') ? 'ru' : 'en'
function rememberIpcLocale(locale: unknown): void { if (locale === 'en' || locale === 'ru') ipcLocale = locale }

function invoke<C extends IpcChannel>(channel: C, ...args: IpcRequest<C>): Promise<IpcResponse<C>> {
  assertIpcRequest(channel, args)
  return ipcRenderer.invoke(channel, ...args).then(
    response => unwrapIpcResult<IpcResponse<C>>(response, ipcLocale),
    () => { throw new IpcRemoteError(ipcError('internal', ipcLocale)) }
  )
}

contextBridge.exposeInMainWorld('electronAPI', {
  detectHapp: () => invoke('detect-happ'),
  getPublicIp: () => invoke('get-public-ip'),
  recheckPublicIp: (rebaseline?: boolean) => invoke('recheck-public-ip', assertOptionalBoolean(rebaseline, 'rebaseline') === true),
  startTun: (proxyAddr: string, proxyType?: 'socks5' | 'http') =>
    invoke('start-tun', assertString(proxyAddr, 'proxyAddr'), proxyType === undefined ? undefined : assertEnum(proxyType, ['socks5', 'http'] as const, 'proxyType')),
  startDirectVpn: () => invoke('start-direct-vpn'),
  stopTun: () => invoke('stop-tun'),
  cancelTun: () => invoke('cancel-tun'),
  cancelTransition: () => invoke('cancel-transition'),
  getTunStatus: () => invoke('get-tun-status'),
  getTrafficStats: () => invoke('get-traffic-stats'),
  applyAutoconfig: (targets: string[], proxyAddr: string, proxyType?: 'socks5' | 'http') =>
    invoke('apply-autoconfig', assertStringArray(targets, 'targets'), assertString(proxyAddr, 'proxyAddr'), proxyType === undefined ? undefined : assertEnum(proxyType, ['socks5', 'http'] as const, 'proxyType')),
  rollbackAutoconfig: (targets: string[]) => invoke('rollback-autoconfig', assertStringArray(targets, 'targets')),
  getAutoconfigStatus: () => invoke('get-autoconfig-status'),
  getSettings: () => invoke('get-settings'),
  saveSettings: (settings: any) => invoke('save-settings', assertPlainObject(settings, 'settings')),
  adaptiveBypassGetStatus: () => invoke('adaptive-bypass:get-status'),
  adaptiveBypassRetry: () => invoke('adaptive-bypass:retry'),
  adaptiveBypassResetLearning: () => invoke('adaptive-bypass:reset-learning'),
  smartRouteRuleSetsGetState: () => invoke('smart-route:rule-sets-state'),
  smartRouteRuleSetsRefresh: (force?: boolean) => invoke('smart-route:rule-sets-refresh', assertOptionalBoolean(force, 'force') === true),
  inspectVpnInput: (input: string) => invoke('inspect-vpn-input', assertString(input, 'input', MAX_VPN_INPUT_CHARS)),
  setLoginItem: (openAtLogin: boolean) => invoke('set-login-item', assertBoolean(openAtLogin, 'openAtLogin')),
  runLeakCheck: (options?: { proxyAddr?: string; proxyType?: 'socks5' | 'http' }) => invoke('run-leak-check', assertLeakOptions(options)),
  runSystemDiagnostics: () => invoke('run-system-diagnostics'),
  getRoutingPlan: () => invoke('get-routing-plan'),
  applyBrowserLeakProtection: () => invoke('apply-browser-leak-protection'),
  rollbackBrowserLeakProtection: () => invoke('rollback-browser-leak-protection'),
  runAutoPilot: () => invoke('run-auto-pilot'),
  repairOrphanedDns: () => invoke('network:repair-orphaned-dns'),
  rollbackAdapterLockdown: () => invoke('network:rollback-adapter-lockdown'),
  killStaleSingbox: () => invoke('tun:kill-stale-singbox'),
  logRenderer: (level: 'debug' | 'info' | 'warn' | 'error', message: string) =>
    invoke('renderer-log', assertEnum(level, ['debug', 'info', 'warn', 'error'] as const, 'level'), assertString(message, 'message', 16 * 1024)),
  getFullLogs: () => invoke('get-full-logs'),
  clearAppLog: () => invoke('clear-app-log'),
  clearDiagnosticArtifacts: () => invoke('clear-diagnostic-artifacts'),
  rollbackTunNetworkBaseline: () => invoke('rollback-tun-network-baseline'),
  disableFirewallKillSwitch: () => invoke('disable-firewall-kill-switch'),
  getFirewallKillSwitchStatus: () => invoke('get-firewall-kill-switch-status'),
  firewallNuclearReset: (confirmationToken: string) => invoke('firewall:nuclear-reset', assertString(confirmationToken, 'confirmationToken', 80)),
  firewallRepairHealth: () => invoke('firewall:repair-health'),
  firewallRepairVpnteRules: () => invoke('firewall:repair-vpnte-rules'),
  detectForeignVpn: () => invoke('system:detect-foreign-vpn'),
  getLocationPrivacy: () => invoke('get-location-privacy'),
  applyLocationPrivacy: () => invoke('apply-location-privacy'),
  rollbackLocationPrivacy: () => invoke('rollback-location-privacy'),
  openTunLogFolder: () => invoke('open-tun-log-folder'),
  openLogFolder: () => invoke('open-log-folder'),
  exportDiagnostics: () => invoke('export-diagnostics'),
  runLeakSelfTest: () => invoke('run-leak-self-test'),
  runRoutingSelfTest: () => invoke('run-routing-self-test'),
  openSnapshotsFolder: () => invoke('open-snapshots-folder'),
  getTrafficForensicsStatus: () => invoke('get-traffic-forensics-status'),
  restartTrafficForensics: () => invoke('restart-traffic-forensics'),
  // Split Tunneling
  splitTunnelGetApps: () => invoke('split-tunnel:get-apps'),
  splitTunnelRefreshApps: () => invoke('split-tunnel:refresh-apps'),
  splitTunnelGetConfig: () => invoke('split-tunnel:get-config'),
  splitTunnelSetRule: (appId: string, rule: 'vpn' | 'direct' | 'none') =>
    invoke('split-tunnel:set-rule', assertString(appId, 'appId'), assertEnum(rule, ['vpn', 'direct', 'none'] as const, 'rule')),
  splitTunnelAddApp: (exePath: string) => invoke('split-tunnel:add-app', assertString(exePath, 'exePath')),
  splitTunnelAddProcess: (name: string) => invoke('split-tunnel:add-process', assertString(name, 'name')),
  splitTunnelRemoveApp: (appId: string) => invoke('split-tunnel:remove-app', assertString(appId, 'appId')),
  // Server Picker
  serversList: () => invoke('servers:list'),
  serversSelect: (id: string) => invoke('servers:select', assertString(id, 'id')),
  serversCancelSwitch: () => invoke('servers:cancel-switch'),
  serversGetActive: () => invoke('servers:get-active'),
  serversPingAll: () => invoke('servers:ping-all'),
  serversResolveIps: () => invoke('servers:resolve-ips'),
  serversPingOne: (host: string, port: number) => invoke('servers:ping-one', assertString(host, 'host'), assertRequiredPort(port, 'port')),
  serversVerifyActiveCountry: (ip: string) => invoke('servers:verify-active-country', assertString(ip, 'ip')),
  serversVerifyCountry: (id: string) => invoke('servers:verify-country', assertString(id, 'id')),
  serversAdd: (input: string, options?: { clientDevice?: ClientDevice }) => invoke('servers:add', assertString(input, 'input', MAX_VPN_INPUT_CHARS), assertClientDeviceOptions(options)),
  serversAddToGroup: (input: string, groupId: string | null, options?: { clientDevice?: ClientDevice }) =>
    invoke('servers:add-to-group', assertString(input, 'input', MAX_VPN_INPUT_CHARS), assertNullableString(groupId, 'groupId'), assertClientDeviceOptions(options)),
  serversSetClientDevice: (id: string, clientDevice: ClientDevice) => invoke('servers:set-client-device', assertString(id, 'id'), assertClientDevice(clientDevice)),
  serversRemove: (id: string) => invoke('servers:remove', assertString(id, 'id')),
  serversCopyKey: (id: string) => invoke('servers:copy-key', assertString(id, 'id')),
  serversExportKey: (id: string) => invoke('servers:export-key', assertString(id, 'id')),
  serversExportKeyToFile: (id: string) => invoke('servers:export-key-file', assertString(id, 'id')),
  serversExportAllKeysToFile: () => invoke('servers:export-all-keys-file'),
  serversExportAllProxiesToFile: () => invoke('servers:export-all-proxies-file'),
  // Server Groups — origin tracking and post-trial-aware refresh.
  groupsList: () => invoke('groups:list'),
  groupsGet: (id: string) => invoke('groups:get', assertString(id, 'id')),
  groupsRename: (id: string, name: string) => invoke('groups:rename', assertString(id, 'id'), assertString(name, 'name')),
  groupsDelete: (id: string, deleteServers: boolean) => invoke('groups:delete', assertString(id, 'id'), assertBoolean(deleteServers, 'deleteServers')),
  groupsRefresh: (id: string) => invoke('groups:refresh', assertString(id, 'id')),
  groupsSetRefreshPolicy: (id: string, intervalMinutes: number | null) =>
    invoke('groups:set-refresh-policy', assertString(id, 'id'), intervalMinutes === null ? null : assertInteger(intervalMinutes, 'intervalMinutes')),
  groupsCheckHealth: (id: string) => invoke('groups:check-health', assertString(id, 'id')),
  serverProbe: (host: string, knownPort?: number) => invoke('server:probe', assertString(host, 'host'), assertPort(knownPort, 'knownPort')),
  serverLiveCheck: (options: LiveServerCheckOptions) =>
    invoke('server:live-check', assertLiveCheckOptions(options)),
  serverLiveCheckBatch: (options: LiveServerBatchCheckOptions) => {
    const checked = assertPlainObject<Record<string, unknown>>(options, 'options')
    if (!Array.isArray(checked.profileIds)) throw new TypeError('options.profileIds must be an array')
    const profileIds = assertStringArray(checked.profileIds, 'options.profileIds')
    if (profileIds.length < 1 || profileIds.length > 12) {
      throw new RangeError('options.profileIds must contain between 1 and 12 profiles')
    }
    return invoke('server:live-check-batch', {
      requestId: assertOptionalString(checked.requestId, 'options.requestId'),
      profileIds,
      mode: checked.mode === undefined
        ? undefined
        : assertEnum(checked.mode, ['basic', 'extended'] as const, 'options.mode')
    }) as Promise<LiveServerBatchCheckResult>
  },
  serverLiveCheckCancel: (requestId?: string) =>
    invoke('server:live-check-cancel', assertOptionalString(requestId, 'requestId')),
  serverLiveCheckHistory: (filter?: { profileId?: string; host?: string }) =>
    invoke('server:live-check-history', assertOptionalPlainObject(filter, 'filter')),
  onLiveCheckProgress: (callback: (progress: LiveCheckProgress) => void) => {
    const handler = (_event: any, data: LiveCheckProgress) => callback(data)
    ipcRenderer.on('server:live-check-progress', handler)
    return () => ipcRenderer.removeListener('server:live-check-progress', handler)
  },
  onLiveBatchCheckProgress: (callback: (progress: LiveServerBatchCheckProgress) => void) => {
    const handler = (_event: any, data: LiveServerBatchCheckProgress) => callback(data)
    ipcRenderer.on('server:live-check-batch-progress', handler)
    return () => ipcRenderer.removeListener('server:live-check-batch-progress', handler)
  },
  // URL Availability — paste a link, get verdict + diagnostics for both
  // the tunnel path and the direct path (clash-direct-out when VPN is on).
  urlAvailabilityCheck: (url: string) => invoke('url-availability:check', assertString(url, 'url', MAX_VPN_INPUT_CHARS)),
  urlAvailabilityHistory: () => invoke('url-availability:history'),
  urlAvailabilityClearHistory: () => invoke('url-availability:clear-history'),
  // Scheduler
  schedulerList: () => invoke('scheduler:list'),
  schedulerCreate: (entry: any) => invoke('scheduler:create', assertPlainObject(entry, 'entry')),
  schedulerUpdate: (id: string, patch: any) => invoke('scheduler:update', assertString(id, 'id'), assertPlainObject(patch, 'patch')),
  schedulerDelete: (id: string) => invoke('scheduler:delete', assertString(id, 'id')),
  schedulerNextEvent: () => invoke('scheduler:next-event'),
  // Kill-Switch
  killSwitchGetLevel: () => invoke('kill-switch:get-level'),
  killSwitchSetLevel: (level: 'off' | 'standard' | 'strict') => invoke('kill-switch:set-level', assertEnum(level, ['off', 'standard', 'strict'] as const, 'level')),
  killSwitchGetExceptions: () => invoke('kill-switch:get-exceptions'),
  killSwitchAddException: (exception: { type: 'app' | 'ip'; value: string; label: string }) => invoke('kill-switch:add-exception', assertPlainObject(exception, 'exception')),
  killSwitchRemoveException: (id: string) => invoke('kill-switch:remove-exception', assertString(id, 'id')),
  killSwitchBrowseApp: () => invoke('kill-switch:browse-app'),
  // Profile Rotation
  rotationGetConfig: () => invoke('rotation:get-config'),
  rotationSetConfig: (config: any) => invoke('rotation:set-config', assertPlainObject(config, 'config')),
  rotationRotateNow: () => invoke('rotation:rotate-now'),
  // DNS Profiles
  dnsList: () => invoke('dns:list'),
  dnsGetActive: () => invoke('dns:get-active'),
  dnsCreate: (profile: { name: string; primary: string; secondary: string; type: 'plain' | 'doh' | 'dot'; primaryType?: 'plain' | 'doh' | 'dot'; secondaryType?: 'plain' | 'doh' | 'dot' }) => invoke('dns:create', assertPlainObject(profile, 'profile')),
  dnsUpdate: (id: string, patch: any) => invoke('dns:update', assertString(id, 'id'), assertPlainObject(patch, 'patch')),
  dnsDelete: (id: string) => invoke('dns:delete', assertString(id, 'id')),
  dnsSelect: (id: string) => invoke('dns:select', assertString(id, 'id')),
  dnsValidate: (address: string) => invoke('dns:validate', assertString(address, 'address')),
  // Domain Routing
  domainRoutingList: () => invoke('domain-routing:list'),
  domainRoutingAdd: (rule: { pattern: string; action: 'vpn' | 'direct' | 'block'; priority: number }) => invoke('domain-routing:add', assertPlainObject(rule, 'rule')),
  domainRoutingUpdate: (id: string, patch: any) => invoke('domain-routing:update', assertString(id, 'id'), assertPlainObject(patch, 'patch')),
  domainRoutingDelete: (id: string) => invoke('domain-routing:delete', assertString(id, 'id')),
  domainRoutingReorder: (ids: string[]) => invoke('domain-routing:reorder', assertStringArray(ids, 'ids')),
  domainRoutingImport: (filePath: string) => invoke('domain-routing:import', assertString(filePath, 'filePath')),
  domainRoutingBrowseFile: () => invoke('domain-routing:browse-file'),
  // Connection History
  connectionHistoryList: () => invoke('connection-history:list'),
  connectionHistoryFilter: (filters: any) => invoke('connection-history:filter', assertPlainObject(filters, 'filters')),
  connectionHistoryStats: (period: 'day' | 'week' | 'month') => invoke('connection-history:stats', assertEnum(period, ['day', 'week', 'month'] as const, 'period')),
  connectionHistoryExportCsv: () => invoke('connection-history:export-csv'),
  connectionHistoryExportJson: () => invoke('connection-history:export-json'),
  connectionHistoryClear: () => invoke('connection-history:clear'),
  // Traffic History
  trafficHistoryList: (vpnIp?: string, scheduleEnrichment?: boolean) => invoke(
    'traffic-history:list',
    assertOptionalString(vpnIp, 'vpnIp'),
    assertOptionalBoolean(scheduleEnrichment, 'scheduleEnrichment') === true
  ),
  trafficHistoryClear: () => invoke('traffic-history:clear'),
  onTrafficHistoryUpdated: (callback: () => void) => {
    const listener = () => callback()
    ipcRenderer.on('traffic-history:enrichment-updated', listener)
    return () => ipcRenderer.removeListener('traffic-history:enrichment-updated', listener)
  },
  // Config Import/Export
  configExport: (mode = 'redacted') => invoke('config:export', assertEnum(mode, ['redacted', 'secrets'] as const, 'mode')),
  configBrowseImport: () => invoke('config:browse-import'),
  configImport: (filePath: string) => invoke('config:import', assertString(filePath, 'filePath')),
  configImportApply: (filePath: string, sections: string[], conflictResolution: 'replace' | 'merge') =>
    invoke('config:import-apply', assertString(filePath, 'filePath'), assertStringArray(sections, 'sections'), assertEnum(conflictResolution, ['replace', 'merge'] as const, 'conflictResolution')),
  // Notification Preferences
  notificationsGetPrefs: () => invoke('notifications:get-prefs'),
  notificationsSetPrefs: (prefs: any) => invoke('notifications:set-prefs', assertPlainObject(prefs, 'prefs')),
  checkOsNotificationState: () => invoke('notifications:check-os-state'),
  // Clear the Windows-side notification block (registry "Enabled = 0" set
  // when the user clicked "Don't show notifications" on a toast). Returns
  // a structured ok/error shape — never throws.
  notificationsResetOsBlock: () => invoke('notifications:reset-os-block'),
  notificationsOpenWindowsSettings: () => invoke('notifications:open-windows-settings'),
  // In-app notification fallback: fired when notify() can't deliver an OS
  // toast (Windows blocks us, or platform unsupported). Returns an
  // unsubscribe handle.
  onInAppNotification: (callback: (data: { level: 'info' | 'warn' | 'error'; title: string; body: string; ts: number }) => void) => {
    const handler = (_event: any, data: { level: 'info' | 'warn' | 'error'; title: string; body: string; ts: number }) => callback(data)
    ipcRenderer.on('inapp-notification', handler)
    return () => ipcRenderer.removeListener('inapp-notification', handler)
  },
  // Main registers these after installing the IPC boundary. Renderer flips
  // them when TUN status moves
  // to 'stopping'/'stopped' to silence false-positive leak events.
  ipMonitorSuspend: () => invoke('ip-monitor:suspend'),
  ipMonitorResume: () => invoke('ip-monitor:resume'),
  // i18n
  i18nGetLocale: () => invoke('i18n:get-locale').then(locale => { rememberIpcLocale(locale); return locale }),
  i18nSetLocale: (locale: string) => invoke('i18n:set-locale', assertString(locale, 'locale')).then(result => { rememberIpcLocale(locale); return result }),
  i18nGetSystemLocale: () => invoke('i18n:get-system-locale'),
  // Theme
  themeList: () => invoke('theme:list'),
  themeGetActive: () => invoke('theme:get-active'),
  themeSetActive: (id: string) => invoke('theme:set-active', assertString(id, 'id')),
  themeCreate: (theme: any) => invoke('theme:create', assertPlainObject(theme, 'theme')),
  themeDelete: (id: string) => invoke('theme:delete', assertString(id, 'id')),
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
    const handler = (_event: any, locale: string) => { rememberIpcLocale(locale); callback(locale) }
    ipcRenderer.on('i18n:locale-changed', handler)
    return () => ipcRenderer.removeListener('i18n:locale-changed', handler)
  },
  // Speed Test
  speedTestRun: () => invoke('speed-test:run'),
  speedTestHistory: () => invoke('speed-test:history'),
  onSpeedTestProgress: (callback: (data: { percent: number; phase: string }) => void) => {
    const handler = (_event: any, data: { percent: number; phase: string }) => callback(data)
    ipcRenderer.on('speed-test:progress', handler)
    return () => ipcRenderer.removeListener('speed-test:progress', handler)
  },
  // External Proxy
  externalProxyStatus: (slot?: number) => invoke('external-proxy:status', assertExternalProxySlot(slot)),
  externalProxyStart: (options?: ExternalProxyStartOptions) => invoke('external-proxy:start', assertExternalProxyStartOptions(options)),
  externalProxyStartProfiles: (profileIds: string[]) => invoke(
    'external-proxy:start-profiles',
    assertStringArray(profileIds, 'profileIds', MAX_EXTERNAL_PROXY_BATCH_PROFILE_IDS)
  ),
  externalProxyStop: (slot?: number) => invoke('external-proxy:stop', assertExternalProxySlot(slot)),
  externalProxyStopAll: () => invoke('external-proxy:stop-all'),
  externalProxyList: (country?: string) => invoke('external-proxy:list', assertOptionalString(country, 'country')),
  externalProxyRotate: (slot?: number) => invoke('external-proxy:rotate', assertExternalProxySlot(slot)),
  // Event listeners
  onIpChanged: (callback: (data: PublicIpInfo) => void) => {
    const handler = (_event: any, data: PublicIpInfo) => callback(data)
    ipcRenderer.on('ip-changed', handler)
    return () => ipcRenderer.removeListener('ip-changed', handler)
  },
  onTunStatusChanged: (callback: (status: string) => void) => {
    const handler = (_event: any, status: string) => callback(status)
    ipcRenderer.on('tun-status-changed', handler)
    return () => ipcRenderer.removeListener('tun-status-changed', handler)
  },
  onSoftStatusChanged: (callback: (connected: boolean) => void) => {
    const handler = (_event: any, connected: boolean) => callback(Boolean(connected))
    ipcRenderer.on('soft-status-changed', handler)
    return () => ipcRenderer.removeListener('soft-status-changed', handler)
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
  },
  onAppResumedFromSleep: (callback: () => void) => {
    const handler = () => callback()
    ipcRenderer.on('app:resumed-from-sleep', handler)
    return () => ipcRenderer.removeListener('app:resumed-from-sleep', handler)
  }
} satisfies ElectronAPI)
