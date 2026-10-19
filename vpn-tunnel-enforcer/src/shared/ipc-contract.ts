import type { ElectronAPI } from './electron-api'
import type { AppSettings } from './settings'
import { IpcValidationError } from './ipc-result'
import { PLANNED_FEATURE_IDS } from './planned-features'

export interface IpcArgumentSchema {
  type: 'string' | 'boolean' | 'number' | 'integer' | 'enum' | 'strings' | 'array' | 'object' | 'json-object'
  optional?: boolean
  nullable?: boolean
  min?: number
  max?: number
  values?: readonly string[]
  fields?: Record<string, IpcArgumentSchema>
  items?: IpcArgumentSchema
  closed?: boolean
}
type RequestMethod = { [M in keyof ElectronAPI]-?: ElectronAPI[M] extends (...args: never[]) => Promise<unknown> ? M : never }[keyof ElectronAPI]
const request = <M extends RequestMethod>(method: M, args: readonly IpcArgumentSchema[]) => ({ method, args })
const text = (max = 4096): IpcArgumentSchema => ({ type: 'string', max })
const string = text()
const boolean: IpcArgumentSchema = { type: 'boolean' }
const integer: IpcArgumentSchema = { type: 'integer' }
const number: IpcArgumentSchema = { type: 'number' }
const port: IpcArgumentSchema = { type: 'integer', min: 1, max: 65535 }
const slot: IpcArgumentSchema = { type: 'integer', min: 1, max: 65535 - 17990 + 1 }
const oneOf = (values: readonly string[]): IpcArgumentSchema => ({ type: 'enum', values })
const optional = (schema: IpcArgumentSchema): IpcArgumentSchema => ({ ...schema, optional: true })
const nullable = (schema: IpcArgumentSchema): IpcArgumentSchema => ({ ...schema, nullable: true })
const strings = (max = 500): IpcArgumentSchema => ({ type: 'strings', max })
const object = (fields?: Record<string, IpcArgumentSchema>, closed = false): IpcArgumentSchema => ({ type: 'object', max: 256 * 1024, fields, closed })
const record = (fields: Record<string, IpcArgumentSchema>) => object(fields, true)
const partial = (schema: IpcArgumentSchema) => record(Object.fromEntries(Object.entries(schema.fields!).map(([key, field]) => [key, optional(field)])))
const array = (items: IpcArgumentSchema, max = 500): IpcArgumentSchema => ({ type: 'array', items, max })
const clientDevice = oneOf(['pc', 'android', 'ios', 'mac'])
const deviceOptions = object({ clientDevice: optional(clientDevice) })
const leakOptions = object({ proxyAddr: optional(string), proxyType: optional(oneOf(['socks5', 'http'])) })
const externalOptions = object({ slot: optional(slot), country: optional(string), profileId: optional(string), port: optional(port) })
const liveOptions = object({ requestId: optional(string), profileId: optional(string), host: optional(string), port: optional(port), mode: optional(oneOf(['basic', 'extended'])) })
const batchOptions = object({ requestId: optional(string), profileIds: { type: 'strings', min: 1, max: 12 }, mode: optional(oneOf(['basic', 'extended'])) })
const schedule = record({ name: string, enabled: boolean, days: array({ type: 'integer', min: 0, max: 6 }),
  startTime: text(5), endTime: text(5), profileId: string, mode: oneOf(['hard', 'soft', 'direct']) })
const schedulePatch = partial(record({ ...schedule.fields, id: string }))
const rotationPatch = partial(record({ enabled: boolean, intervalMinutes: number, order: oneOf(['sequential', 'random']),
  profileIds: array(text(200), 1000), currentIndex: { type: 'integer', min: 0 }, nextRotationAt: nullable({ type: 'number', min: 0 }) }))
const dnsType = oneOf(['plain', 'doh', 'dot'])
const dnsProfile = record({ name: text(120), primary: text(2048), secondary: optional(nullable(text(2048))), type: dnsType,
  primaryType: optional(dnsType), secondaryType: optional(dnsType), isSelected: optional(boolean) })
const dnsPatch = partial(record({ ...dnsProfile.fields, id: string, isBuiltin: boolean }))
// The feature normalizes URL inputs before applying the 253-character hostname limit.
const domainRule = record({ pattern: string, action: oneOf(['vpn', 'direct', 'block']), priority: number })
const domainPatch = partial(record({ ...domainRule.fields, id: string, hitCount: number }))
const notificationPatch = partial(record({ vpnConnect: boolean, vpnDisconnect: boolean, leakDetected: boolean, profileRotation: boolean,
  scheduleTriggered: boolean, connectionError: boolean, method: oneOf(['system', 'inapp', 'both']), sound: boolean }))
// Seven original palette fields remain sufficient for legacy custom themes.
const theme = record({ name: string, mode: oneOf(['light', 'dark', 'system']), colors: record({
  background: text(7), sidebar: text(7), cardBackground: text(7), accent: text(7), text: text(7), textSecondary: text(7), border: text(7),
  cardElevated: optional(text(7)), textMuted: optional(text(7)), borderStrong: optional(text(7)),
  success: optional(text(7)), warning: optional(text(7)), danger: optional(text(7)) }) })
const historyFilter = partial(record({ levels: array(oneOf(['user', 'error', 'rotation', 'schedule', 'crash'])),
  dateFrom: number, dateTo: number, text: string }))
// keyof makes an added/removed public setting fail typecheck until its schema is updated.
const settingsFields: Record<keyof AppSettings, IpcArgumentSchema> = {
  connectionMode: oneOf(['localProxy', 'directVpn']), routingMode: oneOf(['hard', 'soft']),
  proxyOverride: string, proxyType: oneOf(['socks5', 'http']), bootstrapRouteMode: oneOf(['auto', 'direct', 'localProxy']),
  directVpnInput: text(256 * 1024), directVpnSelectedIndex: number,
  directVpnCachedInput: text(256 * 1024), directVpnCachedSource: text(256 * 1024), directVpnCachedAt: nullable(number),
  directVpnCachedProfiles: array(record({ name: string, protocol: string, outbound: { type: 'json-object' } }), 20_000),
  checkInterval: number, autoStart: boolean, autoPilotEnabled: boolean, minimizeToTray: boolean,
  locationPrivacyEnabled: boolean, domainEnrichmentEnabled: boolean, autoNetworkBaseline: boolean,
  firewallKillSwitch: boolean, advancedMode: boolean, firstRunComplete: boolean, autoRestartOnCrash: boolean,
  desktopNotifications: boolean, publicWifiCompatibility: boolean, strictAdapterLockdown: boolean, disableGeoLookup: boolean,
  deepTrafficInspectionEnabled: boolean, deepTrafficInspectionMaxSizeMb: number, deepTrafficInspectionRetainSessions: number,
  stealthMode: boolean, adaptiveBypassEnabled: boolean, adaptiveBypassServerFallback: boolean,
  smartRuSplit: boolean, smartRuMapsDirect: boolean, smartRuRuleSetMode: oneOf(['bundled', 'managed']),
  smartRuRuleSetAutoUpdate: boolean, smartRuRuleSetUseProxy: boolean, smartRuRuleSetUpdateIntervalHours: number,
  proxyEngine: oneOf(['auto', 'sing-box', 'xray'])
}
const settingsPatch = partial(record(settingsFields))

/** Request channels only, with runtime field schemas. Protocol-specific outbound
 * JSON has a recursive value schema; feature validators retain semantic checks
 * such as DNS addresses and normalized domain patterns. Notifications stay separate. */
export const IPC_REQUESTS = {
  'detect-happ': request('detectHapp', []),
  'get-public-ip': request('getPublicIp', []),
  'recheck-public-ip': request('recheckPublicIp', [boolean]),
  'start-tun': request('startTun', [string, optional(oneOf(['socks5', 'http']))]),
  'start-direct-vpn': request('startDirectVpn', []),
  'start-soft-protection': request('startSoftProtection', [string, optional(oneOf(['socks5', 'http']))]),
  'stop-tun': request('stopTun', []),
  'cancel-tun': request('cancelTun', []),
  'cancel-transition': request('cancelTransition', []),
  'get-tun-status': request('getTunStatus', []),
  'get-traffic-stats': request('getTrafficStats', []),
  'apply-autoconfig': request('applyAutoconfig', [strings(), string, optional(oneOf(['socks5', 'http']))]),
  'rollback-autoconfig': request('rollbackAutoconfig', [strings()]),
  'get-autoconfig-status': request('getAutoconfigStatus', []),
  'get-settings': request('getSettings', []),
  'save-settings': request('saveSettings', [settingsPatch]),
  'adaptive-bypass:get-status': request('adaptiveBypassGetStatus', []),
  'adaptive-bypass:retry': request('adaptiveBypassRetry', []),
  'adaptive-bypass:reset-learning': request('adaptiveBypassResetLearning', []),
  'smart-route:rule-sets-state': request('smartRouteRuleSetsGetState', []),
  'smart-route:rule-sets-refresh': request('smartRouteRuleSetsRefresh', [boolean]),
  'inspect-vpn-input': request('inspectVpnInput', [text(256 * 1024)]),
  'set-login-item': request('setLoginItem', [boolean]),
  'run-leak-check': request('runLeakCheck', [optional(leakOptions)]),
  'run-system-diagnostics': request('runSystemDiagnostics', []),
  'get-routing-plan': request('getRoutingPlan', []),
  'apply-browser-leak-protection': request('applyBrowserLeakProtection', []),
  'rollback-browser-leak-protection': request('rollbackBrowserLeakProtection', []),
  'run-auto-pilot': request('runAutoPilot', []),
  'network:repair-orphaned-dns': request('repairOrphanedDns', []),
  'network:rollback-adapter-lockdown': request('rollbackAdapterLockdown', []),
  'tun:kill-stale-singbox': request('killStaleSingbox', []),
  'renderer-log': request('logRenderer', [oneOf(['debug', 'info', 'warn', 'error']), text(16 * 1024)]),
  'get-full-logs': request('getFullLogs', []),
  'clear-app-log': request('clearAppLog', []),
  'clear-diagnostic-artifacts': request('clearDiagnosticArtifacts', []),
  'rollback-tun-network-baseline': request('rollbackTunNetworkBaseline', []),
  'disable-firewall-kill-switch': request('disableFirewallKillSwitch', []),
  'get-firewall-kill-switch-status': request('getFirewallKillSwitchStatus', []),
  'firewall:nuclear-reset': request('firewallNuclearReset', [text(80)]),
  'firewall:repair-health': request('firewallRepairHealth', []),
  'firewall:repair-vpnte-rules': request('firewallRepairVpnteRules', []),
  'system:detect-foreign-vpn': request('detectForeignVpn', []),
  'get-location-privacy': request('getLocationPrivacy', []),
  'apply-location-privacy': request('applyLocationPrivacy', []),
  'rollback-location-privacy': request('rollbackLocationPrivacy', []),
  'open-tun-log-folder': request('openTunLogFolder', []),
  'open-log-folder': request('openLogFolder', []),
  'export-diagnostics': request('exportDiagnostics', []),
  'run-leak-self-test': request('runLeakSelfTest', []),
  'run-routing-self-test': request('runRoutingSelfTest', []),
  'open-snapshots-folder': request('openSnapshotsFolder', []),
  'get-traffic-forensics-status': request('getTrafficForensicsStatus', []),
  'restart-traffic-forensics': request('restartTrafficForensics', []),
  'split-tunnel:get-apps': request('splitTunnelGetApps', []),
  'split-tunnel:refresh-apps': request('splitTunnelRefreshApps', []),
  'split-tunnel:get-config': request('splitTunnelGetConfig', []),
  'split-tunnel:set-rule': request('splitTunnelSetRule', [string, oneOf(['vpn', 'direct', 'none'])]),
  'split-tunnel:add-app': request('splitTunnelAddApp', [string]),
  'split-tunnel:add-process': request('splitTunnelAddProcess', [string]),
  'split-tunnel:remove-app': request('splitTunnelRemoveApp', [string]),
  'servers:list': request('serversList', []),
  'servers:select': request('serversSelect', [string]),
  'servers:cancel-switch': request('serversCancelSwitch', []),
  'servers:get-active': request('serversGetActive', []),
  'servers:ping-all': request('serversPingAll', []),
  'servers:resolve-ips': request('serversResolveIps', []),
  'servers:ping-one': request('serversPingOne', [string, port]),
  'servers:verify-active-country': request('serversVerifyActiveCountry', [string]),
  'servers:verify-country': request('serversVerifyCountry', [string]),
  'servers:add': request('serversAdd', [text(256 * 1024), optional(deviceOptions), optional(text(36))]),
  'servers:add-to-group': request('serversAddToGroup', [text(256 * 1024), nullable(string), optional(deviceOptions), optional(text(36))]),
  'servers:set-client-device': request('serversSetClientDevice', [string, clientDevice]),
  'servers:remove': request('serversRemove', [string]),
  'servers:copy-key': request('serversCopyKey', [string, optional(text(36))]),
  'servers:export-key': request('serversExportKey', [string, optional(text(36))]),
  'servers:export-key-file': request('serversExportKeyToFile', [string, optional(text(36))]),
  'servers:export-all-keys-file': request('serversExportAllKeysToFile', [optional(text(36))]),
  'servers:export-all-proxies-file': request('serversExportAllProxiesToFile', [optional(text(36))]),
  'groups:list': request('groupsList', []),
  'groups:get': request('groupsGet', [string]),
  'groups:rename': request('groupsRename', [string, string]),
  'groups:delete': request('groupsDelete', [string, boolean]),
  'groups:refresh': request('groupsRefresh', [string, optional(text(36))]),
  'groups:set-refresh-policy': request('groupsSetRefreshPolicy', [string, nullable(integer)]),
  'groups:check-health': request('groupsCheckHealth', [string]),
  'server:probe': request('serverProbe', [string, optional(port)]),
  'server:live-check': request('serverLiveCheck', [liveOptions]),
  'server:live-check-batch': request('serverLiveCheckBatch', [batchOptions]),
  'server:live-check-cancel': request('serverLiveCheckCancel', [optional(string)]),
  'server:live-check-history': request('serverLiveCheckHistory', [optional(record({ profileId: optional(string), host: optional(string) }))]),
  'url-availability:check': request('urlAvailabilityCheck', [text(256 * 1024)]),
  'url-availability:history': request('urlAvailabilityHistory', []),
  'url-availability:clear-history': request('urlAvailabilityClearHistory', []),
  'scheduler:list': request('schedulerList', []),
  'scheduler:create': request('schedulerCreate', [schedule]),
  'scheduler:update': request('schedulerUpdate', [string, schedulePatch]),
  'scheduler:delete': request('schedulerDelete', [string]),
  'scheduler:next-event': request('schedulerNextEvent', []),
  'kill-switch:get-level': request('killSwitchGetLevel', []),
  'kill-switch:set-level': request('killSwitchSetLevel', [oneOf(['off', 'standard', 'strict'])]),
  'kill-switch:get-exceptions': request('killSwitchGetExceptions', []),
  'kill-switch:add-exception': request('killSwitchAddException', [record({ type: oneOf(['app', 'ip']), value: text(2048), label: text(200) })]),
  'kill-switch:remove-exception': request('killSwitchRemoveException', [string]),
  'kill-switch:browse-app': request('killSwitchBrowseApp', []),
  'rotation:get-config': request('rotationGetConfig', []),
  'rotation:set-config': request('rotationSetConfig', [rotationPatch]),
  'rotation:rotate-now': request('rotationRotateNow', []),
  'dns:list': request('dnsList', []),
  'dns:get-active': request('dnsGetActive', []),
  'dns:create': request('dnsCreate', [dnsProfile]),
  'dns:update': request('dnsUpdate', [string, dnsPatch]),
  'dns:delete': request('dnsDelete', [string]),
  'dns:select': request('dnsSelect', [string]),
  'dns:validate': request('dnsValidate', [string]),
  'domain-routing:list': request('domainRoutingList', []),
  'domain-routing:add': request('domainRoutingAdd', [domainRule]),
  'domain-routing:update': request('domainRoutingUpdate', [string, domainPatch]),
  'domain-routing:delete': request('domainRoutingDelete', [string]),
  'domain-routing:reorder': request('domainRoutingReorder', [strings()]),
  'domain-routing:import': request('domainRoutingImport', [string]),
  'domain-routing:browse-file': request('domainRoutingBrowseFile', []),
  'connection-history:list': request('connectionHistoryList', []),
  'connection-history:filter': request('connectionHistoryFilter', [historyFilter]),
  'connection-history:stats': request('connectionHistoryStats', [oneOf(['day', 'week', 'month'])]),
  'connection-history:export-csv': request('connectionHistoryExportCsv', []),
  'connection-history:export-json': request('connectionHistoryExportJson', []),
  'connection-history:clear': request('connectionHistoryClear', []),
  'traffic-history:list': request('trafficHistoryList', [optional(string), boolean]),
  'traffic-history:clear': request('trafficHistoryClear', []),
  'config:export': request('configExport', [oneOf(['redacted', 'secrets']), optional(text(36))]),
  'config:browse-import': request('configBrowseImport', [optional(text(36))]),
  'config:import': request('configImport', [string, optional(text(36))]),
  'config:import-apply': request('configImportApply', [string, strings(), oneOf(['replace', 'merge']), optional(text(36))]),
  'config:cancel': request('configCancel', [text(36)]),
  'notifications:get-prefs': request('notificationsGetPrefs', []),
  'notifications:set-prefs': request('notificationsSetPrefs', [notificationPatch]),
  'notifications:check-os-state': request('checkOsNotificationState', []),
  'notifications:reset-os-block': request('notificationsResetOsBlock', []),
  'notifications:open-windows-settings': request('notificationsOpenWindowsSettings', []),
  'ip-monitor:suspend': request('ipMonitorSuspend', []),
  'ip-monitor:resume': request('ipMonitorResume', []),
  'i18n:get-locale': request('i18nGetLocale', []),
  'i18n:set-locale': request('i18nSetLocale', [string]),
  'i18n:get-system-locale': request('i18nGetSystemLocale', []),
  'theme:list': request('themeList', []),
  'theme:get-active': request('themeGetActive', []),
  'theme:set-active': request('themeSetActive', [string]),
  'theme:create': request('themeCreate', [theme]),
  'theme:delete': request('themeDelete', [string]),
  'speed-test:run': request('speedTestRun', [optional(text(36))]),
  'speed-test:cancel': request('speedTestCancel', [text(36)]),
  'operations:list': request('operationsList', []),
  'planned-features:status': request('plannedFeaturesStatus', []),
  'planned-features:activate': request('plannedFeatureActivate', [oneOf(PLANNED_FEATURE_IDS)]),
  'operations:cancel': request('operationsCancel', [text(36)]),
  'operations:cancel-request': request('operationsCancelRequest', [text(36)]),
  'speed-test:history': request('speedTestHistory', []),
  'external-proxy:status': request('externalProxyStatus', [optional(slot)]),
  'external-proxy:start': request('externalProxyStart', [optional(externalOptions)]),
  'external-proxy:start-profiles': request('externalProxyStartProfiles', [strings(65535)]),
  'external-proxy:stop': request('externalProxyStop', [optional(slot)]),
  'external-proxy:stop-all': request('externalProxyStopAll', []),
  'external-proxy:list': request('externalProxyList', [optional(string)]),
  'external-proxy:rotate': request('externalProxyRotate', [optional(slot)]),
} as const

export type IpcChannel = keyof typeof IPC_REQUESTS
export type IpcRequest<C extends IpcChannel> = Parameters<ElectronAPI[typeof IPC_REQUESTS[C]['method']]>
export type IpcResponse<C extends IpcChannel> = Awaited<ReturnType<ElectronAPI[typeof IPC_REQUESTS[C]['method']]>>

export function isIpcChannel(channel: string): channel is IpcChannel { return Object.hasOwn(IPC_REQUESTS, channel) }

/** Protocol-specific outbound fields are JSON-shaped, not unvalidated arbitrary objects.
 * The main payload guard additionally bounds depth/nodes across the entire request. */
function matchesJsonObject(value: unknown): boolean {
  let nodes = 0
  const json = (item: unknown, depth: number): boolean => {
    if (++nodes > 20_000 || depth > 12) return false
    if (item === null || item === undefined || typeof item === 'boolean') return true
    if (typeof item === 'number') return Number.isFinite(item)
    if (typeof item === 'string') return item.length <= 2 * 1024 * 1024
    if (Array.isArray(item)) return Array.from(item).every(child => json(child, depth + 1))
    if (!item || typeof item !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(item))) return false
    return Object.entries(item).every(([key, child]) => !['__proto__', 'constructor', 'prototype'].includes(key) && json(child, depth + 1))
  }
  try {
    return !!value && typeof value === 'object' && !Array.isArray(value)
      && [Object.prototype, null].includes(Object.getPrototypeOf(value)) && json(value, 0)
  } catch { return false }
}

export function matchesIpcArgument(schema: IpcArgumentSchema, value: unknown): boolean {
  if (value === undefined) return schema.optional === true
  if (value === null) return schema.nullable === true
  switch (schema.type) {
    case 'json-object': return matchesJsonObject(value)
    case 'string': return typeof value === 'string' && value.length <= (schema.max ?? 4096)
    case 'boolean': return typeof value === 'boolean'
    case 'enum': return typeof value === 'string' && schema.values?.includes(value) === true
    case 'number': case 'integer': return typeof value === 'number' && Number.isFinite(value)
      && (schema.type !== 'integer' || Number.isInteger(value)) && value >= (schema.min ?? -Infinity) && value <= (schema.max ?? Infinity)
    case 'strings': return Array.isArray(value) && value.length >= (schema.min ?? 0) && value.length <= (schema.max ?? 500)
      && Array.from(value).every(v => typeof v === 'string' && v.length <= 4096)
    case 'array': return Array.isArray(value) && value.length >= (schema.min ?? 0) && value.length <= (schema.max ?? 500)
      && !!schema.items && Array.from(value).every(v => matchesIpcArgument(schema.items!, v))
    case 'object': {
      if (!value || typeof value !== 'object' || Array.isArray(value)
        || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return false
      try {
        return JSON.stringify(value).length <= (schema.max ?? 256 * 1024)
          && (!schema.closed || Object.keys(value).every(key => Object.hasOwn(schema.fields ?? {}, key)))
          && Object.entries(schema.fields ?? {}).every(([key, field]) => matchesIpcArgument(field, (value as Record<string, unknown>)[key]))
      } catch { return false }
    }
  }
}

export function assertIpcRequest(channel: string, args: readonly unknown[]): asserts channel is IpcChannel {
  if (!isIpcChannel(channel)) throw new IpcValidationError('Unknown IPC request channel')
  const schemas = IPC_REQUESTS[channel].args
  if (args.length > schemas.length || schemas.some((schema, index) => !matchesIpcArgument(schema, args[index]))) {
    throw new IpcValidationError('Invalid IPC request arguments')
  }
}
