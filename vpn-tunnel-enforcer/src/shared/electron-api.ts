import type { AppSettings } from './settings'
import type { ConnectionStartResult, ConnectionStopResult, ManagedOperation } from './operation'
import type { TunnelSnapshot } from './tunnel-state'
import type { PlannedFeatureId, PlannedFeatureStatus } from './planned-features'
import type { PublicIpInfo } from './publicIp'
import type { ProxyInfo, AdaptiveBypassStatus, LeakCheckResult, SystemDiagnosticResult, RoutingPlan, LogFileSnapshot, UrlAvailabilityResult, ServerProbeResult } from './diagnostics'
import type { AutoconfigTarget, SmartRouteRuleSetState, BrowserHardeningResult, AutoPilotResult, SystemNetworkResult, FirewallKillSwitchResult, FirewallRepairHealth, LocationPrivacyStatus } from './network'
import type { TrafficHistoryEntry, TrafficForensicsStatus } from './traffic'
import type {
  ClientDevice, ServerProfile,
  SplitTunnelApp, SplitTunnelConfig, ServerGroup, RefreshGroupResult,
  SpeedTestResult,
  ScheduleEntry, ScheduleNextEvent, RotationConfig,
  KillSwitchLevel, KillSwitchException,
  DnsProfile, DnsProfileInput, DomainRule,
  ConnectionLogEntry, ConnectionHistoryFilters, ConnectionHistoryStats,
  NotificationPreferences, ThemeConfig, ThemeInput,
  FirewallKillSwitchStatus,
  ExternalProxyBatchStartResult,
  ExternalProxyStartOptions,
  ExternalProxyStatus,
  ExternalProxyProfileRow,
  LiveCheckProgress,
  LiveServerBatchCheckOptions,
  LiveServerBatchCheckProgress,
  LiveServerBatchCheckResult,
  LiveServerCheck,
  LiveServerCheckOptions
} from './ipc-types'

/** Request failures reject with IpcRemoteErrorData; narrow unknown catches
 * with isIpcRemoteErrorData rather than relying on Error identity across realms. */
export interface ElectronAPI {
  detectHapp: () => Promise<ProxyInfo | null>
  getPublicIp: () => Promise<PublicIpInfo>
  recheckPublicIp: (rebaseline?: boolean) => Promise<PublicIpInfo>
  startTun: (proxyAddr: string, proxyType?: 'socks5' | 'http') => Promise<ConnectionStartResult>
  startDirectVpn: () => Promise<ConnectionStartResult>
  startSoftProtection: (proxyAddr: string, proxyType?: 'socks5' | 'http') => Promise<ConnectionStartResult>
  stopTun: () => Promise<ConnectionStopResult>
  cancelTun: () => Promise<ConnectionStopResult>
  cancelTransition: () => Promise<{ requested: boolean }>
  getTunStatus: () => Promise<{ running: boolean; proxyAddr: string | null; proxyType: 'socks5' | 'http' | null; pid: number | null; warning?: string | null; startedAt?: number | null; restartAttempt?: number; lifecycle: TunnelSnapshot }>
  getTrafficStats: () => Promise<TrafficStats>
  applyAutoconfig: (targets: string[], proxyAddr: string, proxyType?: 'socks5' | 'http') => Promise<Record<string, boolean>>
  rollbackAutoconfig: (targets: string[]) => Promise<Record<string, boolean>>
  getAutoconfigStatus: () => Promise<AutoconfigTarget[]>
  getSettings: () => Promise<AppSettings>
  saveSettings: (settings: Partial<AppSettings>) => Promise<AppSettings>
  adaptiveBypassGetStatus: () => Promise<AdaptiveBypassStatus>
  adaptiveBypassRetry: () => Promise<{ started: boolean; status: AdaptiveBypassStatus }>
  adaptiveBypassResetLearning: () => Promise<{ success: boolean; status: AdaptiveBypassStatus }>
  smartRouteRuleSetsGetState: () => Promise<SmartRouteRuleSetState>
  smartRouteRuleSetsRefresh: (force?: boolean) => Promise<SmartRouteRuleSetState>
  inspectVpnInput: (input: string) => Promise<{ count: number; protocols: Record<string, number>; profiles: Array<{ index: number; name: string; protocol: string }>; fetched: boolean; source: string }>
  setLoginItem: (openAtLogin: boolean) => Promise<AppSettings>
  runLeakCheck: (options?: { proxyAddr?: string; proxyType?: 'socks5' | 'http' }) => Promise<LeakCheckResult>
  runSystemDiagnostics: () => Promise<SystemDiagnosticResult>
  getRoutingPlan: () => Promise<RoutingPlan>
  applyBrowserLeakProtection: () => Promise<BrowserHardeningResult>
  rollbackBrowserLeakProtection: () => Promise<BrowserHardeningResult>
  runAutoPilot: () => Promise<AutoPilotResult>
  repairOrphanedDns: () => Promise<{ repaired: boolean; adapters: string[] }>
  rollbackAdapterLockdown: () => Promise<{ rolledBack: boolean; skipped?: boolean; warnings?: string[]; blocked?: boolean; message?: string }>
  killStaleSingbox: () => Promise<{ success: boolean; message: string; skipped?: boolean; blocked?: boolean; candidates?: number; killed?: number; names?: string[]; error?: string }>
  logRenderer: (level: 'debug' | 'info' | 'warn' | 'error', message: string) => Promise<{ success: boolean }>
  getFullLogs: () => Promise<LogFileSnapshot[]>
  clearAppLog: () => Promise<{ success: boolean }>
  clearDiagnosticArtifacts: () => Promise<{ success: boolean; message: string; cleared: string[] }>
  rollbackTunNetworkBaseline: () => Promise<SystemNetworkResult & { blocked?: boolean }>
  disableFirewallKillSwitch: () => Promise<{ success: boolean; message: string; skipped?: boolean }>
  getFirewallKillSwitchStatus: () => Promise<FirewallKillSwitchStatus>
  firewallNuclearReset: (confirmationToken: string) => Promise<{ success: boolean; message: string }>
  firewallRepairHealth: () => Promise<FirewallRepairHealth>
  firewallRepairVpnteRules: () => Promise<FirewallKillSwitchResult & { health: FirewallRepairHealth; blocked?: boolean }>
  detectForeignVpn: () => Promise<{ foreign: string | null }>
  getLocationPrivacy: () => Promise<LocationPrivacyStatus>
  applyLocationPrivacy: () => Promise<LocationPrivacyStatus>
  rollbackLocationPrivacy: () => Promise<LocationPrivacyStatus>
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
  getTrafficForensicsStatus: () => Promise<TrafficForensicsStatus>
  restartTrafficForensics: () => Promise<TrafficForensicsStatus>
  // Config Import/Export
  configExport: (mode?: 'redacted' | 'secrets', requestId?: string) => Promise<{ success: true; path: string }>
  configBrowseImport: (requestId?: string) => Promise<string | null>
  configImport: (filePath: string, requestId?: string) => Promise<{ success: true; sections: string[]; conflicts: string[] }>
  configImportApply: (filePath: string, sections: string[], conflictResolution: 'replace' | 'merge', requestId?: string) => Promise<{ success: true }>
  configCancel: (requestId: string) => Promise<boolean>
  // Split Tunneling
  splitTunnelGetApps: () => Promise<SplitTunnelApp[]>
  splitTunnelRefreshApps: () => Promise<{ apps: SplitTunnelApp[]; added: number }>
  splitTunnelGetConfig: () => Promise<SplitTunnelConfig>
  splitTunnelSetRule: (appId: string, rule: 'vpn' | 'direct' | 'none') => Promise<void>
  splitTunnelAddApp: (exePath: string) => Promise<SplitTunnelApp | null>
  splitTunnelAddProcess: (name: string) => Promise<SplitTunnelApp>
  splitTunnelRemoveApp: (appId: string) => Promise<void>
  // Server Picker
  serversList: () => Promise<ServerProfile[]>
  serversSelect: (id: string) => Promise<void | { cancelled: true }>
  serversCancelSwitch: () => Promise<{ cancelled: boolean }>
  serversGetActive: () => Promise<{ profile: ServerProfile | null; activeId: string | null }>
  serversPingAll: () => Promise<ServerProfile[]>
  serversResolveIps: () => Promise<ServerProfile[]>
  serversPingOne: (host: string, port: number) => Promise<number | null>
  serversVerifyActiveCountry: (ip: string) => Promise<
    | { ok: true; country: string; profile: ServerProfile }
    | { ok: false; reason: string; country?: string }
  >
  serversVerifyCountry: (id: string) => Promise<
    | { ok: true; country: string; profile: ServerProfile }
    | { ok: false; reason: string; country?: string }
  >
  serversAdd: (input: string, options?: { clientDevice?: ClientDevice }) => Promise<ServerProfile[]>
  serversAddToGroup: (input: string, groupId: string | null, options?: { clientDevice?: ClientDevice }) => Promise<ServerProfile[]>
  serversSetClientDevice: (id: string, clientDevice: ClientDevice) => Promise<ServerProfile>
  serversRemove: (id: string) => Promise<void>
  serversCopyKey: (id: string) => Promise<
    | { ok: true; clearAfterMs: number }
    | { ok: false; cancelled: true }
    | { ok: false; reason: string; protocol?: string }
  >
  serversExportKey: (id: string) => Promise<
    | { ok: true; uri: string; name: string; protocol: string }
    | { ok: false; cancelled: true }
    | { ok: false; reason: string; protocol?: string }
  >
  serversExportKeyToFile: (id: string) => Promise<
    | { ok: true; path: string; name: string; protocol: string }
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
  groupsList: () => Promise<ServerGroup[]>
  groupsGet: (id: string) => Promise<ServerGroup | null>
  groupsRename: (id: string, name: string) => Promise<ServerGroup | null>
  groupsDelete: (id: string, deleteServers: boolean) => Promise<{ ok: boolean }>
  groupsRefresh: (id: string) => Promise<RefreshGroupResult>
  groupsSetRefreshPolicy: (id: string, intervalMinutes: number | null) => Promise<ServerGroup>
  groupsCheckHealth: (id: string) => Promise<
    | { ok: true; results: Array<{ profileId: string; online: boolean; latencyMs: number | null; reason?: string }> }
    | { ok: false; error: string }
  >
  serverProbe: (host: string, knownPort?: number) => Promise<ServerProbeResult | null>
  serverLiveCheck: (options: LiveServerCheckOptions) => Promise<LiveServerCheck>
  serverLiveCheckBatch: (options: LiveServerBatchCheckOptions) => Promise<LiveServerBatchCheckResult>
  serverLiveCheckCancel: (requestId?: string) => Promise<{ cancelled: boolean; reason?: string }>
  serverLiveCheckHistory: (filter?: { profileId?: string; host?: string }) => Promise<LiveServerCheck[]>
  onLiveCheckProgress: (callback: (progress: LiveCheckProgress) => void) => () => void
  onLiveBatchCheckProgress: (callback: (progress: LiveServerBatchCheckProgress) => void) => () => void
  urlAvailabilityCheck: (url: string) => Promise<UrlAvailabilityResult>
  urlAvailabilityHistory: () => Promise<UrlAvailabilityResult[]>
  urlAvailabilityClearHistory: () => Promise<void>
  // Scheduler
  schedulerList: () => Promise<ScheduleEntry[]>
  schedulerCreate: (entry: Omit<ScheduleEntry, 'id'>) => Promise<ScheduleEntry>
  schedulerUpdate: (id: string, patch: Partial<ScheduleEntry>) => Promise<ScheduleEntry>
  schedulerDelete: (id: string) => Promise<void>
  schedulerNextEvent: () => Promise<ScheduleNextEvent | null>
  // Profile Rotation
  rotationGetConfig: () => Promise<RotationConfig>
  rotationSetConfig: (config: Partial<RotationConfig>) => Promise<RotationConfig>
  rotationRotateNow: () => Promise<{ success: boolean; newProfile: string }>
  // Kill-Switch
  killSwitchGetLevel: () => Promise<KillSwitchLevel>
  killSwitchSetLevel: (level: KillSwitchLevel) => Promise<{ success: true; level: KillSwitchLevel }>
  killSwitchGetExceptions: () => Promise<KillSwitchException[]>
  killSwitchAddException: (exception: Omit<KillSwitchException, 'id'>) => Promise<KillSwitchException>
  killSwitchRemoveException: (id: string) => Promise<{ success: true }>
  killSwitchBrowseApp: () => Promise<{ path: string; name: string } | null>
  // DNS Profiles
  dnsList: () => Promise<DnsProfile[]>
  dnsGetActive: () => Promise<string | null>
  dnsCreate: (profile: DnsProfileInput) => Promise<DnsProfile>
  dnsUpdate: (id: string, patch: Partial<DnsProfile>) => Promise<DnsProfile>
  dnsDelete: (id: string) => Promise<void>
  dnsSelect: (id: string) => Promise<void>
  dnsValidate: (address: string) => Promise<{ valid: boolean; type: 'plain' | 'doh' | 'dot'; error?: string }>
  // Domain Routing
  domainRoutingList: () => Promise<DomainRule[]>
  domainRoutingAdd: (rule: Omit<DomainRule, 'id' | 'hitCount'>) => Promise<DomainRule>
  domainRoutingUpdate: (id: string, patch: Partial<DomainRule>) => Promise<DomainRule>
  domainRoutingDelete: (id: string) => Promise<void>
  domainRoutingReorder: (ids: string[]) => Promise<DomainRule[]>
  domainRoutingImport: (filePath: string) => Promise<DomainRule[]>
  domainRoutingBrowseFile: () => Promise<string | null>
  // Connection History
  connectionHistoryList: () => Promise<ConnectionLogEntry[]>
  connectionHistoryFilter: (filters: ConnectionHistoryFilters) => Promise<ConnectionLogEntry[]>
  connectionHistoryStats: (period: 'day' | 'week' | 'month') => Promise<ConnectionHistoryStats>
  connectionHistoryExportCsv: () => Promise<string>
  connectionHistoryExportJson: () => Promise<string>
  connectionHistoryClear: () => Promise<{ success: boolean }>
  // Traffic History
  trafficHistoryList: (vpnIp?: string, scheduleEnrichment?: boolean) => Promise<TrafficHistoryEntry[]>
  trafficHistoryClear: () => Promise<{ success: boolean }>
  onTrafficHistoryUpdated: (callback: () => void) => () => void
  // Notification Preferences
  notificationsGetPrefs: () => Promise<NotificationPreferences>
  notificationsSetPrefs: (prefs: Partial<NotificationPreferences>) => Promise<NotificationPreferences>
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
  themeList: () => Promise<ThemeConfig[]>
  themeGetActive: () => Promise<ThemeConfig>
  themeSetActive: (id: string) => Promise<void>
  themeCreate: (theme: ThemeInput) => Promise<ThemeInput & Pick<ThemeConfig, 'id' | 'isCustom'>>
  themeDelete: (id: string) => Promise<void>
  onThemeChanged: (callback: (theme: ThemeConfig) => void) => () => void
  onServerActiveChanged: (callback: (data: { profileId: string; profileName: string; nextProfileId?: string }) => void) => () => void
  onKillSwitchTrafficBlocked: (callback: (data: { reason: string; steps?: string[] }) => void) => () => void
  onI18nLocaleChanged: (callback: (locale: string) => void) => () => void
  // Speed Test
  speedTestRun: (requestId?: string) => Promise<SpeedTestResult>
  speedTestCancel: (requestId: string) => Promise<boolean>
  operationsList: () => Promise<ManagedOperation[]>
  plannedFeaturesStatus: () => Promise<PlannedFeatureStatus[]>
  plannedFeatureActivate: (featureId: PlannedFeatureId) => Promise<boolean>
  operationsCancel: (operationId: string) => Promise<boolean>
  speedTestHistory: () => Promise<SpeedTestResult[]>
  onSpeedTestProgress: (callback: (data: { percent: number; phase: string; operationId?: string; requestId?: string }) => void) => () => void
  // External Proxy
  externalProxyStatus: (slot?: number) => Promise<ExternalProxyStatus>
  externalProxyStart: (options?: ExternalProxyStartOptions) => Promise<ExternalProxyStatus>
  externalProxyStartProfiles: (profileIds: string[]) => Promise<ExternalProxyBatchStartResult>
  externalProxyStop: (slot?: number) => Promise<ExternalProxyStatus>
  externalProxyStopAll: () => Promise<ExternalProxyStatus>
  externalProxyList: (country?: string) => Promise<ExternalProxyProfileRow[]>
  externalProxyRotate: (slot?: number) => Promise<ExternalProxyStatus>
  // Event listeners
  onIpChanged: (callback: (data: PublicIpInfo) => void) => () => void
  onTunStatusChanged: (callback: (status: string) => void) => () => void
  onTunnelStateChanged: (callback: (snapshot: TunnelSnapshot) => void) => () => void
  onSoftStatusChanged?: (callback: (connected: boolean) => void) => () => void
  onTrafficStats: (callback: (stats: TrafficStats) => void) => () => void
  onLeakDetected: (callback: (result: LeakSelfTestResult) => void) => () => void
  onMainError: (callback: (data: { code: string; message: string }) => void) => () => void
  onAppShuttingDown: (callback: () => void) => () => void
  onAppResumedFromSleep?: (callback: () => void) => () => void
}

export interface TrafficStats {
  ts: number
  running: boolean
  adapterName: string
  adapterFound: boolean
  downloadBps: number
  uploadBps: number
  smoothedDownloadBps: number
  smoothedUploadBps: number
  downloadBurstinessPct: number
  uploadBurstinessPct: number
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
  physicalAdapterInspectionComplete?: boolean
}
