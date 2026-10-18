import type { PublicIpInfo } from './publicIp'
import type {
  ClientDevice,
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
  detectHapp: () => Promise<any>
  getPublicIp: () => Promise<PublicIpInfo>
  recheckPublicIp: (rebaseline?: boolean) => Promise<PublicIpInfo>
  startTun: (proxyAddr: string, proxyType?: 'socks5' | 'http') => Promise<{ success: boolean; error?: string; warning?: string | null; vpnIp?: string | null }>
  startDirectVpn: () => Promise<{ success: boolean; error?: string; warning?: string | null; vpnIp?: string | null }>
  stopTun: () => Promise<{ success: boolean; error?: string; warning?: string }>
  cancelTun: () => Promise<{ success: boolean; error?: string; warning?: string }>
  cancelTransition: () => Promise<{ requested: boolean }>
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
  killStaleSingbox: () => Promise<{ success: boolean; message: string; skipped?: boolean; blocked?: boolean; candidates?: number; killed?: number; names?: string[]; error?: string }>
  logRenderer: (level: 'debug' | 'info' | 'warn' | 'error', message: string) => Promise<any>
  getFullLogs: () => Promise<any>
  clearAppLog: () => Promise<any>
  clearDiagnosticArtifacts: () => Promise<{ success: boolean; message: string; cleared: string[] }>
  rollbackTunNetworkBaseline: () => Promise<any>
  disableFirewallKillSwitch: () => Promise<{ success: boolean; message: string; skipped?: boolean }>
  getFirewallKillSwitchStatus: () => Promise<FirewallKillSwitchStatus>
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
  configExport: (mode?: 'redacted' | 'secrets') => Promise<{ success: boolean; path?: string; error?: string }>
  configBrowseImport: () => Promise<string | null>
  configImport: (filePath: string) => Promise<{ success: boolean; sections: string[]; conflicts: string[]; error?: string }>
  configImportApply: (filePath: string, sections: string[], conflictResolution: 'replace' | 'merge') => Promise<{ success: boolean; error?: string }>
  // Split Tunneling
  splitTunnelGetApps: () => Promise<any[]>
  splitTunnelRefreshApps: () => Promise<{ apps: any[]; added: number }>
  splitTunnelGetConfig: () => Promise<any>
  splitTunnelSetRule: (appId: string, rule: 'vpn' | 'direct' | 'none') => Promise<void>
  splitTunnelAddApp: (exePath: string) => Promise<any>
  splitTunnelAddProcess: (name: string) => Promise<any>
  splitTunnelRemoveApp: (appId: string) => Promise<void>
  // Server Picker
  serversList: () => Promise<any[]>
  serversSelect: (id: string) => Promise<void | { cancelled: true }>
  serversCancelSwitch: () => Promise<{ cancelled: boolean }>
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
  groupsList: () => Promise<any[]>
  groupsGet: (id: string) => Promise<any | null>
  groupsRename: (id: string, name: string) => Promise<any | null>
  groupsDelete: (id: string, deleteServers: boolean) => Promise<{ ok: boolean }>
  groupsRefresh: (id: string) => Promise<
    | { ok: true; group: any; addedCount: number; updatedCount: number; removedCount: number }
    | { ok: false; error: string }
  >
  groupsSetRefreshPolicy: (id: string, intervalMinutes: number | null) => Promise<any | null>
  groupsCheckHealth: (id: string) => Promise<
    | { ok: true; results: Array<{ profileId: string; online: boolean; latencyMs: number | null; reason?: string }> }
    | { ok: false; error: string }
  >
  serverProbe: (host: string, knownPort?: number) => Promise<any>
  serverLiveCheck: (options: LiveServerCheckOptions) => Promise<LiveServerCheck>
  serverLiveCheckBatch: (options: LiveServerBatchCheckOptions) => Promise<LiveServerBatchCheckResult>
  serverLiveCheckCancel: (requestId?: string) => Promise<{ cancelled: boolean; reason?: string }>
  serverLiveCheckHistory: (filter?: { profileId?: string; host?: string }) => Promise<LiveServerCheck[]>
  onLiveCheckProgress: (callback: (progress: LiveCheckProgress) => void) => () => void
  onLiveBatchCheckProgress: (callback: (progress: LiveServerBatchCheckProgress) => void) => () => void
  urlAvailabilityCheck: (url: string) => Promise<any>
  urlAvailabilityHistory: () => Promise<any[]>
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
  trafficHistoryList: (vpnIp?: string, scheduleEnrichment?: boolean) => Promise<any[]>
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
  onIpChanged: (callback: (data: PublicIpInfo) => void) => () => void
  onTunStatusChanged: (callback: (status: string) => void) => () => void
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
