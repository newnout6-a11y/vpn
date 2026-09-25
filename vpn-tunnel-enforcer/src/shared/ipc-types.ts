/**
 * Shared IPC type definitions for VPN Tunnel Enforcer v2.
 *
 * This file defines all typed IPC channel interfaces and data model interfaces
 * used for communication between the Electron main process and the renderer process.
 */

// ─── Data Models ─────────────────────────────────────────────────────────────

/** Split Tunneling app entry */
export interface SplitTunnelApp {
  id: string
  name: string
  path: string
  icon: string | null // base64 encoded icon
  rule: 'vpn' | 'direct' | 'none'
  /**
   * Entry kind:
   *   - 'app'     (default) — a discovered/added installed application; `path`
   *                is a real .exe path on disk.
   *   - 'process' — a bare process/command name the user wants to bypass the
   *                VPN (e.g. `curl.exe`, `git.exe`, `yt-dlp.exe`). `path` holds
   *                just the process name; there is no on-disk validation
   *                because the command may live anywhere on PATH or be invoked
   *                transiently from a terminal.
   * Optional for back-compat: entries saved by older builds have no `kind`
   * and are treated as 'app'.
   */
  kind?: 'app' | 'process'
}

/** Split Tunneling full configuration */
export interface SplitTunnelConfig {
  apps: SplitTunnelApp[]
  enabled: boolean
}

export type ClientDevice = 'pc' | 'android' | 'ios' | 'mac'

/** Server/Profile entry */
export interface ServerProfile {
  id: string
  name: string
  protocol: string
  server: string
  port: number
  /** Latest IPv4 address resolved from `server`, for display only. */
  resolvedIp?: string
  resolvedIpAt?: number
  /**
   * Best-known exit country. This may come from background server IP
   * geolocation, or from the actual public IP observed after connecting.
   * It intentionally overrides country-like words in `name`, because provider
   * labels can drift from the real exit location.
   */
  country?: string
  countryVerifiedAt?: number
  countryVerifiedIp?: string
  /** Real exit/egress IP discovered via health probe or after connecting. */
  egressIp?: string
  countryGeoVersion?: number
  clientDevice?: ClientDevice
  clientFingerprint?: string
  ping?: number | null
  status: 'online' | 'offline' | 'unknown'
  lastChecked?: number
  /** Persisted key-health result, independent from latency ping cleanup. */
  healthStatus?: 'online' | 'offline' | 'unknown'
  healthCheckedAt?: number
  healthLatencyMs?: number | null
  healthReason?: string
  /**
   * Full sing-box outbound configuration. Required for the VPN to actually
   * dial this server. Optional only for backward compatibility with
   * persisted profiles created before the field was introduced — the picker
   * will refuse to start a tunnel for any profile missing this object.
   */
  outbound?: Record<string, any>
  /**
   * FK to {@link ServerGroup}. Undefined for legacy rows; the startup
   * migration assigns every dangling profile to an "Импортированные" group
   * on first run, so any new code can treat this as effectively required.
   */
  groupId?: string
  /**
   * The exact `vless://` / `trojan://` / `ss://` / `vmess://` line as it was
   * imported. Lossless re-export, stable identity for dedupe — two profiles
   * with the same `sourceUri` are the same key, even if their derived
   * `name` (the URL fragment) differs.
   */
  sourceUri?: string
  /**
   * ms timestamp. Updated on every refresh that saw this server in the
   * upstream feed. When the subscription stops listing it, this stays
   * frozen — we use the gap (`now - lastSeenInSubscriptionAt`) to surface
   * "удалён провайдером" in the UI without actually deleting the key.
   */
  lastSeenInSubscriptionAt?: number
  /**
   * Set when a successful non-empty subscription refresh no longer contains
   * this profile. Removed profiles stay visible for audit/history, but cannot
   * be selected for the main VPN or assigned to an external proxy.
   */
  removedFromSubscriptionAt?: number
  /** Previous enabled state restored if the provider publishes the key again. */
  enabledBeforeSubscriptionRemoval?: boolean
  /**
   * Soft-disable. Tunnel start refuses to dial when false. Default: true.
   * We keep it optional for backward compat — undefined === enabled.
   */
  enabled?: boolean
}

/**
 * Origin of a {@link ServerGroup}.
 *
 * - `subscription` — fetched from a remote panel (Marzban / 3X-UI / …).
 *   Has a `sourceUrl` and is refreshable.
 * - `manual` — single VPN URIs the user pasted by hand. No upstream feed,
 *   so a "refresh" call is a no-op and the UI hides the refresh button.
 */
export type GroupSource = 'subscription' | 'manual'

/**
 * Lifecycle of a {@link ServerGroup}'s upstream feed.
 *
 * - `active` — last refresh succeeded.
 * - `expired` — last refresh failed (HTTP 4xx, empty body, panel gone).
 *   Profiles are intentionally left in place: post-trial keys often keep
 *   working for hours/days after the panel itself disappears.
 * - `unreachable` — network error during refresh (DNS, TCP, TLS). Not the
 *   panel's fault per se; usually the user is offline.
 * - `unknown` — never fetched yet (freshly imported manual group, or first
 *   run before the initial refresh completes).
 */
export type GroupStatus = 'active' | 'expired' | 'unreachable' | 'unknown'

/**
 * Top-level grouping for {@link ServerProfile}s. One subscription URL == one
 * group; loose user-pasted keys go into a shared "Ручные ключи" group.
 *
 * Most metadata fields come from the standard subscription-userinfo headers
 * exposed by xray/sing-box panels; they're all optional because many panels
 * publish none of them.
 */
export interface ServerGroup {
  id: string
  /** "feodorn LTE 12" / "Personal vless key" / etc. Free-form, user-renameable. */
  name: string
  source: GroupSource
  /** Only populated when `source === 'subscription'`. */
  sourceUrl?: string
  /** ms timestamp the user added the group. */
  importedAt: number
  /** ms timestamp of the last successful refresh. */
  lastFetchedAt?: number
  /** ms timestamp of the last refresh attempt — success OR failure. */
  lastFetchAttemptAt?: number
  /**
   * Human-readable error from the most recent failed fetch. `null` means
   * the last fetch succeeded (and we explicitly cleared the field), so the
   * UI can distinguish "never failed" (undefined) from "recovered after a
   * failure" (null) from "still failing" (string).
   */
  lastFetchError?: string | null
  status: GroupStatus
  /** Subscription-userinfo: bytes already used (upload + download). */
  trafficUsedBytes?: number
  /** Subscription-userinfo: bytes uploaded. */
  trafficUploadBytes?: number
  /** Subscription-userinfo: bytes downloaded. */
  trafficDownloadBytes?: number
  /** Subscription-userinfo: total quota. */
  trafficTotalBytes?: number
  /** Subscription-userinfo: ms timestamp when the plan expires. */
  expiresAt?: number
  /** Subscription-userinfo: server-recommended refresh interval, in seconds. */
  refreshIntervalSeconds?: number
  /** Subscription-userinfo: panel URL the user can open in a browser. */
  webPageUrl?: string
  /** Server-supplied subscription name from profile-title or content-disposition header. */
  profileTitle?: string
  /** Support/contact URL from support-url header. */
  supportUrl?: string
  /** Number of profiles seen on the most recent successful refresh. */
  lastRefreshProfilesCount?: number
}

// ─── Live Server Extraction & Technical Profile ──────────────────────────────

export type LiveCheckStatus = 'ok' | 'unavailable' | 'error' | 'skipped'

export interface AsnInfo {
  asn: string
  org: string
  network: string
  country: string
}

export type LiveCheckStage =
  | 'dns'
  | 'reachability'
  | 'tls'
  | 'http'
  | 'ports'
  | 'route'
  | 'infrastructure'
  | 'handshake'
  | 'egress'
  | 'mediaStream'
  | 'path'
  | 'pmtu'

export interface LiveMediaStreamDiagnostics {
  status: 'ok' | 'warning' | 'error' | 'skipped'
  durationMs: number
  twitchHlsReachable?: boolean
  quicFallbackGuarded?: boolean
  error2000Risk?: boolean
  testedEndpoints?: Array<{
    endpoint: string
    reachable: boolean
    latencyMs?: number
    protocol?: string
    error?: string
  }>
  detail?: string
  error?: string
}

export interface LiveCheckProgress {
  requestId: string
  sequence: number
  stage: LiveCheckStage
  status: 'running' | 'completed' | 'failed' | 'skipped'
  completedStages: number
  totalStages: number
  elapsedMs: number
  detail?: string
}

export interface DnsRecordEntry {
  name: string
  type: 'A' | 'AAAA' | 'CNAME' | 'PTR'
  value: string
  ttl?: number
  observedAt: string
  resolverId: string
  transport: 'system' | 'doh'
}

export interface DnsResolverComparison {
  resolverId: string
  resolverName: string
  endpoint: string
  status: 'ok' | 'partial' | 'error' | 'timeout' | 'skipped'
  durationMs: number
  error?: string
  authenticatedData?: boolean
  records: DnsRecordEntry[]
  truncated?: boolean
  rcode?: number
  aStatus?: 'ok' | 'nxdomain' | 'servfail' | 'refused' | 'error' | 'timeout'
  aaaaStatus?: 'ok' | 'nxdomain' | 'servfail' | 'refused' | 'error' | 'timeout'
}

export interface DnsDiagnostics {
  status: LiveCheckStatus
  durationMs: number
  error?: string
  a: string[]
  aaaa: string[]
  cnameChain: string[]
  ttl?: number
  resolverUsed?: string
  records?: DnsRecordEntry[]
  resolvers?: DnsResolverComparison[]
  discrepancies?: string[]
  timings?: {
    aMs?: number
    aaaaMs?: number
    cnameMs?: number
  }
}

export interface TunnelHandshakeResult {
  status: 'ok' | 'auth_failed' | 'transport_failed' | 'timeout' | 'skipped' | 'unsupported'
  durationMs: number
  protocol?: string
  error?: string
  evidence?: {
    transport?: string
    alpn?: string
    tlsVersion?: string
    detail?: string
    inboundPort?: number
  }
}

export interface EgressReflectorResult {
  source: string
  ip?: string
  family?: 4 | 6
  country?: string
  durationMs: number
  status: 'ok' | 'error' | 'timeout' | 'unsupported'
  error?: string
}

export interface LiveEgressResult {
  status: 'ok' | 'partial' | 'error' | 'skipped' | 'timeout'
  durationMs: number
  exitIpv4?: string
  exitIpv6?: string
  ipv6Status?: 'ok' | 'unsupported' | 'error'
  country?: string
  reflectors: EgressReflectorResult[]
  endpointIp?: string
  matchesEndpoint?: boolean
  underlayPath?: 'direct' | 'nested' | 'unknown' | 'route-selected'
  error?: string
}

export interface PathDiagnostics {
  status: 'ok' | 'error' | 'skipped'
  durationMs: number
  destination: string
  activeInterfaceIndex?: number
  activeInterfaceAlias?: string
  activeLocalIp?: string
  nextHop?: string
  isTunInterface: boolean
  underlayInterfaceAlias?: string
  evidenceKind: 'etw-corroborated' | 'route-policy' | 'net-route' | 'os-unverified'
  error?: string
}

export interface PmtuDiagnostics {
  status: 'ok' | 'lower_bound' | 'blackhole_suspected' | 'icmp_blocked' | 'skipped'
  durationMs: number
  destination: string
  family?: 4 | 6
  interfaceAlias?: string
  method: 'icmp-df' | 'interface-nlmtu' | 'fallback'
  pmtu?: number
  minTested?: number
  maxTested?: number
  lossRate?: number
  detail?: string
  error?: string
}

export interface ReachabilityDiagnostics {
  status: LiveCheckStatus
  durationMs: number
  error?: string
  tcpReachable: boolean
  port: number
}

export interface LiveLatencyStats {
  min: number
  avg: number
  median: number
  max: number
  jitter: number   // stddev
  loss: number     // 0..1 (fraction of attempted samples that failed to connect)
  connectionFailureRate?: number
  samples: number[]
  samplesAttempted: number
  samplesSucceeded?: number
  pathType?: 'direct' | 'tun' | 'os-selected'
  tunRunning?: boolean
  method: 'tcp'
}

export interface LiveTlsCertInfo {
  status: LiveCheckStatus
  durationMs: number
  error?: string
  hostnameVerified?: boolean
  authorized?: boolean
  authorizationError?: string
  subject?: string
  issuer?: string
  validFrom?: string
  validTo?: string
  daysRemaining?: number
  fingerprint?: string // sha-256
  sans?: string[]
  protocol?: string    // TLSv1.2, TLSv1.3
  cipher?: string
  alpn?: string
  alpnProtocol?: string
}

export interface HttpProbeResult {
  status: LiveCheckStatus
  durationMs: number
  error?: string
  statusCode?: number
  protocol?: string
  serverHeader?: string
  viaHeader?: string
  locationHeader?: string
  contentType?: string
  bodySize?: number
  targetPort?: number
  isTls?: boolean
  confidence: 'low'
}

export interface LivePortScanItem {
  port: number
  open: boolean
  state: 'open' | 'closed' | 'filtered' | 'timeout'
  service?: string
}

export interface RouteDiagnostics {
  status: LiveCheckStatus
  durationMs: number
  error?: string
  hops?: number
  reachedTarget?: boolean
  commandFinished?: boolean
  partial?: boolean
  hopDetails?: string[]
  mtu?: number
  mtuStatus?: 'measured' | 'unavailable' | 'skipped'
  routeMethod?: string
}

export interface InfrastructureHints {
  status: LiveCheckStatus
  error?: string
  egressSource?: 'profile-cache'
  egressObservedAt?: string | null
  asn?: AsnInfo
  egressIp?: string
  egressCountry?: string
  endpointCountry?: string
  activeTunnelMatchesProfile?: boolean
  sharedCidrWithProfiles?: string[]
  changesFromPrevious?: {
    ipChanged?: boolean
    asnChanged?: boolean
    tlsCertChanged?: boolean
    countryChanged?: boolean
    portsChanged?: boolean
    latencySpike?: boolean
    handshakeChanged?: boolean
    egressChanged?: boolean
    pmtuChanged?: boolean
  }
}

export interface LiveCheckFinding {
  code: string
  severity: 'info' | 'warning' | 'error'
  title: string
  detail: string
  evidence?: Record<string, string | number | boolean>
}

export interface LiveServerCheckOptions {
  requestId?: string
  profileId?: string
  host?: string
  port?: number
  mode?: 'basic' | 'extended'
}

export interface LiveServerCheck {
  id: string
  requestId?: string
  profileId?: string
  host: string
  port: number
  mode: 'basic' | 'extended'
  startedAt: string
  finishedAt: string
  durationMs: number
  cancelled?: boolean
  error?: string
  dns: DnsDiagnostics
  reverseDns?: string[]
  asn?: AsnInfo
  reachability: ReachabilityDiagnostics
  latency?: LiveLatencyStats
  tls?: LiveTlsCertInfo
  http?: HttpProbeResult
  openPorts?: LivePortScanItem[]
  portsError?: string
  route?: RouteDiagnostics
  infrastructure?: InfrastructureHints
  handshake?: TunnelHandshakeResult
  egress?: LiveEgressResult
  pathDiagnostics?: PathDiagnostics
  pmtu?: PmtuDiagnostics
  mediaStream?: LiveMediaStreamDiagnostics
  findings: LiveCheckFinding[]
}

export interface LiveServerCheckHistoryDiff {
  previousStartedAt?: string
  ipChanged?: boolean
  previousIps?: string[]
  currentIps?: string[]
  tlsCertChanged?: boolean
  previousTlsFingerprint?: string
  currentTlsFingerprint?: string
  asnChanged?: boolean
  previousAsn?: string
  currentAsn?: string
  countryChanged?: boolean
  previousCountry?: string
  currentCountry?: string
  latencySpike?: boolean
  previousAvgLatency?: number
  currentAvgLatency?: number
  portsChanged?: boolean
  closedPorts?: number[]
  newOpenPorts?: number[]
  handshakeChanged?: boolean
  previousHandshakeStatus?: string
  currentHandshakeStatus?: string
  egressChanged?: boolean
  previousExitIp?: string
  currentExitIp?: string
  pmtuChanged?: boolean
  previousPmtu?: number
  currentPmtu?: number
}

/** Speed test result entry */
export interface SpeedTestResult {
  id: string
  timestamp: number
  downloadMbps: number
  uploadMbps: number
  latencyMs: number
  serverName: string
  profileUsed: string
}

/** Kill-switch severity level */
export type KillSwitchLevel = 'off' | 'standard' | 'strict'

/** Kill-switch exception entry */
export interface KillSwitchException {
  id: string
  type: 'app' | 'ip'
  value: string // exe path or IP/CIDR
  label: string
}

/** Profile rotation configuration */
export interface RotationConfig {
  enabled: boolean
  intervalMinutes: number
  order: 'sequential' | 'random'
  profileIds: string[]
  currentIndex: number
  nextRotationAt: number | null
}

/** Route health for an external proxy instance. */
export type ExternalProxyHealth =
  | 'stopped'
  | 'starting'
  | 'healthy'
  | 'degraded'
  | 'rotating'
  | 'quarantined'
  | 'failed'

export type ExternalProxyLifecycle =
  | 'stopped'
  | 'starting'
  | 'ready'
  | 'healthy'
  | 'degraded'
  | 'rotating'
  | 'quarantined'
  | 'failed'

export interface ExternalProxyAggregate {
  total: number
  running: number
  ready: number
  healthy: number
  uniqueEgress: number
  duplicateEgress: number
  starting: number
  degraded: number
  quarantined: number
}

export interface ExternalProxyInstanceStatus {
  slot: number
  /** True only when the proxy passed its latest external data-plane check. */
  running: boolean
  /** Child-process state, independent from the active health result. */
  processRunning: boolean
  ready: boolean
  health: ExternalProxyHealth
  state: ExternalProxyLifecycle
  generation: number
  egressIp: string | null
  latencyMs: number | null
  lastCheckedAt: number | null
  lastSuccessAt: number | null
  egressCheckedAt: string | null
  updatedAt: string | null
  lastError: string | null
  lastErrorAt: string | null
  degradationReason: string | null
  consecutiveFailures: number
  nextCheckAt: string | null
  lastRotateReason: string | null
  autoDisabled: boolean
  host: string
  port: number | null
  proxyUrl: string | null
  profileId: string | null
  profileName: string | null
  country: string | null
  pid: number | null
  startedAt: string | null
}

/** External proxy status, with the legacy primary instance at the top level. */
export interface ExternalProxyStatus extends ExternalProxyInstanceStatus {
  controlHost: string
  controlPort: number | null
  controlUrl: string | null
  /** null means that the UI does not impose a product-level instance cap. */
  maxInstances: null
  instances: ExternalProxyInstanceStatus[]
  aggregate: ExternalProxyAggregate
}

export interface ExternalProxyStartOptions {
  slot?: number
  country?: string
  profileId?: string
  port?: number
}

/** External proxy profile row (picker entry) */
export interface ExternalProxyProfileRow {
  id: string
  name: string
  country: string | null
  protocol: string
  server: string
  port: number
  groupId: string | null
  /** Last persisted reachability result for this server profile. */
  status: ServerProfile['status']
  pingMs: number | null
  healthLatencyMs: number | null
  healthReason: string | null
  lastCheckedAt: number | null
  selectedForVpn: boolean
  active: boolean
  activeSlots: number[]
}

/** Result of assigning server profiles to independent external proxies. */
export interface ExternalProxyBatchStartResult {
  requested: number
  started: ExternalProxyInstanceStatus[]
  alreadyRunningProfileIds: string[]
  skipped: Array<{ profileId: string; reason: 'active-vpn' | 'unavailable' }>
  failed: Array<{ profileId: string; error: string }>
}

/** Schedule entry for automated connect/disconnect */
export interface ScheduleEntry {
  id: string
  name: string
  enabled: boolean
  days: number[] // 0=Sun, 1=Mon, ..., 6=Sat
  startTime: string // "HH:mm"
  endTime: string // "HH:mm"
  profileId: string
  mode: 'hard' | 'soft' | 'direct'
}

/** DNS profile entry */
export interface DnsProfile {
  id: string
  name: string
  primary: string
  secondary: string
  type: 'plain' | 'doh' | 'dot'
  primaryType?: 'plain' | 'doh' | 'dot'
  secondaryType?: 'plain' | 'doh' | 'dot'
  isBuiltin: boolean
  isSelected?: boolean
}

/** Domain routing action */
export type DomainAction = 'vpn' | 'direct' | 'block'

/** Domain routing rule */
export interface DomainRule {
  id: string
  pattern: string // e.g. "*.google.com"
  action: DomainAction
  priority: number
  hitCount: number
}

/** Notification preferences */
export interface NotificationPreferences {
  vpnConnect: boolean
  vpnDisconnect: boolean
  leakDetected: boolean
  profileRotation: boolean
  scheduleTriggered: boolean
  connectionError: boolean
  method: 'system' | 'inapp' | 'both'
  sound: boolean
}

/** Theme configuration */
export interface ThemeConfig {
  id: string
  name: string
  mode: 'light' | 'dark' | 'system'
  isCustom: boolean
  /**
   * Full surface + state palette.
   *
   * This used to carry only seven values, which split the palette across two
   * disagreeing sources: ThemeProvider wrote those seven onto the document and
   * everything else (cardElevated, borderStrong, textMuted, state colours, and
   * every shadow/glow derived from them) stayed at the globals.css fallbacks —
   * which had been tuned for a canvas 15 levels darker than the built-in dark
   * theme actually shipped. The result was a UI with no depth: layers within a
   * few RGB steps of each other and shadows calibrated for a different
   * background.
   *
   * Every surface level is listed explicitly so one theme fully determines the
   * palette. `cardElevated` and `borderStrong` are optional-in-practice for
   * custom themes stored before this change; themeManager fills them in.
   */
  colors: {
    background: string
    /** Nav rail. Must differ from `background`, or the rail vanishes into it. */
    sidebar: string
    cardBackground: string
    /** Nested/raised surfaces inside a card (inputs, inner panels, hovers). */
    cardElevated: string
    accent: string
    text: string
    textSecondary: string
    /** Lowest-emphasis text: hints, disabled, placeholder. */
    textMuted: string
    border: string
    /** Higher-contrast border for focus and separators that must read. */
    borderStrong: string
    /** State colours travel with the theme — in a VPN client they carry meaning. */
    success: string
    warning: string
    danger: string
  }
}

/** Dashboard widget layout entry */
export interface WidgetLayout {
  id: string
  type: string
  position: number
  size: 'compact' | 'expanded'
  visible: boolean
}

/**
 * Why a VPN session ended (or never started). Finer-grained than
 * `disconnectReason`, which stays as a coarse 5-bucket field for the filter
 * UI and CSV compatibility (see `outcomeKindToDisconnectReason`).
 */
export type SessionOutcomeKind =
  // intentional
  | 'user-stop' // the user pressed "Отключить"
  | 'app-quit' // the app was closed
  | 'server-switch' // the user switched to another server (session continued on it)
  | 'rotation' // auto-rotation moved to the next profile
  | 'schedule' // a schedule window ended
  // node / connectivity problem
  | 'proxy-unreachable' // the upstream proxy/server stopped answering (watchdog)
  | 'server-rejected-key' // REALITY/TLS handshake refused — key / SNI / cert mismatch
  | 'server-down' // connection refused / timeout to the node
  | 'singbox-crash' // the tunnel process exited unexpectedly
  | 'killswitch' // kill-switch engaged and is holding traffic
  | 'tun-setup-failed' // Wintun / routes / DNS bring-up failed
  | 'network-lost' // the physical network dropped or changed under the tunnel
  | 'system-sleep' // the machine suspended
  // never came up
  | 'start-failed'
  | 'unknown'

/** Machine-readable evidence backing a {@link SessionOutcome}. All optional. */
export interface SessionOutcomeEvidence {
  singboxExitCode?: number | null
  singboxStderrTail?: string | null
  outboundFault?: 'reality-key-mismatch' | 'tls-handshake-failed' | 'upstream-unreachable' | null
  adaptiveMode?: 'baseline' | 'tls-compatibility' | 'mtu-compatibility' | 'external-managed' | null
  adaptiveAttempts?: number | null
  autoRestartAttempts?: number | null
  killSwitchEngaged?: boolean | null
  leakDetectedDuringSession?: boolean | null
  networkTransition?: string | null
  egressCountry?: string | null
  egressIp?: string | null
  proxyEngine?: 'sing-box' | 'xray' | null
  /** "What to do" hint, shown for start failures. */
  hint?: string | null
}

export interface SessionOutcome {
  kind: SessionOutcomeKind
  /** One-sentence human summary, composed at write time (Russian). */
  headline: string
  evidence?: SessionOutcomeEvidence
}

/** Connection history log entry */
export interface ConnectionLogEntry {
  id: string
  startedAt: number
  endedAt: number | null
  profileName: string
  profileId: string
  mode: 'hard' | 'soft' | 'direct'
  bytesDown: number
  bytesUp: number
  disconnectReason: 'user' | 'error' | 'rotation' | 'schedule' | 'crash'
  errorMessage?: string | null
  /** Structured cause + evidence. Absent on entries written before v1.1.18. */
  outcome?: SessionOutcome | null
}

/** Locale type */
export type Locale = 'en' | 'ru'

// ─── Extended Settings ───────────────────────────────────────────────────────

/** Extended settings schema incorporating all v2 feature configurations */
export interface ExtendedSettings {
  // Split Tunneling
  splitTunnelRules: SplitTunnelApp[]

  // Granular Kill-Switch
  killSwitchLevel: KillSwitchLevel
  killSwitchExceptions: KillSwitchException[]

  // Profile Rotation
  rotation: RotationConfig

  // Scheduler
  schedules: ScheduleEntry[]

  // DNS Profiles
  dnsProfiles: DnsProfile[]
  activeDnsProfileId: string | null

  // Domain Routing
  domainRules: DomainRule[]

  // i18n
  locale: Locale

  // Notifications
  notificationPrefs: NotificationPreferences

  // Theme
  activeThemeId: string
  customThemes: ThemeConfig[]

  // Widgets
  widgetLayout: WidgetLayout[]

  // Connection History
  connectionHistory: ConnectionLogEntry[]
  speedTestHistory: SpeedTestResult[]
}

// ─── IPC Channel Interfaces ─────────────────────────────────────────────────

/** Split Tunneling IPC channels */
export interface SplitTunnelChannels {
  'split-tunnel:get-apps': () => SplitTunnelApp[]
  'split-tunnel:refresh-apps': () => { apps: SplitTunnelApp[]; added: number }
  'split-tunnel:set-rule': (appId: string, rule: 'vpn' | 'direct' | 'none') => void
  'split-tunnel:add-app': (exePath: string) => SplitTunnelApp
  'split-tunnel:remove-app': (appId: string) => void
  'split-tunnel:get-config': () => SplitTunnelConfig
}

/** Server/Profile Picker IPC channels */
export interface ServerChannels {
  'servers:list': () => ServerProfile[]
  'servers:select': (id: string) => void
  'servers:get-active': () => { profile: ServerProfile | null; activeId: string | null }
  'servers:ping-all': () => ServerProfile[]
  'servers:resolve-ips': () => ServerProfile[]
  'servers:add': (input: string, options?: { clientDevice?: ClientDevice }) => ServerProfile[]
  /**
   * Append a profile (single VPN URI) or a batch of profiles (subscription
   * URL) to a specific group. When `groupId` is null we fall back to the
   * defaults: subscription → new "subscription" group, single URI → the
   * shared "Ручные ключи" group (auto-created).
   */
  'servers:add-to-group': (input: string, groupId: string | null, options?: { clientDevice?: ClientDevice }) => ServerProfile[]
  'servers:set-client-device': (id: string, clientDevice: ClientDevice) => ServerProfile
  'servers:verify-country': (id: string) =>
    | { ok: true; country: string; profile: ServerProfile }
    | { ok: false; reason: string; country?: string }
  'servers:remove': (id: string) => void
  'servers:export-key': (id: string) =>
    | { ok: true; uri: string; name: string; protocol: string }
    | { ok: false; reason: string; protocol?: string }
  'servers:export-key-file': (id: string) =>
    | { ok: true; path: string; uri: string; name: string; protocol: string }
    | { ok: false; cancelled: true }
    | { ok: false; reason: string; protocol?: string; error?: string }
  'servers:export-all-keys-file': () =>
    | { ok: true; path: string; total: number; exported: number; skipped: number }
    | { ok: false; cancelled: true }
    | { ok: false; reason: string; error?: string; total?: number; skipped?: number }
  'servers:export-all-proxies-file': () =>
    | { ok: true; path: string; total: number; exported: number; skipped: number }
    | { ok: false; cancelled: true }
    | { ok: false; reason: string; error?: string; total?: number; skipped?: number }
  // ── Server group management ────────────────────────────────────────────
  'groups:list': () => ServerGroup[]
  'groups:get': (id: string) => ServerGroup | null
  'groups:rename': (id: string, name: string) => ServerGroup | null
  /**
   * If `deleteServers` is true, every profile with `groupId === id` is also
   * removed from the picker store (and the active selection is cleared if
   * it pointed at one of them). Otherwise the profiles are detached
   * (`groupId` cleared) — they end up "ungrouped" and can be reassigned
   * later by the user.
   */
  'groups:delete': (id: string, deleteServers: boolean) => { ok: boolean }
  /**
   * Re-fetch the upstream subscription. On success the group is marked
   * `active`, profiles are dedupe-merged, and `lastSeenInSubscriptionAt` is
   * stamped on every profile that came back. A successful non-empty response
   * archives and disables profiles no longer published upstream. On failure
   * or an empty expired response, the last usable list is retained unchanged.
   *
   * The outer envelope distinguishes "the call itself failed" (network
   * issue, group not found) from "the refresh succeeded but the panel is
   * gone" — the latter still returns `ok: true`.
   */
  'groups:refresh': (id: string) =>
    | { ok: true; group: ServerGroup; addedCount: number; updatedCount: number; removedCount: number }
    | { ok: false; error: string }
  /**
   * Run a TCP/TLS health probe across every profile in the group.
   * Delegates to keyHealthChecker (Agent C). Wrapped in a try/catch so the
   * UI gets a friendly error if the module isn't wired up yet.
   */
  'groups:check-health': (id: string) =>
    | { ok: true; results: Array<{ profileId: string; online: boolean; latencyMs: number | null; reason?: string }> }
    | { ok: false; error: string }
  // ── Live Server Extraction & Technical Profile ──────────────────────────────
  'server:live-check': (options: LiveServerCheckOptions) => Promise<LiveServerCheck>
  'server:live-check-cancel': (requestId?: string) => Promise<{ cancelled: boolean; reason?: string }>
  'server:live-check-history': (filter?: { profileId?: string; host?: string }) => Promise<LiveServerCheck[]>
  'server:live-check-progress': (callback: (progress: LiveCheckProgress) => void) => void
}

/** Speed Test IPC channels */
export interface SpeedTestChannels {
  'speed-test:run': () => SpeedTestResult
  'speed-test:history': () => SpeedTestResult[]
  'speed-test:progress': (callback: (percent: number, phase: string) => void) => void
}

/** Granular Kill-Switch IPC channels */
export interface KillSwitchChannels {
  'kill-switch:get-level': () => KillSwitchLevel
  'kill-switch:set-level': (level: KillSwitchLevel) => void
  'kill-switch:get-exceptions': () => KillSwitchException[]
  'kill-switch:add-exception': (
    exception: Omit<KillSwitchException, 'id'>
  ) => KillSwitchException
  'kill-switch:remove-exception': (id: string) => void
}

/** Profile Rotation IPC channels */
export interface RotationChannels {
  'rotation:get-config': () => RotationConfig
  'rotation:set-config': (config: Partial<RotationConfig>) => RotationConfig
  'rotation:rotate-now': () => { success: boolean; newProfile: string }
}

/** Scheduler IPC channels */
export interface SchedulerChannels {
  'scheduler:list': () => ScheduleEntry[]
  'scheduler:create': (entry: Omit<ScheduleEntry, 'id'>) => ScheduleEntry
  'scheduler:update': (id: string, patch: Partial<ScheduleEntry>) => ScheduleEntry
  'scheduler:delete': (id: string) => void
  'scheduler:next-event': () => {
    type: 'start' | 'stop'
    at: number
    schedule: ScheduleEntry
  } | null
}

/** DNS Profiles IPC channels */
export interface DnsChannels {
  'dns:list': () => DnsProfile[]
  'dns:create': (profile: Omit<DnsProfile, 'id' | 'isBuiltin'>) => DnsProfile
  'dns:update': (id: string, patch: Partial<DnsProfile>) => DnsProfile
  'dns:delete': (id: string) => void
  'dns:select': (id: string) => void
  'dns:validate': (address: string) => {
    valid: boolean
    type: 'plain' | 'doh' | 'dot'
    error?: string
  }
}

/** Per-Domain Routing IPC channels */
export interface DomainRoutingChannels {
  'domain-routing:list': () => DomainRule[]
  'domain-routing:add': (rule: Omit<DomainRule, 'id' | 'hitCount'>) => DomainRule
  'domain-routing:update': (id: string, patch: Partial<DomainRule>) => DomainRule
  'domain-routing:delete': (id: string) => void
  'domain-routing:reorder': (ids: string[]) => DomainRule[]
  'domain-routing:import': (filePath: string) => DomainRule[]
  'domain-routing:reset-hits': () => void
}

/** Import/Export IPC channels */
export interface ImportExportChannels {
  'config:export': () => { success: boolean; path?: string; error?: string }
  'config:import': (filePath: string) => {
    success: boolean
    sections: string[]
    conflicts: string[]
    error?: string
  }
  'config:import-apply': (
    filePath: string,
    sections: string[],
    conflictResolution: 'replace' | 'merge'
  ) => { success: boolean; error?: string }
}

/** i18n IPC channels */
export interface I18nChannels {
  'i18n:get-locale': () => Locale
  'i18n:set-locale': (locale: Locale) => void
  'i18n:get-system-locale': () => Locale
}

/** Notification preferences IPC channels */
export interface NotificationChannels {
  'notifications:get-prefs': () => NotificationPreferences
  'notifications:set-prefs': (
    prefs: Partial<NotificationPreferences>
  ) => NotificationPreferences
  'notifications:check-os-state': () => {
    osNotificationsEnabled: boolean
    appUserModelId: string | null
  }
}

/** Theme IPC channels */
export interface ThemeChannels {
  'theme:list': () => ThemeConfig[]
  'theme:get-active': () => ThemeConfig
  'theme:set-active': (id: string) => void
  'theme:create': (theme: Omit<ThemeConfig, 'id' | 'isCustom'>) => ThemeConfig
  'theme:delete': (id: string) => void
}

/** Dashboard Widget IPC channels */
export interface WidgetChannels {
  'widgets:get-layout': () => WidgetLayout[]
  'widgets:set-layout': (layout: WidgetLayout[]) => void
}
