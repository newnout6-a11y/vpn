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
}

/** Split Tunneling full configuration */
export interface SplitTunnelConfig {
  apps: SplitTunnelApp[]
  enabled: boolean
}

/** Server/Profile entry */
export interface ServerProfile {
  id: string
  name: string
  protocol: string
  server: string
  port: number
  country?: string
  ping?: number | null
  status: 'online' | 'offline' | 'unknown'
  lastChecked?: number
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
  /** Number of profiles seen on the most recent successful refresh. */
  lastRefreshProfilesCount?: number
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
  isBuiltin: boolean
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
  colors: {
    background: string
    cardBackground: string
    accent: string
    text: string
    textSecondary: string
    sidebar: string
    border: string
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
  'servers:add': (input: string) => ServerProfile[]
  /**
   * Append a profile (single VPN URI) or a batch of profiles (subscription
   * URL) to a specific group. When `groupId` is null we fall back to the
   * defaults: subscription → new "subscription" group, single URI → the
   * shared "Ручные ключи" group (auto-created).
   */
  'servers:add-to-group': (input: string, groupId: string | null) => ServerProfile[]
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
    | { ok: false; reason: string; error?: string }
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
   * stamped on every profile that came back. On failure the group is
   * marked `expired` and profiles are LEFT IN PLACE — post-trial keys
   * routinely keep working for hours after the panel goes 403.
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
