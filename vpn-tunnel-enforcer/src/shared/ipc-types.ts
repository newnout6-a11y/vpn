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
