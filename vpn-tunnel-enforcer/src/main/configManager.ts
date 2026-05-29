/**
 * Config Manager — main process module for full settings export/import.
 *
 * Responsibilities:
 * - Export all settings from all stores into a single JSON file (version "2.0")
 * - Validate import files (version check, required keys, type checks)
 * - Support selective import (only chosen sections)
 * - Detect and resolve conflicts (replace or merge)
 * - Register IPC handlers for ImportExportChannels:
 *   - 'config:export' → exports and saves to file
 *   - 'config:import' → validates and returns sections/conflicts
 *   - 'config:import-apply' → applies the import
 *
 * Validates: Requirements 15.1, 15.2, 15.3, 15.4, 15.5
 *
 * Pure functions exported for property testing:
 * - validateImportData(data)
 * - detectConflicts(existing, incoming)
 * - applySelectiveImport(existing, incoming, sections, conflictResolution)
 */

import { ipcMain, dialog, type IpcMainInvokeEvent } from 'electron'
import { readFileSync, writeFileSync } from 'fs'
import Store from 'electron-store'
import { logEvent } from './appLogger'
import type {
  SplitTunnelApp,
  ServerProfile,
  ServerGroup,
  ScheduleEntry,
  DnsProfile,
  DomainRule,
  ThemeConfig,
  WidgetLayout,
  RotationConfig,
  KillSwitchLevel,
  KillSwitchException,
  NotificationPreferences
} from '../shared/ipc-types'

// ─── Constants ───────────────────────────────────────────────────────────────

export const CONFIG_VERSION = '2.0'

export const ALL_SECTIONS = [
  'profiles',
  'serverGroups',
  'schedules',
  'splitTunnel',
  'dns',
  'domainRouting',
  'themes',
  'widgets',
  'rotation',
  'killSwitch',
  'notifications'
] as const

export type ConfigSection = (typeof ALL_SECTIONS)[number]

// ─── Export Data Shape ───────────────────────────────────────────────────────

export interface ConfigExportData {
  version: string
  exportedAt: number
  profiles: ServerProfile[]
  serverGroups: ServerGroup[]
  schedules: ScheduleEntry[]
  splitTunnel: SplitTunnelApp[]
  dns: DnsProfile[]
  domainRouting: DomainRule[]
  themes: ThemeConfig[]
  widgets: WidgetLayout[]
  rotation: RotationConfig
  killSwitch: {
    level: KillSwitchLevel
    exceptions: KillSwitchException[]
  }
  notifications: NotificationPreferences
}

// ─── Stores (read from individual electron-store instances) ──────────────────

const splitTunnelStore = new Store<{ splitTunnelApps: SplitTunnelApp[] }>({
  name: 'split-tunnel',
  defaults: { splitTunnelApps: [] }
})

const serverPickerStore = new Store<{ profiles: ServerProfile[] }>({
  name: 'server-picker',
  defaults: { profiles: [] }
})

const serverGroupsStore = new Store<{ groups: ServerGroup[] }>({
  name: 'server-groups',
  defaults: { groups: [] }
})

const schedulerStore = new Store<{ schedules: ScheduleEntry[] }>({
  name: 'scheduler',
  defaults: { schedules: [] }
})

const dnsStore = new Store<{ customProfiles: DnsProfile[]; activeProfileId: string | null }>({
  name: 'dns-profiles',
  defaults: { customProfiles: [], activeProfileId: null }
})

const domainRoutingStore = new Store<{ domainRules: DomainRule[] }>({
  name: 'domain-routing',
  defaults: { domainRules: [] }
})

const themeStore = new Store<{ activeThemeId: string; customThemes: ThemeConfig[] }>({
  name: 'themes',
  defaults: { activeThemeId: 'builtin-system', customThemes: [] }
})

const widgetStore = new Store<{ widgetLayout: WidgetLayout[] }>({
  name: 'widget-layout',
  defaults: { widgetLayout: [] }
})

const rotationStore = new Store<{ rotation: RotationConfig }>({
  name: 'profile-rotation',
  defaults: {
    rotation: {
      enabled: false,
      intervalMinutes: 30,
      order: 'sequential',
      profileIds: [],
      currentIndex: 0,
      nextRotationAt: null
    }
  }
})

const killSwitchStore = new Store<{
  killSwitchLevel: KillSwitchLevel
  killSwitchExceptions: KillSwitchException[]
}>({
  name: 'granular-kill-switch',
  defaults: { killSwitchLevel: 'off', killSwitchExceptions: [] }
})

// ─── Default Notification Preferences ────────────────────────────────────────

const DEFAULT_NOTIFICATION_PREFS: NotificationPreferences = {
  vpnConnect: true,
  vpnDisconnect: true,
  leakDetected: true,
  profileRotation: true,
  scheduleTriggered: true,
  connectionError: true,
  method: 'system',
  sound: true
}

// Notification prefs store (matches notificationPrefs.ts store schema)
const notificationStore = new Store<{ notificationPrefs: NotificationPreferences }>({
  name: 'notification-prefs',
  defaults: { notificationPrefs: DEFAULT_NOTIFICATION_PREFS }
})

// ─── Built-in DNS profiles (needed for full export) ──────────────────────────

const BUILTIN_DNS_PROFILES: DnsProfile[] = [
  { id: 'builtin-cloudflare', name: 'Cloudflare', primary: '1.1.1.1', secondary: '1.0.0.1', type: 'plain', isBuiltin: true },
  { id: 'builtin-google', name: 'Google', primary: '8.8.8.8', secondary: '8.8.4.4', type: 'plain', isBuiltin: true },
  { id: 'builtin-quad9', name: 'Quad9', primary: '9.9.9.9', secondary: '149.112.112.112', type: 'plain', isBuiltin: true },
  { id: 'builtin-adguard', name: 'AdGuard', primary: '94.140.14.14', secondary: '94.140.15.15', type: 'plain', isBuiltin: true }
]

// ─── Pure Functions (exported for property testing) ──────────────────────────

/**
 * Validates an import data object.
 *
 * Checks:
 * - Must be a non-null object
 * - Must have a 'version' field equal to CONFIG_VERSION
 * - Must have at least one recognized section key
 * - Section values must be of the correct type (arrays for list sections, objects for object sections)
 *
 * Returns { valid, sections, error? } where sections lists the recognized sections present.
 */
export function validateImportData(data: unknown): {
  valid: boolean
  sections: ConfigSection[]
  error?: string
} {
  if (!data || typeof data !== 'object') {
    return { valid: false, sections: [], error: 'Invalid format: expected a JSON object' }
  }

  const obj = data as Record<string, unknown>

  // Version check
  if (!('version' in obj)) {
    return { valid: false, sections: [], error: 'Missing required field: version' }
  }

  if (obj.version !== CONFIG_VERSION) {
    return {
      valid: false,
      sections: [],
      error: `Incompatible version: expected "${CONFIG_VERSION}", got "${String(obj.version)}"`
    }
  }

  // Detect which sections are present
  const foundSections: ConfigSection[] = []

  const arraySections: ConfigSection[] = [
    'profiles',
    'serverGroups',
    'schedules',
    'splitTunnel',
    'dns',
    'domainRouting',
    'themes',
    'widgets'
  ]

  for (const section of arraySections) {
    if (section in obj) {
      if (!Array.isArray(obj[section])) {
        return {
          valid: false,
          sections: [],
          error: `Invalid type for section "${section}": expected array`
        }
      }
      foundSections.push(section)
    }
  }

  // Object sections
  if ('rotation' in obj) {
    if (!obj.rotation || typeof obj.rotation !== 'object') {
      return {
        valid: false,
        sections: [],
        error: 'Invalid type for section "rotation": expected object'
      }
    }
    foundSections.push('rotation')
  }

  if ('killSwitch' in obj) {
    if (!obj.killSwitch || typeof obj.killSwitch !== 'object') {
      return {
        valid: false,
        sections: [],
        error: 'Invalid type for section "killSwitch": expected object'
      }
    }
    foundSections.push('killSwitch')
  }

  if ('notifications' in obj) {
    if (!obj.notifications || typeof obj.notifications !== 'object') {
      return {
        valid: false,
        sections: [],
        error: 'Invalid type for section "notifications": expected object'
      }
    }
    foundSections.push('notifications')
  }

  if (foundSections.length === 0) {
    return {
      valid: false,
      sections: [],
      error: 'No recognized configuration sections found in the file'
    }
  }

  return { valid: true, sections: foundSections }
}

/**
 * Detects conflicts between existing and incoming configuration data.
 *
 * A conflict exists for a section when:
 * - Both existing and incoming have non-empty/non-default data for that section
 *
 * Returns an array of section names that have conflicts.
 */
export function detectConflicts(
  existing: ConfigExportData,
  incoming: ConfigExportData
): ConfigSection[] {
  const conflicts: ConfigSection[] = []

  // Array sections: conflict if both have non-empty arrays
  if (existing.profiles.length > 0 && incoming.profiles.length > 0) {
    conflicts.push('profiles')
  }
  if (existing.serverGroups.length > 0 && incoming.serverGroups.length > 0) {
    conflicts.push('serverGroups')
  }
  if (existing.schedules.length > 0 && incoming.schedules.length > 0) {
    conflicts.push('schedules')
  }
  if (existing.splitTunnel.length > 0 && incoming.splitTunnel.length > 0) {
    conflicts.push('splitTunnel')
  }
  if (existing.dns.length > 0 && incoming.dns.length > 0) {
    conflicts.push('dns')
  }
  if (existing.domainRouting.length > 0 && incoming.domainRouting.length > 0) {
    conflicts.push('domainRouting')
  }
  if (existing.themes.length > 0 && incoming.themes.length > 0) {
    conflicts.push('themes')
  }
  if (existing.widgets.length > 0 && incoming.widgets.length > 0) {
    conflicts.push('widgets')
  }

  // Object sections: conflict if existing has non-default values
  if (existing.rotation.enabled || existing.rotation.profileIds.length > 0) {
    if (
      incoming.rotation &&
      (incoming.rotation.enabled || incoming.rotation.profileIds.length > 0)
    ) {
      conflicts.push('rotation')
    }
  }

  if (existing.killSwitch.level !== 'off' || existing.killSwitch.exceptions.length > 0) {
    if (
      incoming.killSwitch &&
      (incoming.killSwitch.level !== 'off' || incoming.killSwitch.exceptions.length > 0)
    ) {
      conflicts.push('killSwitch')
    }
  }

  // Notifications: conflict if existing differs from defaults
  const existingNotif = existing.notifications
  const incomingNotif = incoming.notifications
  const hasCustomNotifPrefs =
    !existingNotif.vpnConnect ||
    !existingNotif.vpnDisconnect ||
    !existingNotif.leakDetected ||
    !existingNotif.profileRotation ||
    !existingNotif.scheduleTriggered ||
    !existingNotif.connectionError ||
    existingNotif.method !== 'system' ||
    !existingNotif.sound

  if (hasCustomNotifPrefs && incomingNotif) {
    conflicts.push('notifications')
  }

  return conflicts
}

/**
 * Applies a selective import, modifying only the specified sections.
 *
 * - 'replace' mode: overwrites the section entirely with incoming data
 * - 'merge' mode: for array sections, concatenates existing + incoming (deduplicating by id);
 *   for object sections, deep-merges incoming into existing
 *
 * Returns the merged result.
 */
export function applySelectiveImport(
  existing: ConfigExportData,
  incoming: ConfigExportData,
  sections: ConfigSection[],
  conflictResolution: 'replace' | 'merge'
): ConfigExportData {
  const result = { ...existing }

  for (const section of sections) {
    switch (section) {
      case 'profiles':
        result.profiles = mergeArraySection(
          existing.profiles,
          incoming.profiles,
          conflictResolution
        )
        break
      case 'serverGroups':
        result.serverGroups = mergeArraySection(
          existing.serverGroups,
          incoming.serverGroups,
          conflictResolution
        )
        break
      case 'schedules':
        result.schedules = mergeArraySection(
          existing.schedules,
          incoming.schedules,
          conflictResolution
        )
        break
      case 'splitTunnel':
        result.splitTunnel = mergeArraySection(
          existing.splitTunnel,
          incoming.splitTunnel,
          conflictResolution
        )
        break
      case 'dns':
        result.dns = mergeArraySection(existing.dns, incoming.dns, conflictResolution)
        break
      case 'domainRouting':
        result.domainRouting = mergeArraySection(
          existing.domainRouting,
          incoming.domainRouting,
          conflictResolution
        )
        break
      case 'themes':
        result.themes = mergeArraySection(
          existing.themes,
          incoming.themes,
          conflictResolution
        )
        break
      case 'widgets':
        result.widgets = mergeArraySection(
          existing.widgets,
          incoming.widgets,
          conflictResolution
        )
        break
      case 'rotation':
        if (conflictResolution === 'replace') {
          result.rotation = incoming.rotation
        } else {
          result.rotation = { ...existing.rotation, ...incoming.rotation }
        }
        break
      case 'killSwitch':
        if (conflictResolution === 'replace') {
          result.killSwitch = incoming.killSwitch
        } else {
          result.killSwitch = {
            level: incoming.killSwitch.level,
            exceptions: mergeArraySection(
              existing.killSwitch.exceptions,
              incoming.killSwitch.exceptions,
              'merge'
            )
          }
        }
        break
      case 'notifications':
        if (conflictResolution === 'replace') {
          result.notifications = incoming.notifications
        } else {
          result.notifications = { ...existing.notifications, ...incoming.notifications }
        }
        break
    }
  }

  return result
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Merges two arrays of objects with 'id' fields.
 * - 'replace': returns incoming array only
 * - 'merge': concatenates, deduplicating by id (incoming wins on conflict)
 */
function mergeArraySection<T extends { id: string }>(
  existing: T[],
  incoming: T[],
  mode: 'replace' | 'merge'
): T[] {
  if (mode === 'replace') {
    return incoming
  }

  // Merge: existing + incoming, incoming wins on duplicate id
  const map = new Map<string, T>()
  for (const item of existing) {
    map.set(item.id, item)
  }
  for (const item of incoming) {
    map.set(item.id, item)
  }
  return Array.from(map.values())
}

// ─── Collect Current Config ──────────────────────────────────────────────────

/**
 * Collects all current settings from all stores into a ConfigExportData object.
 */
export function collectCurrentConfig(): ConfigExportData {
  const customDns = dnsStore.get('customProfiles') ?? []
  const allDns = [...BUILTIN_DNS_PROFILES, ...customDns]

  return {
    version: CONFIG_VERSION,
    exportedAt: Date.now(),
    profiles: serverPickerStore.get('profiles') ?? [],
    serverGroups: serverGroupsStore.get('groups') ?? [],
    schedules: schedulerStore.get('schedules') ?? [],
    splitTunnel: splitTunnelStore.get('splitTunnelApps') ?? [],
    dns: allDns,
    domainRouting: domainRoutingStore.get('domainRules') ?? [],
    themes: themeStore.get('customThemes') ?? [],
    widgets: widgetStore.get('widgetLayout') ?? [],
    rotation: rotationStore.get('rotation') ?? {
      enabled: false,
      intervalMinutes: 30,
      order: 'sequential',
      profileIds: [],
      currentIndex: 0,
      nextRotationAt: null
    },
    killSwitch: {
      level: killSwitchStore.get('killSwitchLevel') ?? 'off',
      exceptions: killSwitchStore.get('killSwitchExceptions') ?? []
    },
    notifications: notificationStore.get('notificationPrefs') ?? DEFAULT_NOTIFICATION_PREFS
  }
}

/**
 * Writes sections from a ConfigExportData object back to the respective stores.
 */
function writeConfigToStores(config: ConfigExportData, sections: ConfigSection[]): void {
  for (const section of sections) {
    switch (section) {
      case 'profiles':
        serverPickerStore.set('profiles', config.profiles)
        break
      case 'serverGroups':
        serverGroupsStore.set('groups', config.serverGroups)
        break
      case 'schedules':
        schedulerStore.set('schedules', config.schedules)
        break
      case 'splitTunnel':
        splitTunnelStore.set('splitTunnelApps', config.splitTunnel)
        break
      case 'dns': {
        // Separate builtin from custom
        const custom = config.dns.filter((d) => !d.isBuiltin)
        dnsStore.set('customProfiles', custom)
        break
      }
      case 'domainRouting':
        domainRoutingStore.set('domainRules', config.domainRouting)
        break
      case 'themes':
        themeStore.set('customThemes', config.themes)
        break
      case 'widgets':
        widgetStore.set('widgetLayout', config.widgets)
        break
      case 'rotation':
        rotationStore.set('rotation', config.rotation)
        break
      case 'killSwitch':
        killSwitchStore.set('killSwitchLevel', config.killSwitch.level)
        killSwitchStore.set('killSwitchExceptions', config.killSwitch.exceptions)
        break
      case 'notifications':
        notificationStore.set('notificationPrefs', config.notifications)
        break
    }
  }
}

// ─── Export ──────────────────────────────────────────────────────────────────

/**
 * Exports all settings to a JSON file via save dialog.
 */
async function exportConfig(): Promise<{ success: boolean; path?: string; error?: string }> {
  try {
    const result = await dialog.showSaveDialog({
      title: 'Export Configuration',
      defaultPath: `vpn-tunnel-enforcer-config-${Date.now()}.json`,
      filters: [{ name: 'JSON Files', extensions: ['json'] }]
    })

    if (result.canceled || !result.filePath) {
      return { success: false, error: 'Export cancelled' }
    }

    const config = collectCurrentConfig()
    const json = JSON.stringify(config, null, 2)
    writeFileSync(result.filePath, json, 'utf-8')

    logEvent('info', 'config-manager', 'config exported', { path: result.filePath })
    return { success: true, path: result.filePath }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    logEvent('error', 'config-manager', 'export failed', { error: message })
    return { success: false, error: message }
  }
}

// ─── Import (Validate) ──────────────────────────────────────────────────────

/**
 * Validates an import file and returns available sections and conflicts.
 */
function importValidate(filePath: string): {
  success: boolean
  sections: string[]
  conflicts: string[]
  error?: string
} {
  try {
    const raw = readFileSync(filePath, 'utf-8')
    let parsed: unknown

    try {
      parsed = JSON.parse(raw)
    } catch {
      return { success: false, sections: [], conflicts: [], error: 'Invalid JSON format' }
    }

    const validation = validateImportData(parsed)
    if (!validation.valid) {
      return { success: false, sections: [], conflicts: [], error: validation.error }
    }

    // Detect conflicts with current config
    const existing = collectCurrentConfig()
    const incoming = parsed as ConfigExportData
    const conflicts = detectConflicts(existing, incoming)

    // Only report conflicts for sections that are actually in the import
    const relevantConflicts = conflicts.filter((c) => validation.sections.includes(c))

    logEvent('info', 'config-manager', 'import validated', {
      filePath,
      sections: validation.sections,
      conflicts: relevantConflicts
    })

    return {
      success: true,
      sections: validation.sections,
      conflicts: relevantConflicts
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    logEvent('error', 'config-manager', 'import validation failed', { error: message })
    return { success: false, sections: [], conflicts: [], error: message }
  }
}

// ─── Import (Apply) ─────────────────────────────────────────────────────────

/**
 * Applies selected sections from an import file with the specified conflict resolution.
 */
function importApply(
  filePath: string,
  sections: string[],
  conflictResolution: 'replace' | 'merge'
): { success: boolean; error?: string } {
  try {
    const raw = readFileSync(filePath, 'utf-8')
    const parsed = JSON.parse(raw) as ConfigExportData

    // Re-validate
    const validation = validateImportData(parsed)
    if (!validation.valid) {
      return { success: false, error: validation.error }
    }

    // Filter to only valid sections
    const validSections = sections.filter((s) =>
      ALL_SECTIONS.includes(s as ConfigSection)
    ) as ConfigSection[]

    if (validSections.length === 0) {
      return { success: false, error: 'No valid sections selected for import' }
    }

    const existing = collectCurrentConfig()
    const merged = applySelectiveImport(existing, parsed, validSections, conflictResolution)

    // Write merged data back to stores
    writeConfigToStores(merged, validSections)

    // C16: refresh in-memory service state for sections whose live services
    // cache data loaded at init. Without this, imported schedules/rotation/
    // kill-switch values sit on disk but the running services keep using
    // their stale in-memory copies until the next app restart. Best-effort —
    // a refresh failure must not fail the import. Lazy require to avoid
    // pulling these heavy modules into configManager's import graph.
    try {
      if (validSections.includes('rotation')) {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const { initProfileRotation } = require('./profileRotation')
        initProfileRotation()
      }
      if (validSections.includes('schedules')) {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const { schedulerService } = require('./scheduler')
        schedulerService.reschedule?.()
      }
      if (validSections.includes('killSwitch')) {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const { granularKillSwitch } = require('./granularKillSwitch')
        granularKillSwitch.reloadFromStore?.()
      }
    } catch (err) {
      logEvent('warn', 'config-manager', 'post-import service refresh failed', { err: (err as Error)?.message })
    }

    logEvent('info', 'config-manager', 'import applied', {
      filePath,
      sections: validSections,
      conflictResolution
    })

    return { success: true }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    logEvent('error', 'config-manager', 'import apply failed', { error: message })
    return { success: false, error: message }
  }
}

// ─── Public API ──────────────────────────────────────────────────────────────

export const configManager = {
  exportConfig,
  importValidate,
  importApply,
  collectCurrentConfig
}

// ─── IPC Registration ────────────────────────────────────────────────────────

function handleLogged<T>(
  channel: string,
  listener: (event: IpcMainInvokeEvent, ...args: any[]) => Promise<T> | T
): void {
  ipcMain.handle(channel, async (event, ...args) => {
    const started = Date.now()
    logEvent('debug', 'ipc', `${channel} started`, { args })
    try {
      const result = await listener(event, ...args)
      logEvent('debug', 'ipc', `${channel} finished`, { ms: Date.now() - started })
      return result
    } catch (err) {
      logEvent('error', 'ipc', `${channel} failed`, err)
      throw err
    }
  })
}

/**
 * Registers all config manager IPC handlers.
 * Should be called once during app initialization.
 */
export function registerConfigManagerIpcHandlers(): void {
  // config:export — exports all settings and saves to file via dialog
  handleLogged('config:export', async () => {
    return await configManager.exportConfig()
  })

  // config:import — validates a file and returns sections/conflicts
  handleLogged('config:import', async (_event, filePath: string) => {
    return configManager.importValidate(filePath)
  })

  // config:import-apply — applies selected sections from import file
  handleLogged(
    'config:import-apply',
    async (_event, filePath: string, sections: string[], conflictResolution: 'replace' | 'merge') => {
      return configManager.importApply(filePath, sections, conflictResolution)
    }
  )

  // config:browse-import — opens file dialog to select a JSON config file
  ipcMain.handle('config:browse-import', async () => {
    const result = await dialog.showOpenDialog({
      properties: ['openFile'],
      filters: [
        { name: 'JSON Files', extensions: ['json'] },
        { name: 'All Files', extensions: ['*'] }
      ]
    })
    if (result.canceled || result.filePaths.length === 0) {
      return null
    }
    return result.filePaths[0]
  })
}
