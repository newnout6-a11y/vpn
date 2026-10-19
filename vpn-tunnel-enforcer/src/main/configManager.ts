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

import { ipcMain, dialog, type IpcMainInvokeEvent, type WebContents } from 'electron'
import { randomUUID } from 'crypto'
import Store from './versionedStore'
import { logEvent } from './appLogger'
import { compactForIpcLog } from './ipcLogging'
import { withSecretExportConsent } from './secretExportConsent'
import { redactConfigExport } from './configExportPolicy'
import { requireEnum, requireString, requireStringArray } from './ipcValidation'
import { IpcFault, classifyIpcError } from '../shared/ipc-result'
import { ioFailureDetails } from './ioFailureDiagnostics'
import { serverPickerStore, serverGroupsStore, granularKillSwitchStore } from './sharedStores'
import { operations } from './operations'
import type { OperationLease } from './operationRegistry'
import { withProfileStoreWriteLock } from './profileStoreQueue'
import { readSelectedConfig, writeConfigExport } from './configOperationIo'
import { requestDocumentLifetime } from './requestDocumentLifetime'
import type {
  SplitTunnelApp,
  ServerProfile,
  ServerGroup,
  ScheduleEntry,
  DnsProfile,
  DomainRule,
  ThemeConfig,
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
  'rotation',
  'killSwitch',
  'notifications'
] as const

export type ConfigSection = (typeof ALL_SECTIONS)[number]
interface ConfigOperationOptions {
  signal?: AbortSignal
  sender?: WebContents
  requestId?: string
  assertAuthorized?: () => void
}

interface ConfigRequest { controller: AbortController; operationId?: string }
const configRequests = new WeakMap<WebContents, Map<string, ConfigRequest>>()
function configRequestId(value: unknown): string | undefined {
  if (value === undefined) return undefined
  const id = requireString(value, 'requestId', { maxLength: 36 })
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)) throw new IpcFault('validation')
  return id.toLowerCase()
}

/** Main-only lifetime; renderer arguments cannot supply these options. */
async function runConfigOperation<T>(kind: 'import' | 'export', resource: string, effect: (lease: OperationLease) => Promise<T>, options: ConfigOperationOptions = {}): Promise<T> {
  const { sender, requestId } = options
  if (requestId && !sender) throw new IpcFault('validation')
  const requests = sender ? configRequests.get(sender) ?? new Map<string, ConfigRequest>() : undefined
  if (requestId && requests?.has(requestId)) throw new IpcFault('conflict')
  const request: ConfigRequest | undefined = requestId ? { controller: new AbortController() } : undefined
  const signal = request ? options.signal ? AbortSignal.any([options.signal, request.controller.signal]) : request.controller.signal : options.signal
  const lifetime = requestDocumentLifetime(sender, signal)
  if (sender && requestId && request) { requests!.set(requestId, request); configRequests.set(sender, requests!) }
  try { return await operations.run(kind, lease => {
    if (request) request.operationId = lease.operation.operationId
    return effect(lease)
  }, { resource, signal: lifetime.signal }) }
  finally {
    lifetime.dispose()
    if (requestId && requests && requests.get(requestId) === request) requests.delete(requestId)
    if (sender && requests?.size === 0 && configRequests.get(sender) === requests) configRequests.delete(sender)
  }
}

const yieldConfigOperation = (lease: OperationLease) => lease.wait(new Promise<void>(done => setImmediate(done)))

type ImportValidationCode = 'not-object' | 'missing-version' | 'incompatible-version'
  | 'no-sections' | 'profile-entry' | 'rotation-fields' | 'invalid-json' | 'invalid-config' | 'selected-sections'
  | 'file-too-large' | 'file-not-regular' | 'file-changed'
  | `section-type:${ConfigSection}`

// ─── Export Data Shape ───────────────────────────────────────────────────────

export interface ConfigExportData {
  version: string
  exportedAt: number
  profiles: ServerProfile[]
  serverGroups: ServerGroup[]
  schedules: ScheduleEntry[]
  splitTunnel: SplitTunnelApp[]
  dns: DnsProfile[]
  /** Which DNS profile was active at export time (id into `dns`); null = system default. */
  activeDnsProfileId: string | null
  domainRouting: DomainRule[]
  themes: ThemeConfig[]
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

// server-picker, server-groups, granular-kill-switch use shared singletons

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

// granular-kill-switch uses shared singleton from sharedStores.ts

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
function isImportedProfile(value: unknown): boolean {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const profile = value as Record<string, unknown>
  if (!['id', 'name', 'protocol', 'server'].every(key => typeof profile[key] === 'string')
    || typeof profile.port !== 'number' || !Number.isInteger(profile.port) || profile.port < 1 || profile.port > 65535
    || typeof profile.status !== 'string' || !['online', 'offline', 'unknown'].includes(profile.status)) return false
  const strings = ['resolvedIp', 'country', 'countryVerifiedIp', 'egressIp', 'clientFingerprint', 'healthReason', 'groupId', 'sourceUri']
  const numbers = ['resolvedIpAt', 'countryVerifiedAt', 'countryGeoVersion', 'lastChecked', 'healthCheckedAt', 'lastSeenInSubscriptionAt', 'removedFromSubscriptionAt']
  if (!strings.every(key => profile[key] === undefined || typeof profile[key] === 'string')
    || !numbers.every(key => profile[key] === undefined || (typeof profile[key] === 'number' && Number.isFinite(profile[key])))
    || !['enabled', 'enabledBeforeSubscriptionRemoval'].every(key => profile[key] === undefined || typeof profile[key] === 'boolean')
    || !['ping', 'healthLatencyMs'].every(key => profile[key] == null || (typeof profile[key] === 'number' && Number.isFinite(profile[key])))) return false
  return (profile.healthStatus === undefined || (typeof profile.healthStatus === 'string' && ['online', 'offline', 'unknown'].includes(profile.healthStatus)))
    && (profile.clientDevice === undefined || (typeof profile.clientDevice === 'string' && ['pc', 'android', 'ios', 'mac'].includes(profile.clientDevice)))
    && (profile.outbound === undefined || (profile.outbound !== null && typeof profile.outbound === 'object' && !Array.isArray(profile.outbound)))
}

export function validateImportData(data: unknown): {
  valid: boolean
  sections: ConfigSection[]
  error?: string
  reasonCode?: ImportValidationCode
} {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return { valid: false, sections: [], reasonCode: 'not-object', error: 'Invalid format: expected a JSON object' }
  }

  const obj = data as Record<string, unknown>

  // Version check
  if (!('version' in obj)) {
    return { valid: false, sections: [], reasonCode: 'missing-version', error: 'Missing required field: version' }
  }

  if (obj.version !== CONFIG_VERSION) {
    return {
      valid: false,
      sections: [],
      reasonCode: 'incompatible-version',
      error: `Incompatible version: expected "${CONFIG_VERSION}"`
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
    'themes'
  ]

  for (const section of arraySections) {
    if (section in obj) {
      if (!Array.isArray(obj[section])) {
        return {
          valid: false,
          sections: [],
          reasonCode: `section-type:${section}`,
          error: `Invalid type for section "${section}": expected array`
        }
      }
      foundSections.push(section)
    }
  }

  if (Array.isArray(obj.profiles) && !obj.profiles.every(isImportedProfile)) {
    return { valid: false, sections: [], reasonCode: 'profile-entry', error: 'Invalid profile entry' }
  }

  // Object sections
  if ('rotation' in obj) {
    if (!obj.rotation || typeof obj.rotation !== 'object' || Array.isArray(obj.rotation)) {
      return {
        valid: false,
        sections: [],
        reasonCode: 'section-type:rotation',
        error: 'Invalid type for section "rotation": expected object'
      }
    }
    const rotation = obj.rotation as Record<string, unknown>
    if (typeof rotation.enabled !== 'boolean'
      || typeof rotation.intervalMinutes !== 'number' || !Number.isFinite(rotation.intervalMinutes)
      || !['sequential', 'random'].includes(rotation.order as string)
      || !Array.isArray(rotation.profileIds) || !rotation.profileIds.every(id => typeof id === 'string')
      || !Number.isInteger(rotation.currentIndex) || (rotation.currentIndex as number) < 0
      || !(rotation.nextRotationAt === null || (typeof rotation.nextRotationAt === 'number'
        && Number.isFinite(rotation.nextRotationAt) && rotation.nextRotationAt >= 0))) {
      return { valid: false, sections: [], reasonCode: 'rotation-fields', error: 'Invalid rotation fields' }
    }
    foundSections.push('rotation')
  }

  if ('killSwitch' in obj) {
    if (!obj.killSwitch || typeof obj.killSwitch !== 'object' || Array.isArray(obj.killSwitch)) {
      return {
        valid: false,
        sections: [],
        reasonCode: 'section-type:killSwitch',
        error: 'Invalid type for section "killSwitch": expected object'
      }
    }
    foundSections.push('killSwitch')
  }

  if ('notifications' in obj) {
    if (!obj.notifications || typeof obj.notifications !== 'object' || Array.isArray(obj.notifications)) {
      return {
        valid: false,
        sections: [],
        reasonCode: 'section-type:notifications',
        error: 'Invalid type for section "notifications": expected object'
      }
    }
    foundSections.push('notifications')
  }

  if (foundSections.length === 0) {
    return {
      valid: false,
      sections: [],
      reasonCode: 'no-sections',
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
  incoming: Partial<ConfigExportData>
): ConfigSection[] {
  const conflicts: ConfigSection[] = []

  // Array sections: conflict if both have non-empty arrays
  if (existing.profiles.length > 0 && (incoming.profiles?.length ?? 0) > 0) {
    conflicts.push('profiles')
  }
  if (existing.serverGroups.length > 0 && (incoming.serverGroups?.length ?? 0) > 0) {
    conflicts.push('serverGroups')
  }
  if (existing.schedules.length > 0 && (incoming.schedules?.length ?? 0) > 0) {
    conflicts.push('schedules')
  }
  if (existing.splitTunnel.length > 0 && (incoming.splitTunnel?.length ?? 0) > 0) {
    conflicts.push('splitTunnel')
  }
  if (existing.dns.length > 0 && (incoming.dns?.length ?? 0) > 0) {
    conflicts.push('dns')
  }
  if (existing.domainRouting.length > 0 && (incoming.domainRouting?.length ?? 0) > 0) {
    conflicts.push('domainRouting')
  }
  if (existing.themes.length > 0 && (incoming.themes?.length ?? 0) > 0) {
    conflicts.push('themes')
  }

  // Object sections: conflict if existing has non-default values
  if (existing.rotation.enabled || existing.rotation.profileIds.length > 0) {
    if (
      incoming.rotation &&
      (incoming.rotation.enabled || (incoming.rotation.profileIds?.length ?? 0) > 0)
    ) {
      conflicts.push('rotation')
    }
  }

  if (existing.killSwitch.level !== 'off' || existing.killSwitch.exceptions.length > 0) {
    if (
      incoming.killSwitch &&
      (incoming.killSwitch.level !== 'off' || (incoming.killSwitch.exceptions?.length ?? 0) > 0)
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
        // Null explicitly selects system DNS. Named profiles must survive
        // the merge; an omitted selection keeps the current choice.
        if (
          incoming.activeDnsProfileId === null || (
            incoming.activeDnsProfileId && result.dns.some((d) => d.id === incoming.activeDnsProfileId)
          )
        ) {
          result.activeDnsProfileId = incoming.activeDnsProfileId
        }
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
    activeDnsProfileId: dnsStore.get('activeProfileId') ?? null,
    domainRouting: domainRoutingStore.get('domainRules') ?? [],
    themes: themeStore.get('customThemes') ?? [],
    rotation: rotationStore.get('rotation') ?? {
      enabled: false,
      intervalMinutes: 30,
      order: 'sequential',
      profileIds: [],
      currentIndex: 0,
      nextRotationAt: null
    },
    killSwitch: {
      level: granularKillSwitchStore.get('killSwitchLevel') ?? 'off',
      exceptions: granularKillSwitchStore.get('killSwitchExceptions') ?? []
    },
    notifications: notificationStore.get('notificationPrefs') ?? DEFAULT_NOTIFICATION_PREFS
  }
}

/**
 * Writes sections from a ConfigExportData object back to the respective stores.
 */
function writeConfigToStores(config: ConfigExportData, sections: ConfigSection[], restoring = false): void {
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
        // Restore the active-profile selection when the import names one that
        // exists among the profiles we just wrote (custom or builtin).
        // Null selects system DNS; rollback preserves the exact snapshot.
        if (
          restoring || config.activeDnsProfileId === null || (
            config.activeDnsProfileId && config.dns.some((d) => d.id === config.activeDnsProfileId)
          )
        ) {
          dnsStore.set('activeProfileId', config.activeDnsProfileId)
        } else {
          dnsStore.set('activeProfileId', config.dns[0]?.id ?? null)
        }
        break
      }
      case 'domainRouting':
        domainRoutingStore.set('domainRules', config.domainRouting)
        break
      case 'themes':
        themeStore.set('customThemes', config.themes)
        break
      case 'rotation':
        rotationStore.set('rotation', config.rotation)
        break
      case 'killSwitch':
        granularKillSwitchStore.set('killSwitchLevel', config.killSwitch.level)
        granularKillSwitchStore.set('killSwitchExceptions', config.killSwitch.exceptions)
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
async function exportConfig(sender: WebContents, mode: 'redacted' | 'secrets' = 'redacted', options: ConfigOperationOptions = {}): Promise<{ success: true; path: string }> {
  return runConfigOperation('export', 'config:export', lease => exportConfigUnlocked(sender, mode, lease), { ...options, sender })
}

async function exportConfigUnlocked(sender: WebContents, mode: 'redacted' | 'secrets', lease: OperationLease): Promise<{ success: true; path: string }> {
  try {
    if (mode === 'secrets') {
      const consent = await lease.waitForUser(withSecretExportConsent(sender, 'file', () => true))
      if (consent !== true) throw new IpcFault('cancelled')
    }
    if (sender.isDestroyed()) throw new IpcFault('cancelled')
    const result = await lease.waitForUser(dialog.showSaveDialog({
      title: mode === 'secrets' ? 'Экспорт конфигурации с секретами' : 'Экспорт конфигурации без секретов',
      buttonLabel: mode === 'secrets' ? 'Сохранить файл с секретами' : 'Сохранить',
      defaultPath: `vpn-tunnel-enforcer-config-${Date.now()}.json`,
      filters: [{ name: 'JSON Files', extensions: ['json'] }]
    }))

    if (result.canceled || !result.filePath || sender.isDestroyed()) {
      throw new IpcFault('cancelled')
    }

    const config = collectCurrentConfig()
    lease.assertActive()
    const json = JSON.stringify(mode === 'secrets' ? config : redactConfigExport(config), null, 2)
    await yieldConfigOperation(lease)
    const exported = await writeConfigExport(result.filePath, json, lease, { success: true as const, path: result.filePath }, mode)

    logEvent('info', 'config-manager', 'config exported', { path: result.filePath, mode })
    return exported
  } catch (err) {
    logConfigFailure('export failed', err)
    throw err
  }
}

// ─── Import (Validate) ──────────────────────────────────────────────────────

/**
 * Validates an import file and returns available sections and conflicts.
 */
function parseImportJson(raw: string): unknown {
  try { return JSON.parse(raw) }
  catch { return rejectImport('invalid-json') }
}

function rejectImport(validationCode: ImportValidationCode, reason: 'validation' | 'conflict' = 'validation'): never {
  logEvent('warn', 'config-manager', 'import rejected', { reason, validationCode })
  throw new IpcFault(reason)
}

function logConfigFailure(message: string, error: unknown, source = 'config-manager'): void {
  const details = ioFailureDetails(error)
  logEvent(details.reason === 'cancelled' ? 'debug' : 'error', source, message, details)
}

async function importValidate(filePath: string, approvedRaw?: string, options: ConfigOperationOptions = {}): Promise<{
  success: true
  sections: string[]
  conflicts: string[]
}> {
  return runConfigOperation('import', 'config:validate', async lease => {
    try {
      const raw = approvedRaw ?? await lease.wait(readSelectedConfig(filePath, lease, rejectImport))
      await yieldConfigOperation(lease)
      options.assertAuthorized?.()
      const parsed = parseImportJson(raw)

      const validation = validateImportData(parsed)
      if (!validation.valid) {
        rejectImport(validation.reasonCode ?? 'invalid-config')
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
      logConfigFailure('import validation failed', err)
      throw err
    }
  }, options)
}

// ─── Import (Apply) ─────────────────────────────────────────────────────────

/**
 * Applies selected sections from an import file with the specified conflict resolution.
 */
async function importApply(
  filePath: string,
  sections: string[],
  conflictResolution: 'replace' | 'merge',
  approvedRaw?: string,
  options: ConfigOperationOptions = {}
): Promise<{ success: true }> {
  return runConfigOperation('import', 'config:apply', async lease => {
    try {
      const raw = approvedRaw ?? await lease.wait(readSelectedConfig(filePath, lease, rejectImport))
      await yieldConfigOperation(lease)
      options.assertAuthorized?.()
      const parsed = parseImportJson(raw)

      // Re-validate
      const validation = validateImportData(parsed)
      if (!validation.valid) {
        rejectImport(validation.reasonCode ?? 'invalid-config')
      }

      // Filter to only valid sections
      const validSections = sections.filter((s) =>
        ALL_SECTIONS.includes(s as ConfigSection)
      ) as ConfigSection[]

      if (validSections.length === 0 || validSections.length !== sections.length
        || validSections.some(section => !validation.sections.includes(section))) {
        rejectImport('selected-sections')
      }

      // Keep the whole synchronous commit in the shared profile-write queue.
      // The enclosing effect awaits this raw queue promise until physical drain.
      return await withProfileStoreWriteLock(() => {
        lease.assertActive()
        options.assertAuthorized?.()
        return lease.commit(() => {
          const existing = collectCurrentConfig()
          const merged = applySelectiveImport(existing, parsed as ConfigExportData, validSections, conflictResolution)

          // Write as a transaction from the caller's perspective: restore the
          // exact pre-import snapshot if any store rejects a write.
          try {
            writeConfigToStores(merged, validSections)
          } catch (writeError) {
            try { writeConfigToStores(existing, validSections, true) } catch (rollbackError) {
              logConfigFailure('config import rollback failed', rollbackError)
            }
            throw writeError
          }

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
            logEvent('warn', 'config-manager', 'post-import service refresh failed', { reason: classifyIpcError(err) })
          }

          logEvent('info', 'config-manager', 'import applied', {
            filePath,
            sections: validSections,
            conflictResolution
          })

          return { success: true as const }
        })
      })
    } catch (err) {
      logConfigFailure('import apply failed', err)
      throw err
    }
  }, options)
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
    logEvent('debug', 'ipc', `${channel} started`, { args: compactForIpcLog(args) })
    try {
      const result = await listener(event, ...args)
      logEvent('debug', 'ipc', `${channel} finished`, { ms: Date.now() - started })
      return result
    } catch (err) {
      logConfigFailure(`${channel} failed`, err, 'ipc')
      throw err
    }
  })
}

/**
 * Registers all config manager IPC handlers.
 * Should be called once during app initialization.
 */
interface ApprovedConfigImport { path: string; raw: string; requestId?: string; claimed: boolean; expiresAt: number; release: () => void }
const approvedConfigImports = new WeakMap<WebContents, ApprovedConfigImport>()
const configImportDialogs = new WeakMap<WebContents, object>()
function requireApprovedConfigImport(sender: WebContents, path: string, expected?: ApprovedConfigImport, requestId?: string): ApprovedConfigImport {
  const approved = approvedConfigImports.get(sender)
  if (approved && (sender.isDestroyed?.() || Date.now() >= approved.expiresAt)) approved.release()
  if (!approved || approvedConfigImports.get(sender) !== approved || approved.path !== path || approved.requestId !== requestId
    || (expected && expected !== approved) || (approved.claimed && expected !== approved)) {
    throw new IpcFault('permission')
  }
  return approved
}

export function registerConfigManagerIpcHandlers(): void {
  handleLogged('config:cancel', (event, value: unknown) => {
    const id = configRequestId(value)
    if (!id) throw new IpcFault('validation')
    const request = configRequests.get(event.sender)?.get(id)
    let cancelled = false
    if (request && !request.controller.signal.aborted) {
      if (request.operationId) cancelled = operations.cancel(request.operationId)
      else { request.controller.abort(); cancelled = true }
    }
    const approved = approvedConfigImports.get(event.sender)
    if (approved?.requestId === id) { approved.release(); cancelled = true }
    return cancelled
  })
  // config:export — exports all settings and saves to file via dialog
  handleLogged('config:export', async (event, mode: unknown = 'redacted', requestId?: unknown) => {
    return await configManager.exportConfig(event.sender, requireEnum(mode, 'mode', ['redacted', 'secrets']), { requestId: configRequestId(requestId) })
  })

  // config:import — validates a file and returns sections/conflicts
  handleLogged('config:import', async (event, filePath: string, value?: unknown) => {
    filePath = requireString(filePath, 'filePath', { maxLength: 4096 })
    const requestId = configRequestId(value)
    const approved = requireApprovedConfigImport(event.sender, filePath, undefined, requestId)
    return configManager.importValidate(filePath, approved.raw, {
      sender: event.sender, requestId, assertAuthorized: () => { requireApprovedConfigImport(event.sender, filePath, approved, requestId) }
    })
  })

  // config:import-apply — applies selected sections from import file
  handleLogged(
    'config:import-apply',
    async (event, filePath: string, sections: string[], conflictResolution: 'replace' | 'merge', value?: unknown) => {
      filePath = requireString(filePath, 'filePath', { maxLength: 4096 })
      sections = requireStringArray(sections, 'sections', { maxItems: 32, itemMaxLength: 80 })
      conflictResolution = requireEnum(conflictResolution, 'conflictResolution', ['replace', 'merge'])
      const requestId = configRequestId(value)
      if (requestId && configRequests.get(event.sender)?.has(requestId)) throw new IpcFault('conflict')
      const approved = requireApprovedConfigImport(event.sender, filePath, undefined, requestId)
      approved.claimed = true
      try { return await configManager.importApply(filePath, sections, conflictResolution, approved.raw, {
        sender: event.sender, requestId, assertAuthorized: () => { requireApprovedConfigImport(event.sender, filePath, approved, requestId) }
      }) }
      finally { approved.release() }
    }
  )

  // config:browse-import — opens file dialog to select a JSON config file
  ipcMain.handle('config:browse-import', async (event, value?: unknown) => {
    const requestId = configRequestId(value)
    if (requestId && configRequests.get(event.sender)?.has(requestId)) throw new IpcFault('conflict')
    approvedConfigImports.get(event.sender)?.release()
    const request = {}
    configImportDialogs.set(event.sender, request)
    return runConfigOperation('import', 'config:browse:' + randomUUID(), async lease => {
      try {
        const result = await lease.waitForUser(dialog.showOpenDialog({
          properties: ['openFile'],
          filters: [
            { name: 'JSON Files', extensions: ['json'] },
            { name: 'All Files', extensions: ['*'] }
          ]
        }))
        // Only the newest dialog may grant a capability, even if an older one
        // completes later. Cancellation also invalidates the older selection.
        if (configImportDialogs.get(event.sender) !== request) return null
        if (result.canceled || result.filePaths.length === 0) return null
        if (event.sender.isDestroyed?.()) throw new IpcFault('cancelled')
        const path = result.filePaths[0]
        const raw = await lease.wait(readSelectedConfig(path, lease, rejectImport))
        if (configImportDialogs.get(event.sender) !== request) return null
        lease.assertActive()
        return lease.commit(() => {
          let timer: ReturnType<typeof setTimeout>
          const lifetime = requestDocumentLifetime(event.sender)
          const approved: ApprovedConfigImport = { path, raw, requestId, claimed: false, expiresAt: Date.now() + 60_000, release: () => {
            clearTimeout(timer)
            lifetime.signal.removeEventListener('abort', approved.release)
            lifetime.dispose()
            if (approvedConfigImports.get(event.sender) === approved) approvedConfigImports.delete(event.sender)
            approved.raw = ''
          } }
          timer = setTimeout(approved.release, 60_000); timer.unref?.()
          approvedConfigImports.set(event.sender, approved)
          lifetime.signal.addEventListener('abort', approved.release, { once: true })
          return path
        })
      } finally { if (configImportDialogs.get(event.sender) === request) configImportDialogs.delete(event.sender) }
    }, { sender: event.sender, requestId })
  })
}
