/**
 * DNS Profiles Service — management of DNS profiles with validation.
 *
 * Responsibilities:
 * - Provide built-in DNS profiles (Cloudflare, Google, Quad9, AdGuard)
 * - CRUD operations for custom DNS profiles stored in electron-store
 * - Validate DNS addresses (IPv4, IPv6, DoH https://, DoT tls://)
 * - Apply the selected DNS profile to sing-box configuration on connect
 * - Register IPC handlers for all DnsChannels
 *
 * Exports pure function `validateDnsAddress` for property testing.
 */

import { ipcMain, type IpcMainInvokeEvent } from 'electron'
import Store from 'electron-store'
import { logEvent } from './appLogger'
import type { DnsProfile } from '../shared/ipc-types'

// ─── Built-in Profiles ───────────────────────────────────────────────────────

const BUILTIN_PROFILES: DnsProfile[] = [
  {
    id: 'builtin-cloudflare',
    name: 'Cloudflare',
    primary: '1.1.1.1',
    secondary: '1.0.0.1',
    type: 'plain',
    isBuiltin: true
  },
  {
    id: 'builtin-google',
    name: 'Google',
    primary: '8.8.8.8',
    secondary: '8.8.4.4',
    type: 'plain',
    isBuiltin: true
  },
  {
    id: 'builtin-quad9',
    name: 'Quad9',
    primary: '9.9.9.9',
    secondary: '149.112.112.112',
    type: 'plain',
    isBuiltin: true
  },
  {
    id: 'builtin-adguard',
    name: 'AdGuard',
    primary: '94.140.14.14',
    secondary: '94.140.15.15',
    type: 'plain',
    isBuiltin: true
  }
]

// ─── Pure Validation Function (exported for property testing) ────────────────

/**
 * Validates a DNS address string and determines its type.
 *
 * Returns:
 * - { valid: true, type: 'plain' } for valid IPv4 or IPv6 addresses
 * - { valid: true, type: 'doh' } for strings starting with https:// with a valid hostname
 * - { valid: true, type: 'dot' } for strings starting with tls:// with a valid hostname
 * - { valid: false, type: 'plain', error: string } for invalid addresses
 */
export function validateDnsAddress(address: string): {
  valid: boolean
  type: 'plain' | 'doh' | 'dot'
  error?: string
} {
  if (!address || typeof address !== 'string') {
    return { valid: false, type: 'plain', error: 'Address is required' }
  }

  const trimmed = address.trim()

  if (trimmed.length === 0) {
    return { valid: false, type: 'plain', error: 'Address is required' }
  }

  // DoH: starts with https://
  if (trimmed.startsWith('https://')) {
    const hostname = extractHostname(trimmed.slice('https://'.length))
    if (hostname && isValidHostname(hostname)) {
      return { valid: true, type: 'doh' }
    }
    return { valid: false, type: 'doh', error: 'Invalid DoH address: invalid hostname' }
  }

  // DoT: starts with tls://
  if (trimmed.startsWith('tls://')) {
    const hostname = extractHostname(trimmed.slice('tls://'.length))
    if (hostname && isValidHostname(hostname)) {
      return { valid: true, type: 'dot' }
    }
    return { valid: false, type: 'dot', error: 'Invalid DoT address: invalid hostname' }
  }

  // Plain: valid IPv4 or IPv6
  if (isValidIPv4(trimmed)) {
    return { valid: true, type: 'plain' }
  }

  if (isValidIPv6(trimmed)) {
    return { valid: true, type: 'plain' }
  }

  return { valid: false, type: 'plain', error: 'Invalid DNS address: must be a valid IPv4, IPv6, https:// (DoH), or tls:// (DoT) address' }
}

// ─── Validation Helpers ──────────────────────────────────────────────────────

/**
 * Extracts the hostname from a URL path (everything before the first / or : after the scheme).
 */
function extractHostname(afterScheme: string): string | null {
  if (!afterScheme || afterScheme.length === 0) return null
  // Take everything before the first / or port separator
  const match = afterScheme.match(/^([^/:]+)/)
  return match ? match[1] : null
}

/**
 * Validates a hostname (domain name).
 * Must have at least one dot, each label 1-63 chars, total max 253 chars.
 * Labels can contain alphanumeric and hyphens (not starting/ending with hyphen).
 */
function isValidHostname(hostname: string): boolean {
  if (!hostname || hostname.length === 0 || hostname.length > 253) return false

  const labels = hostname.split('.')
  if (labels.length < 2) return false

  for (const label of labels) {
    if (label.length === 0 || label.length > 63) return false
    if (label.startsWith('-') || label.endsWith('-')) return false
    if (!/^[a-zA-Z0-9-]+$/.test(label)) return false
  }

  return true
}

/**
 * Validates an IPv4 address.
 * Must be exactly 4 octets separated by dots, each 0-255.
 */
function isValidIPv4(address: string): boolean {
  const parts = address.split('.')
  if (parts.length !== 4) return false

  for (const part of parts) {
    if (part.length === 0 || part.length > 3) return false
    // No leading zeros (except "0" itself)
    if (part.length > 1 && part.startsWith('0')) return false
    if (!/^\d+$/.test(part)) return false
    const num = parseInt(part, 10)
    if (num < 0 || num > 255) return false
  }

  return true
}

/**
 * Validates an IPv6 address.
 * Supports full form and :: abbreviation.
 */
function isValidIPv6(address: string): boolean {
  if (!address || address.length === 0) return false

  // Handle IPv6 with zone ID (remove it)
  const zoneIdx = address.indexOf('%')
  const addr = zoneIdx >= 0 ? address.slice(0, zoneIdx) : address

  // Check for :: abbreviation
  const doubleColonCount = (addr.match(/::/g) || []).length
  if (doubleColonCount > 1) return false

  if (doubleColonCount === 1) {
    const parts = addr.split('::')
    const left = parts[0] ? parts[0].split(':') : []
    const right = parts[1] ? parts[1].split(':') : []

    // Total groups must be <= 8
    if (left.length + right.length > 7) return false

    for (const group of [...left, ...right]) {
      if (!isValidIPv6Group(group)) return false
    }

    return true
  }

  // Full form: exactly 8 groups
  const groups = addr.split(':')
  if (groups.length !== 8) return false

  for (const group of groups) {
    if (!isValidIPv6Group(group)) return false
  }

  return true
}

/**
 * Validates a single IPv6 group (1-4 hex digits).
 */
function isValidIPv6Group(group: string): boolean {
  if (group.length === 0 || group.length > 4) return false
  return /^[0-9a-fA-F]+$/.test(group)
}

// ─── Persistent Store ────────────────────────────────────────────────────────

interface DnsStore {
  customProfiles: DnsProfile[]
  activeProfileId: string | null
}

const store = new Store<DnsStore>({
  name: 'dns-profiles',
  defaults: {
    customProfiles: [],
    activeProfileId: null
  }
})

// ─── Profile Management ──────────────────────────────────────────────────────

function getAllProfiles(): DnsProfile[] {
  const custom = store.get('customProfiles') ?? []
  return [...BUILTIN_PROFILES, ...custom]
}

function getCustomProfiles(): DnsProfile[] {
  return store.get('customProfiles') ?? []
}

function saveCustomProfiles(profiles: DnsProfile[]): void {
  store.set('customProfiles', profiles)
}

function getActiveProfileId(): string | null {
  return store.get('activeProfileId') ?? null
}

function setActiveProfileId(id: string | null): void {
  store.set('activeProfileId', id)
}

/**
 * Returns the currently active DNS profile, or null if none selected.
 */
function getActiveDnsProfile(): DnsProfile | null {
  const activeId = getActiveProfileId()
  if (!activeId) return null

  const all = getAllProfiles()
  return all.find((p) => p.id === activeId) ?? null
}

function generateId(): string {
  return `dns-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`
}

// ─── Sing-box Config Integration ─────────────────────────────────────────────

/**
 * Applies the active DNS profile to a sing-box configuration object.
 * Modifies the config's DNS section with the active profile's servers.
 *
 * If no active profile is selected, the config is returned unchanged.
 */
export function applyToSingboxConfig(config: Record<string, any>): Record<string, any> {
  const profile = getActiveDnsProfile()
  if (!profile) return config

  const servers: Array<{ address: string; tag: string }> = []

  // Build server entries based on profile type
  if (profile.type === 'doh') {
    servers.push({ address: profile.primary, tag: 'dns-primary' })
    if (profile.secondary) {
      servers.push({ address: profile.secondary, tag: 'dns-secondary' })
    }
  } else if (profile.type === 'dot') {
    servers.push({ address: profile.primary, tag: 'dns-primary' })
    if (profile.secondary) {
      servers.push({ address: profile.secondary, tag: 'dns-secondary' })
    }
  } else {
    // Plain IPv4/IPv6
    servers.push({ address: profile.primary, tag: 'dns-primary' })
    if (profile.secondary) {
      servers.push({ address: profile.secondary, tag: 'dns-secondary' })
    }
  }

  return {
    ...config,
    dns: {
      ...(config.dns ?? {}),
      servers,
      rules: [
        {
          server: 'dns-primary',
          outbound: 'any'
        }
      ]
    }
  }
}

// ─── IPC Handlers ────────────────────────────────────────────────────────────

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
 * Registers all DNS profile IPC handlers.
 * Should be called once during app initialization.
 */
export function registerDnsHandlers(): void {
  // dns:list — returns all profiles (builtin + custom)
  handleLogged('dns:list', async () => {
    return getAllProfiles()
  })

  // dns:create — creates a new custom DNS profile
  handleLogged('dns:create', async (_event, profile: Omit<DnsProfile, 'id' | 'isBuiltin'>) => {
    const newProfile: DnsProfile = {
      ...profile,
      id: generateId(),
      isBuiltin: false
    }

    const custom = getCustomProfiles()
    custom.push(newProfile)
    saveCustomProfiles(custom)

    logEvent('info', 'dns-profiles', 'custom profile created', {
      id: newProfile.id,
      name: newProfile.name,
      type: newProfile.type
    })

    return newProfile
  })

  // dns:update — updates an existing custom DNS profile
  handleLogged('dns:update', async (_event, id: string, patch: Partial<DnsProfile>) => {
    const custom = getCustomProfiles()
    const index = custom.findIndex((p) => p.id === id)

    if (index === -1) {
      throw new Error(`DNS profile not found: ${id}`)
    }

    // Cannot modify builtin profiles
    if (custom[index].isBuiltin) {
      throw new Error('Cannot modify built-in DNS profiles')
    }

    const updated: DnsProfile = {
      ...custom[index],
      ...patch,
      id: custom[index].id, // Prevent ID change
      isBuiltin: false // Prevent marking as builtin
    }

    custom[index] = updated
    saveCustomProfiles(custom)

    logEvent('info', 'dns-profiles', 'profile updated', {
      id: updated.id,
      name: updated.name
    })

    return updated
  })

  // dns:delete — deletes a custom DNS profile
  handleLogged('dns:delete', async (_event, id: string) => {
    // Cannot delete builtin profiles
    if (id.startsWith('builtin-')) {
      throw new Error('Cannot delete built-in DNS profiles')
    }

    const custom = getCustomProfiles()
    const filtered = custom.filter((p) => p.id !== id)

    if (filtered.length === custom.length) {
      throw new Error(`DNS profile not found: ${id}`)
    }

    saveCustomProfiles(filtered)

    // If the deleted profile was active, clear the selection
    if (getActiveProfileId() === id) {
      setActiveProfileId(null)
    }

    logEvent('info', 'dns-profiles', 'profile deleted', { id })
  })

  // dns:select — sets the active DNS profile
  handleLogged('dns:select', async (_event, id: string) => {
    const all = getAllProfiles()
    const profile = all.find((p) => p.id === id)

    if (!profile) {
      throw new Error(`DNS profile not found: ${id}`)
    }

    setActiveProfileId(id)

    logEvent('info', 'dns-profiles', 'active profile changed', {
      id: profile.id,
      name: profile.name
    })
  })

  // dns:validate — validates a DNS address
  handleLogged('dns:validate', async (_event, address: string) => {
    return validateDnsAddress(address)
  })
}

// ─── Initialization ──────────────────────────────────────────────────────────

/**
 * Initializes the DNS profiles service.
 */
export function initDnsProfiles(): void {
  logEvent('info', 'dns-profiles', 'service initialized', {
    builtinCount: BUILTIN_PROFILES.length,
    customCount: getCustomProfiles().length,
    activeProfileId: getActiveProfileId()
  })
}

// ─── Exports ─────────────────────────────────────────────────────────────────

export const dnsProfiles = {
  getAllProfiles,
  getActiveDnsProfile,
  applyToSingboxConfig,
  registerHandlers: registerDnsHandlers,
  init: initDnsProfiles
}
