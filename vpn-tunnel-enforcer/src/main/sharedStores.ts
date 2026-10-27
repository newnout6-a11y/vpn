import Store from './versionedStore'
import { createHash } from 'node:crypto'
import { isIP } from 'node:net'
import { assertMigrationReadBack, migrateSecretStore } from './storeMigrations'
import type { ServerProfile, ServerProfileDisplay, ServerGroup, KillSwitchLevel, KillSwitchException } from '../shared/ipc-types'
import { asJsonObject } from '../shared/json'
import { normalizeServerPort } from '../shared/portValidation'
import {
  decryptJsonSecret,
  decryptSecret,
  encryptJsonSecret,
  encryptSecret,
  isSecretEncryptionAvailable,
  isSecretRef,
  type SecretRef
} from './secretStorage'

export interface ServerPickerStoreShape {
  profiles: ServerProfile[]
  activeProfileId: string | null
}

interface PersistedServerProfile extends Omit<ServerProfile, 'outbound' | 'sourceUri'> {
  outbound?: Record<string, any> | SecretRef
  sourceUri?: string | SecretRef
}

interface PersistedServerPickerStoreShape {
  schemaVersion: number
  profiles: PersistedServerProfile[]
  activeProfileId: string | null
  migration?: Record<string, unknown>
}

export interface ServerGroupsStoreShape {
  groups: ServerGroup[]
}

export interface GranularKillSwitchStoreShape {
  killSwitchLevel: KillSwitchLevel
  killSwitchExceptions: KillSwitchException[]
}

const persistedServerPickerStore = new Store<PersistedServerPickerStoreShape>({
  name: 'server-picker'
})

function profileContainsPlaintextSecret(profile: PersistedServerProfile): boolean {
  return Boolean(
    (profile.outbound && !isSecretRef(profile.outbound)) ||
    (typeof profile.sourceUri === 'string' && profile.sourceUri.length > 0)
  )
}

function encryptProfile(profile: ServerProfile): PersistedServerProfile {
  const { outbound, sourceUri, display: _display, ...metadata } = profile
  return {
    ...metadata,
    ...(outbound ? { outbound: encryptJsonSecret(outbound) } : {}),
    ...(sourceUri ? { sourceUri: encryptSecret(sourceUri) } : {})
  }
}

// Only public primitives are retained. A changed ciphertext or display input
// requires a fresh decode; neither a persisted hint nor this cache can dial VPN.
const profileDisplays = new Map<string, { key: string; display: ServerProfileDisplay; port: number }>()
function profileDisplayKey(profile: PersistedServerProfile): string {
  return createHash('sha256').update(JSON.stringify([
    profile.outbound, profile.sourceUri, profile.protocol, profile.port, profile.clientFingerprint
  ])).digest('hex')
}

function rememberProfileDisplay(raw: PersistedServerProfile, profile: ServerProfile): void {
  const outbound = asJsonObject(profile.outbound)
  const configuredTls = asJsonObject(outbound?.tls)
  const tls = configuredTls?.enabled !== false ? configuredTls : undefined
  const configuredEch = asJsonObject(tls?.ech)
  const ech = configuredEch?.enabled !== false ? configuredEch : undefined
  const reality = asJsonObject(tls?.reality), utls = asJsonObject(tls?.utls)
  const protocol = (profile.protocol || (typeof outbound?.type === 'string' ? outbound.type : '')).toLowerCase()
  const stealth: ServerProfileDisplay['stealth'] = ech && (Array.isArray(ech.config) || ech.config_path || ech.query_server_name)
    ? 'ech' : reality && reality.enabled !== false ? 'reality' : protocol === 'naive' ? 'naive'
      : protocol === 'hysteria2' && asJsonObject(outbound?.obfs) ? 'obfs'
        : utls && utls.enabled !== false ? 'utls' : tls ? 'tls'
          : ['vless', 'vmess', 'trojan'].includes(protocol) ? 'plain' : undefined
  const fingerprint = profile.clientFingerprint || utls?.fingerprint
  profileDisplays.set(raw.id, {
    key: profileDisplayKey(raw),
    port: normalizeServerPort(profile.port ?? outbound?.server_port, 443)!,
    display: { hasOutbound: Boolean(outbound), ...(stealth ? { stealth } : {}),
      ...(typeof fingerprint === 'string' && /^[a-zA-Z0-9_.-]{1,64}$/.test(fingerprint) ? { clientFingerprint: fingerprint } : {}) }
  })
}

function decryptProfile(profile: PersistedServerProfile): ServerProfile {
  const { outbound, sourceUri, display: _display, ...metadata } = profile
  const decoded: ServerProfile = {
    ...metadata,
    ...(outbound
      ? { outbound: isSecretRef(outbound) ? decryptJsonSecret<Record<string, any>>(outbound) : outbound }
      : {}),
    ...(sourceUri
      ? { sourceUri: isSecretRef(sourceUri) ? decryptSecret(sourceUri) : sourceUri }
      : {})
  }
  rememberProfileDisplay(profile, decoded)
  return decoded
}

function migrateProfilesIfNeeded(): void {
  migrateSecretStore('server-picker', {
    path: persistedServerPickerStore.path,
    read: () => ({ ...persistedServerPickerStore.store }),
    write: value => { persistedServerPickerStore.store = value },
    hasPlaintext: value => (value.profiles ?? []).some(profileContainsPlaintextSecret),
    prepare(value) {
      const decoded = value.profiles.map(decryptProfile)
      const encrypted = decoded.map(encryptProfile)
      assertMigrationReadBack(decoded, encrypted.map(decryptProfile))
      return { ...value, profiles: encrypted, migration: {
        migratedProfiles: value.profiles.filter(profileContainsPlaintextSecret).length
      } }
    }
  })
}

/**
 * Compatibility facade over electron-store. Callers continue to receive the
 * existing ServerProfile model while outbound/sourceUri are always encrypted
 * in the persisted JSON file.
 */
export const serverPickerStore = {
  /** Metadata reads still refuse unavailable OS encryption and failed backfill. */
  getProfileSummaries(): ServerProfile[] {
    migrateProfilesIfNeeded()
    const profiles = persistedServerPickerStore.get('profiles', [])
    if (profiles.some(profile => profile.outbound || profile.sourceUri) && !isSecretEncryptionAvailable()) {
      throw new Error('Secure storage is unavailable; encrypted VPN profiles cannot be opened')
    }
    const ids = new Set(profiles.map(profile => profile.id))
    for (const id of profileDisplays.keys()) if (!ids.has(id)) profileDisplays.delete(id)
    return profiles.map(profile => {
      if (profileDisplays.get(profile.id)?.key !== profileDisplayKey(profile)) decryptProfile(profile)
      const cached = profileDisplays.get(profile.id)!
      const { outbound: _outbound, sourceUri: _sourceUri, display: _display, ...metadata } = profile
      return { ...metadata, port: cached.port, display: { ...cached.display } }
    })
  },

  getProfile(id: string | null, fallbackToFirst = false): ServerProfile | null {
    migrateProfilesIfNeeded()
    const profiles = persistedServerPickerStore.get('profiles', []).filter(profile => !fallbackToFirst || profile.enabled !== false && !profile.removedFromSubscriptionAt)
    const profile = profiles.find(profile => profile.id === id) ?? (fallbackToFirst ? profiles[0] : undefined)
    if (!profile) return null
    const decoded = decryptProfile(profile)
    const port = normalizeServerPort(decoded.port ?? decoded.outbound?.server_port, 443)!
    return { ...decoded, port, ...(decoded.outbound ? { outbound: { ...decoded.outbound, server_port: port } } : {}) }
  },

  /** Called under the profile write queue; preserve ciphertext and fresh edits. */
  mergeResolvedIps(updates: ReadonlyMap<string, { server: string; ip: string; at: number }>): void {
    migrateProfilesIfNeeded()
    let changed = false
    const current = persistedServerPickerStore.get('profiles', [])
    if (current.some(profile => profile.outbound || profile.sourceUri) && !isSecretEncryptionAvailable()) {
      throw new Error('Secure storage is unavailable; VPN profile metadata was not written')
    }
    const profiles = current.map(profile => {
      const update = updates.get(profile.id)
      if (!update || profile.server !== update.server || isIP(update.ip) !== 4 || profile.resolvedIp === update.ip) return profile
      changed = true
      return { ...profile, resolvedIp: update.ip, resolvedIpAt: update.at }
    })
    if (changed) persistedServerPickerStore.set('profiles', profiles)
  },

  get<K extends keyof ServerPickerStoreShape>(
    key: K,
    defaultValue?: ServerPickerStoreShape[K]
  ): ServerPickerStoreShape[K] {
    if (key === 'profiles') {
      migrateProfilesIfNeeded()
      const profiles = persistedServerPickerStore.get('profiles', []).map(decryptProfile)
      return profiles as ServerPickerStoreShape[K]
    }
    return persistedServerPickerStore.get(key, defaultValue as any) as ServerPickerStoreShape[K]
  },

  set<K extends keyof ServerPickerStoreShape>(key: K, value: ServerPickerStoreShape[K]): void {
    if (key === 'profiles') {
      const profiles = value as ServerProfile[]
      if (profiles.some(profile => profile.outbound || profile.sourceUri) && !isSecretEncryptionAvailable()) {
        throw new Error('Secure storage is unavailable; VPN profiles were not written')
      }
      persistedServerPickerStore.set('profiles', profiles.map(encryptProfile))
      persistedServerPickerStore.set('schemaVersion', 2)
      return
    }
    persistedServerPickerStore.set(key, value as any)
  },

  get path(): string {
    return persistedServerPickerStore.path
  }
}

const persistedServerGroupsStore = new Store<{ groups: Array<ServerGroup | SecretRef>; schemaVersion?: number }>({
  name: 'server-groups'
})
export const serverGroupsStore = {
  get(_key: 'groups', fallback: ServerGroup[] = []): ServerGroup[] {
    migrateSecretStore('server-groups', {
      path: persistedServerGroupsStore.path,
      read: () => ({ ...persistedServerGroupsStore.store }),
      write: value => { persistedServerGroupsStore.store = value },
      hasPlaintext(value) {
        if (value.groups === undefined) return false
        if (!Array.isArray(value.groups)) throw new Error('Invalid server group store')
        return value.groups.some(group => !isSecretRef(group))
      },
      prepare(value) {
        const groups = value.groups.map(group => isSecretRef(group) ? decryptJsonSecret<ServerGroup>(group) : group)
        const encrypted = groups.map(encryptJsonSecret)
        assertMigrationReadBack(groups, encrypted.map(group => decryptJsonSecret<ServerGroup>(group)))
        return { ...value, groups: encrypted }
      }
    })
    return persistedServerGroupsStore.get('groups', fallback).map(group => isSecretRef(group) ? decryptJsonSecret<ServerGroup>(group) : group)
  },
  set(_key: 'groups', groups: ServerGroup[]): void {
    if (!Array.isArray(groups)) throw new Error('Invalid server group array')
    persistedServerGroupsStore.set('groups', groups.map(encryptJsonSecret))
  },
  get path(): string { return persistedServerGroupsStore.path }
}

export const granularKillSwitchStore = new Store<GranularKillSwitchStoreShape>({
  name: 'granular-kill-switch',
  defaults: { killSwitchLevel: 'off', killSwitchExceptions: [] }
})
