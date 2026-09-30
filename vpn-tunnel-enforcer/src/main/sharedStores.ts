import Store from 'electron-store'
import type { ServerProfile, ServerGroup, KillSwitchLevel, KillSwitchException } from '../shared/ipc-types'
import {
  protectLegacySecretBackup,
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
  migration?: {
    id: 'safe-storage-v1'
    completedAt: number
    migratedProfiles: number
  }
}

export interface ServerGroupsStoreShape {
  groups: ServerGroup[]
}

export interface GranularKillSwitchStoreShape {
  killSwitchLevel: KillSwitchLevel
  killSwitchExceptions: KillSwitchException[]
}

const persistedServerPickerStore = new Store<PersistedServerPickerStoreShape>({
  name: 'server-picker',
  defaults: { schemaVersion: 1, profiles: [], activeProfileId: null }
})

function profileContainsPlaintextSecret(profile: PersistedServerProfile): boolean {
  return Boolean(
    (profile.outbound && !isSecretRef(profile.outbound)) ||
    (typeof profile.sourceUri === 'string' && profile.sourceUri.length > 0)
  )
}

function encryptProfile(profile: ServerProfile): PersistedServerProfile {
  const { outbound, sourceUri, ...metadata } = profile
  return {
    ...metadata,
    ...(outbound ? { outbound: encryptJsonSecret(outbound) } : {}),
    ...(sourceUri ? { sourceUri: encryptSecret(sourceUri) } : {})
  }
}

function decryptProfile(profile: PersistedServerProfile): ServerProfile {
  const { outbound, sourceUri, ...metadata } = profile
  return {
    ...metadata,
    ...(outbound
      ? { outbound: isSecretRef(outbound) ? decryptJsonSecret<Record<string, any>>(outbound) : outbound }
      : {}),
    ...(sourceUri
      ? { sourceUri: isSecretRef(sourceUri) ? decryptSecret(sourceUri) : sourceUri }
      : {})
  }
}

function migrateProfilesIfNeeded(): void {
  protectLegacySecretBackup(`${persistedServerPickerStore.path}.pre-safe-storage-v1.bak`)
  const profiles = persistedServerPickerStore.get('profiles', [])
  const plaintextProfiles = profiles.filter(profileContainsPlaintextSecret)
  if (plaintextProfiles.length === 0) return
  if (!isSecretEncryptionAvailable()) {
    throw new Error('VPN profile migration requires Windows secure storage; plaintext data was left unchanged')
  }

  protectLegacySecretBackup(`${persistedServerPickerStore.path}.pre-safe-storage-v1.bak`, persistedServerPickerStore.path)

  const activeProfileId = persistedServerPickerStore.get('activeProfileId', null)
  const encrypted = profiles.map(profile => encryptProfile(decryptProfile(profile)))
  persistedServerPickerStore.store = {
    schemaVersion: 1,
    profiles: encrypted,
    activeProfileId,
    migration: {
      id: 'safe-storage-v1',
      completedAt: Date.now(),
      migratedProfiles: plaintextProfiles.length
    }
  }
}

/**
 * Compatibility facade over electron-store. Callers continue to receive the
 * existing ServerProfile model while outbound/sourceUri are always encrypted
 * in the persisted JSON file.
 */
export const serverPickerStore = {
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
      persistedServerPickerStore.set('schemaVersion', 1)
      return
    }
    persistedServerPickerStore.set(key, value as any)
  },

  get path(): string {
    return persistedServerPickerStore.path
  }
}

const persistedServerGroupsStore = new Store<{ groups: Array<ServerGroup | SecretRef> }>({
  name: 'server-groups', defaults: { groups: [] }
})
export const serverGroupsStore = {
  get(_key: 'groups', fallback: ServerGroup[] = []): ServerGroup[] {
    protectLegacySecretBackup(`${persistedServerGroupsStore.path}.pre-safe-storage-v1.bak`)
    const persisted = persistedServerGroupsStore.get('groups', fallback)
    if (!Array.isArray(persisted)) throw new Error('Invalid server group store')
    const groups = persisted.map(group => isSecretRef(group) ? decryptJsonSecret<ServerGroup>(group) : group)
    if (persisted.some(group => !isSecretRef(group))) {
      // Prepare the entire encrypted replacement before committing any field.
      const encrypted = groups.map(encryptJsonSecret)
      protectLegacySecretBackup(`${persistedServerGroupsStore.path}.pre-safe-storage-v1.bak`, persistedServerGroupsStore.path)
      persistedServerGroupsStore.set('groups', encrypted)
    }
    return groups
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
