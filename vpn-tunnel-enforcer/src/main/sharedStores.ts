import Store from './versionedStore'
import { assertMigrationReadBack, migrateSecretStore } from './storeMigrations'
import type { ServerProfile, ServerGroup, KillSwitchLevel, KillSwitchException } from '../shared/ipc-types'
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
