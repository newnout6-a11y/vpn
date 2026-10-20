import { createHash, randomUUID } from 'node:crypto'
import { isDeepStrictEqual } from 'node:util'
import { existsSync, lstatSync, readFileSync } from 'node:fs'
import { classifyIpcError, IpcFault } from '../shared/ipc-result'
import { assertStoreSchema, storeSchemaVersion, type StoreId } from './storeSchema'
import { decryptSecret, protectLegacySecretBackup } from './secretStorage'
import { logEvent } from './appLogger'
import { withCorrelation } from './actionCorrelation'

/** Released startup repairs, in dependency order. These checks must run on
 * every startup; completion does not imply a store was changed. */
export const STARTUP_STORE_MIGRATIONS = Object.freeze([
  'migrateLegacyDirectVpnProfiles',
  'backfillMissingOutbounds',
  'migrateProfilesIntoGroups',
  'consolidateBogusSniGroups',
  'backfillProfileSourceUris',
  'backfillProfileCountriesFromNames',
  'clearStaleStoredPings'
] as const)

type StartupMigrationTarget = Record<typeof STARTUP_STORE_MIGRATIONS[number], () => void>

export function runStartupStoreMigrations(target: StartupMigrationTarget): void {
  withCorrelation('op_' + randomUUID().replaceAll('-', ''), () => {
    for (const migrationStep of STARTUP_STORE_MIGRATIONS) {
      logEvent('info', 'store-migration', 'startup store step started', { migrationStep, status: 'started' })
      try {
        target[migrationStep]()
        logEvent('info', 'store-migration', 'startup store step completed', { migrationStep, status: 'success' })
      } catch (error) {
        logEvent('error', 'store-migration', 'startup store step failed', {
          migrationStep, status: 'error', category: classifyIpcError(error)
        })
        throw error
      }
    }
  }, { source: 'lifecycle', owner: 'recovery' })
}

type SecretStoreId = 'settings' | 'server-picker' | 'server-groups'
type Document = Record<string, unknown>

/** Versions 0 and 1 of settings/profiles both predate safeStorage. There is
 * no invented 0 -> 1 conversion: either historical format goes directly to 2.
 * Some released files already say 2 but contain plaintext (Conf defaults also
 * supplied that version). Those need a separately identified repair step. */
export const STORE_MIGRATIONS = Object.freeze({
  settings: Object.freeze({ id: 'safe-storage-v1', from: Object.freeze([0, 1]), to: 2 }),
  'server-picker': Object.freeze({ id: 'safe-storage-v1', from: Object.freeze([0, 1]), to: 2 }),
  // The released schema-0 reader already supports SecretRefs: encryption does
  // not introduce a new group format or force users to abandon older builds.
  'server-groups': Object.freeze({ id: 'safe-storage-v1', from: Object.freeze([0]), to: 0 })
})

export interface StoreMigrationStep {
  id: string
  from: number
  to: number
}

export function planStoreMigrations(name: StoreId, value: Document, plaintext = false): StoreMigrationStep[] {
  assertStoreSchema(name, value)
  const version = Number(value.schemaVersion ?? 0)
  if (!Object.hasOwn(STORE_MIGRATIONS, name)) {
    if (version !== storeSchemaVersion(name)) throw new IpcFault('validation')
    return []
  }
  const migration = STORE_MIGRATIONS[name as SecretStoreId]
  if (migration.to !== storeSchemaVersion(name)) throw new IpcFault('internal')
  // No secret conversion means no migration: this includes new installs,
  // empty/public legacy data and files already encrypted by released builds.
  if (!plaintext) return []
  if (version < migration.to) {
    if (!migration.from.includes(version)) throw new IpcFault('validation')
    return [{ id: migration.id, from: version, to: migration.to }]
  }
  return [{ id: migration.from.includes(version) ? migration.id : `${migration.id}-repair`, from: version, to: version }]
}

function checksum(value: Document): string {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex')
}

export function assertMigrationReadBack(expected: unknown, actual: unknown): void {
  if (!isDeepStrictEqual(expected, actual)) throw new IpcFault('internal')
}

const migrating = new Set<SecretStoreId>()

function backupBeforeMigration(path: string, name: SecretStoreId): { backupSuffix: string; backupChecksum: string | null } {
  let backupSuffix = '.pre-safe-storage-v1.bak'
  let source: Buffer | undefined
  if (existsSync(path)) {
    const info = lstatSync(path)
    if (!info.isFile() || info.isSymbolicLink() || info.size > 16 * 1024 * 1024) throw new IpcFault('validation')
    source = readFileSync(path)
  }
  const backupChecksum = source ? createHash('sha256').update(source).digest('hex') : null
  protectLegacySecretBackup(path + backupSuffix, path, name)
  if (backupChecksum) {
    const restoredChecksum = () => createHash('sha256').update(decryptSecret(
      JSON.parse(readFileSync(path + backupSuffix, 'utf8')).contents
    )).digest('hex')
    // An earlier successful/failed migration may have left a backup of a
    // different input. Keep it, and protect this transaction's exact input too.
    if (restoredChecksum() !== backupChecksum) {
      backupSuffix = `.pre-safe-storage-v1-${backupChecksum}.bak`
      protectLegacySecretBackup(path + backupSuffix, path, name)
      if (restoredChecksum() !== backupChecksum) throw new IpcFault('conflict')
    }
  }
  return { backupSuffix, backupChecksum }
}

/** Main-only synchronous transaction: all transformations/read-back happen on
 * a detached candidate before the one atomic Conf replacement. Preparation
 * failure needs no disk rollback; the original file and encrypted backup stay.
 * The check before commit detects intervening changes, but is not an OS-level
 * cross-process compare-and-swap. Callers must not mistake it for one. */
export function migrateSecretStore<T extends Document>(name: SecretStoreId, options: {
  path: string
  read(): T
  write(value: T): void
  hasPlaintext(value: T): boolean
  prepare(value: T): T
}): void {
  if (migrating.has(name)) throw new IpcFault('conflict')
  migrating.add(name)
  try {
    const original = options.read()
    assertStoreSchema(name, original)
    const backup = `${options.path}.pre-safe-storage-v1.bak`
    // Protect legacy backups even when the main file is already encrypted.
    protectLegacySecretBackup(backup, undefined, name)
    const steps = planStoreMigrations(name, original, options.hasPlaintext(original))
    if (!steps.length) return
    const backupRecord = backupBeforeMigration(options.path, name)
    // Preserve unknown metadata. A preparation callback cannot mutate the
    // original snapshot, including when it throws halfway through encryption.
    let candidate = JSON.parse(JSON.stringify(original)) as T
    let stage: 'prepare' | 'commit' | 'read-back' = 'prepare'
    try {
      for (const step of steps) {
        logEvent('info', 'store-migration', 'migration step started', {
          store: name, migrationStep: step.id, from: step.from, to: step.to, status: 'started'
        })
        const inputChecksum = checksum(candidate)
        // Normalize optional fields to the representation JSON actually stores.
        candidate = JSON.parse(JSON.stringify(options.prepare(candidate))) as T
        const completedAt = Date.now()
        const history = candidate.migrationHistory ?? []
        if (!Array.isArray(history)) throw new IpcFault('validation')
        candidate = { ...candidate, schemaVersion: step.to,
          migration: { ...candidate.migration as Document, id: step.id, completedAt } }
        // Checksum covers the resulting document before appending this record;
        // excluding the record avoids a self-referential checksum.
        const outputChecksum = checksum(candidate)
        candidate = { ...candidate, migrationHistory: [...history, {
          ...step, inputChecksum, outputChecksum, ...backupRecord, completedAt, status: 'success'
        }] }
        assertStoreSchema(name, candidate)
      }
      if (!isDeepStrictEqual(options.read(), original)) throw new IpcFault('conflict')
      stage = 'commit'
      options.write(candidate)
      stage = 'read-back'
      assertMigrationReadBack(candidate, options.read())
      for (const step of steps) {
        logEvent('info', 'store-migration', 'migration step committed', {
          store: name, migrationStep: step.id, from: step.from, to: step.to, status: 'success'
        })
      }
    } catch (error) {
      logEvent('error', 'store-migration', 'migration transaction failed', { store: name, stage, status: 'error' })
      throw error
    }
  } finally {
    migrating.delete(name)
  }
}
