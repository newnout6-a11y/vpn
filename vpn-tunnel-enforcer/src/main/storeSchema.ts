import { IpcFault } from '../shared/ipc-result'

/** 0 denotes the existing unversioned format. This inventory does not perform
 * migrations: format changes register their steps in storeMigrations.ts. */
export const STORE_SCHEMA_VERSIONS = Object.freeze({
  'adaptive-bypass': 0,
  'connection-history': 0,
  'dns-profiles': 0,
  'domain-intelligence': 0,
  'domain-routing': 0,
  'external-proxy-leases': 0,
  'granular-kill-switch': 0,
  i18n: 0,
  'notification-prefs': 0,
  'profile-rotation': 0,
  scheduler: 0,
  'server-groups': 1,
  'server-picker': 2,
  settings: 2,
  'smart-route-rule-sets': 0,
  'speed-test': 0,
  'split-tunnel': 0,
  themes: 0,
  'traffic-domains': 0,
  'url-availability': 0
})

export type StoreId = keyof typeof STORE_SCHEMA_VERSIONS
type SchemaFailure = 'STORE_SCHEMA_FUTURE' | 'STORE_SCHEMA_INVALID' | 'STORE_SCHEMA_UNREGISTERED'

export class StoreSchemaError extends IpcFault {
  constructor(readonly code: SchemaFailure) {
    super(code === 'STORE_SCHEMA_FUTURE' ? 'conflict' : 'validation')
    this.name = 'StoreSchemaError'
    // Never include file paths, raw JSON or an untrusted version value.
    this.message = code === 'STORE_SCHEMA_FUTURE'
      ? 'Storage schema is newer than this application; file left unchanged'
      : code === 'STORE_SCHEMA_INVALID' ? 'Invalid storage schema version; file left unchanged'
        : 'Storage schema is not registered'
  }
}

export function storeSchemaVersion(name: string): number {
  if (!Object.hasOwn(STORE_SCHEMA_VERSIONS, name)) throw new StoreSchemaError('STORE_SCHEMA_UNREGISTERED')
  return STORE_SCHEMA_VERSIONS[name as StoreId]
}

export function assertStoreSchema(name: string, value: unknown): void {
  const supported = storeSchemaVersion(name)
  // Preserve existing feature-specific validation/corruption handling.
  if (!value || typeof value !== 'object' || !Object.hasOwn(value, 'schemaVersion')) return
  const version = (value as Record<string, unknown>).schemaVersion
  if (typeof version !== 'number' || !Number.isSafeInteger(version) || version < 0) {
    throw new StoreSchemaError('STORE_SCHEMA_INVALID')
  }
  if (version > supported) throw new StoreSchemaError('STORE_SCHEMA_FUTURE')
}
