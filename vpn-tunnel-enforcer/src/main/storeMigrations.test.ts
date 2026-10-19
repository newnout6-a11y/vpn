// AT-00-006 / AT-01-001/010 / F-074: historical fixtures through the actual
// settings/shared-store facades and Conf disk backend. Only DPAPI is replaced.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync, truncateSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { join } from 'node:path'
import { STORE_SCHEMA_VERSIONS } from './storeSchema'

const state = vi.hoisted(() => ({ dir: '', calls: 0, failAt: 0, available: true, log: vi.fn() }))
vi.mock('electron', () => ({ app: { isPackaged: true }, safeStorage: {
  isEncryptionAvailable: () => state.available,
  encryptString: (value: string) => {
    if (++state.calls === state.failAt) throw new Error('injected-encryption-failure')
    return Buffer.from(`protected:${value}`)
  },
  decryptString: (value: Buffer) => value.toString().replace(/^protected:/, '')
} }))
vi.mock('./appLogger', () => ({ logEvent: state.log }))
vi.mock('./admin', () => ({ execElevated: vi.fn() }))
vi.mock('./domainEnrichment', () => ({ domainEnrichmentService: { setEnabled: vi.fn() } }))
vi.mock('./recoveryManifest', () => ({ readBootRecoveryReport: vi.fn() }))
vi.mock('electron-store', async () => {
  const { default: Conf } = await vi.importActual<typeof import('conf')>('conf')
  return { default: class extends Conf {
    constructor(options: Record<string, unknown>) {
      super({ ...options, cwd: state.dir, configName: String(options.name), projectVersion: '1.1.24' })
    }
  } }
})

type Name = 'settings' | 'server-picker' | 'server-groups'
const names: Name[] = ['settings', 'server-picker', 'server-groups']
const file = (name: Name) => join(state.dir, `${name}.json`)
const digest = (value: string | Buffer) => createHash('sha256').update(value).digest('hex')
const marker = 'FAKE-MIGRATION-SECRET'
function fixture(name: Name, version?: number) {
  const payload = name === 'settings' ? { settings: {
    proxyOverride: `http://user:${marker}@127.0.0.1:8080`, directVpnInput: marker,
    directVpnCachedInput: marker, directVpnCachedSource: marker, directVpnCachedProfiles: []
  } } : name === 'server-picker' ? { activeProfileId: 'p1', profiles: [{
    id: 'p1', name: 'Fixture', protocol: 'vless', server: 'vpn.test', port: 443,
    outbound: { uuid: marker }, sourceUri: `vless://${marker}@vpn.test:443`
  }] } : { groups: [{ id: 'g1', name: 'Fixture', sourceUrl: `https://subscription.test/${marker}` }] }
  return { ...payload, ...(version === undefined ? {} : { schemaVersion: version }), extension: { preserve: [1, 2] } }
}
async function facade(name: Name) {
  if (name === 'settings') {
    const { settingsStore } = await import('./settings')
    return () => settingsStore.get()
  }
  const { serverPickerStore, serverGroupsStore } = await import('./sharedStores')
  return () => name === 'server-picker' ? serverPickerStore.get('profiles') : serverGroupsStore.get('groups')
}

beforeEach(() => {
  vi.resetModules()
  mkdirSync('.tmp', { recursive: true })
  state.dir = mkdtempSync(join(process.cwd(), '.tmp', 'store-migrations-'))
  state.calls = 0; state.failAt = 0; state.available = true; state.log.mockClear()
})
afterEach(() => rmSync(state.dir, { recursive: true, force: true }))

describe('registered historical migrations', () => {
  it('reopens a valid store whose encrypted migration backup exceeds 16 MiB', async () => {
    const seed = { ...fixture('settings', 0), padding: 'x'.repeat(13 * 1024 * 1024) }
    writeFileSync(file('settings'), JSON.stringify(seed))
    const read = await facade('settings')
    expect(read()).toMatchObject({ directVpnInput: marker })
    expect(readFileSync(file('settings') + '.pre-safe-storage-v1.bak').length).toBeGreaterThan(16 * 1024 * 1024)
    vi.resetModules()
    expect((await facade('settings'))()).toMatchObject({ directVpnInput: marker })
  })

  it.each(['source', 'authenticated-plaintext', 'encrypted-envelope'] as const)('retains the separate %s size bound', async boundary => {
    const seed = { ...fixture('settings', 0), ...(boundary === 'source' ? { padding: 'x'.repeat(17 * 1024 * 1024) } : {}) }
    const raw = JSON.stringify(seed), backup = file('settings') + '.pre-safe-storage-v1.bak'
    writeFileSync(file('settings'), raw)
    if (boundary === 'authenticated-plaintext') {
      const { encryptSecret } = await import('./secretStorage')
      writeFileSync(backup, JSON.stringify({ __vpnteEncryptedBackup: 1, contents: encryptSecret('x'.repeat(17 * 1024 * 1024)) }))
    }
    if (boundary === 'encrypted-envelope') { writeFileSync(backup, ''); truncateSync(backup, 33 * 1024 * 1024) }
    const read = await facade('settings')
    expect(read).toThrow(boundary === 'source'
      ? expect.objectContaining({ category: 'validation' })
      : 'Invalid secret migration backup artifact')
    expect(readFileSync(file('settings'), 'utf8')).toBe(raw)
    expect(state.log.mock.calls.some(call => call[2] === 'migration step committed')).toBe(false)
  })

  it('reads empty legacy groups without DPAPI, file writes or a fake migration', async () => {
    const raw = '{"groups":[]}'
    writeFileSync(file('server-groups'), raw)
    const read = await facade('server-groups')
    state.available = false
    expect(read()).toEqual([])
    expect(readFileSync(file('server-groups'), 'utf8')).toBe(raw)
    expect(state.calls).toBe(0)
    expect(state.log.mock.calls.some(call => call[1] === 'store-migration')).toBe(false)
  })

  it.each(names)('does not create a fake legacy migration on a fresh %s install', async name => {
    const read = await facade(name)
    read()
    expect(existsSync(file(name))).toBe(false)
    expect(state.log.mock.calls.some(call => call[1] === 'store-migration')).toBe(false)
  })

  it('keeps encrypted groups compatible with the previous schema-0 admission guard', async () => {
    writeFileSync(file('server-groups'), JSON.stringify(fixture('server-groups', 0)))
    ;(await facade('server-groups'))()
    const stored = JSON.parse(readFileSync(file('server-groups'), 'utf8'))
    expect(stored.schemaVersion).toBe(0)
    expect(stored.migrationHistory[0]).toMatchObject({ id: 'safe-storage-v1', from: 0, to: 0 })
    expect(JSON.stringify(stored)).not.toContain(marker)
  })

  const cases = names.flatMap(name => [undefined, ...Array.from({ length: STORE_SCHEMA_VERSIONS[name] + 1 }, (_, v) => v)]
    .map(version => ({ name, version })))
  it.each(cases)('migrates $name version $version once, retaining metadata and the exact original backup', async ({ name, version }) => {
    const seed = fixture(name, version), raw = JSON.stringify(seed, null, 2)
    writeFileSync(file(name), raw)
    const read = await facade(name)
    // Construction must not merge/write schema/defaults before backup.
    expect(readFileSync(file(name), 'utf8')).toBe(raw)
    expect(JSON.stringify(read())).toContain(marker)
    const persisted = JSON.parse(readFileSync(file(name), 'utf8'))
    expect(persisted.extension).toEqual(seed.extension)
    expect(persisted.schemaVersion).toBe(STORE_SCHEMA_VERSIONS[name])
    expect(JSON.stringify(persisted)).not.toContain(marker)
    const step = persisted.migrationHistory[0]
    expect(persisted.migrationHistory).toHaveLength(1)
    expect(step).toMatchObject({
      id: name !== 'server-groups' && version === STORE_SCHEMA_VERSIONS[name] ? 'safe-storage-v1-repair' : 'safe-storage-v1',
      from: version ?? 0, to: STORE_SCHEMA_VERSIONS[name], status: 'success'
    })
    expect(step.completedAt).toEqual(expect.any(Number))
    expect(step.inputChecksum).toBe(digest(JSON.stringify(seed)))
    expect(step.backupChecksum).toBe(digest(raw))
    expect(step.backupSuffix).toBe('.pre-safe-storage-v1.bak')
    const { migrationHistory: _history, ...output } = persisted
    expect(step.outputChecksum).toBe(digest(JSON.stringify(output)))
    const { decryptSecret } = await import('./secretStorage')
    const backup = JSON.parse(readFileSync(file(name) + '.pre-safe-storage-v1.bak', 'utf8'))
    expect(digest(decryptSecret(backup.contents))).toBe(digest(raw))
    const after = readFileSync(file(name)), backupAfter = readFileSync(file(name) + '.pre-safe-storage-v1.bak')
    vi.resetModules()
    expect(JSON.stringify((await facade(name))())).toContain(marker)
    expect(readFileSync(file(name))).toEqual(after)
    expect(readFileSync(file(name) + '.pre-safe-storage-v1.bak')).toEqual(backupAfter)
    expect(state.log.mock.calls.filter(call => call[2] === 'migration step committed')).toHaveLength(1)
    expect(JSON.stringify(state.log.mock.calls)).not.toContain(marker)
    expect(JSON.stringify(state.log.mock.calls)).not.toContain(state.dir)
  })

  it.each(names)('retains %s on mid-preparation failure, then retries', async name => {
    const raw = JSON.stringify(fixture(name, 0)); writeFileSync(file(name), raw)
    const read = await facade(name)
    state.failAt = 2 // Backup encryption succeeds; the actual transformation fails.
    expect(read).toThrow('injected-encryption-failure')
    expect(readFileSync(file(name), 'utf8')).toBe(raw)
    expect(state.log).toHaveBeenLastCalledWith('error', 'store-migration', expect.any(String), {
      store: name, stage: 'prepare', status: 'error'
    })
    state.failAt = 0
    expect(JSON.stringify(read())).toContain(marker)
    expect(JSON.parse(readFileSync(file(name), 'utf8')).migrationHistory).toHaveLength(1)
  })

  it('encrypts partial legacy settings without filling or dropping unrelated settings', async () => {
    writeFileSync(file('settings'), JSON.stringify({ settings: { directVpnInput: marker, unknownOption: 42 } }))
    const read = await facade('settings')
    expect(read()).toMatchObject({ directVpnInput: marker })
    const stored = JSON.parse(readFileSync(file('settings'), 'utf8'))
    expect(stored.settings.unknownOption).toBe(42)
    expect(Object.keys(stored.settings).sort()).toEqual(['directVpnInput', 'unknownOption'])
    expect(stored.migrationHistory[0]).toMatchObject({ from: 0, to: 2 })
  })

  it('preserves a previous backup and creates a verified snapshot of a changed migration input', async () => {
    const raw = JSON.stringify(fixture('settings', 0)), earlier = JSON.stringify({ settings: { directVpnInput: 'EARLIER' } })
    writeFileSync(file('settings'), raw)
    writeFileSync(file('settings') + '.pre-safe-storage-v1.bak', earlier)
    const read = await facade('settings')
    read()
    const { decryptSecret } = await import('./secretStorage')
    const record = JSON.parse(readFileSync(file('settings'), 'utf8')).migrationHistory[0]
    expect(record.backupChecksum).toBe(digest(raw))
    expect(record.backupSuffix).toBe(`.pre-safe-storage-v1-${digest(raw)}.bak`)
    const restore = (suffix: string) => decryptSecret(JSON.parse(readFileSync(file('settings') + suffix, 'utf8')).contents)
    expect(restore('.pre-safe-storage-v1.bak')).toBe(earlier)
    expect(restore(record.backupSuffix)).toBe(raw)
  })

  it.each(names)('retains %s without secure storage and creates no plaintext backup', async name => {
    const raw = JSON.stringify(fixture(name)); writeFileSync(file(name), raw)
    const read = await facade(name)
    state.available = false
    expect(read).toThrow('unavailable')
    expect(readFileSync(file(name), 'utf8')).toBe(raw)
    expect(existsSync(file(name) + '.pre-safe-storage-v1.bak')).toBe(false)
  })

  it.each(names)('refuses future %s before backup or encryption', async name => {
    const raw = JSON.stringify(fixture(name, STORE_SCHEMA_VERSIONS[name] + 1)); writeFileSync(file(name), raw)
    await expect(facade(name)).rejects.toMatchObject({ code: 'STORE_SCHEMA_FUTURE' })
    expect(readFileSync(file(name), 'utf8')).toBe(raw)
    expect(state.calls).toBe(0)
    expect(existsSync(file(name) + '.pre-safe-storage-v1.bak')).toBe(false)
  })
})

describe('migration transaction boundaries', () => {
  it('dry-run plans all registered stores without effects', async () => {
    const { planStoreMigrations } = await import('./storeMigrations')
    for (const [name, version] of Object.entries(STORE_SCHEMA_VERSIONS)) {
      const id = name as keyof typeof STORE_SCHEMA_VERSIONS
      expect(planStoreMigrations(id, { schemaVersion: version })).toEqual([])
      expect(() => planStoreMigrations(id, { schemaVersion: version + 1 })).toThrow(expect.objectContaining({ code: 'STORE_SCHEMA_FUTURE' }))
    }
    expect(planStoreMigrations('settings', { schemaVersion: 1 }, true)).toEqual([{ id: 'safe-storage-v1', from: 1, to: 2 }])
    expect(planStoreMigrations('settings', { schemaVersion: 1 })).toEqual([])
    expect(state.calls).toBe(0); expect(state.log).not.toHaveBeenCalled()
  })

  it.each(['prepare', 'commit', 'changed', 'reentrant', 'read-back'] as const)('reports %s failure without a success event', async boundary => {
    const { migrateSecretStore } = await import('./storeMigrations')
    let current: Record<string, unknown> = { schemaVersion: 0, value: { keep: true } }
    const write = vi.fn((value: Record<string, unknown>) => {
      if (boundary === 'commit') throw new Error('injected-commit-failure')
      current = boundary === 'read-back' ? { schemaVersion: 2, lost: true } : value
    })
    const options = { path: file('settings'), read: () => structuredClone(current), write,
      hasPlaintext: () => Number(current.schemaVersion) < 2, prepare: (value: Record<string, unknown>) => {
        if (boundary === 'prepare') { (value.value as Record<string, unknown>).keep = false; throw new Error('injected-prepare-failure') }
        if (boundary === 'changed') current = { schemaVersion: 0, concurrent: true }
        if (boundary === 'reentrant') migrateSecretStore('settings', options)
        return value
      } }
    expect(() => migrateSecretStore('settings', options)).toThrow()
    expect(state.log.mock.calls.some(call => call[2] === 'migration step committed')).toBe(false)
    if (boundary === 'prepare' || boundary === 'commit' || boundary === 'reentrant') expect(current).toEqual({ schemaVersion: 0, value: { keep: true } })
    if (boundary === 'changed') { expect(write).not.toHaveBeenCalled(); expect(current).toEqual({ schemaVersion: 0, concurrent: true }) }
    // Failure releases the main-process admission guard for a later retry.
    current = { schemaVersion: 2 }
    expect(() => migrateSecretStore('settings', options)).not.toThrow()
  })
})
