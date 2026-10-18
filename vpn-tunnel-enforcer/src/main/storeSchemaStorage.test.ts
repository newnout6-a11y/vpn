// AT-00-006 / F-074: real Conf disk backend, not an in-memory Store mock.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mkdtemp, readFile, rm, writeFile, mkdir } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { join, dirname } from 'node:path'
import Store from './versionedStore'
import { STORE_SCHEMA_VERSIONS } from './storeSchema'
import { classifyIpcError } from '../shared/ipc-result'

const state = vi.hoisted(() => ({ dir: '', secretEffect: vi.fn() }))
vi.mock('electron', () => ({ ipcMain: { handle: vi.fn() }, app: {} }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./secretStorage', () => ({
  protectLegacySecretBackup: state.secretEffect, encryptSecret: state.secretEffect,
  encryptJsonSecret: state.secretEffect, decryptSecret: state.secretEffect,
  decryptJsonSecret: state.secretEffect, isSecretRef: () => false, isSecretEncryptionAvailable: () => true
}))
vi.mock('electron-store', async () => {
  const { default: Conf } = await vi.importActual<typeof import('conf')>('conf')
  return { default: class extends Conf {
    constructor(options: Record<string, unknown>) {
      super({ ...options, cwd: state.dir, configName: String(options.name), projectVersion: '1.1.24' })
    }
  } }
})

const file = (name: string) => join(state.dir, `${name}.json`)
const hash = async (name: string) => createHash('sha256').update(await readFile(file(name))).digest('hex')
beforeEach(async () => {
  await mkdir(join(process.cwd(), '.tmp'), { recursive: true })
  state.dir = await mkdtemp(join(process.cwd(), '.tmp', 'store-schema-'))
  state.secretEffect.mockClear()
})
afterEach(async () => {
  expect(dirname(state.dir)).toBe(join(process.cwd(), '.tmp'))
  await rm(state.dir, { recursive: true, force: true })
})

describe('store schema admission', () => {
  it.each(Object.entries(STORE_SCHEMA_VERSIONS))('refuses future %s before defaults or custom deserialization/write', async (name, version) => {
    await writeFile(file(name), JSON.stringify({ schemaVersion: version + 1, privateValue: 'must-not-log' }))
    const before = await hash(name), deserialize = vi.fn(() => ({})), serialize = vi.fn(() => '{}')
    let caught: unknown
    try { new Store({ name, defaults: { value: 1 }, deserialize, serialize }) } catch (error) { caught = error }
    expect(caught).toMatchObject({ code: 'STORE_SCHEMA_FUTURE', category: 'conflict' })
    expect(classifyIpcError(caught)).toBe('conflict')
    expect(String(caught)).not.toContain('must-not-log')
    expect(deserialize).not.toHaveBeenCalled()
    expect(serialize).not.toHaveBeenCalled()
    expect(await hash(name)).toBe(before)
  })

  it.each([undefined, 0, 1, 2])('preserves supported settings metadata version %s without claiming migration', async version => {
    const initial = { ...(version === undefined ? {} : { schemaVersion: version }), value: 5, unknownMetadata: { keep: true } }
    await writeFile(file('settings'), JSON.stringify(initial))
    const before = await hash('settings')
    const store = new Store({ name: 'settings', defaults: { value: 0 } })
    expect(store.get('value')).toBe(5)
    expect(await hash('settings')).toBe(before)
    store.set('value', 6)
    expect(JSON.parse(await readFile(file('settings'), 'utf8'))).toEqual({ ...initial, value: 6 })
  })

  it.each([null, '2', -1, 0.5, { secret: 'must-not-log' }])('rejects malformed version %j without rewriting it', async version => {
    await writeFile(file('settings'), JSON.stringify({ schemaVersion: version }))
    const before = await hash('settings')
    expect(() => new Store({ name: 'settings', defaults: { value: 0 } })).toThrow(expect.objectContaining({ code: 'STORE_SCHEMA_INVALID' }))
    expect(await hash('settings')).toBe(before)
  })

  it.each(['unknown', 'toString', '../settings'])('rejects unregistered store %s', name => {
    expect(() => new Store({ name })).toThrow(expect.objectContaining({ code: 'STORE_SCHEMA_UNREGISTERED' }))
  })

  it.each(['set', 'replace', 'clear', 'delete', 'reset'] as const)('rejects %s after a newer file replaces an open store', async action => {
    const store = new Store({ name: 'settings', defaults: { value: 0 } })
    await writeFile(file('settings'), '{"schemaVersion":3,"value":42,"newerField":"retained"}')
    const before = await hash('settings')
    const mutate = () => {
      if (action === 'set') store.set('value', 1)
      if (action === 'replace') store.store = { value: 1 }
      if (action === 'clear') store.clear()
      if (action === 'delete') store.delete('value')
      if (action === 'reset') store.reset('value')
    }
    expect(mutate).toThrow(expect.objectContaining({ code: 'STORE_SCHEMA_FUTURE' }))
    expect(await hash('settings')).toBe(before)
  })

  it('refuses to write a future version from an otherwise supported handle', async () => {
    const store = new Store<{ schemaVersion?: number; value: number }>({ name: 'settings', defaults: { value: 0 } })
    const before = await hash('settings')
    expect(() => store.set('schemaVersion', 3)).toThrow(expect.objectContaining({ code: 'STORE_SCHEMA_FUTURE' }))
    expect(await hash('settings')).toBe(before)
  })

  it('does not treat future schema refusal as clearable invalid JSON', async () => {
    await writeFile(file('connection-history'), '{"schemaVersion":1,"newerField":"retained"}')
    const before = await hash('connection-history')
    expect(() => new Store({ name: 'connection-history', clearInvalidConfig: true, defaults: { value: 0 } }))
      .toThrow(expect.objectContaining({ code: 'STORE_SCHEMA_FUTURE' }))
    expect(await hash('connection-history')).toBe(before)
  })

  it.each(['settings', 'server-picker', 'server-groups', 'granular-kill-switch', 'connection-history'] as const)('protects actual %s import before defaults/repair/migration', async name => {
    vi.resetModules()
    await writeFile(file(name), JSON.stringify({ schemaVersion: STORE_SCHEMA_VERSIONS[name] + 1, newerField: 'retained' }))
    const before = await hash(name)
    const load = name === 'settings' ? import('./settings') : name === 'connection-history' ? import('./connectionHistory') : import('./sharedStores')
    let caught: unknown
    try { await load } catch (error) { caught = error }
    expect(await hash(name)).toBe(before)
    expect(caught).toMatchObject({ code: 'STORE_SCHEMA_FUTURE' })
    expect(state.secretEffect).not.toHaveBeenCalled()
  })
})
