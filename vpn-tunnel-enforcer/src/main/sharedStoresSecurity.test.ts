import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { logEvent } from './appLogger'

const state = vi.hoisted(() => ({
  stores: {} as Record<string, Record<string, any>>,
  failOnEncryptCall: 0,
  encryptCalls: 0,
  failDecrypt: false,
  directory: ''
}))

vi.mock('electron', () => ({
  safeStorage: {
    isEncryptionAvailable: () => true,
    encryptString: (value: string) => {
      state.encryptCalls += 1
      if (state.failOnEncryptCall === state.encryptCalls) throw new Error('injected safeStorage failure')
      return Buffer.from(`encrypted:${value}`, 'utf8')
    },
    decryptString: (value: Buffer) => {
      if (state.failDecrypt) throw new Error('FAKE-DECRYPT-ERROR')
      return value.toString('utf8').replace(/^encrypted:/, '')
    }
  }
}))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))

vi.mock('electron-store', () => ({
  default: class MockStore {
    private name: string
    constructor(options: { name: string; defaults?: Record<string, any> }) {
      this.name = options.name
      state.stores[this.name] ??= { ...(options.defaults ?? {}) }
    }
    get(key: string, fallback?: unknown) {
      return state.stores[this.name][key] ?? fallback
    }
    set(key: string, value: unknown) {
      state.stores[this.name][key] = value
      if (state.directory) writeFileSync(this.path, JSON.stringify(state.stores[this.name]))
    }
    get path() {
      return state.directory ? join(state.directory, `${this.name}.json`) : `/path-that-does-not-exist/${this.name}.json`
    }
    get store() {
      return state.stores[this.name]
    }
    set store(value: Record<string, any>) {
      state.stores[this.name] = value
      if (state.directory) writeFileSync(this.path, JSON.stringify(value))
    }
  }
}))

afterEach(() => {
  if (state.directory) rmSync(state.directory, { recursive: true, force: true })
  state.directory = ''; state.failDecrypt = false
})

function plaintextProfile(id: string) {
  return {
    id,
    name: id,
    protocol: 'vless',
    server: 'vpn.example',
    port: 443,
    status: 'unknown',
    sourceUri: `vless://${id}@vpn.example:443`,
    outbound: { type: 'vless', uuid: id, server: 'vpn.example', server_port: 443 }
  }
}

describe('server profile safeStorage migration (AT-01-001)', () => {
  beforeEach(() => {
    vi.resetModules()
    state.encryptCalls = 0
    state.failOnEncryptCall = 0
    state.stores = {
      'server-picker': {
        schemaVersion: 1,
        profiles: [plaintextProfile('FAKE-UUID-1'), plaintextProfile('FAKE-UUID-2')],
        activeProfileId: 'FAKE-UUID-1'
      }
    }
  })

  it('atomically replaces plaintext profiles with SecretRef values', async () => {
    const { serverPickerStore } = await import('./sharedStores')
    const profiles = serverPickerStore.get('profiles')
    expect(profiles[0].outbound?.uuid).toBe('FAKE-UUID-1')
    const raw = JSON.stringify(state.stores['server-picker'])
    expect(raw).not.toContain('vless://')
    expect(raw).not.toContain('"uuid":"FAKE-UUID-1"')
    expect(raw).toContain('vpnte-safe-storage-v1')
  })

  it('leaves the entire legacy store unchanged after an injected encryption failure', async () => {
    const before = JSON.stringify(state.stores['server-picker'])
    state.failOnEncryptCall = 3
    const { serverPickerStore } = await import('./sharedStores')
    expect(() => serverPickerStore.get('profiles')).toThrow(/injected safeStorage failure/)
    expect(JSON.stringify(state.stores['server-picker'])).toBe(before)
  })
})

describe('shared-store backup audit and rollback (AT-01-001/010)', () => {
  beforeEach(() => {
    vi.resetModules(); vi.mocked(logEvent).mockClear()
    state.encryptCalls = 0; state.failOnEncryptCall = 0; state.failDecrypt = false
    state.directory = mkdtempSync(join(tmpdir(), 'vpnte-shared-backup-'))
    state.stores = {
      'server-picker': { schemaVersion: 1, profiles: [plaintextProfile('FAKE-UUID')], activeProfileId: 'FAKE-UUID' },
      'server-groups': { groups: [{ id: 'group', name: 'group', source: 'subscription', sourceUrl: 'https://sub.test/FAKE-TOKEN' }] }
    }
    for (const [name, data] of Object.entries(state.stores)) writeFileSync(join(state.directory, `${name}.json`), JSON.stringify(data))
  })
  it.each([
    ['server-picker', 'existing', 'encrypt'], ['server-picker', 'create', 'encrypt'],
    ['server-picker', 'existing', 'decrypt'], ['server-picker', 'create', 'decrypt'],
    ['server-groups', 'existing', 'encrypt'], ['server-groups', 'create', 'encrypt'],
    ['server-groups', 'existing', 'decrypt'], ['server-groups', 'create', 'decrypt']
  ] as const)('audits %s %s backup %s failure and retries without loss', async (name, mode, fault) => {
    const path = join(state.directory, `${name}.json`); const backup = path + '.pre-safe-storage-v1.bak'
    const before = readFileSync(path)
    if (mode === 'existing') writeFileSync(backup, before)
    // Groups prepare one encrypted entry before creating a new backup.
    state.failOnEncryptCall = fault === 'encrypt' ? (name === 'server-groups' && mode === 'create' ? 2 : 1) : 0
    state.failDecrypt = fault === 'decrypt'
    const { serverPickerStore, serverGroupsStore } = await import('./sharedStores')
    const read = () => name === 'server-picker' ? serverPickerStore.get('profiles') : serverGroupsStore.get('groups')
    expect(read).toThrow()
    expect(readFileSync(path)).toEqual(before)
    expect(JSON.stringify(state.stores[name])).toBe(before.toString())
    if (mode === 'existing') expect(readFileSync(backup)).toEqual(before)
    else expect(existsSync(backup)).toBe(false)
    expect(logEvent).toHaveBeenLastCalledWith('error', 'secret-migration', 'secret backup step failed; original data retained', {
      store: name, step: mode === 'existing' ? 'backup-existing' : 'backup-create', status: 'error'
    })
    const audit = JSON.stringify(vi.mocked(logEvent).mock.calls)
    expect(audit).not.toContain('FAKE-'); expect(audit).not.toContain(state.directory)
    state.failOnEncryptCall = 0; state.failDecrypt = false
    const restored = read()[0]
    if (name === 'server-picker') expect(restored).toEqual(plaintextProfile('FAKE-UUID'))
    else expect(restored).toMatchObject({ sourceUrl: 'https://sub.test/FAKE-TOKEN' })
    expect(readFileSync(path, 'utf8')).not.toContain('FAKE-TOKEN')
    const { decryptSecret } = await import('./secretStorage')
    expect(decryptSecret(JSON.parse(readFileSync(backup, 'utf8')).contents)).toBe(before.toString())
  })
})

describe('subscription group encryption (AT-01-001)', () => {
  beforeEach(() => {
    vi.resetModules(); state.encryptCalls = 0; state.failOnEncryptCall = 0
    state.stores = { 'server-groups': { groups: [{ id: 'group', name: 'group', source: 'subscription', sourceUrl: 'https://sub.test/PRIVATE-TOKEN', importedAt: 1, status: 'ok' }] } }
  })
  it('migrates group URL secrets atomically and still returns the original model', async () => {
    const { serverGroupsStore } = await import('./sharedStores')
    expect(serverGroupsStore.get('groups')[0].sourceUrl).toBe('https://sub.test/PRIVATE-TOKEN')
    expect(JSON.stringify(state.stores['server-groups'])).not.toContain('PRIVATE-TOKEN')
    expect(JSON.stringify(state.stores['server-groups'])).toContain('vpnte-safe-storage-v1')
    serverGroupsStore.set('groups', serverGroupsStore.get('groups'))
    expect(serverGroupsStore.get('groups')[0].sourceUrl).toBe('https://sub.test/PRIVATE-TOKEN')
  })
  it('does not partially replace groups after failed encryption', async () => {
    const before = JSON.stringify(state.stores['server-groups']); state.failOnEncryptCall = 1
    const { serverGroupsStore } = await import('./sharedStores')
    expect(() => serverGroupsStore.get('groups')).toThrow('injected')
    expect(JSON.stringify(state.stores['server-groups'])).toBe(before)
  })
})
