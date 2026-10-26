import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { logEvent } from './appLogger'
import ts from 'typescript'
import type { ServerProfile } from '../shared/ipc-types'
import { withProfileStoreWriteLock } from './profileStoreQueue'

const state = vi.hoisted(() => ({
  stores: {} as Record<string, Record<string, any>>,
  failOnEncryptCall: 0,
  encryptCalls: 0,
  failDecrypt: false,
  available: true,
  decryptCalls: 0,
  directory: ''
}))

vi.mock('electron', () => ({
  app: { isPackaged: true },
  safeStorage: {
    isEncryptionAvailable: () => state.available,
    encryptString: (value: string) => {
      state.encryptCalls += 1
      if (state.failOnEncryptCall === state.encryptCalls) throw new Error('injected safeStorage failure')
      return Buffer.from(`encrypted:${value}`, 'utf8')
    },
    decryptString: (value: Buffer) => {
      state.decryptCalls += 1
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
  state.directory = ''; state.failDecrypt = false; state.available = true
})

describe('public profile metadata and DNS merge (AT-01-001/008/010, AT-04-008)', () => {
  beforeEach(() => {
    vi.resetModules()
    state.encryptCalls = 0; state.decryptCalls = 0; state.failOnEncryptCall = 0; state.failDecrypt = false; state.available = true
    state.stores = { 'server-picker': { schemaVersion: 2, profiles: [], activeProfileId: 'a' } }
  })

  it('decodes once for public hints, then refreshes without secret decrypts or returning credentials', async () => {
    const { serverPickerStore: store } = await import('./sharedStores')
    store.set('profiles', [{ ...plaintextProfile('a'), outbound: { type: 'vless', uuid: 'FAKE-SECRET',
      tls: { enabled: true, reality: { enabled: true, public_key: 'FAKE-KEY' }, utls: { fingerprint: 'chrome' } } } } as ServerProfile])
    const first = store.getProfileSummaries()
    const decoded = state.decryptCalls
    expect(first[0]).toMatchObject({ id: 'a', port: 443, display: { hasOutbound: true, stealth: 'reality', clientFingerprint: 'chrome' } })
    expect(first[0]).not.toHaveProperty('outbound'); expect(first[0]).not.toHaveProperty('sourceUri')
    expect(JSON.stringify(first)).not.toContain('FAKE-')
    first[0].display!.stealth = 'plain'
    expect(store.getProfileSummaries()[0].display?.stealth).toBe('reality')
    expect(state.decryptCalls).toBe(decoded)
    expect(store.get('profiles')[0].outbound?.uuid).toBe('FAKE-SECRET')
  })

  it('decodes only the selected usable profile for runtime and preserves the full outbound', async () => {
    const { serverPickerStore: store } = await import('./sharedStores')
    store.set('profiles', [plaintextProfile('a'), { ...plaintextProfile('b'), enabled: false }, plaintextProfile('c')] as ServerProfile[])
    state.decryptCalls = 0
    expect(store.getProfile('c', true)?.outbound?.uuid).toBe('c')
    expect(state.decryptCalls).toBe(2)
    expect(store.getProfile('b', true)?.id).toBe('a')
  })

  it.each([
    [undefined, '8443', 8443], [0, 8443, 443], [65536, 8443, 443], [443, 8443, 443]
  ])('preserves runtime port normalization for %s / %s', async (port, serverPort, expected) => {
    const { serverPickerStore: store } = await import('./sharedStores')
    store.set('profiles', [{ ...plaintextProfile('a'), port, outbound: { type: 'vless', server_port: serverPort } }] as ServerProfile[])
    expect(store.getProfile('a')).toMatchObject({ port: expected, outbound: { server_port: expected } })
    expect(store.getProfileSummaries()[0].port).toBe(expected)
  })

  it.each([
    [{ tls: { enabled: true, ech: { config: ['config'] } } }, 'vless', 'ech'],
    [{ tls: { enabled: true, ech: { enabled: false, config: ['config'] }, utls: { enabled: true } } }, 'vless', 'utls'],
    [{ tls: { enabled: true, reality: { enabled: true } } }, 'vless', 'reality'],
    [{ tls: { enabled: true, utls: { enabled: true } } }, 'vless', 'utls'],
    [{ tls: { enabled: true, utls: { enabled: false } } }, 'vless', 'tls'],
    [{ tls: { enabled: false, reality: { enabled: true } } }, 'vless', 'plain'],
    [{ tls: { reality: [], utls: [], ech: [] } }, 'vless', 'tls'],
    [{ tls: [] }, 'vless', 'plain'], [{ tls: 'invalid' }, 'vless', 'plain'],
    [{ type: 'naive' }, '', 'naive'], [{ type: { invalid: true } }, '', undefined],
    [{ obfs: { type: 'salamander' } }, 'hysteria2', 'obfs'], [{ obfs: [] }, 'hysteria2', undefined]
  ])('derives safe display markers from current encrypted configuration %j', async (outbound, protocol, stealth) => {
    const { serverPickerStore: store } = await import('./sharedStores')
    store.set('profiles', [{ ...plaintextProfile('a'), protocol, outbound }] as ServerProfile[])
    expect(store.getProfileSummaries()[0].display).toEqual({ hasOutbound: true, ...(stealth ? { stealth } : {}) })
  })

  it('discards caller-provided hints and refreshes them when public inputs change', async () => {
    const { serverPickerStore: store } = await import('./sharedStores')
    store.set('profiles', [{ ...plaintextProfile('a'), display: { hasOutbound: false, stealth: 'ech', clientFingerprint: 'forged' } }] as ServerProfile[])
    expect(state.stores['server-picker'].profiles[0]).not.toHaveProperty('display')
    expect(store.getProfileSummaries()[0].display).toEqual({ hasOutbound: true, stealth: 'plain' })
    Object.assign(state.stores['server-picker'].profiles[0], { protocol: 'naive', port: 8443, clientFingerprint: 'firefox' })
    expect(store.getProfileSummaries()[0]).toMatchObject({ port: 8443, display: { hasOutbound: true, stealth: 'naive', clientFingerprint: 'firefox' } })
  })

  it.each(['outbound', 'sourceUri'] as const)('invalidates public hints when current %s ciphertext changes', async field => {
    const { serverPickerStore: store } = await import('./sharedStores')
    store.set('profiles', [plaintextProfile('a')] as ServerProfile[])
    store.getProfileSummaries()
    state.stores['server-picker'].profiles[0][field].ciphertext += 'invalid'
    state.failDecrypt = true
    const before = JSON.stringify(state.stores['server-picker'])
    expect(() => store.getProfileSummaries()).toThrow('FAKE-DECRYPT-ERROR')
    expect(JSON.stringify(state.stores['server-picker'])).toBe(before)
  })

  it('refuses cached summaries and metadata writes when safeStorage becomes unavailable', async () => {
    const { serverPickerStore: store } = await import('./sharedStores')
    store.set('profiles', [plaintextProfile('a')] as ServerProfile[])
    store.getProfileSummaries()
    const before = JSON.stringify(state.stores['server-picker'])
    state.available = false
    expect(() => store.getProfileSummaries()).toThrow('unavailable')
    expect(() => store.getProfile('a')).toThrow('unavailable')
    expect(() => store.mergeResolvedIps(new Map([['a', { server: 'vpn.example', ip: '198.51.100.1', at: 5 }]]))).toThrow('unavailable')
    expect(JSON.stringify(state.stores['server-picker'])).toBe(before)
  })

  it('merges a delayed DNS result into current rows under the existing write queue', async () => {
    const { serverPickerStore: store } = await import('./sharedStores')
    store.set('profiles', ['a', 'deleted', 'changed'].map(plaintextProfile) as ServerProfile[])
    const source = ts.createSourceFile('serverPicker.ts', readFileSync('src/main/serverPicker.ts', 'utf8'), ts.ScriptTarget.Latest, true)
    const fn = source.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'resolveAndPersistProfileIps')!
    const compiled = ts.transpileModule('let resolveIpsInFlight = null;\n' + fn.getText(source) + '\nreturn resolveAndPersistProfileIps', {
      compilerOptions: { target: ts.ScriptTarget.ES2022 }
    }).outputText
    let finish!: (profiles: ServerProfile[]) => void
    const dns = new Promise<ServerProfile[]>(resolve => { finish = resolve })
    const profilesForDisplay = vi.fn(() => dns)
    const resolve = new Function('store', 'profilesForDisplay', 'withProfileStoreWriteLock', compiled)(store, profilesForDisplay, withProfileStoreWriteLock) as () => Promise<ServerProfile[]>
    const pending = resolve()
    const original = store.getProfileSummaries()
    store.set('profiles', [{ ...plaintextProfile('a'), name: 'New name' }, { ...plaintextProfile('changed'), server: 'new.example' }, plaintextProfile('new')] as ServerProfile[])
    const ciphertext = state.stores['server-picker'].profiles[0].outbound.ciphertext
    let release!: () => void
    const held = withProfileStoreWriteLock(() => new Promise<void>(done => { release = done }))
    await Promise.resolve()
    finish(original.map(profile => ({ ...profile, resolvedIp: '198.51.100.7', resolvedIpAt: 42 })))
    await Promise.resolve(); await Promise.resolve()
    expect(state.stores['server-picker'].profiles[0].resolvedIp).toBeUndefined()
    release(); await held
    const result = await pending
    expect(result.map(profile => profile.id)).toEqual(['a', 'changed', 'new'])
    expect(result[0]).toMatchObject({ name: 'New name', resolvedIp: '198.51.100.7', resolvedIpAt: 42 })
    expect(result[1].resolvedIp).toBeUndefined(); expect(result[2].resolvedIp).toBeUndefined()
    expect(state.stores['server-picker'].profiles[0].outbound.ciphertext).toBe(ciphertext)
    expect(result[0]).not.toHaveProperty('outbound')
  })
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
    // The shared runner now protects the backup before preparing every store.
    state.failOnEncryptCall = fault === 'encrypt' ? 1 : 0
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
