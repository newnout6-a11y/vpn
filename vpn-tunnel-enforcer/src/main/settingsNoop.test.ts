// AT-09-013 / AT-01-010: unchanged settings retain ciphertext and trust checks.
import { beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({ data: {} as Record<string, any>, failRead: false, writes: vi.fn(), encrypt: vi.fn() }))
vi.mock('electron', () => ({ app: { isPackaged: true }, dialog: {} }))
vi.mock('./versionedStore', () => ({ default: class {
  constructor(options: { defaults?: Record<string, any> }) { state.data = structuredClone(options.defaults ?? {}) }
  get(key: string, fallback?: unknown) { return state.data[key] ?? fallback }
  set(key: string, value: unknown) { state.writes(key, value); state.data[key] = value }
  get store() { return state.data }
  get path() { return '/fixture/settings.json' }
} }))
vi.mock('./storeMigrations', () => ({
  migrateSecretStore: () => { if (state.failRead) throw new Error('trust unavailable') },
  assertMigrationReadBack: vi.fn()
}))
vi.mock('./secretStorage', () => ({
  isSecretRef: (value: any) => value?.fixtureSecret === true,
  decryptSecret: (value: any) => value.value,
  decryptJsonSecret: (value: any) => value.value,
  encryptSecret: (value: unknown) => { state.encrypt(); return { fixtureSecret: true, value } },
  encryptJsonSecret: (value: unknown) => { state.encrypt(); return { fixtureSecret: true, value } },
  isSecretEncryptionAvailable: () => true
}))
vi.mock('./admin', () => ({ execElevated: vi.fn() }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./domainEnrichment', () => ({ domainEnrichmentService: { setEnabled: vi.fn() } }))
vi.mock('./recoveryManifest', () => ({ readBootRecoveryReport: vi.fn() }))

beforeEach(() => { vi.resetModules(); state.failRead = false; state.writes.mockClear(); state.encrypt.mockClear() })

describe('settings saves without changes', () => {
  it('does not re-encrypt or write a structurally equal settings snapshot', async () => {
    const { settingsStore } = await import('./settings')
    settingsStore.save({ directVpnInput: 'SYNTHETIC-KEY', directVpnCachedProfiles: [
      { name: 'fixture', protocol: 'vless', outbound: { type: 'vless', server: 'fixture.invalid' } }
    ] })
    const before = structuredClone(state.data)
    state.writes.mockClear(); state.encrypt.mockClear()
    const settings = settingsStore.get()
    expect(settingsStore.save(structuredClone(settings))).toEqual(settings)
    expect(state.writes).not.toHaveBeenCalled()
    expect(state.encrypt).not.toHaveBeenCalled()
    expect(state.data).toEqual(before)
  })

  it('still persists a changed normalized value', async () => {
    const { settingsStore } = await import('./settings')
    const before = settingsStore.get()
    const saved = settingsStore.save({ checkInterval: before.checkInterval + 5000 })
    expect(saved.checkInterval).toBe(before.checkInterval + 5000)
    expect(state.writes).toHaveBeenCalledTimes(2)
  })

  it('does not bypass current trust inspection for an empty patch', async () => {
    const { settingsStore } = await import('./settings')
    state.failRead = true
    expect(() => settingsStore.save({})).toThrow('trust unavailable')
    expect(state.writes).not.toHaveBeenCalled()
  })
})
