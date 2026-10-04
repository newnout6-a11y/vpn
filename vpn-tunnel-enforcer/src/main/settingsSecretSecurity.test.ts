// AT-01-001/010, F-001: backup-stage audit and retry without losing settings.
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { logEvent } from './appLogger'

const state = vi.hoisted(() => ({ directory: '', data: {} as Record<string, any>,
  available: true, failEncrypt: false, failDecrypt: false }))
vi.mock('electron', () => ({ app: { isPackaged: true }, safeStorage: {
  isEncryptionAvailable: () => state.available,
  encryptString: (value: string) => {
    if (state.failEncrypt) throw new Error('FAKE-ENCRYPT-ERROR')
    return Buffer.from('protected:' + value)
  },
  decryptString: (value: Buffer) => {
    if (state.failDecrypt) throw new Error('FAKE-DECRYPT-ERROR')
    return value.toString().replace(/^protected:/, '')
  }
} }))
vi.mock('electron-store', () => ({ default: class {
  get(key: string) { return state.data[key] }
  get path() { return join(state.directory, 'settings.json') }
  set store(value: Record<string, any>) {
    writeFileSync(this.path, JSON.stringify(value)); state.data = value
  }
} }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./admin', () => ({ execElevated: vi.fn() }))
vi.mock('./domainEnrichment', () => ({ domainEnrichmentService: { setEnabled: vi.fn() } }))
vi.mock('./recoveryManifest', () => ({ readBootRecoveryReport: vi.fn() }))

beforeEach(() => {
  vi.resetModules(); vi.mocked(logEvent).mockClear()
  state.directory = mkdtempSync(join(tmpdir(), 'vpnte-settings-backup-'))
  state.available = true; state.failEncrypt = false; state.failDecrypt = false
  state.data = { schemaVersion: 0, settings: {
    proxyOverride: 'http://user:FAKE-PROXY@127.0.0.1:8080',
    directVpnInput: 'vless://FAKE-UUID@vpn.test:443', directVpnCachedInput: 'FAKE-INPUT',
    directVpnCachedSource: 'https://sub.test/FAKE-TOKEN',
    directVpnCachedProfiles: [{ name: 'Fixture', protocol: 'vless', outbound: { uuid: 'FAKE-UUID' } }]
  } }
  writeFileSync(join(state.directory, 'settings.json'), JSON.stringify(state.data))
})
afterEach(() => rmSync(state.directory, { recursive: true, force: true }))

describe('settings backup audit', () => {
  it.each([
    ['existing', 'encrypt'], ['create', 'encrypt'],
    ['existing', 'decrypt'], ['create', 'decrypt']
  ] as const)('audits %s backup %s failure and retains original secrets for retry', async (mode, fault) => {
    const path = join(state.directory, 'settings.json'); const backup = path + '.pre-safe-storage-v1.bak'
    const before = readFileSync(path); const original = JSON.parse(before.toString()).settings
    if (mode === 'existing') writeFileSync(backup, before)
    state.failEncrypt = fault === 'encrypt'; state.failDecrypt = fault === 'decrypt'
    const { settingsStore } = await import('./settings')
    expect(() => settingsStore.get()).toThrow()
    expect(readFileSync(path)).toEqual(before)
    expect(JSON.stringify(state.data)).toBe(before.toString())
    if (mode === 'existing') expect(readFileSync(backup)).toEqual(before)
    else expect(existsSync(backup)).toBe(false)
    expect(logEvent).toHaveBeenLastCalledWith('error', 'secret-migration', 'secret backup step failed; original data retained', {
      store: 'settings', step: mode === 'existing' ? 'backup-existing' : 'backup-create', status: 'error'
    })
    expect(JSON.stringify(vi.mocked(logEvent).mock.calls)).not.toContain('FAKE-')
    expect(JSON.stringify(vi.mocked(logEvent).mock.calls)).not.toContain(state.directory)
    state.failEncrypt = false; state.failDecrypt = false
    expect(settingsStore.get()).toMatchObject(original)
    expect(state.data.schemaVersion).toBe(2)
    expect(readFileSync(path, 'utf8')).not.toContain('FAKE-')
    const { decryptSecret } = await import('./secretStorage')
    expect(decryptSecret(JSON.parse(readFileSync(backup, 'utf8')).contents)).toBe(before.toString())
    vi.resetModules()
    expect((await import('./settings')).settingsStore.get()).toMatchObject(original)
  })
  it('audits encrypted-backup refusal and preserves both files until DPAPI recovers', async () => {
    const { settingsStore } = await import('./settings')
    const original = structuredClone(state.data.settings)
    expect(settingsStore.get()).toMatchObject(original)
    const path = join(state.directory, 'settings.json'); const backup = path + '.pre-safe-storage-v1.bak'
    const before = readFileSync(path); const backupBefore = readFileSync(backup)
    state.available = false
    expect(() => settingsStore.get()).toThrow('unavailable')
    expect(readFileSync(path)).toEqual(before); expect(readFileSync(backup)).toEqual(backupBefore)
    expect(logEvent).toHaveBeenLastCalledWith('error', 'secret-migration', expect.any(String), {
      store: 'settings', step: 'backup-existing', status: 'error'
    })
    state.available = true
    expect(settingsStore.get()).toMatchObject(original)
  })
})
