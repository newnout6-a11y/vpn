// AT-01-001/010, F-001: never persist a plaintext adaptive HMAC key.
import { createHmac } from 'crypto'
import { beforeEach, describe, expect, it, vi } from 'vitest'
const state = vi.hoisted(() => ({ available: true, data: {} as Record<string, any>, failEncrypt: false, failDecrypt: false, failCommit: false, wrongReadBack: false }))
vi.mock('electron', () => ({ app: { isPackaged: true }, safeStorage: {
  isEncryptionAvailable: () => state.available,
  encryptString: (value: string) => { if (state.failEncrypt) throw new Error('encrypt failed'); return Buffer.from('protected:' + value) },
  decryptString: (value: Buffer) => { if (state.failDecrypt) throw new Error('decrypt failed'); return state.wrongReadBack ? 'wrong secret' : value.toString().replace(/^protected:/, '') }
} }))
vi.mock('electron-store', () => ({ default: class {
  get(key: string) { return state.data[key] }
  set(key: string, value: unknown) { if (state.failCommit) throw new Error('commit failed'); state.data[key] = value }
  get store() { return state.data }
  set store(value: Record<string, any>) { if (state.failCommit) throw new Error('commit failed'); state.data = value }
} }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
const interfaces: any = { 'Wi-Fi': [{ address: '192.168.1.1', netmask: '255.255.255.0', family: 'IPv4', mac: '00:11:22:33:44:55', internal: false }] }
beforeEach(() => {
  vi.resetModules(); state.available = true; state.failEncrypt = false; state.failDecrypt = false
  state.failCommit = false; state.wrongReadBack = false; state.data = { learning: {} }
})
async function fingerprint() { return (await import('./adaptiveBypass')).networkFingerprint(interfaces) }
describe('adaptive secret persistence', () => {
  it('uses only an in-memory identity when encryption is unavailable on a new store', async () => {
    state.available = false
    await fingerprint()
    expect(state.data).toEqual({ learning: {} })
  })
  it('atomically migrates a legacy fallback key and retains learning', async () => {
    state.data = { fallbackInstallSecret: 'FAKE-KEY', learning: { fixture: 'metadata' } }
    await fingerprint()
    expect(state.data.fallbackInstallSecret).toBeUndefined()
    expect(state.data.encryptedInstallSecret).toMatch(/^enc:dpapi:v1:/)
    expect(state.data.learning).toEqual({ fixture: 'metadata' })
    const { decryptSecret, SECRET_REF_KIND } = await import('./secretStorage')
    expect(decryptSecret({ __vpnteSecretRef: SECRET_REF_KIND, ciphertext: state.data.encryptedInstallSecret })).toBe('FAKE-KEY')
  })
  it.each(['unavailable', 'encrypt-failure', 'decrypt-failure', 'read-back-mismatch', 'commit-failure'])('retains original data on %s', async scenario => {
    state.data = { fallbackInstallSecret: 'FAKE-KEY', learning: {} }
    if (scenario === 'unavailable') state.available = false
    if (scenario === 'encrypt-failure') state.failEncrypt = true
    if (scenario === 'decrypt-failure') state.failDecrypt = true
    if (scenario === 'read-back-mismatch') state.wrongReadBack = true
    if (scenario === 'commit-failure') state.failCommit = true
    const before = JSON.stringify(state.data)
    await expect(fingerprint()).rejects.toThrow()
    expect(JSON.stringify(state.data)).toBe(before)
    state.available = true; state.failEncrypt = false; state.failDecrypt = false
    state.wrongReadBack = false; state.failCommit = false
    const originalFingerprint = await fingerprint()
    expect(state.data.encryptedInstallSecret).toMatch(/^enc:dpapi:v1:/)
    vi.resetModules()
    expect(await fingerprint()).toBe(originalFingerprint)
  })
  it.each(['legacy', 'prefixed'] as const)('reads %s encrypted identities without rewriting the store (AT-01-001)', async format => {
    const ciphertext = Buffer.from('protected:FAKE-KEY').toString('base64')
    state.data = { encryptedInstallSecret: format === 'prefixed' ? 'enc:dpapi:v1:' + ciphertext : ciphertext,
      learning: { fixture: 'metadata' } }
    const before = JSON.stringify(state.data)
    const { profileFingerprint } = await import('./adaptiveBypass')
    expect(profileFingerprint(undefined)).toBe(createHmac('sha256', 'FAKE-KEY').update('local-proxy').digest('base64url'))
    expect(JSON.stringify(state.data)).toBe(before)
  })
  it.each(['legacy', 'prefixed'] as const)('retains %s identities while DPAPI is unavailable (AT-01-010)', async format => {
    const ciphertext = Buffer.from('protected:FAKE-KEY').toString('base64')
    state.data = { encryptedInstallSecret: format === 'prefixed' ? 'enc:dpapi:v1:' + ciphertext : ciphertext, learning: {} }
    const before = JSON.stringify(state.data); state.available = false
    await expect(fingerprint()).rejects.toThrow('unavailable')
    expect(JSON.stringify(state.data)).toBe(before)
    state.available = true
    await fingerprint()
    expect(JSON.stringify(state.data)).toBe(before)
  })
  it('persists a prefixed new identity that survives a module restart', async () => {
    const first = await fingerprint()
    expect(state.data.encryptedInstallSecret).toMatch(/^enc:dpapi:v1:/)
    expect(state.data.fallbackInstallSecret).toBeUndefined()
    vi.resetModules()
    expect(await fingerprint()).toBe(first)
  })
  it.each(['encrypt', 'decrypt', 'read-back', 'commit'] as const)('does not cache an uncommitted new identity after %s fails', async fault => {
    state.failEncrypt = fault === 'encrypt'; state.failDecrypt = fault === 'decrypt'
    state.wrongReadBack = fault === 'read-back'; state.failCommit = fault === 'commit'
    await expect(fingerprint()).rejects.toThrow()
    expect(state.data).toEqual({ learning: {} })
    state.failEncrypt = false; state.failDecrypt = false; state.wrongReadBack = false; state.failCommit = false
    const first = await fingerprint()
    expect(state.data.encryptedInstallSecret).toMatch(/^enc:dpapi:v1:/)
    vi.resetModules()
    expect(await fingerprint()).toBe(first)
  })
  it('does not delete or replace an existing encrypted key after decryption fails', async () => {
    state.data = { encryptedInstallSecret: 'cHJvdGVjdGVkOkZBS0UtS0VZ', learning: {} }; state.failDecrypt = true
    const before = JSON.stringify(state.data)
    await expect(fingerprint()).rejects.toThrow('decrypt failed')
    expect(JSON.stringify(state.data)).toBe(before)
  })
})
