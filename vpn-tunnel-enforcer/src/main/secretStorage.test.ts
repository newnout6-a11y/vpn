import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync, symlinkSync, readdirSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import { afterEach, describe, expect, it, vi } from 'vitest'

const safeStorageMock = vi.hoisted(() => ({
  available: true,
  packaged: false,
  isEncryptionAvailable: vi.fn(() => safeStorageMock.available),
  encryptString: vi.fn((value: string) => Buffer.from(`encrypted:${value}`, 'utf8')),
  decryptString: vi.fn((value: Buffer) => value.toString('utf8').replace(/^encrypted:/, ''))
}))

vi.mock('electron', () => ({ app: { get isPackaged() { return safeStorageMock.packaged } }, safeStorage: safeStorageMock }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
const fileFault = vi.hoisted(() => ({ failRename: false }))
vi.mock('fs', async original => {
  const fs = await original<typeof import('fs')>()
  const mocked = { ...fs, renameSync: (...args: Parameters<typeof fs.renameSync>) => {
    if (fileFault.failRename) throw new Error('FAKE-RENAME-SECRET')
    return fs.renameSync(...args)
  } }
  return { ...mocked, default: mocked }
})
import { logEvent } from './appLogger'

import {
  decryptJsonSecret,
  decryptSecret,
  encryptJsonSecret,
  encryptSecret,
  isSecretRef,
  protectLegacySecretBackup
} from './secretStorage'

describe('safeStorage secret references (AT-01-001, AT-01-010)', () => {
  const previousNodeEnv = process.env.NODE_ENV
  let directory = ''
  afterEach(() => {
    safeStorageMock.available = true
    safeStorageMock.packaged = false
    fileFault.failRename = false
    safeStorageMock.encryptString.mockReset().mockImplementation(value => Buffer.from(`encrypted:${value}`, 'utf8'))
    safeStorageMock.decryptString.mockReset().mockImplementation(value => value.toString('utf8').replace(/^encrypted:/, ''))
    vi.mocked(logEvent).mockClear()
    if (directory) rmSync(directory, { recursive: true, force: true })
    directory = ''
    if (previousNodeEnv === undefined) delete process.env.NODE_ENV
    else process.env.NODE_ENV = previousNodeEnv
  })

  it('round-trips strings and structured outbounds without plaintext fields', () => {
    const stringRef = encryptSecret('FAKE-PASSWORD')
    const jsonRef = encryptJsonSecret({ uuid: 'FAKE-UUID', tls: { enabled: true } })
    expect(isSecretRef(stringRef)).toBe(true)
    expect(JSON.stringify(stringRef)).not.toContain('FAKE-PASSWORD')
    expect(JSON.stringify(jsonRef)).not.toContain('FAKE-UUID')
    expect(decryptSecret(stringRef)).toBe('FAKE-PASSWORD')
    expect(decryptJsonSecret(jsonRef)).toEqual({ uuid: 'FAKE-UUID', tls: { enabled: true } })
    expect(stringRef.ciphertext).toMatch(/^enc:dpapi:v1:/)
  })

  it('keeps read compatibility with previously released unprefixed SecretRefs', () => {
    const legacy = { __vpnteSecretRef: 'vpnte-safe-storage-v1' as const, ciphertext: Buffer.from('encrypted:FAKE-LEGACY').toString('base64') }
    expect(decryptSecret(legacy)).toBe('FAKE-LEGACY')
  })

  it('fails closed when OS encryption is unavailable', () => {
    process.env.NODE_ENV = 'production'
    safeStorageMock.available = false
    expect(() => encryptSecret('FAKE-PASSWORD')).toThrow(/refusing to persist/)
  })
  it('does not enable a test cipher in a packaged application via NODE_ENV', () => {
    process.env.NODE_ENV = 'test'
    safeStorageMock.available = false; safeStorageMock.packaged = true
    expect(() => encryptSecret('PRIVATE')).toThrow('refusing')
    expect(() => decryptSecret({ __vpnteSecretRef: 'vpnte-safe-storage-v1', ciphertext: 'test:UFJJVkFURQ==' })).toThrow('unavailable')
  })
  it('encrypts existing plaintext backups and creates new backups without plaintext copies', () => {
    directory = mkdtempSync(join(tmpdir(), 'vpnte-encrypted-backup-'))
    const source = join(directory, 'store.json')
    const backup = source + '.pre-safe-storage-v1.bak'
    const plaintext = '{"sourceUri":"vless://PRIVATE-KEY@vpn.test","token":"PRIVATE-TOKEN"}'
    writeFileSync(source, plaintext)
    protectLegacySecretBackup(backup, source)
    const first = JSON.parse(readFileSync(backup, 'utf8'))
    expect(readFileSync(backup, 'utf8')).not.toContain('PRIVATE-KEY')
    expect(decryptSecret(first.contents)).toBe(plaintext)
    expect(readFileSync(source, 'utf8')).toBe(plaintext)
    writeFileSync(backup, plaintext)
    protectLegacySecretBackup(backup)
    expect(decryptSecret(JSON.parse(readFileSync(backup, 'utf8')).contents)).toBe(plaintext)
    const protectedBytes = readFileSync(backup, 'utf8')
    protectLegacySecretBackup(backup)
    expect(readFileSync(backup, 'utf8')).toBe(protectedBytes)
  })
  it('leaves the source unchanged and creates no backup if encryption fails', () => {
    directory = mkdtempSync(join(tmpdir(), 'vpnte-encrypted-backup-'))
    const source = join(directory, 'store.json'); const backup = source + '.bak'
    writeFileSync(source, 'PRIVATE-TOKEN')
    safeStorageMock.available = false; process.env.NODE_ENV = 'production'
    expect(() => protectLegacySecretBackup(backup, source)).toThrow('unavailable')
    expect(readFileSync(source, 'utf8')).toBe('PRIVATE-TOKEN')
    expect(existsSync(backup)).toBe(false)
  })
  it.each(['create', 'existing'] as const)('audits %s backup success and encrypted-backup verification (AT-01-001)', mode => {
    directory = mkdtempSync(join(tmpdir(), 'vpnte-backup-audit-'))
    const source = join(directory, 'store.json'); const backup = source + '.bak'
    const plaintext = '{"token":"FAKE-BACKUP-SECRET"}'
    writeFileSync(source, plaintext)
    if (mode === 'existing') writeFileSync(backup, plaintext)
    protectLegacySecretBackup(backup, mode === 'create' ? source : undefined, 'settings')
    expect(logEvent).toHaveBeenLastCalledWith('info', 'secret-migration', 'secret backup step completed', {
      store: 'settings', step: mode === 'create' ? 'backup-create' : 'backup-existing',
      status: 'success', result: mode === 'create' ? 'created' : 'protected'
    })
    const bytes = readFileSync(backup)
    protectLegacySecretBackup(backup, undefined, 'settings')
    expect(readFileSync(backup)).toEqual(bytes)
    expect(logEvent).toHaveBeenLastCalledWith('info', 'secret-migration', 'secret backup step completed', {
      store: 'settings', step: 'backup-existing', status: 'success', result: 'verified'
    })
    expect(decryptSecret(JSON.parse(bytes.toString()).contents)).toBe(plaintext)
    expect(readFileSync(source, 'utf8')).toBe(plaintext)
    expect(JSON.stringify(vi.mocked(logEvent).mock.calls)).not.toContain('FAKE-')
    expect(JSON.stringify(vi.mocked(logEvent).mock.calls)).not.toContain(directory)
  })
  it.each(['create', 'existing'] as const)('audits each %s backup failure without changing files (AT-01-001/010)', mode => {
    directory = mkdtempSync(join(tmpdir(), 'vpnte-backup-failure-'))
    const source = join(directory, 'store.json'); const backup = source + '.bak'
    const plaintext = '{"token":"FAKE-BACKUP-SECRET"}'
    writeFileSync(source, plaintext)
    if (mode === 'existing') writeFileSync(backup, plaintext)
    const sourceBefore = readFileSync(source)
    for (const fault of ['encrypt', 'decrypt', 'read-back', 'rename', 'unavailable'] as const) {
      safeStorageMock.encryptString.mockImplementation(value => {
        if (fault === 'encrypt') throw new Error('FAKE-ENCRYPT-SECRET')
        return Buffer.from(`encrypted:${value}`)
      })
      safeStorageMock.decryptString.mockImplementation(value => {
        if (fault === 'decrypt') throw new Error('FAKE-DECRYPT-SECRET')
        return fault === 'read-back' ? 'incorrect plaintext' : value.toString().replace(/^encrypted:/, '')
      })
      fileFault.failRename = fault === 'rename'
      safeStorageMock.available = fault !== 'unavailable'; safeStorageMock.packaged = true
      expect(() => protectLegacySecretBackup(backup, mode === 'create' ? source : undefined, 'settings'), fault).toThrow()
      expect(readFileSync(source)).toEqual(sourceBefore)
      if (mode === 'existing') expect(readFileSync(backup)).toEqual(sourceBefore)
      else expect(existsSync(backup)).toBe(false)
      expect(readdirSync(directory).sort()).toEqual(mode === 'existing' ? ['store.json', 'store.json.bak'] : ['store.json'])
      expect(logEvent).toHaveBeenLastCalledWith('error', 'secret-migration', 'secret backup step failed; original data retained', {
        store: 'settings', step: mode === 'create' ? 'backup-create' : 'backup-existing', status: 'error'
      })
    }
    expect(JSON.stringify(vi.mocked(logEvent).mock.calls)).not.toContain('FAKE-')
    expect(JSON.stringify(vi.mocked(logEvent).mock.calls)).not.toContain(directory)
  })
  it('audits an unreadable encrypted backup and leaves its bytes unchanged (AT-01-010)', () => {
    directory = mkdtempSync(join(tmpdir(), 'vpnte-protected-backup-'))
    const source = join(directory, 'store.json'); const backup = source + '.bak'
    writeFileSync(source, 'FAKE-SECRET')
    protectLegacySecretBackup(backup, source)
    const before = readFileSync(backup)
    safeStorageMock.available = false; safeStorageMock.packaged = true
    expect(() => protectLegacySecretBackup(backup)).toThrow('unavailable')
    expect(readFileSync(backup)).toEqual(before)
    expect(logEvent).toHaveBeenLastCalledWith('error', 'secret-migration', expect.any(String), {
      store: 'secrets', step: 'backup-existing', status: 'error'
    })
  })
  it('rejects symlinked backup inputs rather than reading arbitrary files', () => {
    directory = mkdtempSync(join(tmpdir(), 'vpnte-encrypted-backup-'))
    const source = join(directory, 'store.json'); const backup = source + '.bak'
    writeFileSync(source, 'PRIVATE-TOKEN'); symlinkSync(source, backup)
    expect(() => protectLegacySecretBackup(backup)).toThrow('artifact')
    expect(readFileSync(source, 'utf8')).toBe('PRIVATE-TOKEN')
  })

})
