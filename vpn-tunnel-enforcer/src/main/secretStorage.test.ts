import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync, symlinkSync } from 'fs'
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
  it('rejects symlinked backup inputs rather than reading arbitrary files', () => {
    directory = mkdtempSync(join(tmpdir(), 'vpnte-encrypted-backup-'))
    const source = join(directory, 'store.json'); const backup = source + '.bak'
    writeFileSync(source, 'PRIVATE-TOKEN'); symlinkSync(source, backup)
    expect(() => protectLegacySecretBackup(backup)).toThrow('artifact')
    expect(readFileSync(source, 'utf8')).toBe('PRIVATE-TOKEN')
  })

})