import * as electron from 'electron'
import { existsSync, lstatSync, readFileSync, openSync, writeFileSync, fsyncSync, closeSync, renameSync, unlinkSync } from 'fs'
import { randomUUID } from 'crypto'
import { logEvent } from './appLogger'

export const SECRET_REF_KIND = 'vpnte-safe-storage-v1' as const
const DPAPI_PREFIX = 'enc:dpapi:v1:'

export interface SecretRef {
  __vpnteSecretRef: typeof SECRET_REF_KIND
  ciphertext: string
}

export function isSecretRef(value: unknown): value is SecretRef {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const candidate = value as Partial<SecretRef>
  return candidate.__vpnteSecretRef === SECRET_REF_KIND && typeof candidate.ciphertext === 'string'
}

function testCipherAvailable(): boolean {
  return process.env.NODE_ENV === 'test' && !('app' in electron && electron.app?.isPackaged === true)
}

function getSafeStorage(): typeof electron.safeStorage | undefined {
  return 'safeStorage' in electron ? electron.safeStorage : undefined
}

export function isSecretEncryptionAvailable(): boolean {
  const safeStorage = getSafeStorage()
  return Boolean(safeStorage?.isEncryptionAvailable?.()) || testCipherAvailable()
}

export function encryptSecret(value: string): SecretRef {
  const safeStorage = getSafeStorage()
  if (safeStorage?.isEncryptionAvailable?.()) {
    return {
      __vpnteSecretRef: SECRET_REF_KIND,
      ciphertext: DPAPI_PREFIX + safeStorage.encryptString(value).toString('base64')
    }
  }
  if (testCipherAvailable()) {
    return {
      __vpnteSecretRef: SECRET_REF_KIND,
      ciphertext: `test:${Buffer.from(value, 'utf8').toString('base64')}`
    }
  }
  throw new Error('Secure storage is unavailable; refusing to persist VPN secrets in plaintext')
}

export function decryptSecret(ref: SecretRef): string {
  if (ref.ciphertext.startsWith('test:') && testCipherAvailable()) {
    return Buffer.from(ref.ciphertext.slice(5), 'base64').toString('utf8')
  }
  const safeStorage = getSafeStorage()
  if (!safeStorage?.isEncryptionAvailable?.()) {
    throw new Error('Secure storage is unavailable; encrypted VPN secrets cannot be opened')
  }
  // Previously released SecretRefs used raw base64; preserve read compatibility.
  const ciphertext = ref.ciphertext.startsWith(DPAPI_PREFIX) ? ref.ciphertext.slice(DPAPI_PREFIX.length) : ref.ciphertext
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(ciphertext)) throw new Error('Invalid encrypted secret encoding')
  return safeStorage.decryptString(Buffer.from(ciphertext, 'base64'))
}

export function encryptJsonSecret(value: unknown): SecretRef {
  return encryptSecret(JSON.stringify(value))
}

export function decryptJsonSecret<T>(ref: SecretRef): T {
  return JSON.parse(decryptSecret(ref)) as T
}

/** Protect existing plaintext migration backups and create new ones without a
 * plaintext temporary file. The original source is never changed on failure. */
export function protectLegacySecretBackup(
  backupPath: string,
  sourcePath?: string,
  store: 'settings' | 'server-picker' | 'server-groups' | 'secrets' = 'secrets'
): void {
  const step = sourcePath ? 'backup-create' : 'backup-existing'
  try {
    const result = protectSecretBackup(backupPath, sourcePath)
    logEvent('info', 'secret-migration', 'secret backup step completed', {
      store, step, status: result === 'skipped' ? 'skipped' : 'success', result
    })
  } catch (error) {
    // Paths, file contents and exception text can contain credentials.
    logEvent('error', 'secret-migration', 'secret backup step failed; original data retained', {
      store, step, status: 'error'
    })
    throw error
  }
}

function protectSecretBackup(backupPath: string, sourcePath?: string): 'created' | 'protected' | 'verified' | 'skipped' {
  const exists = existsSync(backupPath)
  const input = exists ? backupPath : sourcePath
  if (!input || !existsSync(input)) return 'skipped'
  const info = lstatSync(input)
  if (!info.isFile() || info.isSymbolicLink() || info.size > 16 * 1024 * 1024) throw new Error('Invalid secret migration backup artifact')
  const raw = readFileSync(input, 'utf8')
  if (exists) {
    let parsed: any
    try { parsed = JSON.parse(raw) } catch { /* Legacy stores can contain malformed JSON; encrypt the original bytes. */ }
    if (parsed?.__vpnteEncryptedBackup === 1) {
      if (!isSecretRef(parsed.contents)) throw new Error('Invalid encrypted migration backup')
      decryptSecret(parsed.contents) // Authenticate/read-back before calling it protected.
      return 'verified'
    }
  }
  const contents = encryptSecret(raw)
  if (decryptSecret(contents) !== raw) throw new Error('Encrypted migration backup read-back failed')
  const temporary = `${backupPath}.tmp-${randomUUID()}`
  try {
    const fd = openSync(temporary, 'wx', 0o600)
    try { writeFileSync(fd, JSON.stringify({ __vpnteEncryptedBackup: 1, contents }), 'utf8'); fsyncSync(fd) }
    finally { closeSync(fd) }
    renameSync(temporary, backupPath)
  } finally {
    try { unlinkSync(temporary) } catch (error: any) { if (error?.code !== 'ENOENT') throw error }
  }
  return exists ? 'protected' : 'created'
}
