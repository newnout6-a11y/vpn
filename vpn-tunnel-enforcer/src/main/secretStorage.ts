import * as electron from 'electron'

export const SECRET_REF_KIND = 'vpnte-safe-storage-v1' as const

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
  return process.env.NODE_ENV === 'test'
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
      ciphertext: safeStorage.encryptString(value).toString('base64')
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
  return safeStorage.decryptString(Buffer.from(ref.ciphertext, 'base64'))
}

export function encryptJsonSecret(value: unknown): SecretRef {
  return encryptSecret(JSON.stringify(value))
}

export function decryptJsonSecret<T>(ref: SecretRef): T {
  return JSON.parse(decryptSecret(ref)) as T
}
