import { afterEach, describe, expect, it, vi } from 'vitest'

const safeStorageMock = vi.hoisted(() => ({
  available: true,
  isEncryptionAvailable: vi.fn(() => safeStorageMock.available),
  encryptString: vi.fn((value: string) => Buffer.from(`encrypted:${value}`, 'utf8')),
  decryptString: vi.fn((value: Buffer) => value.toString('utf8').replace(/^encrypted:/, ''))
}))

vi.mock('electron', () => ({ safeStorage: safeStorageMock }))

import {
  decryptJsonSecret,
  decryptSecret,
  encryptJsonSecret,
  encryptSecret,
  isSecretRef
} from './secretStorage'

describe('safeStorage secret references (AT-01-001, AT-01-010)', () => {
  const previousNodeEnv = process.env.NODE_ENV
  afterEach(() => {
    safeStorageMock.available = true
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
})