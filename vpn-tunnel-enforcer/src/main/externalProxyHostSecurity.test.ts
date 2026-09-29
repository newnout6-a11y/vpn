import { describe, expect, it, vi } from 'vitest'

vi.mock('electron', () => ({
  app: {
    getPath: vi.fn(() => '/tmp/vpnte-test'),
    isPackaged: false
  },
  ipcMain: { handle: vi.fn() }
}))

import { isTrustedExternalProxyHostHeader } from './externalProxy'

describe('external proxy Host validation (AT-01-005)', () => {
  it('accepts only the bound loopback endpoint', () => {
    expect(isTrustedExternalProxyHostHeader('127.0.0.1:17873', 17873)).toBe(true)
    expect(isTrustedExternalProxyHostHeader('localhost:17873', 17873)).toBe(true)
    expect(isTrustedExternalProxyHostHeader('attacker.example:17873', 17873)).toBe(false)
    expect(isTrustedExternalProxyHostHeader('127.0.0.1:9999', 17873)).toBe(false)
    expect(isTrustedExternalProxyHostHeader(undefined, 17873)).toBe(false)
  })
})