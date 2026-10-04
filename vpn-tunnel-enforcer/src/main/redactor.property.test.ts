import { describe, expect, it } from 'vitest'
import fc from 'fast-check'
import { redactSensitiveConfig, redactSensitiveText } from './vpnProfiles'

describe('secret redactor properties (AT-01-011)', () => {
  it('scrubs realistic keys, credential assignments and user paths while retaining clean values', () => {
    fc.assert(fc.property(fc.uint8Array({ minLength: 32, maxLength: 32 }), fc.integer({ min: 1, max: 999999 }), (bytes, number) => {
      const key = Buffer.from(bytes).toString('base64')
      const path = `C:\\Users\\user${number}\\private\\config.json`
      const uuid = `123e4567-e89b-42d3-a456-${String(number).padStart(12, '0')}`
      const output = redactSensitiveText(`private_key=${key} ${uuid} ${path}`)
      expect(output).not.toContain(key); expect(output).not.toContain(uuid); expect(output).not.toContain(path)
      const clean = { count: number, enabled: true, phase: 'ready' }
      expect(redactSensitiveConfig(clean)).toEqual(clean)
    }), { numRuns: process.env.VPNTE_WP1_FUZZ === '1' ? 100_000 : 1000, seed: 1004 })
  })
  it('never returns values stored under secret-bearing keys', () => {
    fc.assert(
      fc.property(
        fc.constantFrom('uuid', 'password', 'token', 'client_secret', 'private_key', 'short-id'),
        fc.string({ minLength: 8, maxLength: 128 }),
        (key, secret) => {
          const redacted = redactSensitiveConfig({ safeCounter: 7, nested: { [key]: secret } })
          const serialized = JSON.stringify(redacted)
          expect(serialized).not.toContain(JSON.stringify(secret).slice(1, -1))
          expect(serialized).toContain('<redacted>')
          expect(serialized).toContain('"safeCounter":7')
        }
      ),
      { numRuns: process.env.VPNTE_WP1_FUZZ === '1' ? 100_000 : 1000, seed: 1004 }
    )
  })

  it('removes complete VPN URIs while preserving adjacent diagnostic text', () => {
    fc.assert(
      fc.property(
        fc.constantFrom('vless', 'trojan', 'ss', 'vmess', 'hysteria2', 'tuic'),
        fc.webUrl(),
        (scheme, payload) => {
          const uri = `${scheme}://${encodeURIComponent(payload)}@vpn.example:443?token=secret`
          const output = redactSensitiveText(`before ${uri} after`)
          expect(output).not.toContain(uri)
          expect(output).toContain('before ')
          expect(output).toContain(' after')
        }
      ),
      { numRuns: process.env.VPNTE_WP1_FUZZ === '1' ? 100_000 : 1000, seed: 1004 }
    )
  })
})
