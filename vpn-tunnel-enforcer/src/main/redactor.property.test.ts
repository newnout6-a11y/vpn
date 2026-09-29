import { describe, expect, it } from 'vitest'
import fc from 'fast-check'
import { redactSensitiveConfig, redactSensitiveText } from './vpnProfiles'

describe('secret redactor properties (AT-01-011)', () => {
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
      { numRuns: 250 }
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
      { numRuns: 250 }
    )
  })
})