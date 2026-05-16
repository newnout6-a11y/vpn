/**
 * Unit tests for DNS Profiles Service.
 *
 * Tests the pure `validateDnsAddress` function and `applyToSingboxConfig` logic.
 */

import { describe, it, expect } from 'vitest'
import { validateDnsAddress } from './dnsProfiles'

describe('validateDnsAddress', () => {
  describe('valid IPv4 addresses', () => {
    it('accepts standard IPv4 addresses', () => {
      expect(validateDnsAddress('1.1.1.1')).toEqual({ valid: true, type: 'plain' })
      expect(validateDnsAddress('8.8.8.8')).toEqual({ valid: true, type: 'plain' })
      expect(validateDnsAddress('192.168.1.1')).toEqual({ valid: true, type: 'plain' })
      expect(validateDnsAddress('255.255.255.255')).toEqual({ valid: true, type: 'plain' })
      expect(validateDnsAddress('0.0.0.0')).toEqual({ valid: true, type: 'plain' })
    })
  })

  describe('invalid IPv4 addresses', () => {
    it('rejects IPv4 with octets > 255', () => {
      const result = validateDnsAddress('256.1.1.1')
      expect(result.valid).toBe(false)
    })

    it('rejects IPv4 with leading zeros', () => {
      const result = validateDnsAddress('01.1.1.1')
      expect(result.valid).toBe(false)
    })

    it('rejects IPv4 with too few octets', () => {
      const result = validateDnsAddress('1.1.1')
      expect(result.valid).toBe(false)
    })

    it('rejects IPv4 with too many octets', () => {
      const result = validateDnsAddress('1.1.1.1.1')
      expect(result.valid).toBe(false)
    })

    it('rejects IPv4 with non-numeric characters', () => {
      const result = validateDnsAddress('1.1.1.a')
      expect(result.valid).toBe(false)
    })
  })

  describe('valid IPv6 addresses', () => {
    it('accepts full IPv6 addresses', () => {
      expect(validateDnsAddress('2001:0db8:85a3:0000:0000:8a2e:0370:7334')).toEqual({
        valid: true,
        type: 'plain'
      })
    })

    it('accepts abbreviated IPv6 with ::', () => {
      expect(validateDnsAddress('2001:db8::1')).toEqual({ valid: true, type: 'plain' })
      expect(validateDnsAddress('::1')).toEqual({ valid: true, type: 'plain' })
      expect(validateDnsAddress('fe80::')).toEqual({ valid: true, type: 'plain' })
    })

    it('accepts all-zeros abbreviated', () => {
      expect(validateDnsAddress('::')).toEqual({ valid: true, type: 'plain' })
    })
  })

  describe('invalid IPv6 addresses', () => {
    it('rejects IPv6 with multiple ::', () => {
      const result = validateDnsAddress('2001::db8::1')
      expect(result.valid).toBe(false)
    })

    it('rejects IPv6 with too many groups', () => {
      const result = validateDnsAddress('2001:db8:85a3:0000:0000:8a2e:0370:7334:extra')
      expect(result.valid).toBe(false)
    })

    it('rejects IPv6 with invalid hex', () => {
      const result = validateDnsAddress('2001:db8:85a3:0000:0000:8a2e:0370:gggg')
      expect(result.valid).toBe(false)
    })
  })

  describe('valid DoH addresses', () => {
    it('accepts https:// with valid hostname', () => {
      expect(validateDnsAddress('https://dns.cloudflare.com')).toEqual({
        valid: true,
        type: 'doh'
      })
      expect(validateDnsAddress('https://dns.google')).toEqual({ valid: true, type: 'doh' })
      expect(validateDnsAddress('https://doh.opendns.com/dns-query')).toEqual({
        valid: true,
        type: 'doh'
      })
    })
  })

  describe('invalid DoH addresses', () => {
    it('rejects https:// without valid hostname', () => {
      const result = validateDnsAddress('https://')
      expect(result.valid).toBe(false)
      expect(result.type).toBe('doh')
    })

    it('rejects https:// with single-label hostname', () => {
      const result = validateDnsAddress('https://localhost')
      expect(result.valid).toBe(false)
      expect(result.type).toBe('doh')
    })
  })

  describe('valid DoT addresses', () => {
    it('accepts tls:// with valid hostname', () => {
      expect(validateDnsAddress('tls://dns.cloudflare.com')).toEqual({
        valid: true,
        type: 'dot'
      })
      expect(validateDnsAddress('tls://dns.google')).toEqual({ valid: true, type: 'dot' })
    })
  })

  describe('invalid DoT addresses', () => {
    it('rejects tls:// without valid hostname', () => {
      const result = validateDnsAddress('tls://')
      expect(result.valid).toBe(false)
      expect(result.type).toBe('dot')
    })

    it('rejects tls:// with single-label hostname', () => {
      const result = validateDnsAddress('tls://localhost')
      expect(result.valid).toBe(false)
      expect(result.type).toBe('dot')
    })
  })

  describe('invalid inputs', () => {
    it('rejects empty string', () => {
      const result = validateDnsAddress('')
      expect(result.valid).toBe(false)
    })

    it('rejects whitespace-only string', () => {
      const result = validateDnsAddress('   ')
      expect(result.valid).toBe(false)
    })

    it('rejects random text', () => {
      const result = validateDnsAddress('not-a-dns-address')
      expect(result.valid).toBe(false)
    })

    it('rejects http:// (not https://)', () => {
      const result = validateDnsAddress('http://dns.google')
      expect(result.valid).toBe(false)
    })

    it('rejects ftp:// scheme', () => {
      const result = validateDnsAddress('ftp://dns.google')
      expect(result.valid).toBe(false)
    })
  })
})
