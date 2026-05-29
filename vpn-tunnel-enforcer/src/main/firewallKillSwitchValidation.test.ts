/**
 * Tests for isValidIpOrCidr() — the allow-list gate that guards user-supplied
 * kill-switch IP/CIDR exceptions before they are interpolated into a
 * New-NetFirewallRule -RemoteAddress argument. Must reject anything that isn't
 * a clean IPv4/IPv6 address or CIDR (hostnames, ranges, injection attempts).
 */

import { describe, it, expect, vi } from 'vitest'

vi.mock('electron', () => ({
  app: { getPath: () => '/tmp/vpnte-test' }
}))
vi.mock('./admin', () => ({ execElevated: vi.fn() }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))

import { isValidIpOrCidr } from './firewallKillSwitch'

describe('isValidIpOrCidr', () => {
  it('accepts plain IPv4', () => {
    expect(isValidIpOrCidr('203.0.113.4')).toBe(true)
    expect(isValidIpOrCidr('10.0.0.1')).toBe(true)
    expect(isValidIpOrCidr('255.255.255.255')).toBe(true)
  })

  it('accepts IPv4 CIDR', () => {
    expect(isValidIpOrCidr('203.0.113.0/24')).toBe(true)
    expect(isValidIpOrCidr('10.0.0.0/8')).toBe(true)
    expect(isValidIpOrCidr('0.0.0.0/0')).toBe(true)
    expect(isValidIpOrCidr('192.168.1.1/32')).toBe(true)
  })

  it('accepts IPv6 and IPv6 CIDR', () => {
    expect(isValidIpOrCidr('2001:db8::1')).toBe(true)
    expect(isValidIpOrCidr('2001:db8::/32')).toBe(true)
    expect(isValidIpOrCidr('::1')).toBe(true)
  })

  it('rejects out-of-range IPv4 octets', () => {
    expect(isValidIpOrCidr('256.0.0.1')).toBe(false)
    expect(isValidIpOrCidr('999.999.999.999')).toBe(false)
  })

  it('rejects out-of-range prefix lengths', () => {
    expect(isValidIpOrCidr('10.0.0.0/33')).toBe(false)
    expect(isValidIpOrCidr('2001:db8::/129')).toBe(false)
    expect(isValidIpOrCidr('10.0.0.0/-1')).toBe(false)
  })

  it('rejects hostnames and ranges', () => {
    expect(isValidIpOrCidr('example.com')).toBe(false)
    expect(isValidIpOrCidr('10.0.0.1-10.0.0.5')).toBe(false)
  })

  it('rejects empty / whitespace / double-slash', () => {
    expect(isValidIpOrCidr('')).toBe(false)
    expect(isValidIpOrCidr('   ')).toBe(false)
    expect(isValidIpOrCidr('10.0.0.0/24/8')).toBe(false)
  })

  it('rejects PowerShell injection attempts', () => {
    expect(isValidIpOrCidr("10.0.0.1'; Remove-NetFirewallRule -All; '")).toBe(false)
    expect(isValidIpOrCidr('10.0.0.1 | Out-Null')).toBe(false)
    expect(isValidIpOrCidr('$(whoami)')).toBe(false)
    expect(isValidIpOrCidr('10.0.0.1`n')).toBe(false)
  })

  it('trims surrounding whitespace before validating', () => {
    expect(isValidIpOrCidr('  10.0.0.1  ')).toBe(true)
  })
})
