/**
 * Tests for isValidIpOrCidr() — the allow-list gate that guards user-supplied
 * kill-switch IP/CIDR exceptions before they are interpolated into a
 * New-NetFirewallRule -RemoteAddress argument. Must reject anything that isn't
 * a clean IPv4/IPv6 address or CIDR (hostnames, ranges, injection attempts).
 */

import { describe, it, expect, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import fc from 'fast-check'

vi.mock('electron', () => ({
  app: { getPath: () => '/tmp/vpnte-test' }
}))
vi.mock('./admin', () => ({ execElevated: vi.fn() }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))

import { isValidIpOrCidr } from './firewallKillSwitch'

const source = readFileSync(join(process.cwd(), 'src/main/firewallKillSwitch.ts'), 'utf8')

describe('isValidIpOrCidr', () => {
  it('accepts plain IPv4', () => {
    expect(isValidIpOrCidr('203.0.113.4')).toBe(true)
    expect(isValidIpOrCidr('10.0.0.1')).toBe(true)
    expect(isValidIpOrCidr('255.255.255.255')).toBe(true)
  })

  it('accepts IPv4 CIDR', () => {
    expect(isValidIpOrCidr('203.0.113.0/24')).toBe(true)
    expect(isValidIpOrCidr('10.0.0.0/8')).toBe(true)
    expect(isValidIpOrCidr('192.168.1.1/32')).toBe(true)
  })

  it('accepts IPv6 and IPv6 CIDR', () => {
    expect(isValidIpOrCidr('2001:db8::1')).toBe(true)
    expect(isValidIpOrCidr('2001:db8::/32')).toBe(true)
    expect(isValidIpOrCidr('::1')).toBe(true)
  })

  it('rejects wildcard and unspecified exceptions', () => {
    expect(isValidIpOrCidr('0.0.0.0')).toBe(false)
    expect(isValidIpOrCidr('0.0.0.0/0')).toBe(false)
    expect(isValidIpOrCidr('203.0.113.0/0')).toBe(false)
    expect(isValidIpOrCidr('::')).toBe(false)
    expect(isValidIpOrCidr('::/0')).toBe(false)
    expect(isValidIpOrCidr('2001:db8::/0')).toBe(false)
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

  it.each(['+24', '24.0', '0x10', '0b10', '0o10', '1e1', ' 24', '\t24', '', 'Infinity', 'NaN'])(
    'rejects non-decimal CIDR prefix %j (AT-03-009; F-042/F-147)', prefix => {
      expect(isValidIpOrCidr(`192.0.2.1/${prefix}`)).toBe(false)
      expect(isValidIpOrCidr(`2001:db8::1/${prefix}`)).toBe(false)
    }
  )

  it('accepts generated IPv4/IPv6 decimal prefixes within their bounds (AT-03-009)', () => {
    fc.assert(fc.property(fc.ipV4(), fc.integer({ min: 1, max: 32 }), (address, prefix) => {
      fc.pre(address !== '0.0.0.0')
      expect(isValidIpOrCidr(`${address}/${prefix}`)).toBe(true)
    }), { seed: 30009, numRuns: 200 })
    fc.assert(fc.property(fc.ipV6(), fc.integer({ min: 1, max: 128 }), (address, prefix) => {
      fc.pre(address !== '::')
      expect(isValidIpOrCidr(`${address}/${prefix}`)).toBe(true)
    }), { seed: 30010, numRuns: 200 })
  })

  it('rejects generated numeric coercions of otherwise valid prefixes (AT-03-009)', () => {
    fc.assert(fc.property(fc.integer({ min: 1, max: 32 }), prefix => {
      for (const coerced of [`+${prefix}`, `${prefix}.0`, `${prefix}e0`, `0x${prefix.toString(16)}`, ` ${prefix}`]) {
        expect(isValidIpOrCidr(`192.0.2.1/${coerced}`)).toBe(false)
        expect(isValidIpOrCidr(`2001:db8::1/${coerced}`)).toBe(false)
      }
    }), { seed: 30011, numRuns: 100 })
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

describe('external proxy kill-switch allow-list', () => {
  it('always includes the VPNTE external proxy runtime path in kill-switch program rules', () => {
    expect(source).toContain("const EXTERNAL_PROXY_RUNTIME_EXE_NAME = 'vpnte-external-proxy.exe'")
    expect(source).toContain('externalProxyProgramPath()')
    expect(source).toContain("join(getPrivilegedRuntimeDir('external-proxy-runtime'), EXTERNAL_PROXY_RUNTIME_EXE_NAME)")
    expect(source).toContain('...(opts.proxyOwnerProgramPaths ?? []), externalProxyProgramPath()')
  })

  it('exposes an idempotent helper for adding a program allow rule while kill-switch is already active', () => {
    expect(source).toContain('export async function ensureKillSwitchProgramAllowed')
    const start = source.indexOf('async function ensureKillSwitchProgramAllowedUnlocked')
    const helper = source.slice(start, source.indexOf('\n}', start) + 2)
    expect(helper).toContain('const manifest = await readManifest()')
    expect(helper).toContain('if (!manifest && !(await probeFirewallForOurRules()))')
    expect(source).toContain('New-VpnteFirewallRule')
    expect(source).toContain('-Program $program')
  })
})

describe('NTP clock-sync kill-switch allow rule', () => {
  it('allows outbound UDP 123 for Windows Time sync and includes it in required rules', () => {
    expect(source).toContain("const ntpAllow = `${RULE_PREFIX}-allow-ntp`")
    expect(source).toContain('-Protocol UDP -RemotePort 123')
    expect(source).toContain('${psSingleQuote(ntpAllow)}')
  })
})

describe('Electron app binary kill-switch allow rule', () => {
  it('allows outbound traffic for process.execPath so internal probes are not blocked with connect EACCES', () => {
    expect(source).toContain("const appAllow = `${RULE_PREFIX}-allow-app`")
    expect(source).toContain('-Program ${psSingleQuote(process.execPath)}')
    expect(source).toContain('${psSingleQuote(appAllow)}')
  })
})

describe('dynamic TUN adapter alias in kill-switch', () => {
  it('uses dynamic tunAlias from options or getTunAdapterAlias() for adapter rule', () => {
    expect(source).toContain('const tunAlias = opts.tunAdapterAlias || getTunAdapterAlias()')
    expect(source).toContain('Get-NetAdapter -Name ${psSingleQuote(tunAlias)}')
    expect(source).toContain('-InterfaceAlias ${psSingleQuote(tunAlias)}')
  })
})

describe('loopback kill-switch allow rules (IPv4 and IPv6)', () => {
  it('defines dedicated Outbound and Inbound loopback rules for local IPC', () => {
    expect(source).toContain("const loopbackOutAllow = `${RULE_PREFIX}-allow-loopback-out`")
    expect(source).toContain("const loopbackInAllow = `${RULE_PREFIX}-allow-loopback-in`")
    expect(source).toContain("-DisplayName ${psSingleQuote(loopbackOutAllow)}")
    expect(source).toContain("-Direction Outbound -Action Allow")
    expect(source).toContain("-RemoteAddress '127.0.0.0/8'")
    expect(source).toContain("-RemoteAddress '::1/128'")
    expect(source).toContain("-DisplayName ${psSingleQuote(loopbackInAllow)}")
    expect(source).toContain("-Direction Inbound -Action Allow")
    expect(source).toContain("-LocalAddress '127.0.0.0/8'")
    expect(source).toContain("-LocalAddress '::1/128'")
  })

  it('includes loopbackOutAllow and loopbackInAllow in requiredRules', () => {
    expect(source).toContain('${psSingleQuote(loopbackOutAllow)}')
    expect(source).toContain('${psSingleQuote(loopbackInAllow)}')
  })
})

describe('curl.exe kill-switch exclusion (regression test for leak self-test false-positive)', () => {
  it('does not create an allow rule for curl.exe so physical adapter probes and leak tests are strictly enforced', () => {
    expect(source).not.toContain('allow-curl')
    expect(source).not.toContain('System32\\curl.exe')
  })
})

