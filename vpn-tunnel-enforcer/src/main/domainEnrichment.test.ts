import { describe, expect, it, vi } from 'vitest'

vi.mock('electron', () => ({ BrowserWindow: class {} }))
vi.mock('electron-store', () => ({
  default: class {
    private values: Record<string, unknown> = { entries: {} }
    get(key: string) { return this.values[key] }
    set(key: string, value: unknown) { this.values[key] = value }
  }
}))

import {
  buildEnrichmentProxyRules,
  isAllowedMetadataUrl,
  isPrivateOrReservedIp,
  isSafePublicDomain,
  normalizeEnrichmentDomain,
  registrableEnrichmentDomain,
  sanitizePageMetadata
} from './domainEnrichment'

describe('domain enrichment safeguards', () => {
  it('normalizes only public hostnames', () => {
    expect(normalizeEnrichmentDomain('WWW.Example.com.')).toBe('www.example.com')
    expect(normalizeEnrichmentDomain('localhost')).toBeNull()
    expect(normalizeEnrichmentDomain('127.0.0.1')).toBeNull()
    expect(normalizeEnrichmentDomain('printer.local')).toBeNull()
  })

  it('groups technical subdomains under their registrable site', () => {
    expect(registrableEnrichmentDomain('contacts.google.com')).toBe('google.com')
    expect(registrableEnrichmentDomain('browser-resources.s3.yandex.net')).toBe('yandex.net')
  })

  it('allows only normal HTTPS metadata documents', () => {
    expect(isAllowedMetadataUrl('https://example.com')).toBe(true)
    expect(isAllowedMetadataUrl('http://example.com')).toBe(false)
    expect(isAllowedMetadataUrl('https://127.0.0.1')).toBe(false)
    expect(isAllowedMetadataUrl('https://example.com:8443')).toBe(false)
    expect(isAllowedMetadataUrl('https://user@example.com')).toBe(false)
  })

  it('builds an Electron proxy rule without credentials or a path', () => {
    expect(buildEnrichmentProxyRules('127.0.0.1:1080', 'socks5')).toBe('socks5://127.0.0.1:1080')
    expect(buildEnrichmentProxyRules('https://proxy.example.com:443', 'http')).toBeNull()
    expect(buildEnrichmentProxyRules('proxy.example.com:8080/path', 'http')).toBeNull()
  })

  it('keeps only bounded, safe page metadata', () => {
    const metadata = sanitizePageMetadata({
      finalUrl: 'https://example.com/landing',
      siteName: ' Example  Site ',
      title: 'Example title',
      description: 'A public page description',
      canonicalUrl: 'https://example.com/canonical',
      faviconUrl: 'http://example.com/favicon.ico'
    })
    expect(metadata.siteName).toBe('Example Site')
    expect(metadata.canonicalUrl).toBe('https://example.com/canonical')
    expect(metadata.faviconUrl).toBeNull()
  })

  it('identifies private, loopback, link-local, and reserved IP addresses', () => {
    // Loopback
    expect(isPrivateOrReservedIp('127.0.0.1')).toBe(true)
    expect(isPrivateOrReservedIp('127.255.255.254')).toBe(true)
    expect(isPrivateOrReservedIp('::1')).toBe(true)

    // Private RFC 1918
    expect(isPrivateOrReservedIp('10.0.0.1')).toBe(true)
    expect(isPrivateOrReservedIp('10.255.255.255')).toBe(true)
    expect(isPrivateOrReservedIp('172.16.0.1')).toBe(true)
    expect(isPrivateOrReservedIp('172.31.255.254')).toBe(true)
    expect(isPrivateOrReservedIp('192.168.0.1')).toBe(true)
    expect(isPrivateOrReservedIp('192.168.254.254')).toBe(true)

    // Link-local / Cloud metadata (169.254.169.254)
    expect(isPrivateOrReservedIp('169.254.169.254')).toBe(true)
    expect(isPrivateOrReservedIp('169.254.1.1')).toBe(true)
    expect(isPrivateOrReservedIp('fe80::1')).toBe(true)

    // Carrier-grade NAT (100.64.0.0/10)
    expect(isPrivateOrReservedIp('100.64.0.1')).toBe(true)
    expect(isPrivateOrReservedIp('100.127.255.254')).toBe(true)

    // Multicast & Broadcast
    expect(isPrivateOrReservedIp('224.0.0.1')).toBe(true)
    expect(isPrivateOrReservedIp('255.255.255.255')).toBe(true)
    expect(isPrivateOrReservedIp('ff02::1')).toBe(true)

    // IPv6 Unique Local
    expect(isPrivateOrReservedIp('fc00::1')).toBe(true)
    expect(isPrivateOrReservedIp('fd12:3456:789a::1')).toBe(true)

    // IPv4-mapped IPv6
    expect(isPrivateOrReservedIp('::ffff:127.0.0.1')).toBe(true)
    expect(isPrivateOrReservedIp('::ffff:192.168.1.10')).toBe(true)
    expect(isPrivateOrReservedIp('::ffff:169.254.169.254')).toBe(true)

    // Public Internet IP addresses must be allowed (return false)
    expect(isPrivateOrReservedIp('1.1.1.1')).toBe(false)
    expect(isPrivateOrReservedIp('8.8.8.8')).toBe(false)
    expect(isPrivateOrReservedIp('93.184.216.34')).toBe(false)
    expect(isPrivateOrReservedIp('172.32.0.1')).toBe(false)
    expect(isPrivateOrReservedIp('100.128.0.1')).toBe(false)
    expect(isPrivateOrReservedIp('2606:4700:4700::1111')).toBe(false)
    expect(isPrivateOrReservedIp('::ffff:1.1.1.1')).toBe(false)
  })

  it('rejects domains that resolve to internal or reserved IPs (SSRF & DNS rebinding guard)', async () => {
    // Public domain resolving to public IP is safe
    const mockPublicResolver = vi.fn().mockResolvedValue(['93.184.216.34'])
    expect(await isSafePublicDomain('example.com', mockPublicResolver)).toBe(true)

    // Domain resolving to loopback is blocked
    const mockLoopbackResolver = vi.fn().mockResolvedValue(['127.0.0.1'])
    expect(await isSafePublicDomain('rebind.attacker.com', mockLoopbackResolver)).toBe(false)

    // Domain resolving to private LAN is blocked
    const mockLanResolver = vi.fn().mockResolvedValue(['192.168.1.1'])
    expect(await isSafePublicDomain('router.attacker.com', mockLanResolver)).toBe(false)

    // Domain resolving to AWS/GCP cloud metadata IP is blocked
    const mockMetadataResolver = vi.fn().mockResolvedValue(['169.254.169.254'])
    expect(await isSafePublicDomain('metadata.attacker.com', mockMetadataResolver)).toBe(false)

    // Domain resolving to mixed public + private IPs (DNS rebinding) is blocked
    const mockMixedResolver = vi.fn().mockResolvedValue(['93.184.216.34', '127.0.0.1'])
    expect(await isSafePublicDomain('mixed.attacker.com', mockMixedResolver)).toBe(false)

    // Failed DNS resolution is blocked
    const mockFailingResolver = vi.fn().mockRejectedValue(new Error('ENOTFOUND'))
    expect(await isSafePublicDomain('nonexistent.corp', mockFailingResolver)).toBe(false)

    // Empty DNS response is blocked
    const mockEmptyResolver = vi.fn().mockResolvedValue([])
    expect(await isSafePublicDomain('empty.corp', mockEmptyResolver)).toBe(false)
  })
})
