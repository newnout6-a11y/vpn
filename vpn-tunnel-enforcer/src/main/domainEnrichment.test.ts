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
})
