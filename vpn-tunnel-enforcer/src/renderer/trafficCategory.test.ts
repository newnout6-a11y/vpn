import { describe, expect, it } from 'vitest'
import {
  categorizeTrafficDomain,
  normalizeTrafficDomain,
  registrableDomain
} from './trafficCategory'

describe('traffic category detection', () => {
  it('normalizes URLs, ports, wildcards and trailing dots', () => {
    expect(normalizeTrafficDomain('https://*.API.GitHub.com:443/repos.')).toBe('api.github.com')
  })

  it('uses common multi-label suffixes for site grouping', () => {
    expect(registrableDomain('cdn.shop.example.co.uk')).toBe('example.co.uk')
  })

  it('detects ad tech and RTB domains before generic infrastructure', () => {
    expect(categorizeTrafficDomain('pubads.g.doubleclick.net')?.label).toBe('Реклама / RTB')
    expect(categorizeTrafficDomain('bidding.openx.net')?.label).toBe('Реклама / RTB')
  })

  it('detects analytics and telemetry with current tracker-style domains', () => {
    expect(categorizeTrafficDomain('static.cloudflareinsights.com')?.label).toBe('Аналитика / Трекинг')
    expect(categorizeTrafficDomain('watson.events.data.microsoft.com')?.label).toBe('Телеметрия')
    expect(categorizeTrafficDomain('firebaselogging-pa.googleapis.com')?.label).toBe('Телеметрия')
  })

  it('does not classify every api subdomain as development traffic', () => {
    expect(categorizeTrafficDomain('api.github.com')?.label).toBe('Разработка / AI')
    expect(categorizeTrafficDomain('api.random-example.invalid')).toBeNull()
  })

  it('keeps product traffic above generic CDN matches', () => {
    expect(categorizeTrafficDomain('cdn.discordapp.com')?.label).toBe('Мессенджеры')
    expect(categorizeTrafficDomain('r4---sn.googlevideo.com')?.label).toBe('Медиа / Стриминг')
  })

  it('classifies cloud, auth, payments and system update traffic', () => {
    expect(categorizeTrafficDomain('assets.example.cloudfront.net')?.label).toBe('Облако / CDN')
    expect(categorizeTrafficDomain('login.microsoftonline.com')?.label).toBe('Авторизация / SSO')
    expect(categorizeTrafficDomain('checkout.stripe.com')?.label).toBe('Платежи')
    expect(categorizeTrafficDomain('download.windowsupdate.com')?.label).toBe('Системные обновления')
  })
})
