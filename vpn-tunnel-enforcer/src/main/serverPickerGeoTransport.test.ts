/**
 * Guards the transport of the server-geolocation lookups.
 *
 * The request carries the IP addresses of the user's own VPN servers, so
 * sending it in the clear hands an on-path observer — including the DPI system
 * this app exists to evade — the exact endpoint inventory of the user. This
 * used to POST to `http://ip-api.com/batch` (their free tier is HTTP-only).
 * These tests exist so that never silently comes back.
 */

import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it, vi } from 'vitest'

// serverPicker pulls a heavy import graph; stub the pieces that touch electron
// or the network so the module loads under vitest.
vi.mock('electron', () => ({
  app: { getPath: () => '/tmp/vpnte-test', getAppPath: () => '/tmp/vpnte-test' },
  dialog: {},
  ipcMain: { handle: vi.fn() }
}))
vi.mock('electron-store', () => ({
  default: class MockStore {
    get() { return [] }
    set() {}
  }
}))
vi.mock('axios', () => ({ default: { get: vi.fn() } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({}) } }))
vi.mock('./vpnProfiles', () => ({
  resolveVpnProfiles: vi.fn(),
  exportOutboundToUri: vi.fn()
}))
vi.mock('./tunController', () => ({
  tunController: { getStatus: () => ({ running: false }) },
  getDirectProxyPort: () => null
}))
vi.mock('./serverGroups', () => ({
  serverGroups: { getGroups: () => [], createGroup: vi.fn(), deleteGroup: vi.fn() },
  ensureManualKeysGroup: vi.fn(),
  findGroupBySourceUrl: vi.fn(),
  canonicalizeSubscriptionUrl: (s: string) => s,
  refreshGroup: vi.fn()
}))

import { isHttpsGeoUrl } from './serverPicker'

const serverPickerSource = () => readFileSync(join(process.cwd(), 'src', 'main', 'serverPicker.ts'), 'utf8')
const smartRouteSource = () => readFileSync(join(process.cwd(), 'src', 'main', 'smartRoute.ts'), 'utf8')

/**
 * Strip comments so the assertions below scan real code only. The doc comment
 * on batchGeolocateIps deliberately names the old `http://ip-api.com` endpoint
 * to explain why it was dropped, and that history should stay readable.
 */
const stripComments = (source: string): string =>
  source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^[ \t]*\/\/.*$/gm, '')

describe('isHttpsGeoUrl', () => {
  it('accepts https', () => {
    expect(isHttpsGeoUrl('https://get.geojs.io/v1/ip/country.json?ip=8.8.8.8')).toBe(true)
    expect(isHttpsGeoUrl('https://ipwho.is/8.8.8.8')).toBe(true)
  })

  it('rejects plaintext http', () => {
    expect(isHttpsGeoUrl('http://ip-api.com/batch?fields=status,country')).toBe(false)
    expect(isHttpsGeoUrl('http://get.geojs.io/v1/ip/country.json')).toBe(false)
  })

  it('rejects other schemes and malformed input', () => {
    expect(isHttpsGeoUrl('ftp://example.com/x')).toBe(false)
    expect(isHttpsGeoUrl('file:///c:/windows/win.ini')).toBe(false)
    expect(isHttpsGeoUrl('//get.geojs.io/v1/ip/country.json')).toBe(false)
    expect(isHttpsGeoUrl('get.geojs.io/v1/ip/country.json')).toBe(false)
    expect(isHttpsGeoUrl('')).toBe(false)
  })

  it('is not fooled by https appearing elsewhere in the URL', () => {
    expect(isHttpsGeoUrl('http://evil.example/?u=https://get.geojs.io')).toBe(false)
    expect(isHttpsGeoUrl('http://https.example.com/lookup')).toBe(false)
  })
})

describe('geo lookup transport', () => {
  it('sends no geo request over plaintext HTTP', () => {
    const code = stripComments(serverPickerSource())
    const httpLiterals = code.match(/['"`]http:\/\/[^'"`]+['"`]/g) ?? []
    expect(httpLiterals).toEqual([])
    expect(code).not.toContain('ip-api.com/batch')
  })

  it('gates fetchGeoJson on the scheme before spawning curl', () => {
    const source = serverPickerSource()
    const fnStart = source.indexOf('async function fetchGeoJson<T>')
    const guard = source.indexOf('if (!isHttpsGeoUrl(url))', fnStart)
    const exec = source.indexOf('execFile(CURL_BIN', fnStart)

    expect(fnStart).toBeGreaterThanOrEqual(0)
    expect(guard).toBeGreaterThan(fnStart)
    expect(guard).toBeLessThan(exec)
  })

  it('pins curl to https so a redirect cannot downgrade the request', () => {
    const source = serverPickerSource()
    const fnStart = source.indexOf('async function fetchGeoJson<T>')
    const fnEnd = source.indexOf('function chooseGeoCountry', fnStart)
    const body = source.slice(fnStart, fnEnd)

    expect(body).toContain("'--proto'")
    expect(body).toContain("'=https'")
    expect(body).toContain("'--proto-redir'")
  })

  it('batch-geolocates through the geojs HTTPS endpoint', () => {
    const source = serverPickerSource()
    const fnStart = source.indexOf('async function batchGeolocateIps')
    const fnEnd = source.indexOf('export async function geolocateIp', fnStart)
    const body = source.slice(fnStart, fnEnd)

    expect(body).toContain("new URL('https://get.geojs.io/v1/ip/country.json')")
    expect(body).toContain("url.searchParams.set('ip', chunk.join(','))")
    expect(body).toContain("addGeoVote(votes, 'geojs.io', row.name, row.country)")
    // The privacy gate must still come first.
    expect(body.indexOf('if (geoLookupDisabled() || unique.length === 0) return out')).toBeLessThan(
      body.indexOf('get.geojs.io')
    )
  })

  it('keeps every secondary geo provider on https', () => {
    const code = stripComments(serverPickerSource())
    const fnStart = code.indexOf('async function fetchSecondaryGeoVote')
    const fnEnd = code.indexOf('async function batchGeolocateIps', fnStart)
    const body = code.slice(fnStart, fnEnd)
    const urls = body.match(/https?:\/\/[^`'"$]+/g) ?? []

    expect(fnStart).toBeGreaterThanOrEqual(0)
    expect(urls.length).toBeGreaterThan(0)
    for (const url of urls) expect(url.startsWith('https://')).toBe(true)
  })

  it('pins the geo provider to proxy-out so lookups never egress direct', () => {
    // Smart-RU routing would otherwise send the lookup out the physical NIC,
    // which reveals the server list to the local network path even over TLS
    // (SNI) and reports the wrong country for the user's own IP.
    expect(smartRouteSource()).toContain("'.geojs.io'")
  })
})
