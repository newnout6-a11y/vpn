// AT-07-007 / AT-00-003: shared geo reads, provider backoff, stale session results.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({
  data: new Map<string, any>(), handlers: new Map<string, (...args: any[]) => any>(),
  settings: {} as Record<string, unknown>, session: { running: true, startedAt: 1 },
  curl: vi.fn<(url: string) => Promise<string>>()
}))
vi.mock('electron', () => ({
  app: { getPath: () => '/tmp/vpnte-test', getAppPath: () => '/tmp/vpnte-test' }, dialog: {},
  ipcMain: { handle: (channel: string, handler: (...args: any[]) => any) => state.handlers.set(channel, handler) }
}))
vi.mock('electron-store', () => ({ default: class {
  get(key: string) { return state.data.get(key) }
  set(key: string, value: unknown) { state.data.set(key, value) }
} }))
vi.mock('child_process', async importOriginal => {
  const actual = await importOriginal<typeof import('child_process')>()
  const { promisify } = await import('util')
  const execFile = Object.assign((_bin: string, args: string[], _options: unknown, callback: (...args: any[]) => void) => {
    state.curl(args[args.length - 1]).then(stdout => callback(null, stdout, ''), error => callback(error, error.stdout ?? '', error.stderr ?? ''))
  }, { [promisify.custom]: async (_bin: string, args: string[]) => ({ stdout: await state.curl(args[args.length - 1]), stderr: '' }) })
  return { ...actual, default: { ...actual, execFile }, execFile }
})
vi.mock('axios', () => ({ default: { get: vi.fn() } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./settings', () => ({ settingsStore: { get: () => state.settings } }))
vi.mock('./vpnProfiles', () => ({
  applyClientDeviceToOutbound: vi.fn(), clientFingerprintForDevice: vi.fn(), normalizeClientDevice: vi.fn(),
  resolveVpnProfiles: vi.fn(), exportOutboundToUri: vi.fn()
}))
vi.mock('./tunController', () => ({ getDirectProxyPort: () => null, tunController: { getStatus: () => state.session } }))
vi.mock('./serverGroups', () => ({
  serverGroups: { getGroups: () => [], createGroup: vi.fn(), deleteGroup: vi.fn() },
  ensureManualKeysGroup: vi.fn(), findGroupBySourceUrl: vi.fn(),
  canonicalizeSubscriptionUrl: (value: string) => value, refreshGroup: vi.fn()
}))

const ip = '198.51.100.20'
function response(country = 'NO', target = ip) {
  return `HTTP/1.1 200 Connection established\r\n\r\nHTTP/2 200\r\ncontent-type: application/json\r\n\r\n${JSON.stringify([{ip:target, country, name:country === 'NO' ? 'Norway' : 'Sweden'}])}`
}
function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(done => { resolve = done })
  return {promise, resolve}
}
let picker: typeof import('./serverPicker')
let verify: (...args: any[]) => Promise<any>
beforeEach(async () => {
  vi.resetModules(); vi.useFakeTimers()
  state.data.clear(); state.handlers.clear(); state.settings = {bootstrapRouteMode:'auto'}
  state.session = {running:true,startedAt:1}
  state.data.set('activeProfileId', 'a')
  state.data.set('profiles', ['a','b'].map(id => ({id,name:id,server:`${id}.test`,port:443,protocol:'vless',enabled:true,country:'Original'})))
  state.curl.mockReset().mockImplementation(async url => url.includes('geojs.io') ? response() : '{}')
  picker = await import('./serverPicker')
  picker.registerServerPickerHandlers()
  verify = state.handlers.get('servers:verify-active-country')!
})
afterEach(() => { vi.useRealTimers() })

describe('country verification lifecycle', () => {
  it('shares one five-provider lookup across 50 duplicate requests and caches the country', async () => {
    const held = deferred<string>()
    state.curl.mockImplementation(async url => url.includes('geojs.io') ? held.promise : '{}')
    const reads = Array.from({length:50}, () => picker.geolocateIp(ip))
    expect(state.curl).toHaveBeenCalledOnce()
    held.resolve(response())
    expect(await Promise.all(reads)).toEqual(Array(50).fill('Norway'))
    expect(state.curl).toHaveBeenCalledTimes(5)
    expect(await picker.geolocateIp(ip)).toBe('Norway')
    expect(state.curl).toHaveBeenCalledTimes(5)
    await vi.advanceTimersByTimeAsync(5 * 60_000)
    await picker.geolocateIp(ip)
    expect(state.curl).toHaveBeenCalledTimes(10)
  })
  it('publishes only the current duplicate request', async () => {
    const results = await Promise.all([verify({},ip),verify({},ip),verify({},ip)])
    expect(results.filter(result => result.ok)).toHaveLength(1)
    expect(state.curl).toHaveBeenCalledTimes(5)
    expect(state.data.get('profiles')[0].country).toBe('Norway')
  })
  it.each(['selected profile', 'same profile reselected', 'tunnel session', 'disconnect', 'privacy'])('discards a late result after %s changes', async kind => {
    const held = deferred<string>()
    state.curl.mockImplementation(async url => url.includes('geojs.io') ? held.promise : '{}')
    const pending = verify({},ip)
    if (kind === 'selected profile') picker.selectProfile('b')
    if (kind === 'same profile reselected') { picker.selectProfile('b'); picker.selectProfile('a') }
    if (kind === 'tunnel session') state.session.startedAt = 2
    if (kind === 'disconnect') state.session.running = false
    if (kind === 'privacy') state.settings.disableGeoLookup = true
    held.resolve(response())
    expect(await pending).toMatchObject({ok:false})
    expect(state.data.get('profiles').map((profile: any) => profile.country)).toEqual(['Original','Original'])
  })
  it('never lets a slower old IP overwrite the newest IP', async () => {
    const old = deferred<string>()
    const nextIp = '198.51.100.21'
    state.curl.mockImplementation(async url => url.includes('geojs.io') ? url.includes(ip) ? old.promise : response('SE',nextIp) : '{}')
    const pending = verify({},ip)
    expect(await verify({},nextIp)).toMatchObject({ok:true,country:'Sweden'})
    old.resolve(response())
    expect(await pending).toMatchObject({ok:false,reason:'superseded'})
    expect(state.data.get('profiles')[0]).toMatchObject({country:'Sweden',countryVerifiedIp:nextIp})
  })
  it('sends no requests while geo lookup is disabled, even with a cached country', async () => {
    await picker.geolocateIp(ip)
    state.curl.mockClear(); state.settings.disableGeoLookup = true
    expect(await picker.geolocateIp(ip)).toBeNull()
    expect(await verify({},ip)).toMatchObject({ok:false,reason:'geo-lookup-disabled'})
    expect(state.curl).not.toHaveBeenCalled()
  })
  it('rejects hostnames and malformed addresses without spawning curl', async () => {
    expect(await picker.geolocateIp('not-an-ip')).toBeNull()
    expect(await verify({},'lookup.example')).toMatchObject({ok:false,reason:'invalid-ip'})
    expect(state.curl).not.toHaveBeenCalled()
  })
  it('guards a background owner both before reading and before publication', async () => {
    expect(await picker.verifyActiveCountryForIp(ip, () => false)).toMatchObject({ok:false,reason:'superseded'})
    expect(state.curl).not.toHaveBeenCalled()
    const held = deferred<string>()
    state.curl.mockImplementation(async url => url.includes('geojs.io') ? held.promise : '{}')
    let current = true
    const pending = picker.verifyActiveCountryForIp(ip, () => current)
    current = false
    held.resolve(response())
    expect(await pending).toMatchObject({ok:false,reason:'superseded'})
    expect(state.data.get('profiles')[0].country).toBe('Original')
  })
  it('does not cache a failed lookup as a verified country and allows a later retry', async () => {
    state.curl.mockResolvedValue('{}')
    expect(await picker.geolocateIp(ip)).toBeNull()
    expect(state.curl).toHaveBeenCalledTimes(5)
    expect(await picker.geolocateIp(ip)).toBeNull()
    expect(state.curl).toHaveBeenCalledTimes(5)
    await vi.advanceTimersByTimeAsync(5000)
    state.curl.mockImplementation(async url => url.includes('geojs.io') ? response() : '{}')
    expect(await picker.geolocateIp(ip)).toBe('Norway')
  })
  it.each(['120', 'invalid', 'date'])('backs off HTTP 429 with Retry-After %s without replaying other routes', async retryAfter => {
    vi.setSystemTime(new Date('2026-10-03T18:00:00Z'))
    const value = retryAfter === 'date' ? 'Sat, 03 Oct 2026 18:02:00 GMT' : retryAfter
    state.curl.mockImplementation(async url => {
      if (url.includes('geojs.io')) throw Object.assign(new Error('quota'), {
        stdout:`HTTP/2 429\r\nretry-after: ${value}\r\n\r\n`, stderr:'curl: (22) The requested URL returned error: 429'
      })
      return '{}'
    })
    await picker.geolocateIp(ip)
    const quotaCalls = () => state.curl.mock.calls.filter(([url]) => url.includes('geojs.io')).length
    expect(quotaCalls()).toBe(1)
    await picker.geolocateIp('198.51.100.21')
    expect(quotaCalls()).toBe(1)
    const delay = retryAfter === 'invalid' ? 60_000 : 120_000
    await vi.advanceTimersByTimeAsync(delay)
    await picker.geolocateIp('198.51.100.22')
    expect(quotaCalls()).toBe(2)
    // The second 429 doubles the base backoff, even if Retry-After was invalid.
    await vi.advanceTimersByTimeAsync(60_000)
    await picker.geolocateIp('198.51.100.23')
    expect(quotaCalls()).toBe(2)
  })
})
