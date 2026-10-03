// AT-00-003 / AT-02-005: delayed bootstrap DNS cannot continue a cancelled start.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
const mocks = vi.hoisted(() => ({ resolve4: vi.fn(), lookup: vi.fn(), getServers: vi.fn(), resolvers: [] as any[] }))
vi.mock('node:dns', () => {
  class Resolver {
    resolve4 = vi.fn().mockImplementation((host: string) => mocks.resolve4(host))
    setServers = vi.fn()
    cancel = vi.fn()
    constructor() { mocks.resolvers.push(this) }
  }
  const promises = { resolve4: mocks.resolve4, lookup: mocks.lookup, getServers: mocks.getServers, Resolver }
  return { promises, default: { promises } }
})
import { resolveXrayEndpoint, XRAY_DNS_LOOKUP_DELAY_MS } from './xrayDns'
function held<T>() {
  let resolve!: (value: T) => void, reject!: (error: Error) => void
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}
beforeEach(() => {
  mocks.resolve4.mockReset().mockResolvedValue(['192.0.2.1'])
  mocks.lookup.mockReset().mockResolvedValue({ address: '192.0.2.2' })
  mocks.getServers.mockReset().mockReturnValue(['192.0.2.53', '[2001:db8::53]:5353'])
  mocks.resolvers.length = 0
})
afterEach(() => vi.useRealTimers())
describe('Xray operation-owned bootstrap DNS', () => {
  it('avoids an extra OS lookup when primary DNS completes before the hedge', async () => {
    vi.useFakeTimers()
    expect(await resolveXrayEndpoint('fixture.example')).toBe('192.0.2.1')
    await vi.advanceTimersByTimeAsync(XRAY_DNS_LOOKUP_DELAY_MS + 1)
    expect(mocks.lookup).not.toHaveBeenCalled()
    expect(vi.getTimerCount()).toBe(0)
  })
  it('finishes a 3025 ms primary DNS scenario in 120 ms through system lookup (AT-02-002)', async () => {
    vi.useFakeTimers()
    const began = Date.now(), report = vi.fn()
    mocks.resolve4.mockImplementation(() => new Promise(resolve => setTimeout(() => resolve(['192.0.2.1']), 3025)))
    mocks.lookup.mockImplementation(() => new Promise(resolve => setTimeout(() => resolve({ address: '192.0.2.2' }), 20)))
    const pending = resolveXrayEndpoint('secret.example', new AbortController().signal, report)
    await vi.advanceTimersByTimeAsync(99)
    expect(mocks.lookup).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(21)
    expect(await pending).toBe('192.0.2.2')
    expect(Date.now() - began).toBe(120)
    expect(mocks.resolvers[0].cancel).toHaveBeenCalledOnce()
    expect(report).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({
      method: 'system-lookup', hedged: true, elapsedMs: 20, totalElapsedMs: 120
    }))
    await vi.advanceTimersByTimeAsync(3025)
    expect(report).toHaveBeenCalledOnce()
    expect(JSON.stringify(report.mock.calls)).not.toMatch(/secret|192\.0\.2/)
  })
  it.each(['reject', 'invalid'] as const)('keeps waiting for primary DNS after an early hedge %s', async outcome => {
    vi.useFakeTimers()
    const primary = held<string[]>()
    mocks.resolve4.mockReturnValue(primary.promise)
    if (outcome === 'reject') mocks.lookup.mockRejectedValue(new Error('OS resolver unavailable'))
    else mocks.lookup.mockResolvedValue({ address: '2001:db8::1' })
    let settled = false
    const pending = resolveXrayEndpoint('fixture.example').then(value => { settled = true; return value })
    await vi.advanceTimersByTimeAsync(100)
    expect(settled).toBe(false)
    expect(mocks.resolvers[0].cancel).not.toHaveBeenCalled()
    primary.resolve(['192.0.2.7'])
    expect(await pending).toBe('192.0.2.7')
    expect(vi.getTimerCount()).toBe(0)
  })
  it('returns null only after both DNS paths fail (AT-02-004)', async () => {
    vi.useFakeTimers()
    const primary = held<string[]>()
    mocks.resolve4.mockReturnValue(primary.promise)
    mocks.lookup.mockRejectedValue(new Error('OS failure'))
    const pending = resolveXrayEndpoint('fixture.example')
    await vi.advanceTimersByTimeAsync(100)
    primary.reject(new Error('c-ares failure'))
    expect(await pending).toBeNull()
    expect(mocks.lookup).toHaveBeenCalledOnce()
    expect(vi.getTimerCount()).toBe(0)
  })
  it.each(['resolve', 'reject'] as const)('consumes late OS hedge %s after primary wins', async outcome => {
    vi.useFakeTimers()
    const primary = held<string[]>(), lookup = held<{ address: string }>(), report = vi.fn()
    mocks.resolve4.mockReturnValue(primary.promise)
    mocks.lookup.mockReturnValue(lookup.promise)
    const pending = resolveXrayEndpoint('fixture.example', undefined, report)
    await vi.advanceTimersByTimeAsync(100)
    primary.resolve(['192.0.2.8'])
    expect(await pending).toBe('192.0.2.8')
    if (outcome === 'resolve') lookup.resolve({ address: '192.0.2.99' })
    else lookup.reject(new Error('late OS failure'))
    await vi.advanceTimersByTimeAsync(1)
    expect(report).toHaveBeenCalledOnce()
  })
  it.each([50, 150])('cancels immediately at %s ms without publishing either late result (AT-02-005)', async at => {
    vi.useFakeTimers()
    const primary = held<string[]>(), lookup = held<{ address: string }>(), report = vi.fn()
    mocks.resolve4.mockReturnValue(primary.promise)
    mocks.lookup.mockReturnValue(lookup.promise)
    const owner = new AbortController()
    const rejected = expect(resolveXrayEndpoint('fixture.example', owner.signal, report)).rejects.toMatchObject({ name: 'AbortError' })
    await vi.advanceTimersByTimeAsync(at)
    owner.abort()
    await rejected
    primary.resolve(['192.0.2.1'])
    lookup.reject(new Error('late OS failure'))
    // A lookup not started before cancellation has no consumer to reject it.
    if (at < 100) lookup.promise.catch(() => undefined)
    await vi.advanceTimersByTimeAsync(200)
    expect(mocks.lookup).toHaveBeenCalledTimes(at < 100 ? 0 : 1)
    expect(report).not.toHaveBeenCalled()
    expect(mocks.resolvers[0].cancel).toHaveBeenCalledOnce()
    expect(vi.getTimerCount()).toBe(0)
  })
  it('accepts only a valid IPv4 and does not carry answers across operations', async () => {
    mocks.resolve4.mockResolvedValueOnce(['invalid', '2001:db8::1']).mockResolvedValueOnce(['192.0.2.3'])
    expect(await resolveXrayEndpoint('fixture.example')).toBe('192.0.2.2')
    expect(await resolveXrayEndpoint('fixture.example')).toBe('192.0.2.3')
    expect(mocks.resolve4).toHaveBeenCalledTimes(2)
  })
  it('records both resolver failures and successful fallback without topology/secrets (AT-08-001)', async () => {
    mocks.resolve4.mockRejectedValue(Object.assign(new Error('secret.example 192.0.2.53'), { code: 'ESERVFAIL' }))
    const report = vi.fn()
    expect(await resolveXrayEndpoint('secret.example', undefined, report)).toBe('192.0.2.2')
    expect(report.mock.calls[0][0]).toMatchObject({ method: 'resolve4', ok: false, code: 'ESERVFAIL' })
    expect(report.mock.calls[1][0]).toMatchObject({ method: 'system-lookup', ok: true, family: 4 })
    expect(JSON.stringify(report.mock.calls)).not.toMatch(/secret|192\.0\.2/)
  })
  it('does not let failed diagnostic reporting alter resolution', async () => {
    expect(await resolveXrayEndpoint('fixture.example', undefined, () => { throw new Error('logger down') })).toBe('192.0.2.1')
  })
  it.each(['', '  ', '192.0.2.10', '2001:db8::1'])('keeps literal/empty handling without DNS: %s', async server => {
    expect(await resolveXrayEndpoint(server)).toBe(server === '192.0.2.10' ? server : null)
    expect(mocks.resolve4).not.toHaveBeenCalled()
    expect(mocks.lookup).not.toHaveBeenCalled()
  })
  it('preserves IPv4 fallback and owns its resolver even without an external signal', async () => {
    mocks.resolve4.mockRejectedValue(new Error('normal DNS failure'))
    expect(await resolveXrayEndpoint(' fixture.example ')).toBe('192.0.2.2')
    expect(mocks.resolve4).toHaveBeenCalledWith('fixture.example')
    expect(mocks.lookup).toHaveBeenCalledWith('fixture.example', { family: 4 })
    expect(mocks.resolvers).toHaveLength(1)
  })
  it('returns the primary IPv4 value without lookup and preserves global server overrides', async () => {
    expect(await resolveXrayEndpoint('fixture.example', new AbortController().signal)).toBe('192.0.2.1')
    expect(mocks.lookup).not.toHaveBeenCalled()
    expect(mocks.resolvers[0].setServers).toHaveBeenCalledWith(['192.0.2.53', '[2001:db8::53]:5353'])
    expect(mocks.resolvers[0].cancel).not.toHaveBeenCalled()
  })
  it('does no DNS work for an already cancelled owner', async () => {
    const owner = new AbortController()
    owner.abort()
    await expect(resolveXrayEndpoint('fixture.example', owner.signal)).rejects.toMatchObject({ name: 'AbortError' })
    expect(mocks.resolvers).toHaveLength(0)
    expect(mocks.lookup).not.toHaveBeenCalled()
  })
  it.each(['resolve', 'reject'] as const)('reacts to cancellation without waiting for a late resolver %s', async outcome => {
    const old = held<string[]>()
    mocks.resolve4.mockReturnValue(old.promise)
    const owner = new AbortController()
    const pending = resolveXrayEndpoint('fixture.example', owner.signal)
    const rejected = expect(pending).rejects.toMatchObject({ name: 'AbortError' })
    owner.abort()
    await rejected
    expect(mocks.resolvers[0].cancel).toHaveBeenCalledOnce()
    if (outcome === 'resolve') old.resolve(['192.0.2.9'])
    else old.reject(new Error('late DNS failure'))
    await Promise.resolve()
    expect(mocks.lookup).not.toHaveBeenCalled()
  })
  it('does not cancel another operation resolver or adopt its sample', async () => {
    const old = held<string[]>(), fresh = held<string[]>()
    mocks.resolve4.mockReturnValueOnce(old.promise).mockReturnValueOnce(fresh.promise)
    const first = new AbortController(), second = new AbortController()
    const cancelled = expect(resolveXrayEndpoint('first.example', first.signal)).rejects.toThrow('cancelled')
    const next = resolveXrayEndpoint('second.example', second.signal)
    first.abort()
    await cancelled
    expect(mocks.resolvers[0].cancel).toHaveBeenCalledOnce()
    expect(mocks.resolvers[1].cancel).not.toHaveBeenCalled()
    old.resolve(['192.0.2.1'])
    fresh.resolve(['192.0.2.2'])
    expect(await next).toBe('192.0.2.2')
  })
  it.each(['resolve', 'reject'] as const)('discards uncancellable OS lookup %s without holding the caller', async outcome => {
    mocks.resolve4.mockResolvedValue([])
    const lookup = held<{ address: string }>()
    mocks.lookup.mockReturnValue(lookup.promise)
    const owner = new AbortController()
    const pending = resolveXrayEndpoint('fixture.example', owner.signal)
    const rejected = expect(pending).rejects.toThrow('cancelled')
    await vi.waitFor(() => expect(mocks.lookup).toHaveBeenCalledOnce())
    owner.abort()
    await rejected
    if (outcome === 'resolve') lookup.resolve({ address: '192.0.2.99' })
    else lookup.reject(new Error('late lookup failure'))
    await Promise.resolve()
  })
  it('retains the ordinary null result for failed/non-IPv4 lookup', async () => {
    mocks.resolve4.mockResolvedValue([])
    mocks.lookup.mockResolvedValue({ address: '2001:db8::1' })
    expect(await resolveXrayEndpoint('fixture.example', new AbortController().signal)).toBeNull()
    mocks.lookup.mockRejectedValue(new Error('lookup failed'))
    expect(await resolveXrayEndpoint('fixture.example')).toBeNull()
  })
})
