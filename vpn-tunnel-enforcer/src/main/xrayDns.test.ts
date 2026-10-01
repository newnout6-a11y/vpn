// AT-00-003 / AT-02-005: delayed bootstrap DNS cannot continue a cancelled start.
import { beforeEach, describe, expect, it, vi } from 'vitest'
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
import { resolveXrayEndpoint } from './xrayDns'
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
describe('Xray operation-owned bootstrap DNS', () => {
  it.each(['', '  ', '192.0.2.10', '2001:db8::1'])('keeps literal/empty handling without DNS: %s', async server => {
    expect(await resolveXrayEndpoint(server)).toBe(server === '192.0.2.10' ? server : null)
    expect(mocks.resolve4).not.toHaveBeenCalled()
    expect(mocks.lookup).not.toHaveBeenCalled()
  })
  it('preserves unscoped resolve4 then IPv4 lookup fallback', async () => {
    mocks.resolve4.mockRejectedValue(new Error('normal DNS failure'))
    expect(await resolveXrayEndpoint(' fixture.example ')).toBe('192.0.2.2')
    expect(mocks.resolve4).toHaveBeenCalledWith('fixture.example')
    expect(mocks.lookup).toHaveBeenCalledWith('fixture.example', { family: 4 })
    expect(mocks.resolvers).toHaveLength(0)
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
