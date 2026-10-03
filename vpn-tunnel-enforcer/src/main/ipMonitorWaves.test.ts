// AT-07-007/012, AT-00-003: bounded provider waves, cancellation and fresh owners.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import axios from 'axios'
vi.mock('axios')
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
let module: typeof import('./ipMonitor')
const response = (ip = '198.51.100.1') => ({ data: ip }) as any
function held() {
  let resolve!: (value: any) => void
  const promise = new Promise<any>(done => { resolve = done })
  return { promise, resolve }
}
beforeEach(async () => {
  vi.useFakeTimers()
  vi.resetModules()
  vi.mocked(axios.get).mockReset().mockResolvedValue(response())
  module = await import('./ipMonitor')
})
afterEach(() => { module.ipMonitor.clearVpnIp(); vi.clearAllTimers(); vi.useRealTimers() })
describe('IP provider wave budget', () => {
  it.each([false, true])('coalesces 50 concurrent reads for the same owner; scoped=%s', async scoped => {
    const pending = held(), guard = scoped ? () => true : undefined
    vi.mocked(axios.get).mockReturnValue(pending.promise)
    const reads = Array.from({ length: 50 }, () => module.fetchPublicIp(guard))
    expect(axios.get).toHaveBeenCalledTimes(4)
    pending.resolve(response())
    expect(await Promise.all(reads)).toEqual(Array(50).fill('198.51.100.1'))
    await module.fetchPublicIp(guard)
    expect(axios.get).toHaveBeenCalledTimes(8) // no cached result on the next wave
  })
  it('aborts outstanding providers after the first valid response', async () => {
    const first = held(), aborted = vi.fn()
    vi.mocked(axios.get).mockImplementation((_url, options) => {
      if (vi.mocked(axios.get).mock.calls.length === 1) return first.promise
      return new Promise((_resolve, reject) => options?.signal?.addEventListener?.('abort', () => { aborted(); reject(new Error('cancelled loser')) }))
    })
    const result = module.fetchPublicIp()
    first.resolve(response())
    expect(await result).toBe('198.51.100.1')
    expect(aborted).toHaveBeenCalledTimes(3)
  })
  it('never shares the sample with a different session owner', async () => {
    const old = held(), fresh = held()
    let generation = 1
    vi.mocked(axios.get).mockImplementation(() => vi.mocked(axios.get).mock.calls.length <= 4 ? old.promise : fresh.promise)
    const first = module.fetchPublicIp(() => generation === 1)
    generation++
    const second = module.fetchPublicIp(() => generation === 2)
    expect(axios.get).toHaveBeenCalledTimes(8)
    old.resolve(response('198.51.100.2'))
    fresh.resolve(response('198.51.100.3'))
    expect(await first).toBeNull()
    expect(await second).toBe('198.51.100.3')
  })
  it('discards pre-stop reads even if a provider ignores abort and monitoring resumes', async () => {
    const old = held()
    vi.mocked(axios.get).mockReturnValue(old.promise)
    const read = module.ipMonitor.getCurrentIp()
    const signals = vi.mocked(axios.get).mock.calls.map(call => call[1]?.signal)
    module.ipMonitor.suspend()
    module.ipMonitor.resume()
    old.resolve(response())
    expect((await read).ip).toBeNull()
    expect(module.ipMonitor.getLastSuccessAt()).toBe(0)
    expect(signals.every(signal => signal?.aborted)).toBe(true)
    vi.mocked(axios.get).mockResolvedValue(response('198.51.100.2'))
    expect((await module.ipMonitor.getCurrentIp()).ip).toBe('198.51.100.2')
  })
  it('adopts one fresh baseline without starting a duplicate immediate monitoring wave', async () => {
    expect((await module.ipMonitor.recheck(true)).vpnIp).toBe('198.51.100.1')
    expect(axios.get).toHaveBeenCalledTimes(4)
    await vi.advanceTimersByTimeAsync(30000)
    expect(axios.get).toHaveBeenCalledTimes(8)
  })
  it('does not report a cached IP as a successful fresh baseline when all providers fail', async () => {
    await module.ipMonitor.recheck(true)
    module.ipMonitor.stopMonitoring()
    const notify = vi.fn()
    module.ipMonitor.onIpChange(notify)
    vi.mocked(axios.get).mockRejectedValue(new Error('unreachable'))
    expect(await module.ipMonitor.recheck(true)).toEqual({ ip: null, vpnIp: '198.51.100.1', isLeak: false })
    expect(notify).toHaveBeenCalledWith('198.51.100.1', false, { vpnIp: '198.51.100.1', verdict: 'not-checked' })
    expect((await module.ipMonitor.getCurrentIp()).ip).toBe('198.51.100.1')
    expect(vi.getTimerCount()).toBe(0)
  })
  it('backs off a 429 provider while retaining other providers and retries after the deadline', async () => {
    vi.mocked(axios.get).mockImplementation(async url => {
      if (url === module.IP_CHECK_URLS[0]) throw { response: { status: 429, headers: { 'retry-after': '60' } } }
      return response()
    })
    expect(await module.fetchPublicIp()).toBe('198.51.100.1')
    vi.mocked(axios.get).mockClear()
    await module.fetchPublicIp()
    expect(axios.get).toHaveBeenCalledTimes(3)
    await vi.advanceTimersByTimeAsync(60000)
    vi.mocked(axios.get).mockClear()
    await module.fetchPublicIp()
    expect(axios.get).toHaveBeenCalledTimes(4)
  })
  it('makes no periodic HTTP requests during rollback suspension', async () => {
    await module.ipMonitor.recheck(true)
    module.ipMonitor.suspend()
    vi.mocked(axios.get).mockClear()
    await vi.advanceTimersByTimeAsync(60000)
    expect(axios.get).not.toHaveBeenCalled()
  })
})
