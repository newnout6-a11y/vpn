// AT-00-003: delayed provider responses cannot publish into another session.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import axios from 'axios'
vi.mock('axios')
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))

let module: typeof import('./ipMonitor')
const response = (ip: string) => ({ data: ip }) as any
function held() {
  let resolve!: (value: any) => void
  const promise = new Promise<any>(done => { resolve = done })
  return { promise, resolve }
}
beforeEach(async () => {
  vi.useFakeTimers()
  vi.resetModules()
  vi.mocked(axios.get).mockReset().mockResolvedValue(response('203.0.113.1'))
  module = await import('./ipMonitor')
  await module.ipMonitor.getCurrentIp()
  module.ipMonitor.setVpnIp('203.0.113.1')
  await Promise.resolve()
  module.ipMonitor.stopMonitoring()
  vi.mocked(axios.get).mockClear()
})
afterEach(() => { module.ipMonitor.stopMonitoring(); vi.clearAllTimers(); vi.useRealTimers() })

describe('IP monitor session ownership (AT-00-003 / AT-02-005)', () => {
  it.each(['read', 'probe', 'rebaseline'])('does not start a cancelled %s request', async kind => {
    if (kind === 'read') await module.ipMonitor.getCurrentIp(() => false)
    if (kind === 'probe') await module.ipMonitor.recheck(false, () => false)
    if (kind === 'rebaseline') await module.ipMonitor.recheck(true, () => false)
    expect(axios.get).not.toHaveBeenCalled()
  })
  it.each(['read', 'probe', 'rebaseline'])('discards a late %s result, health timestamp and notifications', async kind => {
    const pending = held()
    vi.mocked(axios.get).mockReturnValue(pending.promise)
    const notify = vi.fn(), recovered = vi.fn()
    module.ipMonitor.onIpChange(notify)
    module.setIpMonitorRecoveryCallback(recovered)
    const lastSuccess = module.ipMonitor.getLastSuccessAt()
    vi.setSystemTime(lastSuccess + 10000)
    let current = true
    const guard = () => current
    const result = kind === 'read' ? module.ipMonitor.getCurrentIp(guard) : module.ipMonitor.recheck(kind === 'rebaseline', guard)
    expect(axios.get).toHaveBeenCalledTimes(4)
    current = false
    pending.resolve(response('198.51.100.99'))
    expect(await result).toEqual({ ip: '203.0.113.1', vpnIp: '203.0.113.1', isLeak: false })
    expect(module.ipMonitor.getLastSuccessAt()).toBe(lastSuccess)
    expect(notify).not.toHaveBeenCalled()
    expect(recovered).not.toHaveBeenCalled()
  })
  it('takes a fresh sample for a new session instead of joining a cancelled rebaseline', async () => {
    const old = held()
    let request = 0, generation = 1
    vi.mocked(axios.get).mockImplementation(() => ++request <= 4 ? old.promise : Promise.resolve(response('198.51.100.2')))
    const notify = vi.fn()
    module.ipMonitor.onIpChange(notify)
    const first = module.ipMonitor.recheck(true, () => generation === 1)
    generation = 2
    const detached = module.ipMonitor.recheck
    const second = detached(true, () => generation === 2)
    expect(axios.get).toHaveBeenCalledTimes(4)
    old.resolve(response('198.51.100.1'))
    expect((await first).vpnIp).toBe('203.0.113.1')
    expect((await second).vpnIp).toBe('198.51.100.2')
    expect(notify.mock.calls.every(call => call[0] === '198.51.100.2')).toBe(true)
    expect(request).toBeGreaterThanOrEqual(8)
  })
  it('does not fetch for a queued session cancelled while the older owner settles', async () => {
    const old = held()
    vi.mocked(axios.get).mockReturnValue(old.promise)
    let generation = 1
    const first = module.ipMonitor.recheck(true, () => generation === 1)
    generation = 2
    const second = module.ipMonitor.recheck(true, () => generation === 2)
    generation = 3
    old.resolve(response('198.51.100.1'))
    expect((await first).vpnIp).toBe('203.0.113.1')
    expect((await second).vpnIp).toBe('203.0.113.1')
    expect(axios.get).toHaveBeenCalledTimes(4)
  })
  it.each([false, true])('coalesces rebaseline only for the same owner; scoped=%s', async scoped => {
    // Keep the periodic monitor active so adoption does not start another probe.
    module.ipMonitor.startMonitoring()
    await Promise.resolve()
    const pending = held()
    vi.mocked(axios.get).mockClear().mockReturnValue(pending.promise)
    const guard = scoped ? () => true : undefined
    const first = module.ipMonitor.recheck(true, guard)
    const second = module.ipMonitor.recheck(true, guard)
    expect(axios.get).toHaveBeenCalledTimes(4)
    pending.resolve(response('198.51.100.3'))
    expect((await first).vpnIp).toBe('198.51.100.3')
    expect(await second).toEqual(await first)
    expect(axios.get).toHaveBeenCalledTimes(4)
  })
})
