import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import axios from 'axios'
vi.mock('axios')
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
let monitor: typeof import('./ipMonitor').ipMonitor
beforeEach(async () => {
  vi.resetModules(); vi.useFakeTimers()
  vi.mocked(axios.get).mockReset().mockResolvedValue({ data: '198.51.100.1' })
  monitor = (await import('./ipMonitor')).ipMonitor
  await monitor.recheck(true)
})
afterEach(() => { monitor.clearVpnIp(); vi.clearAllTimers(); vi.useRealTimers() })
describe('public IP evidence (AT-07-001 / AT-07-005 / AT-07-006)', () => {
  it('marks a changed VPN exit indeterminate rather than claiming the real IP is visible', async () => {
    vi.mocked(axios.get).mockResolvedValue({ data: '13.143.217.2' })
    const changed = vi.fn(); monitor.onIpChange(changed)
    await vi.advanceTimersByTimeAsync(30000)
    expect(await monitor.getCurrentIp()).toEqual({ ip: '13.143.217.2', vpnIp: '198.51.100.1', isLeak: false })
    expect(monitor.getEvidence()).toEqual({ vpnIp: '198.51.100.1', verdict: 'indeterminate' })
    expect(changed).toHaveBeenCalledWith('13.143.217.2', false, { vpnIp: '198.51.100.1', verdict: 'indeterminate' })
  })
  it('does not bless an unverified mismatch by reading it again', async () => {
    vi.mocked(axios.get).mockResolvedValue({ data: '198.51.100.2' })
    await monitor.getCurrentIp(); await monitor.recheck(false)
    expect(monitor.getEvidence().verdict).toBe('indeterminate')
    expect(monitor.getEvidence().vpnIp).toBe('198.51.100.1')
    await monitor.recheck(true)
    expect(monitor.getEvidence()).toEqual({ vpnIp: '198.51.100.2', verdict: 'passed' })
  })
  it('shows unavailable checks as not checked while keeping cache distinct', async () => {
    vi.mocked(axios.get).mockRejectedValue(new Error('offline'))
    expect((await monitor.getCurrentIp()).ip).toBe('198.51.100.1')
    expect(monitor.getEvidence().verdict).toBe('not-checked')
  })
  it('invalidates the former server baseline before a protected swap', () => {
    const changed = vi.fn(); monitor.onIpChange(changed)
    monitor.deferResume(); monitor.invalidateVpnIpBaseline()
    expect(monitor.getEvidence()).toEqual({ vpnIp: null, verdict: 'not-checked' })
    expect(changed).toHaveBeenCalledWith('198.51.100.1', false, { vpnIp: null, verdict: 'not-checked' })
  })
})
