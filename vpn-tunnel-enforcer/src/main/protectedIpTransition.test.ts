import { beforeEach, describe, expect, it, vi } from 'vitest'
const monitor = vi.hoisted(() => ({
  deferResume: vi.fn(), invalidateVpnIpBaseline: vi.fn(), clearVpnIp: vi.fn(),
  releaseDeferredResume: vi.fn(), recheck: vi.fn()
}))
vi.mock('./ipMonitor', () => ({ ipMonitor: monitor }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
import { withProtectedIpTransition } from './protectedIpTransition'
beforeEach(() => { vi.clearAllMocks(); monitor.recheck.mockReset().mockResolvedValue({ ip: '203.0.113.1' }) })
const base = () => ({ reason: 'fixture', restart: vi.fn(async () => ({ success: true })), isCurrent: () => true, areRoutesActive: vi.fn(async () => true) })
describe('protected IP transition (AT-07-006 / AT-07-012 / AT-10-003)', () => {
  it('invalidates old evidence before restart, commits profile before one fresh wave and releases last', async () => {
    const options = { ...base(), onRestarted: vi.fn() }
    await withProtectedIpTransition(options)
    expect(monitor.deferResume.mock.invocationCallOrder[0]).toBeLessThan(options.restart.mock.invocationCallOrder[0])
    expect(monitor.invalidateVpnIpBaseline.mock.invocationCallOrder[0]).toBeLessThan(options.restart.mock.invocationCallOrder[0])
    expect(options.onRestarted.mock.invocationCallOrder[0]).toBeLessThan(monitor.recheck.mock.invocationCallOrder[0])
    expect(monitor.recheck).toHaveBeenCalledExactlyOnceWith(true, options.isCurrent)
    expect(monitor.releaseDeferredResume.mock.invocationCallOrder[0]).toBeGreaterThan(monitor.recheck.mock.invocationCallOrder[0])
  })
  it('accepts a fresh unchanged egress without six unnecessary probes', async () => {
    await withProtectedIpTransition(base())
    expect(monitor.recheck).toHaveBeenCalledOnce()
  })
  it('leaves missing route evidence unverified without accepting a cached IP', async () => {
    const options = base(); options.areRoutesActive.mockResolvedValue(false)
    await withProtectedIpTransition(options)
    expect(monitor.recheck).not.toHaveBeenCalled()
    expect(monitor.invalidateVpnIpBaseline).toHaveBeenCalledTimes(2)
    expect(monitor.releaseDeferredResume).toHaveBeenCalledOnce()
  })
  it('does not select a fallback or publish a baseline when manual selection supersedes restart', async () => {
    let current = true
    const options = { ...base(), isCurrent: () => current, onRestarted: vi.fn(), restart: async () => { current = false; return { success: true } } }
    await withProtectedIpTransition(options)
    expect(options.onRestarted).not.toHaveBeenCalled()
    expect(monitor.recheck).not.toHaveBeenCalled()
    expect(monitor.releaseDeferredResume).toHaveBeenCalledOnce()
  })
  it('discards a post-restart IP response from a superseded owner', async () => {
    let current = true
    monitor.recheck.mockImplementation(async () => { current = false; return { ip: '198.51.100.5' } })
    await withProtectedIpTransition({ ...base(), isCurrent: () => current })
    expect(monitor.recheck).toHaveBeenCalledOnce()
    expect(monitor.invalidateVpnIpBaseline).toHaveBeenCalledOnce()
  })
  it('clears failed restart evidence even though the tunnel is now stopped', async () => {
    await withProtectedIpTransition({ ...base(), isCurrent: () => false, isOwner: () => true, restart: async () => ({ success: false }) })
    expect(monitor.clearVpnIp).toHaveBeenCalledOnce()
  })
  it('never clears a newer owner after an obsolete restart fails', async () => {
    await withProtectedIpTransition({ ...base(), isCurrent: () => false, isOwner: () => false, restart: async () => ({ success: false }) })
    expect(monitor.clearVpnIp).not.toHaveBeenCalled()
  })
  it.each(['failure', 'exception'])('clears stale evidence and releases suppression after restart %s', async kind => {
    const options = base()
    if (kind === 'failure') options.restart.mockResolvedValue({ success: false })
    else options.restart.mockRejectedValue(new Error('fixture failure'))
    if (kind === 'exception') await expect(withProtectedIpTransition(options)).rejects.toThrow('fixture failure')
    else await expect(withProtectedIpTransition(options)).resolves.toEqual({ success: false })
    expect(monitor.clearVpnIp).toHaveBeenCalledOnce()
    expect(monitor.releaseDeferredResume).toHaveBeenCalledOnce()
    expect(monitor.recheck).not.toHaveBeenCalled()
  })
})
