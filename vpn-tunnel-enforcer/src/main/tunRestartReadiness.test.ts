// AT-02-002/004/005 / AT-00-003: release proof, timeout and cancellation.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const state = vi.hoisted(() => ({ interfaces: vi.fn() }))
vi.mock('os', async importOriginal => {
  const actual = await importOriginal<typeof import('os')>()
  return { ...actual, default: { ...actual, networkInterfaces: state.interfaces }, networkInterfaces: state.interfaces }
})
import { waitForTunRelease } from './tunRestartReadiness'

const owned = { 'Ethernet 5': [{ address: '192.168.250.253', internal: false }] }
beforeEach(() => { vi.useFakeTimers(); state.interfaces.mockReset().mockReturnValue({}) })
afterEach(() => { vi.useRealTimers() })

describe('TUN release readiness', () => {
  it('returns immediately once the old active address is absent', async () => {
    expect(await waitForTunRelease(() => false)).toBe('released')
    expect(state.interfaces).toHaveBeenCalledOnce()
    expect(vi.getTimerCount()).toBe(0)
  })
  it('waits for a delayed interface release rather than a fixed pause', async () => {
    state.interfaces.mockReturnValue(owned)
    const complete = vi.fn()
    const pending = waitForTunRelease(() => false).then(complete)
    await vi.advanceTimersByTimeAsync(50)
    expect(complete).not.toHaveBeenCalled()
    state.interfaces.mockReturnValue({})
    await vi.advanceTimersByTimeAsync(25)
    await pending
    expect(complete).toHaveBeenCalledWith('released')
    expect(vi.getTimerCount()).toBe(0)
  })
  it('does not confuse a physical adapter with the old owned TUN', async () => {
    state.interfaces.mockReturnValue({ 'Ethernet 5': [{ address: '192.168.1.20', internal: false }] })
    expect(await waitForTunRelease(() => false)).toBe('released')
  })
  it('also waits for active legacy TUN addresses', async () => {
    state.interfaces.mockReturnValue({ 'VPNTE-TUN': [{ address: '172.19.0.1', internal: false }] })
    const pending = waitForTunRelease(() => false, 100)
    await vi.advanceTimersByTimeAsync(100)
    expect(await pending).toBe('unverified')
    expect(vi.getTimerCount()).toBe(0)
  })
  it('does not convert a failed interface read into release proof', async () => {
    state.interfaces.mockImplementation(() => { throw new Error('enumeration failed') })
    expect(await waitForTunRelease(() => false)).toBe('unverified')
  })
  it('also blocks recreation while the old owned IPv6 address remains', async () => {
    state.interfaces.mockReturnValue({ 'Ethernet 5': [{ address: 'fdfe:dcba:9876::1', internal: false }] })
    const pending = waitForTunRelease(() => false, 100)
    await vi.advanceTimersByTimeAsync(100)
    expect(await pending).toBe('unverified')
  })
  it('honours cancellation before reading and while waiting', async () => {
    expect(await waitForTunRelease(() => true)).toBe('cancelled')
    expect(state.interfaces).not.toHaveBeenCalled()
    state.interfaces.mockReturnValue(owned)
    let cancelled = false
    const pending = waitForTunRelease(() => cancelled)
    cancelled = true
    await vi.advanceTimersByTimeAsync(25)
    expect(await pending).toBe('cancelled')
    expect(vi.getTimerCount()).toBe(0)
  })
})
