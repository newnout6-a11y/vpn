import { beforeEach, describe, expect, it, vi } from 'vitest'
import axios from 'axios'
import { runProtectedOutboundSwitch, selectProtectedOutbound, type OutboundSlot, type ProtectedOutboundSwitch } from './protectedOutboundSwitch'

vi.mock('axios', () => ({ default: { put: vi.fn(), get: vi.fn() } }))
function gate() {
  let resolve!: () => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<void>((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}
function fixture() {
  const controller = new AbortController()
  const running = new Set<OutboundSlot>(['a'])
  let owner = true
  const calls: string[] = []
  const options: ProtectedOutboundSwitch = {
    previous: 'a', candidate: 'b', signal: controller.signal, isOwner: () => owner,
    stage: vi.fn(async slot => { calls.push(`stage:${slot}`); running.add(slot) }),
    probe: vi.fn(async slot => { calls.push(`probe:${slot}`) }),
    select: vi.fn(async slot => { calls.push(`select:${slot}`) }),
    confirm: vi.fn(async slot => { calls.push(`confirm:${slot}`) }),
    alive: slot => running.has(slot),
    stop: vi.fn(async slot => { calls.push(`stop:${slot}`); running.delete(slot) }),
    commit: vi.fn(slot => { calls.push(`commit:${slot}`) })
  }
  return { options, controller, running, calls, supersede: () => { owner = false } }
}

describe('protected upstream switch (AT-00-003 / AT-02-002 / AT-02-011)', () => {
  it('keeps the old upstream alive through candidate health and fresh tunnel proof', async () => {
    const f = fixture()
    const proof = gate()
    f.options.confirm = vi.fn(() => proof.promise)
    const pending = runProtectedOutboundSwitch(f.options)
    await vi.waitFor(() => expect(f.options.confirm).toHaveBeenCalledWith('b'))
    expect([...f.running]).toEqual(['a', 'b'])
    expect(f.options.commit).not.toHaveBeenCalled()
    expect(f.options.stop).not.toHaveBeenCalled()
    proof.resolve()
    expect(await pending).toMatchObject({ outcome: 'success', committed: true, activeSlot: 'b', previousStopped: true })
    expect(f.calls).toEqual(['stage:b', 'probe:b', 'select:b', 'commit:b', 'stop:a'])
  })

  it.each(['stage', 'probe', 'select', 'confirm'] as const)('cancels at %s, drains only candidate and freshly proves the retained upstream', async boundary => {
    const f = fixture(), held = gate()
    const original = f.options[boundary]
    f.options[boundary] = vi.fn(async (slot: OutboundSlot, signal?: AbortSignal) => {
      await (original as (slot: OutboundSlot, signal?: AbortSignal) => Promise<void>)(slot, signal)
      if (slot === 'b') await held.promise
    })
    const pending = runProtectedOutboundSwitch(f.options)
    await vi.waitFor(() => expect(f.options[boundary]).toHaveBeenCalled())
    f.controller.abort()
    held.resolve()
    expect(await pending).toMatchObject({ outcome: 'cancelled', committed: false, activeSlot: 'a', previousPreserved: true, candidateStopped: true })
    expect(f.options.commit).not.toHaveBeenCalled()
    expect(f.options.stop).toHaveBeenCalledExactlyOnceWith('b')
    expect(f.calls.at(-1)).toBe('confirm:a')
    expect(f.calls.includes('select:a')).toBe(boundary === 'select' || boundary === 'confirm')
    expect(f.running.has('a')).toBe(true)
  })

  it.each(['stage', 'probe', 'select', 'confirm'] as const)('supersession at %s prevents further selector writes or state publication', async boundary => {
    const f = fixture(), held = gate()
    const original = f.options[boundary]
    f.options[boundary] = vi.fn(async (slot: OutboundSlot, signal?: AbortSignal) => {
      await (original as (slot: OutboundSlot, signal?: AbortSignal) => Promise<void>)(slot, signal)
      await held.promise
    })
    const pending = runProtectedOutboundSwitch(f.options)
    await vi.waitFor(() => expect(f.options[boundary]).toHaveBeenCalled())
    const writes = vi.mocked(f.options.select).mock.calls.length
    f.supersede(); held.resolve()
    expect(await pending).toMatchObject({ outcome: 'cancelled', committed: false, previousPreserved: false, activeSlot: null, candidateStopped: true })
    expect(f.options.select).toHaveBeenCalledTimes(writes)
    expect(f.options.commit).not.toHaveBeenCalled()
    expect(f.options.stop).toHaveBeenCalledExactlyOnceWith('b')
  })

  it.each(['stage', 'probe', 'select', 'confirm'] as const)('failure at %s never stops the original upstream', async boundary => {
    const f = fixture(), original = f.options[boundary]
    f.options[boundary] = vi.fn(async (slot: OutboundSlot, signal?: AbortSignal) => {
      if (slot === 'b') throw new Error('candidate failed')
      await (original as (slot: OutboundSlot, signal?: AbortSignal) => Promise<void>)(slot, signal)
    })
    expect(await runProtectedOutboundSwitch(f.options)).toMatchObject({ outcome: 'failed', committed: false, previousPreserved: true, candidateStopped: true })
    expect(f.options.stop).toHaveBeenCalledExactlyOnceWith('b')
    expect(f.running.has('a')).toBe(true)
    expect(f.options.commit).not.toHaveBeenCalled()
  })

  it('does not claim preservation when selector restoration fails', async () => {
    const f = fixture()
    f.options.confirm = vi.fn(async slot => { if (slot === 'b') throw new Error('unhealthy') })
    f.options.select = vi.fn(async slot => { if (slot === 'a') throw new Error('restore failed') })
    expect(await runProtectedOutboundSwitch(f.options)).toMatchObject({ outcome: 'failed', previousPreserved: false, activeSlot: null, candidateStopped: true })
    expect(f.options.confirm).toHaveBeenCalledExactlyOnceWith('b')
  })

  it.each(['alive', 'throw'] as const)('does not claim preservation when candidate exit is unconfirmed: %s', async failure => {
    const f = fixture()
    f.options.probe = vi.fn(async () => { throw new Error('bad candidate') })
    f.options.stop = vi.fn(async () => { if (failure === 'throw') throw new Error('exit unknown') })
    expect(await runProtectedOutboundSwitch(f.options)).toMatchObject({ outcome: 'failed', candidateStopped: false, previousPreserved: false, activeSlot: null })
    expect(f.options.confirm).not.toHaveBeenCalled()
  })

  it('retains the committed selection and explicit old ownership when old exit fails', async () => {
    const f = fixture()
    f.options.stop = vi.fn(async () => { throw new Error('exit not confirmed') })
    expect(await runProtectedOutboundSwitch(f.options)).toMatchObject({ outcome: 'failed', committed: true, activeSlot: 'b', previousStopped: false, failures: [{ phase: 'stop-previous' }] })
    expect(f.options.select).toHaveBeenCalledExactlyOnceWith('b')
    expect(f.options.commit).toHaveBeenCalledExactlyOnceWith('b')
    expect([...f.running]).toEqual(['a', 'b'])
  })

  it.each(['previous', 'candidate'] as const)('rejects %s death during protected proof', async target => {
    const f = fixture()
    f.options.confirm = vi.fn(async slot => { if (slot === 'b') f.running.delete(target === 'previous' ? 'a' : 'b') })
    expect(await runProtectedOutboundSwitch(f.options)).toMatchObject({ outcome: 'failed', committed: false, previousPreserved: target === 'candidate' })
    expect(f.options.commit).not.toHaveBeenCalled()
  })

  it('never touches an already occupied candidate or identical slot', async () => {
    const f = fixture(); f.running.add('b')
    expect(await runProtectedOutboundSwitch(f.options)).toMatchObject({ outcome: 'failed', committed: false, candidateStopped: false })
    expect(f.options.stage).not.toHaveBeenCalled(); expect(f.options.stop).not.toHaveBeenCalled()
    f.options.candidate = 'a'
    expect(await runProtectedOutboundSwitch(f.options)).toMatchObject({ outcome: 'failed', previousPreserved: false })
    expect(f.options.select).not.toHaveBeenCalled()
  })

  it('fences late restoration proof after disconnect takes ownership', async () => {
    const f = fixture(), held = gate()
    f.options.probe = vi.fn(async () => { throw new Error('candidate failed') })
    f.options.confirm = vi.fn(() => held.promise)
    const pending = runProtectedOutboundSwitch(f.options)
    await vi.waitFor(() => expect(f.options.confirm).toHaveBeenCalledWith('a'))
    f.supersede(); held.resolve()
    expect(await pending).toMatchObject({ outcome: 'cancelled', previousPreserved: false, activeSlot: null })
    expect(f.options.commit).not.toHaveBeenCalled()
  })

  it('does not publish success when the committed candidate dies during old cleanup', async () => {
    const f = fixture(), held = gate()
    f.options.stop = vi.fn(async slot => { await held.promise; f.running.delete(slot) })
    const pending = runProtectedOutboundSwitch(f.options)
    await vi.waitFor(() => expect(f.options.commit).toHaveBeenCalledWith('b'))
    f.running.delete('b'); held.resolve()
    expect(await pending).toMatchObject({ outcome: 'failed', committed: true, activeSlot: null, previousStopped: true })
    expect(f.options.select).toHaveBeenCalledExactlyOnceWith('b')
  })

  it('retains commit receipt when disconnect supersedes old cleanup', async () => {
    const f = fixture(), held = gate()
    f.options.stop = vi.fn(async slot => { await held.promise; f.running.delete(slot) })
    const pending = runProtectedOutboundSwitch(f.options)
    await vi.waitFor(() => expect(f.options.commit).toHaveBeenCalledWith('b'))
    f.supersede(); held.resolve()
    expect(await pending).toMatchObject({ outcome: 'cancelled', committed: true, activeSlot: null, previousPreserved: false, previousStopped: true })
    expect(f.options.select).toHaveBeenCalledExactlyOnceWith('b')
    expect(f.options.stop).toHaveBeenCalledExactlyOnceWith('a')
  })

  it('does not begin work or touch the selector after ownership was already lost', async () => {
    const f = fixture(); f.supersede()
    expect(await runProtectedOutboundSwitch(f.options)).toMatchObject({ outcome: 'cancelled', committed: false, previousPreserved: false })
    expect(f.options.stage).not.toHaveBeenCalled()
    expect(f.options.select).not.toHaveBeenCalled()
    expect(f.options.confirm).not.toHaveBeenCalled()
    expect(f.options.stop).not.toHaveBeenCalled()
  })
})

describe('authenticated protected selector (AT-01-002 / AT-01-005 / AT-00-003)', () => {
  const api = { port: 18001, secret: 'a'.repeat(32) }
  beforeEach(() => { vi.resetAllMocks() })
  const response = (slot = 'a') => ({ status: 200, data: { type: 'Selector', now: `vpnte-upstream-${slot}`, all: ['vpnte-upstream-a', 'vpnte-upstream-b'] } })
  it('requires PUT and fresh exact selector readback over authenticated loopback', async () => {
    vi.mocked(axios.put).mockResolvedValue({ status: 204 })
    vi.mocked(axios.get).mockResolvedValue(response('b'))
    await expect(selectProtectedOutbound(api, 'b')).resolves.toBeUndefined()
    expect(axios.put).toHaveBeenCalledWith('http://127.0.0.1:18001/proxies/proxy-out', { name: 'vpnte-upstream-b' }, expect.objectContaining({ proxy: false, maxRedirects: 0, timeout: 1000, headers: { Authorization: `Bearer ${api.secret}` } }))
    expect(axios.get).toHaveBeenCalledExactlyOnceWith('http://127.0.0.1:18001/proxies/proxy-out', expect.objectContaining({ proxy: false, maxRedirects: 0 }))
    expect(vi.mocked(axios.put).mock.invocationCallOrder[0]).toBeLessThan(vi.mocked(axios.get).mock.invocationCallOrder[0])
  })
  it.each([null, [], {}, { type: 'Selector', now: 'vpnte-upstream-b', all: ['vpnte-upstream-a', 'vpnte-upstream-b'] }, { type: 'Direct', now: 'vpnte-upstream-a', all: ['vpnte-upstream-a', 'vpnte-upstream-b'] }, { type: 'Selector', now: 'vpnte-upstream-a', all: ['vpnte-upstream-a', 'vpnte-upstream-a'] }, { type: 'Selector', now: 'vpnte-upstream-a', all: ['vpnte-upstream-a', 'vpnte-upstream-b', 'direct-out'] }])('rejects malformed, stale, duplicate or bypass selector state %j', async data => {
    vi.mocked(axios.put).mockResolvedValue({ status: 204 })
    vi.mocked(axios.get).mockResolvedValue({ status: 200, data })
    await expect(selectProtectedOutbound(api, 'a')).rejects.toThrow('not confirmed')
  })
  it('does not expose Axios request headers when a request fails', async () => {
    vi.mocked(axios.put).mockRejectedValue(new Error(`Authorization: Bearer ${api.secret}`))
    const result = await selectProtectedOutbound(api, 'a').catch(error => error)
    expect(String(result)).not.toContain(api.secret)
    expect(axios.get).not.toHaveBeenCalled()
  })
  it.each([0, 65536, 1.5])('rejects invalid controller port %s before any request', async port => {
    await expect(selectProtectedOutbound({ ...api, port }, 'a')).rejects.toThrow('Invalid')
    expect(axios.put).not.toHaveBeenCalled()
  })
  it('bounds both requests with one deadline and clears its timer', async () => {
    vi.useFakeTimers()
    try {
      vi.mocked(axios.put).mockImplementation((_url, _body, config) => new Promise((_resolve, reject) => {
        config?.signal?.addEventListener?.('abort', () => reject(new Error('deadline')))
      }))
      const pending = selectProtectedOutbound(api, 'a')
      const rejected = expect(pending).rejects.toThrow('not confirmed')
      await vi.advanceTimersByTimeAsync(1000)
      await rejected
      expect(vi.getTimerCount()).toBe(0)
    } finally { vi.useRealTimers() }
  })
})
