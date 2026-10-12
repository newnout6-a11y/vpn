// AT-07-002 / AT-12-007: the native-read host client survives every way the host can fail and never turns a
// failure into data. A fake process stands in for Electron's utilityProcess.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createHostClient, type HostProcess } from './hostClient'
import { NativeHostError, type HostRequest } from './hostProtocol'

class FakeHost implements HostProcess {
  sent: HostRequest[] = []
  killed = false
  private onMessage: Array<(m: unknown) => void> = []
  private onExit: Array<(code: number) => void> = []
  postMessage(message: unknown): void { this.sent.push(message as HostRequest) }
  on(event: 'message' | 'exit', listener: never): unknown {
    if (event === 'message') this.onMessage.push(listener as (m: unknown) => void)
    else this.onExit.push(listener as (code: number) => void)
    return this
  }
  kill(): boolean { this.killed = true; return true }
  reply(message: unknown): void { for (const cb of this.onMessage) cb(message) }
  exit(code = 1): void { for (const cb of this.onExit) cb(code) }
}

function harness(overrides: Partial<Parameters<typeof createHostClient>[0]> = {}) {
  const hosts: FakeHost[] = []
  const log = vi.fn()
  let clock = 0
  const client = createHostClient({
    fork: () => { const h = new FakeHost(); hosts.push(h); return h },
    defaultTimeoutMs: 1000, maxDeaths: 3, deathWindowMs: 60_000, now: () => clock, log, ...overrides
  })
  return { client, hosts, log, advanceClock: (ms: number) => { clock += ms } }
}

const kindOf = async (promise: Promise<unknown>) => {
  try { await promise } catch (error) { return error instanceof NativeHostError ? error.kind : `other:${String(error)}` }
  return 'resolved'
}

beforeEach(() => { vi.useFakeTimers() })
afterEach(() => { vi.useRealTimers() })

describe('native host client', () => {
  it('starts lazily and resolves a reply by request id', async () => {
    const { client, hosts } = harness()
    expect(hosts).toHaveLength(0)
    const promise = client.call<number[]>('adapters')
    expect(hosts).toHaveLength(1)
    hosts[0].reply({ id: hosts[0].sent[0].id, ok: true, value: [1, 2] })
    await expect(promise).resolves.toEqual([1, 2])
  })

  it('matches concurrent requests by id even when replies arrive out of order', async () => {
    const { client, hosts } = harness()
    const a = client.call<string>('adapters'), b = client.call<string>('routes', { prefixes: [] })
    const [first, second] = hosts[0].sent
    hosts[0].reply({ id: second.id, ok: true, value: 'second' })
    hosts[0].reply({ id: first.id, ok: true, value: 'first' })
    await expect(a).resolves.toBe('first')
    await expect(b).resolves.toBe('second')
    expect(hosts).toHaveLength(1)
  })

  it('maps a refused read to read-refused and keeps the host alive', async () => {
    const { client, hosts } = harness()
    const promise = client.call('physical-snapshot')
    hosts[0].reply({ id: hosts[0].sent[0].id, ok: false, kind: 'read-refused', message: 'no adapters' })
    expect(await kindOf(promise)).toBe('read-refused')
    expect(hosts[0].killed).toBe(false)
  })

  it('keeps a WinINet false authoritative: kind wininet-false survives the boundary', async () => {
    const { client, hosts } = harness()
    const promise = client.call('wininet')
    hosts[0].reply({ id: hosts[0].sent[0].id, ok: false, kind: 'wininet-false', message: 'WinINet refresh failed' })
    await expect(promise).rejects.toMatchObject({ kind: 'wininet-false', message: 'WinINet refresh failed' })
  })

  it('rejects every pending request as unavailable when the host exits mid-request, then respawns', async () => {
    const { client, hosts } = harness()
    const a = client.call('adapters'), b = client.call('ipconfig')
    hosts[0].exit(3221226505)
    expect(await kindOf(a)).toBe('unavailable')
    expect(await kindOf(b)).toBe('unavailable')
    const next = client.call<string>('adapters')
    expect(hosts).toHaveLength(2)
    hosts[1].reply({ id: hosts[1].sent[0].id, ok: true, value: 'fresh' })
    await expect(next).resolves.toBe('fresh')
  })

  it('kills the host on timeout (a hung FFI call cannot be cancelled) and rejects as unavailable', async () => {
    const { client, hosts } = harness()
    const promise = client.call('adapters', undefined, 500)
    const settled = kindOf(promise)
    await vi.advanceTimersByTimeAsync(501)
    expect(await settled).toBe('unavailable')
    expect(hosts[0].killed).toBe(true)
  })

  it('does not let the late exit of a killed host fail requests sent to its replacement', async () => {
    const { client, hosts } = harness()
    const first = kindOf(client.call('adapters', undefined, 100))
    await vi.advanceTimersByTimeAsync(101)
    expect(await first).toBe('unavailable')
    const second = client.call<string>('adapters')
    expect(hosts).toHaveLength(2)
    hosts[0].exit(1) // the killed process finally reports its exit
    hosts[1].reply({ id: hosts[1].sent[0].id, ok: true, value: 'ok' })
    await expect(second).resolves.toBe('ok')
  })

  it('treats a malformed reply as a broken host: kills it and fails the request', async () => {
    const { client, hosts } = harness()
    const promise = client.call('adapters')
    hosts[0].reply({ nonsense: true })
    expect(await kindOf(promise)).toBe('unavailable')
    expect(hosts[0].killed).toBe(true)
  })

  it('ignores a late reply for a request that already timed out', async () => {
    const { client, hosts } = harness()
    const promise = kindOf(client.call('adapters', undefined, 100))
    const id = hosts[0].sent[0].id
    await vi.advanceTimersByTimeAsync(101)
    expect(await promise).toBe('unavailable')
    expect(() => hosts[0].reply({ id, ok: true, value: 'late' })).not.toThrow()
  })

  it('reports a failed spawn as unavailable', async () => {
    const { client } = harness({ fork: () => { throw new Error('spawn EACCES') } })
    expect(await kindOf(client.call('adapters'))).toBe('unavailable')
  })

  it('disables the host for the session after repeated deaths in the window (crash-loop breaker)', async () => {
    const { client, hosts, log, advanceClock } = harness()
    for (let i = 0; i < 3; i++) {
      const promise = client.call('adapters')
      hosts[i].exit(1)
      expect(await kindOf(promise)).toBe('unavailable')
      advanceClock(1000)
    }
    expect(client.status().disabled).toBe(true)
    const callsBefore = hosts.length
    expect(await kindOf(client.call('adapters'))).toBe('unavailable')
    expect(hosts).toHaveLength(callsBefore) // no further spawn
    expect(log).toHaveBeenCalledWith('warn', expect.stringContaining('disabled for this session'), expect.anything())
  })

  it('does not count deaths older than the window', async () => {
    const { client, hosts, advanceClock } = harness()
    for (let i = 0; i < 4; i++) {
      const promise = client.call('adapters')
      hosts[i].exit(1)
      await kindOf(promise)
      advanceClock(61_000)
    }
    expect(client.status().disabled).toBe(false)
  })

  it('shutdown stops the host without counting a crash and refuses further calls', async () => {
    const { client, hosts } = harness()
    const pending = client.call('adapters')
    client.shutdown()
    expect(hosts[0].killed).toBe(true)
    expect(await kindOf(pending)).toBe('unavailable')
    hosts[0].exit(0)
    expect(client.status().deaths).toBe(0)
    expect(await kindOf(client.call('adapters'))).toBe('unavailable')
    expect(hosts).toHaveLength(1)
  })
})
