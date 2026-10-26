// AT-00-003 / AT-02-002: an overdue ownership host cannot block/kill unrelated native reads.
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import type { HostProcess } from './hostClient'
import type { HostRequest } from './hostProtocol'
const clients = vi.hoisted(() => ({ create: vi.fn() }))
vi.mock('./hostClient', () => ({ createHostClient: clients.create }))

beforeEach(() => { vi.resetModules(); clients.create.mockReset(); vi.stubEnv('VPNTE_DISABLE_NATIVE_NET', '0') })
afterEach(() => { vi.unstubAllEnvs(); vi.useRealTimers() })

it.runIf(process.platform === 'win32')('isolates pending ownership and its timeout from the ordinary native host', async () => {
  let refuse!: (error: Error) => void
  const ownership = { call: vi.fn((_op: string, _args?: unknown, _timeout?: number) => new Promise((_resolve, reject) => { refuse = reject })), shutdown: vi.fn() }
  const ordinary = { call: vi.fn(async (_op: string, _args?: unknown, _timeout?: number) => [7, 7, 7]), shutdown: vi.fn() }
  clients.create.mockReturnValueOnce(ordinary).mockReturnValueOnce(ownership)
  const { callNativeHost, shutdownNativeHost } = await import('./nativeHost')
  expect(await callNativeHost('selected-route-interfaces')).toEqual([7, 7, 7])
  const pending = callNativeHost('owned-tun-index', { alias: 'Ethernet 5', guid: 'guid' }).catch(error => error.message)
  expect(await callNativeHost('selected-route-interfaces')).toEqual([7, 7, 7])
  refuse(new Error('ownership host timed out'))
  expect(await pending).toBe('ownership host timed out')
  expect(await callNativeHost('adapters')).toEqual([7, 7, 7])
  expect(ordinary.call.mock.calls.map(call => call[0])).toEqual(['selected-route-interfaces', 'selected-route-interfaces', 'adapters'])
  expect(ownership.call).toHaveBeenCalledExactlyOnceWith('owned-tun-index', { alias: 'Ethernet 5', guid: 'guid' }, undefined)
  expect(clients.create).toHaveBeenCalledTimes(2)
  expect(ordinary.shutdown).not.toHaveBeenCalled()
  shutdownNativeHost()
  expect(ordinary.shutdown).toHaveBeenCalledOnce()
  expect(ownership.shutdown).toHaveBeenCalledOnce()
  await expect(callNativeHost('owned-tun-index')).rejects.toThrow(/stopped/)
  await expect(callNativeHost('adapters')).rejects.toThrow(/stopped/)
  expect(clients.create).toHaveBeenCalledTimes(2)
})

// AT-07-002 / AT-08-007: use real client deadlines, with no native/system calls.
it.runIf(process.platform === 'win32')('isolates traffic deadlines from pending inventory reads in both directions', async () => {
  const { createHostClient } = await vi.importActual<typeof import('./hostClient')>('./hostClient')
  class FakeHost implements HostProcess {
    sent: HostRequest[] = []
    killed = false
    message?: (value: unknown) => void
    postMessage(value: unknown) { this.sent.push(value as HostRequest) }
    on(event: 'message' | 'exit', listener: never) { if (event === 'message') this.message = listener; return this }
    kill() { this.killed = true; return true }
    reply(value: unknown) { this.message?.({ id: this.sent.at(-1)!.id, ok: true, value }) }
  }
  const ordinaryHosts: FakeHost[] = [], trafficHosts: FakeHost[] = []
  const makeClient = (hosts: FakeHost[]) => createHostClient({ fork: () => { const host = new FakeHost(); hosts.push(host); return host } })
  clients.create.mockReturnValueOnce(makeClient(ordinaryHosts)).mockReturnValueOnce(makeClient(trafficHosts))
  const { callNativeHost, shutdownNativeHost } = await import('./nativeHost')
  vi.useFakeTimers()
  const inventory = callNativeHost('physical-snapshot', undefined, 5000)
  const sample = callNativeHost('traffic-counters', { adapterName: 'VPNTE' }, 1500).catch(error => error.kind)
  await vi.advanceTimersByTimeAsync(1500)
  expect(await sample).toBe('unavailable')
  expect(trafficHosts[0].killed).toBe(true)
  expect(ordinaryHosts[0].killed).toBe(false)
  ordinaryHosts[0].reply({ selected: 7 })
  await expect(inventory).resolves.toEqual({ selected: 7 })

  const nextSample = callNativeHost('traffic-counters', { adapterName: 'VPNTE' }, 5000)
  const nextInventory = callNativeHost('adapters', undefined, 1500).catch(error => error.kind)
  await vi.advanceTimersByTimeAsync(1500)
  expect(await nextInventory).toBe('unavailable')
  expect(ordinaryHosts[0].killed).toBe(true)
  expect(trafficHosts[1].killed).toBe(false)
  trafficHosts[1].reply({ found: true })
  await expect(nextSample).resolves.toEqual({ found: true })
  expect(clients.create).toHaveBeenCalledTimes(2)
  shutdownNativeHost()
  expect(trafficHosts[1].killed).toBe(true)
  await expect(callNativeHost('traffic-counters')).rejects.toThrow(/stopped/)
})
