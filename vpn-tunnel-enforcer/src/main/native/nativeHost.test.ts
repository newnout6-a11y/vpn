// AT-00-003 / AT-02-002: an overdue ownership host cannot block/kill unrelated native reads.
import { afterEach, beforeEach, expect, it, vi } from 'vitest'
const clients = vi.hoisted(() => ({ create: vi.fn() }))
vi.mock('./hostClient', () => ({ createHostClient: clients.create }))

beforeEach(() => { vi.resetModules(); clients.create.mockReset(); vi.stubEnv('VPNTE_DISABLE_NATIVE_NET', '0') })
afterEach(() => vi.unstubAllEnvs())

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
