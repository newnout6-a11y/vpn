// AT-06-003 / AT-00-003: default shared-host deadline and complete uint32 interface replies.
import { beforeEach, expect, it, vi } from 'vitest'
const call = vi.hoisted(() => vi.fn())
vi.mock('./nativeHost', () => ({ callNativeHost: call }))
import { nativeSelectedIpv4Interfaces } from './selectedRouteInterfaces'

beforeEach(() => { call.mockReset() })
it('requests unrestricted route selection using the shared host deadline', async () => {
  call.mockResolvedValue([7, 8, 7])
  expect(await nativeSelectedIpv4Interfaces()).toEqual([7, 8, 7])
  expect(call).toHaveBeenCalledExactlyOnceWith('selected-route-interfaces')
})
it.each([null, {}, [], [7, 7], [7, 7, 7, 7], ['7', 7, 7], [0, 7, 7], [-1, 7, 7],
  [1.5, 7, 7], [NaN, 7, 7], [Infinity, 7, 7], [0x100000000, 7, 7], Array(3), [7, , 7]].map(indexes => ({ indexes })))('refuses partial or malformed interface replies $indexes', async ({ indexes }) => {
  call.mockResolvedValue(indexes)
  await expect(nativeSelectedIpv4Interfaces()).rejects.toThrow(/response is invalid/)
})
it('preserves native refusal for the controller fallback', async () => {
  const error = new Error('unavailable'); call.mockRejectedValue(error)
  await expect(nativeSelectedIpv4Interfaces()).rejects.toBe(error)
})
