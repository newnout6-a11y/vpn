// AT-02-001/005, AT-03-007/012: shared host timeout and strict absence receipts.
import { beforeEach, expect, it, vi } from 'vitest'
const call = vi.hoisted(() => vi.fn())
vi.mock('./nativeHost', () => ({ callNativeHost: call }))
import { readOwnedRuntimeStateNative } from './ownedRuntimeState'

beforeEach(() => { call.mockReset() })
it.each([true, false])('reads fresh presence=%s using the normal shared host deadline', async running => {
  call.mockResolvedValueOnce(running)
  expect(await readOwnedRuntimeStateNative('C:\\runtime')).toBe(running)
  expect(call).toHaveBeenCalledExactlyOnceWith('owned-runtime-state', { runtimeDir: 'C:\\runtime' })
})
it.each([undefined, null, 0, 1, '', 'false', 'true', {}, []].map(value => ({ value })))('rejects malformed state $value', async ({ value }) => {
  call.mockResolvedValue(value)
  await expect(readOwnedRuntimeStateNative('C:\\runtime')).rejects.toThrow(/state response is invalid/)
})
it('preserves native refusal for the complete independent fallback', async () => {
  const error = new Error('unknown path'); call.mockRejectedValue(error)
  await expect(readOwnedRuntimeStateNative('C:\\runtime')).rejects.toBe(error)
})
