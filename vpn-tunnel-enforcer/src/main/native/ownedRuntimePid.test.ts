// AT-00-002 / AT-02-002: protocol shape and native-read failures must not become fabricated PIDs.
import { beforeEach, expect, it, vi } from 'vitest'
const call = vi.hoisted(() => vi.fn())
vi.mock('./nativeHost', () => ({ callNativeHost: call }))
import { readOwnedRuntimePidNative } from './ownedRuntimePid'

beforeEach(() => { call.mockReset() })
it('requests the exact expected executable through the isolated host with a bounded timeout', async () => {
  call.mockResolvedValue(731)
  expect(await readOwnedRuntimePidNative('C:\\VPNTE\\runtime\\vpnte-sing-box.exe')).toBe(731)
  expect(call).toHaveBeenCalledExactlyOnceWith('owned-runtime-pid', { executable: 'C:\\VPNTE\\runtime\\vpnte-sing-box.exe' }, 1500)
})
it.each([null, undefined, '731', {}, 0, -1, 1.5, NaN, Infinity, 0x100000000])('refuses invalid host PID output %j', async value => {
  call.mockResolvedValue(value)
  await expect(readOwnedRuntimePidNative('C:\\VPNTE\\runtime\\vpnte-sing-box.exe')).rejects.toThrow(/response is invalid/)
})
it('preserves refusal/unavailability so the controller can obtain a fresh PowerShell proof', async () => {
  const error = new Error('native read refused'); call.mockRejectedValue(error)
  await expect(readOwnedRuntimePidNative('C:\\VPNTE\\runtime\\vpnte-sing-box.exe')).rejects.toBe(error)
})
