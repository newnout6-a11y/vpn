// AT-00-002 / AT-02-002: main never loads FFI; malformed host output is not a PID proof.
import { callNativeHost } from './nativeHost'

export async function readOwnedRuntimePidNative(executable: string): Promise<number> {
  const pid = await callNativeHost<unknown>('owned-runtime-pid', { executable })
  if (typeof pid !== 'number' || !Number.isSafeInteger(pid) || pid <= 0 || pid > 0xffffffff) {
    throw new Error('Native owned runtime PID response is invalid')
  }
  return pid
}
