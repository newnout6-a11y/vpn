// AT-02-001/005, AT-03-007/012: only a complete boolean reply may prove presence/absence.
import { callNativeHost } from './nativeHost'

export async function readOwnedRuntimeStateNative(runtimeDir: string): Promise<boolean> {
  const running = await callNativeHost<unknown>('owned-runtime-state', { runtimeDir })
  if (typeof running !== 'boolean') throw new Error('Native owned runtime state response is invalid')
  return running
}
