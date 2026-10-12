// AT-03-003 / AT-03-007: WinINet change notification through the native-read host.
// Fail closed: a crash or any other host problem rejects with a NativeHostError and the caller uses PowerShell.
// A genuine `false` from WinINet is authoritative: it is re-thrown as WinInetCallError and never retried.
import { callNativeHost } from './nativeHost'
import { NativeHostError } from './hostProtocol'
import { WinInetCallError } from './winInetCore'

export { WinInetCallError }

export async function notifyWinInetSettingsChangedNative(): Promise<void> {
  try {
    await callNativeHost('wininet')
  } catch (error) {
    if (error instanceof NativeHostError && error.kind === 'wininet-false') throw new WinInetCallError(error.message)
    throw error
  }
}
