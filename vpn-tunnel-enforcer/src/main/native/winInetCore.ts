// WinINet change notification via koffi. Runs INSIDE the native-read host (a utility process), never in main:
// see hostProtocol.ts. A genuine `false` is a WinInetCallError; any other error means koffi is unusable.
const INTERNET_OPTION_SETTINGS_CHANGED = 39
const INTERNET_OPTION_REFRESH = 37

/** A genuine `false` from WinINet: authoritative, must NOT be retried through PowerShell. */
export class WinInetCallError extends Error {
  constructor(message: string) { super(message); this.name = 'WinInetCallError' }
}

type InternetSetOptionW = (handle: null, option: number, buffer: null, length: number) => boolean
let cached: Promise<InternetSetOptionW> | null = null

async function loadInternetSetOption(): Promise<InternetSetOptionW> {
  const mod = await import('koffi')
  // koffi is CJS: interop may expose it as `default` or as the namespace itself. Loosely typed on purpose
  // (the string-based prototype form is not covered by koffi's overloads).
  type KoffiLike = { load(name: string): { func(...args: unknown[]): unknown } }
  const koffi = ((mod as unknown as { default?: KoffiLike }).default ?? mod) as unknown as KoffiLike
  const lib = koffi.load('wininet.dll')
  return lib.func('InternetSetOptionW', 'bool', ['void*', 'uint32', 'void*', 'uint32'], '__stdcall') as InternetSetOptionW
}

/** Lazy-loads koffi on first use; a failed load is not cached so the next call retries. */
function getInternetSetOption(): Promise<InternetSetOptionW> {
  if (!cached) cached = loadInternetSetOption().catch(error => { cached = null; throw error })
  return cached
}

/** Throws WinInetCallError if WinINet returns false; any other error means koffi is unusable (caller falls back). */
export async function notifyWinInetInProcess(): Promise<void> {
  if (process.platform !== 'win32') throw new Error('WinINet notification is only available on Windows')
  const internetSetOption = await getInternetSetOption()
  if (!internetSetOption(null, INTERNET_OPTION_SETTINGS_CHANGED, null, 0)) throw new WinInetCallError('WinINet settings notification failed')
  if (!internetSetOption(null, INTERNET_OPTION_REFRESH, null, 0)) throw new WinInetCallError('WinINet refresh failed')
}

/** Test seam: forget the cached binding. */
export function resetWinInetNativeForTests(): void { cached = null }
