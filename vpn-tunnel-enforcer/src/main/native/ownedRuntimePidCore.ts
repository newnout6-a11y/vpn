// AT-00-002 / AT-02-002/009: fresh PID + exact executable ownership, in the isolated native host.
import { win32 } from 'node:path'
import { assertKoffiAllowedHere, defineStruct } from './koffiTypes'

type Handle = number | bigint
export interface ProcessReadApi {
  snapshot(flags: number, pid: number): Handle
  first(handle: Handle, entry: Buffer): boolean
  next(handle: Handle, entry: Buffer): boolean
  open(access: number, inherit: boolean, pid: number): Handle
  image(handle: Handle, flags: number, path: Buffer, length: number[]): boolean
  compare(a: string, alen: number, b: string, blen: number, ignoreCase: boolean): number
  close(handle: Handle): boolean
  error(): number
}

const ENTRY_SIZE = 568, NAME_OFFSET = 44, NAME_BYTES = 520, PATH_CHARS = 32768
const invalidHandle = (handle: Handle) => [0n, -1n, 0xffffffffffffffffn].includes(BigInt(handle))
let cached: ProcessReadApi | undefined

function getApi(): ProcessReadApi {
  assertKoffiAllowedHere('runtime PID')
  if (process.platform !== 'win32' || !['x64', 'arm64'].includes(process.arch)) throw new Error('runtime PID: unsupported platform')
  if (cached) return cached
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const koffi = require('koffi'), kernel = koffi.load('kernel32.dll')
  const entry = defineStruct(koffi, 'VPNTE_PROCESSENTRY32W', {
    dwSize: 'uint32_t', cntUsage: 'uint32_t', th32ProcessID: 'uint32_t', th32DefaultHeapID: 'uintptr_t',
    th32ModuleID: 'uint32_t', cntThreads: 'uint32_t', th32ParentProcessID: 'uint32_t',
    pcPriClassBase: 'int32_t', dwFlags: 'uint32_t', szExeFile: koffi.array('uint16_t', 260)
  })
  if (koffi.sizeof(entry) !== ENTRY_SIZE || koffi.offsetof(entry, 'th32ProcessID') !== 8 || koffi.offsetof(entry, 'szExeFile') !== NAME_OFFSET) {
    throw new Error('runtime PID: unexpected PROCESSENTRY32W layout')
  }
  cached = {
    snapshot: kernel.func('intptr_t __stdcall CreateToolhelp32Snapshot(uint32_t flags, uint32_t pid)'),
    first: kernel.func('bool __stdcall Process32FirstW(intptr_t handle, _Inout_ uint8_t *entry)'),
    next: kernel.func('bool __stdcall Process32NextW(intptr_t handle, _Inout_ uint8_t *entry)'),
    open: kernel.func('intptr_t __stdcall OpenProcess(uint32_t access, bool inherit, uint32_t pid)'),
    image: kernel.func('bool __stdcall QueryFullProcessImageNameW(intptr_t handle, uint32_t flags, _Out_ uint8_t *path, _Inout_ uint32_t *length)'),
    compare: kernel.func('int32_t __stdcall CompareStringOrdinal(str16 a, int32_t alen, str16 b, int32_t blen, bool ignoreCase)'),
    close: kernel.func('bool __stdcall CloseHandle(intptr_t handle)'),
    error: kernel.func('uint32_t __stdcall GetLastError()')
  }
  return cached!
}

/** The explicit API is a test seam. Production code loads FFI only inside the utility process. */
export function readOwnedRuntimePidInProcess(executable: string, supplied?: ProcessReadApi): number {
  if (typeof executable !== 'string' || executable.length >= PATH_CHARS || !win32.isAbsolute(executable) || executable.includes('\0') || !/\.exe$/i.test(executable)) {
    throw new Error('runtime PID: invalid executable path')
  }
  const api = supplied ?? getApi(), name = win32.basename(executable)
  const equal = (a: string, b: string) => {
    const result = api.compare(a, a.length, b, b.length, true)
    if (![1, 2, 3].includes(result)) throw new Error('runtime PID: ordinal comparison failed')
    return result === 2 // CSTR_EQUAL
  }
  const close = (handle: Handle) => { if (!api.close(handle)) throw new Error('runtime PID: handle close failed') }
  const snapshot = api.snapshot(2, 0) // TH32CS_SNAPPROCESS
  if (invalidHandle(snapshot)) throw new Error('runtime PID: snapshot unavailable')
  try {
    const entry = Buffer.alloc(ENTRY_SIZE), seen = new Set<number>()
    entry.writeUInt32LE(ENTRY_SIZE)
    let more = api.first(snapshot, entry), pid = 0
    for (let count = 0; ; count++) {
      if (!more) {
        if (api.error() !== 18) throw new Error('runtime PID: incomplete process enumeration') // ERROR_NO_MORE_FILES
        break
      }
      if (count >= 100000 || entry.readUInt32LE(0) !== ENTRY_SIZE) throw new Error('runtime PID: malformed process entry')
      const names = entry.subarray(NAME_OFFSET, NAME_OFFSET + NAME_BYTES).toString('utf16le'), end = names.indexOf('\0')
      if (end < 0) throw new Error('runtime PID: unterminated process name')
      if (equal(names.slice(0, end), name)) {
        const candidate = entry.readUInt32LE(8)
        if (!candidate || seen.has(candidate)) throw new Error('runtime PID: invalid or duplicate process identity')
        seen.add(candidate)
        const processHandle = api.open(0x1000, false, candidate) // PROCESS_QUERY_LIMITED_INFORMATION
        if (invalidHandle(processHandle)) throw new Error('runtime PID: executable path unavailable')
        try {
          const buffer = Buffer.alloc(PATH_CHARS * 2), length = [PATH_CHARS]
          if (!api.image(processHandle, 0, buffer, length) || !Number.isInteger(length[0]) || length[0] <= 0 || length[0] >= PATH_CHARS) {
            throw new Error('runtime PID: executable path unavailable')
          }
          const path = buffer.toString('utf16le', 0, length[0] * 2)
          if (path.includes('\0')) throw new Error('runtime PID: invalid executable path response')
          if (equal(path, executable)) {
            if (pid) throw new Error('runtime PID: exactly one owned process required')
            pid = candidate
          }
        } finally { close(processHandle) }
      }
      more = api.next(snapshot, entry)
    }
    if (!pid) throw new Error('runtime PID: exactly one owned process required')
    return pid
  } finally { close(snapshot) }
}
