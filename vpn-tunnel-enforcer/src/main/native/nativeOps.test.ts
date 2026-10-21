// AT-07-002 / AT-12-007: what the native-read host accepts. Arguments are validated before any koffi call, and the
// crash-injection op does not exist in the production host.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { runNativeOp } from './nativeOps'
import { isHostResponse, NativeHostError } from './hostProtocol'

const platform = Object.getOwnPropertyDescriptor(process, 'platform')!
beforeEach(() => { Object.defineProperty(process, 'platform', { value: 'win32' }) })
afterEach(() => {
  Object.defineProperty(process, 'platform', platform)
})

describe('native host operations', () => {
  it('does not implement the test-only crash op: the production host rejects it as unknown', async () => {
    const abort = vi.spyOn(process, 'abort').mockImplementation((() => { throw new Error('process.abort was called') }) as () => never)
    await expect(runNativeOp('abort-for-test', undefined)).rejects.toThrow(/unknown native op/)
    expect(abort).not.toHaveBeenCalled()
    abort.mockRestore()
  })

  it.each([
    ['routes', { prefixes: 'not-an-array' }, /prefixes/],
    ['routes', { prefixes: [1, 2] }, /prefixes/],
    ['routes', undefined, /prefixes/],
    ['tunnels', {}, /alias and prefix/],
    ['tunnels', { vpnteAlias: 'VPNTE' }, /alias and prefix/],
    ['physical-snapshot', { profiles: 'x' }, /pairs/],
    ['physical-snapshot', { profiles: [['17', ['Office']]] }, /malformed/],
    ['physical-snapshot', { profiles: [[17, [1]]] }, /array of strings/],
    ['physical-snapshot', { profiles: [], retainedGuids: 'invalid' }, /array of strings/],
    ['physical-snapshot', { profiles: [], retainedGuids: ["'; throw 'injected'"] }, /Invalid retained adapter GUID/],
    ['owned-runtime-pid', {}, /executable path is required/],
    ['owned-runtime-pid', { executable: 'relative.exe' }, /invalid executable path/],
    ['owned-runtime-pid', { executable: 'C:\\runtime\\core.dll' }, /invalid executable path/]
  ] as const)('rejects bad arguments for %s before touching koffi', async (op, args, message) => {
    await expect(runNativeOp(op, args)).rejects.toThrow(message)
  })

  it('rejects an unknown operation', async () => {
    await expect(runNativeOp('nope' as never, undefined)).rejects.toThrow(/unknown native op/)
  })

  it('refuses everything off Windows', async () => {
    Object.defineProperty(process, 'platform', { value: 'linux' })
    await expect(runNativeOp('adapters', undefined)).rejects.toThrow(/Windows-only/)
  })
})

describe('host protocol', () => {
  it('accepts only well-formed responses', () => {
    expect(isHostResponse({ id: 1, ok: true, value: [] })).toBe(true)
    expect(isHostResponse({ id: 1, ok: false, kind: 'read-refused', message: 'x' })).toBe(true)
    expect(isHostResponse({ id: 1, ok: false, kind: 'wininet-false', message: 'x' })).toBe(true)
    expect(isHostResponse({ id: 1, ok: false, kind: 'unavailable', message: 'x' })).toBe(false) // only the client produces this
    expect(isHostResponse({ id: '1', ok: true, value: 1 })).toBe(false)
    expect(isHostResponse({ id: 1, ok: true })).toBe(false)
    expect(isHostResponse(null)).toBe(false)
  })

  it('NativeHostError carries its kind', () => {
    expect(new NativeHostError('unavailable', 'x').kind).toBe('unavailable')
  })
})
