// AT-07-002 / AT-12-007: what the native-read host accepts. Arguments are validated before any koffi call, and the
// test-only abort is unreachable unless the host was started with VPNTE_NATIVE_HOST_TEST=1.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { runNativeOp } from './nativeOps'
import { isHostResponse, NativeHostError } from './hostProtocol'

const platform = Object.getOwnPropertyDescriptor(process, 'platform')!
const savedFlag = process.env.VPNTE_NATIVE_HOST_TEST
beforeEach(() => { Object.defineProperty(process, 'platform', { value: 'win32' }); delete process.env.VPNTE_NATIVE_HOST_TEST })
afterEach(() => {
  Object.defineProperty(process, 'platform', platform)
  if (savedFlag === undefined) delete process.env.VPNTE_NATIVE_HOST_TEST; else process.env.VPNTE_NATIVE_HOST_TEST = savedFlag
})

describe('native host operations', () => {
  it('refuses the test-only abort unless the host runs in test mode (and does not abort)', async () => {
    const abort = vi.spyOn(process, 'abort').mockImplementation((() => { throw new Error('process.abort was called') }) as () => never)
    await expect(runNativeOp('abort-for-test', undefined)).rejects.toThrow('abort-for-test is not available')
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
    ['physical-snapshot', { profiles: [[17, [1]]] }, /array of strings/]
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
