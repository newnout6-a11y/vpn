// AT-06-003 / AT-02-002: selected routes may differ; partial or malformed evidence is refused.
import { expect, it, vi } from 'vitest'
import { assertSelectedRouteLayout, readSelectedIpv4InterfacesInProcess, type BestRouteQuery } from './selectedRouteInterfacesCore'

it('checks the compiler layout before GetBestRoute2 can write a raw buffer', () => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const koffi = require('koffi')
  assertSelectedRouteLayout(koffi)
  assertSelectedRouteLayout(koffi) // A refused/retried binding does not redeclare a named type.
  expect(() => assertSelectedRouteLayout({ ...koffi, sizeof: () => 1 })).toThrow(/unsupported MIB_IPFORWARD_ROW2 layout/)
  expect(() => assertSelectedRouteLayout({ ...koffi, offsetof: () => 999 })).toThrow(/unsupported MIB_IPFORWARD_ROW2 layout/)
})

function fixture() {
  let index = 6
  const query = vi.fn<BestRouteQuery>((_destination, route, source) => {
    route.writeUInt32LE(++index, 8)
    route.writeUInt16LE(2, 12)
    source.writeUInt16LE(2)
    return 0
  })
  return { query, read: () => readSelectedIpv4InterfacesInProcess(query) }
}

it('asks for the same three public destinations and returns each Windows-selected interface', () => {
  const f = fixture()
  expect(f.read()).toEqual([7, 8, 9])
  expect(f.query.mock.calls.map(([destination]) => [...destination.subarray(4, 8)]))
    .toEqual([[1, 1, 1, 1], [8, 8, 8, 8], [208, 67, 222, 222]])
  for (const [destination, route, source] of f.query.mock.calls) {
    expect(destination.length).toBe(28)
    expect(destination.readUInt16LE(0)).toBe(2)
    expect(destination.subarray(2, 4)).toEqual(Buffer.alloc(2))
    expect(destination.subarray(8)).toEqual(Buffer.alloc(20))
    expect(route.length).toBe(104)
    expect(source.length).toBe(28)
  }
})

it.each(['API failure', 'zero index', 'wrong route family', 'wrong source family'])('refuses %s after an earlier successful lookup', kind => {
  const f = fixture(), normal = f.query.getMockImplementation()!
  let count = 0
  f.query.mockImplementation((destination, route, source) => {
    const rc = normal(destination, route, source)
    if (++count !== 2) return rc
    if (kind === 'API failure') return 1231
    if (kind === 'zero index') route.writeUInt32LE(0, 8)
    if (kind === 'wrong route family') route.writeUInt16LE(23, 12)
    if (kind === 'wrong source family') source.writeUInt16LE(23)
    return rc
  })
  expect(f.read).toThrow(/complete IPv4 route selection unavailable/)
  expect(f.query).toHaveBeenCalledTimes(2)
})

it('does not turn a binding exception into an empty or partial answer', () => {
  const f = fixture()
  f.query.mockImplementationOnce(() => { throw new Error('binding unavailable') })
  expect(f.read).toThrow('binding unavailable')
})

it('refuses FFI in the Electron main process', () => {
  const descriptor = Object.getOwnPropertyDescriptor(process, 'type')
  Object.defineProperty(process, 'type', { configurable: true, value: 'browser' })
  try { expect(() => readSelectedIpv4InterfacesInProcess()).toThrow(/must not run in the Electron main/) }
  finally {
    if (descriptor) Object.defineProperty(process, 'type', descriptor)
    else Reflect.deleteProperty(process, 'type')
  }
})
