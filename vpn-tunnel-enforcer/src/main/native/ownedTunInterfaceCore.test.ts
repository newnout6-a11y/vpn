// AT-00-003 / AT-02-002 / AT-06-003: full fresh ownership, no alias/address-only success.
import { beforeEach, expect, it, vi, type Mock } from 'vitest'
const reads = vi.hoisted(() => ({ adapters: vi.fn(), configs: vi.fn() }))
const getValue = vi.hoisted(() => vi.fn())
vi.mock('./ipHelperReads', () => ({ readRawAdapters: reads.adapters, readRawIfConfigs: reads.configs }))
import { createRegistryReader, readOwnedTunIndexInProcess } from './ownedTunInterfaceCore'

const guid = '{11111111-2222-3333-4444-555555555555}', alias = 'Ethernet 5'
const pnp = `SWD\\Wintun\\${guid}`, driver = '{4d36e972-e325-11ce-bfc1-08002be10318}\\0015'
let adapter: Record<string, unknown>, address: Record<string, unknown>, registry: Mock<(key: string, name: string) => string>
beforeEach(() => {
  reads.adapters.mockReset(); reads.configs.mockReset()
  getValue.mockReset()
  adapter = { ifIndex: 7, alias, guid, operStatus: 1 }
  address = { family: 4, address: '192.168.250.253', prefixLength: 30 }
  reads.adapters.mockImplementation(() => [adapter])
  reads.configs.mockImplementation(() => [{ ifIndex: 7, unicast: [address] }])
  registry = vi.fn((key: string, name: string) => {
    if (name === 'PnpInstanceID') { expect(key).toContain(`\\${guid}\\Connection`); return pnp }
    if (name === 'Driver') { expect(key).toBe(`SYSTEM\\CurrentControlSet\\Enum\\${pnp}`); return driver }
    expect(key).toBe(`SYSTEM\\CurrentControlSet\\Control\\Class\\${driver}`)
    if (name === 'NetCfgInstanceId') return guid
    if (name === 'DriverDesc') return 'Wintun Userspace Tunnel'
    throw new Error('unexpected registry read')
  })
})
const run = () => readOwnedTunIndexInProcess(alias, guid, registry)

it('links fresh up GUID/alias, PnP device, driver and exact /30 address', () => {
  expect(run()).toBe(7)
  expect(reads.adapters).toHaveBeenCalledExactlyOnceWith(false)
  expect(reads.configs).toHaveBeenCalledOnce()
  expect(registry.mock.calls.map(call => call[1])).toEqual(['PnpInstanceID', 'Driver', 'NetCfgInstanceId', 'DriverDesc'])
  adapter.operStatus = 2
  expect(run()).toBeNull() // never cache the first proof
})
it('compares GUID/alias without case sensitivity or optional outer braces', () => {
  adapter.alias = 'ETHERNET 5'; adapter.guid = guid.toUpperCase()
  expect(readOwnedTunIndexInProcess(alias, guid.slice(1, -1), registry)).toBe(7)
})
it.each(['down', 'guid', 'alias', 'missing', 'ambiguous', 'pnp', 'driver-guid', 'driver-name', 'address', 'prefix', 'duplicate-address'])('refuses %s without success', scenario => {
  if (scenario === 'down') adapter.operStatus = 2
  if (scenario === 'guid') adapter.guid = '{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}'
  if (scenario === 'alias') adapter.alias = 'Ethernet 6'
  if (scenario === 'missing') reads.adapters.mockReturnValue([])
  if (scenario === 'ambiguous') reads.adapters.mockReturnValue([adapter, adapter])
  if (scenario === 'pnp') registry.mockImplementation(() => 'SWD\\Foreign\\device')
  if (scenario === 'driver-guid' || scenario === 'driver-name') {
    const valid = registry.getMockImplementation()!
    registry.mockImplementation((key, name) => name === (scenario === 'driver-guid' ? 'NetCfgInstanceId' : 'DriverDesc') ? 'foreign' : valid(key, name))
  }
  if (scenario === 'address') address.address = '192.168.1.1'
  if (scenario === 'prefix') address.prefixLength = 24
  if (scenario === 'duplicate-address') reads.configs.mockReturnValue([{ ifIndex: 7, unicast: [address, address] }])
  expect(run()).toBeNull()
})
it.each(['adapters', 'configs', 'registry', 'driver-key', 'missing-prefix', 'missing-config', 'duplicate-config', 'bad-index'])('throws for incomplete %s evidence so the caller can fall back', scenario => {
  if (scenario === 'adapters') reads.adapters.mockImplementation(() => { throw new Error('unavailable') })
  if (scenario === 'configs') reads.configs.mockImplementation(() => { throw new Error('unavailable') })
  if (scenario === 'registry') registry.mockImplementation(() => { throw new Error('access denied') })
  if (scenario === 'driver-key') registry.mockImplementation((_key, name) => name === 'Driver' ? '..\\foreign' : pnp)
  if (scenario === 'missing-prefix') delete address.prefixLength
  if (scenario === 'missing-config') reads.configs.mockReturnValue([])
  if (scenario === 'duplicate-config') reads.configs.mockReturnValue([{ ifIndex: 7 }, { ifIndex: 7 }])
  if (scenario === 'bad-index') adapter.ifIndex = 0
  expect(run).toThrow()
})
it.each(['WintunX', 'WintunЯ', 'Wintun1', 'Wintun_'])('rejects a driver name with no word boundary: %s', description => {
  const valid = registry.getMockImplementation()!
  registry.mockImplementation((key, name) => name === 'DriverDesc' ? description : valid(key, name))
  expect(run()).toBeNull()
})
it.each([['', guid], [alias, 'invalid'], [null, guid], [alias, null]])('validates arguments before reads (%s, %s)', (name, id) => {
  expect(() => readOwnedTunIndexInProcess(name as string, id as string, registry)).toThrow(/invalid/)
  expect(reads.adapters).not.toHaveBeenCalled()
})
it('uses bounded 64-bit REG_SZ reads for the complete device-to-driver chain', () => {
  getValue.mockImplementation((root, key, name, flags, type, data, size) => {
    expect(root).toBe(-2147483646n); expect(flags).toBe(0x10002); expect(type).toBeNull()
    expect(size).toEqual([8192])
    const bytes = Buffer.from(registry(key, name) + '\0', 'utf16le')
    bytes.copy(data); size[0] = bytes.length
    return 0
  })
  expect(readOwnedTunIndexInProcess(alias, guid, createRegistryReader(getValue))).toBe(7)
  expect(getValue).toHaveBeenCalledTimes(4)
})
it.each(['absent', 'denied', 'growing', 'odd-size', 'oversized', 'empty', 'unterminated', 'embedded-nul'])('rejects incomplete native registry %s results', scenario => {
  getValue.mockImplementation((_root, _key, _name, _flags, _type, data, size) => {
    const bytes = Buffer.from('SWD\\Wintun\\fixture\0', 'utf16le')
    bytes.copy(data); size[0] = bytes.length
    if (scenario === 'absent') return 2
    if (scenario === 'denied') return 5
    if (scenario === 'growing') return 234
    if (scenario === 'odd-size') size[0]--
    if (scenario === 'oversized') size[0] = 8194
    if (scenario === 'empty') size[0] = 2
    if (scenario === 'unterminated') data.writeUInt16LE(88, size[0] - 2)
    if (scenario === 'embedded-nul') data.writeUInt16LE(0, 4)
    return 0
  })
  expect(() => readOwnedTunIndexInProcess(alias, guid, createRegistryReader(getValue))).toThrow(/registry string/)
})
