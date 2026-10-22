// AT-00-003 / AT-02-002 / AT-06-003: fresh equivalent of the CIM TUN ownership read.
import { readRawAdapters, readRawIfConfigs } from './ipHelperReads'
import { assertKoffiAllowedHere } from './koffiTypes'

const NET_CLASS = '{4d36e972-e325-11ce-bfc1-08002be10318}'
type RegistryString = (key: string, name: string) => string
type RegGetValue = (root: bigint, key: string, name: string, flags: number, type: null, data: Buffer, size: number[]) => number
let registryString: RegistryString | undefined

export function createRegistryReader(get: RegGetValue): RegistryString {
  return (key, name) => {
    // Fixed bounded REG_SZ read; absent, growing, malformed or inaccessible = unknown.
    const data = Buffer.alloc(8192), size = [data.length]
    const rc = get(-2147483646n, key, name, 0x2 | 0x10000, null, data, size) // REG_SZ | 64-bit view
    if (rc !== 0 || size[0] < 4 || size[0] > data.length || size[0] % 2 !== 0 || data.readUInt16LE(size[0] - 2) !== 0) {
      throw new Error('TUN ownership: registry string unavailable')
    }
    const value = data.toString('utf16le', 0, size[0] - 2)
    if (value.includes('\0')) throw new Error('TUN ownership: malformed registry string')
    return value
  }
}

function getRegistryReader(): RegistryString {
  assertKoffiAllowedHere('TUN ownership')
  if (process.platform !== 'win32' || !['x64', 'arm64'].includes(process.arch)) throw new Error('TUN ownership: unsupported platform')
  if (registryString) return registryString
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const koffi = require('koffi')
  const get = koffi.load('advapi32.dll').func('int32_t __stdcall RegGetValueW(int64_t root, str16 key, str16 name, uint32_t flags, _Out_ uint32_t *type, _Out_ uint8_t *data, _Inout_ uint32_t *size)')
  registryString = createRegistryReader(get)
  return registryString
}

/** No cached adapter/address/driver data. Missing ownership is null; incomplete evidence throws. */
export function readOwnedTunIndexInProcess(alias: string, guid: string, suppliedRegistry?: RegistryString): number | null {
  if (typeof alias !== 'string' || !alias || alias.includes('\0') || typeof guid !== 'string'
      || !/^\{?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}?$/i.test(guid)) {
    throw new Error('TUN ownership: invalid alias or GUID')
  }
  const canonical = `{${guid.replace(/[{}]/g, '').toLowerCase()}}`
  const matches = readRawAdapters(false).filter(row => row.alias.toLowerCase() === alias.toLowerCase())
  if (matches.length !== 1) return null
  const adapter = matches[0], index = adapter.ifIndex
  if (adapter.guid.toLowerCase() !== canonical || adapter.operStatus !== 1) return null
  if (!Number.isSafeInteger(index) || index <= 0 || index > 0xffffffff) throw new Error('TUN ownership: invalid interface index')
  const read = suppliedRegistry ?? getRegistryReader()
  const pnp = read(`SYSTEM\\CurrentControlSet\\Control\\Network\\${NET_CLASS}\\${canonical}\\Connection`, 'PnpInstanceID')
  if (!/^SWD\\Wintun\\.+/i.test(pnp)) return null
  const driver = read(`SYSTEM\\CurrentControlSet\\Enum\\${pnp}`, 'Driver')
  if (!/^\{4d36e972-e325-11ce-bfc1-08002be10318\}\\\d{4}$/i.test(driver)) throw new Error('TUN ownership: invalid driver key')
  const driverKey = `SYSTEM\\CurrentControlSet\\Control\\Class\\${driver}`
  if (read(driverKey, 'NetCfgInstanceId').toLowerCase() !== canonical) return null
  // .NET's case-insensitive word boundary includes Unicode letters and digits.
  if (!/^Wintun(?![\p{L}\p{N}\p{M}\p{Pc}])/iu.test(read(driverKey, 'DriverDesc'))) return null
  const configs = readRawIfConfigs().filter(row => row.ifIndex === index)
  if (configs.length !== 1) throw new Error('TUN ownership: incomplete address snapshot')
  const addresses = configs[0].unicast.filter(row => row.family === 4 && row.address === '192.168.250.253')
  if (addresses.some(row => row.prefixLength === undefined)) throw new Error('TUN ownership: missing prefix length')
  return addresses.filter(row => row.prefixLength === 30).length === 1 ? index : null
}
