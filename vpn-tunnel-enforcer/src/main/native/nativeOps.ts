// AT-07-002 / AT-12-007: the operations the native-read host runs. This module and everything it imports must stay
// free of Electron main-process code: it is bundled into the utility process (nativeHostWorker.ts).
//
// Every operation returns data in the same shape the corresponding PowerShell script produced, or THROWS. A throw
// means "no answer"; callers fall back to PowerShell and never treat it as an empty (= "clean") result.
import { readRawAdapters, readRawIfConfigs, readRawRoutes } from './ipHelperReads'
import { toActiveTunnels, toAdapterRows, toIpConfigRows, toPhysicalIpv4Sources, toRouteRows } from './ipHelperTransforms'
import { createKoffiSource, snapshotFromSource } from './physicalAdapterCore'
import { notifyWinInetInProcess } from './winInetCore'
import type { HostOp } from './hostProtocol'

function stringArray(value: unknown, what: string): string[] {
  if (!Array.isArray(value) || !value.every(item => typeof item === 'string')) throw new Error(`${what}: expected an array of strings`)
  return value
}

function profileMap(value: unknown): Map<number, string[]> {
  if (!Array.isArray(value)) throw new Error('physical-snapshot: expected an array of [ifIndex, names] pairs')
  const map = new Map<number, string[]>()
  for (const entry of value) {
    if (!Array.isArray(entry) || !Number.isInteger(entry[0])) throw new Error('physical-snapshot: malformed profile entry')
    map.set(entry[0], stringArray(entry[1], 'physical-snapshot profile names'))
  }
  return map
}

export async function runNativeOp(op: HostOp, args: unknown): Promise<unknown> {
  if (process.platform !== 'win32') throw new Error('native network reads are Windows-only')
  const a = (args ?? {}) as Record<string, unknown>
  switch (op) {
    case 'adapters':
      return toAdapterRows(readRawAdapters())
    case 'ipconfig':
      return toIpConfigRows(readRawAdapters(), readRawIfConfigs())
    case 'routes':
      return toRouteRows(readRawAdapters(), [...readRawRoutes(4), ...readRawRoutes(6)], stringArray(a.prefixes, 'routes prefixes'))
    case 'physical-sources':
      return toPhysicalIpv4Sources(readRawAdapters(), readRawIfConfigs())
    case 'tunnels': {
      if (typeof a.vpnteAlias !== 'string' || typeof a.vpnteIpv4Prefix !== 'string') throw new Error('tunnels: alias and prefix are required')
      return toActiveTunnels(readRawAdapters(), readRawIfConfigs(), { vpnteAlias: a.vpnteAlias, vpnteIpv4Prefix: a.vpnteIpv4Prefix })
    }
    case 'physical-snapshot':
      return snapshotFromSource(createKoffiSource(profileMap(a.profiles)))
    case 'wininet':
      await notifyWinInetInProcess()
      return true
    case 'abort-for-test':
      return abortForTest()
    default:
      throw new Error(`unknown native op ${String(op)}`)
  }
}

/**
 * Reproduces the real failure class on purpose (koffi.view over foreign memory is a fatal N-API error under
 * Electron), then aborts regardless. Reachable only when the host is started with VPNTE_NATIVE_HOST_TEST=1.
 */
function abortForTest(): never {
  if (process.env.VPNTE_NATIVE_HOST_TEST !== '1') throw new Error('abort-for-test is not available')
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const koffi = require('koffi')
    koffi.view(koffi.alloc('int32_t', 4), 8)
  } catch { /* fall through to the explicit abort */ }
  process.abort()
}
