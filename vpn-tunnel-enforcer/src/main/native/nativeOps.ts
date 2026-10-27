// AT-07-002 / AT-12-007: the operations the native-read host runs. This module and everything it imports must stay
// free of Electron main-process code: it is bundled into the utility process (nativeHostWorker.ts).
//
// Every operation returns data in the same shape the corresponding PowerShell script produced, or THROWS. A throw
// means "no answer"; callers fall back to PowerShell and never treat it as an empty (= "clean") result.
import { readRawAdapters, readRawIfConfigs, readRawRoutes, readTrafficCounters } from './ipHelperReads'
import { validateTrafficAdapterName } from './trafficCounters'
import { toActiveTunnels, toAdapterRows, toIpConfigRows, toPhysicalIpv4Sources, toRouteRows } from './ipHelperTransforms'
import { createKoffiSource, snapshotFromSource } from './physicalAdapterCore'
import { notifyWinInetInProcess } from './winInetCore'
import type { HostOp } from './hostProtocol'
import { normalizeRetainedAdapterGuids } from '../physicalAdapterSnapshot'
import { readOwnedRuntimePidInProcess, readOwnedRuntimeStateInProcess } from './ownedRuntimePidCore'
import { readSelectedIpv4InterfacesInProcess } from './selectedRouteInterfacesCore'
import { readOwnedTunIndexInProcess } from './ownedTunInterfaceCore'

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
    case 'traffic-counters':
      if (!args || typeof args !== 'object' || Array.isArray(args) || Object.keys(a).length !== 1) throw new Error('traffic counters: adapter name is required')
      return readTrafficCounters(validateTrafficAdapterName(a.adapterName))
    case 'adapters':
      return toAdapterRows(readRawAdapters())
    case 'ipconfig':
      return toIpConfigRows(readRawAdapters(), readRawIfConfigs())
    case 'routes': {
      // Validate before any native read: call arguments are evaluated left to right.
      const prefixes = stringArray(a.prefixes, 'routes prefixes')
      return toRouteRows(readRawAdapters(), [...readRawRoutes(4), ...readRawRoutes(6)], prefixes)
    }
    case 'physical-sources':
      return toPhysicalIpv4Sources(readRawAdapters(), readRawIfConfigs())
    case 'tunnels': {
      if (typeof a.vpnteAlias !== 'string' || typeof a.vpnteIpv4Prefix !== 'string') throw new Error('tunnels: alias and prefix are required')
      return toActiveTunnels(readRawAdapters(), readRawIfConfigs(), { vpnteAlias: a.vpnteAlias, vpnteIpv4Prefix: a.vpnteIpv4Prefix })
    }
    case 'physical-snapshot': {
      const retained = normalizeRetainedAdapterGuids(stringArray(a.retainedGuids ?? [], 'retained GUIDs'))
      return snapshotFromSource(createKoffiSource(profileMap(a.profiles)), retained)
    }
    case 'owned-runtime-pid':
      if (typeof a.executable !== 'string') throw new Error('runtime PID: executable path is required')
      return readOwnedRuntimePidInProcess(a.executable)
    case 'selected-route-interfaces':
      return readSelectedIpv4InterfacesInProcess()
    case 'owned-tun-index':
      if (typeof a.alias !== 'string' || typeof a.guid !== 'string') throw new Error('TUN ownership: alias and GUID are required')
      return readOwnedTunIndexInProcess(a.alias, a.guid)
    case 'owned-runtime-state':
      if (typeof a.runtimeDir !== 'string') throw new Error('runtime status: runtime directory is required')
      return readOwnedRuntimeStateInProcess(a.runtimeDir)
    case 'wininet':
      await notifyWinInetInProcess()
      return true
    default:
      throw new Error(`unknown native op ${String(op)}`)
  }
}
