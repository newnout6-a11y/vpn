/**
 * AT-07-002 / AT-07-012 / AT-08-007: caller-facing native network reads.
 *
 * Each function returns data in the same shape the corresponding PowerShell
 * script produced, or THROWS. Callers must treat a throw as "native path
 * unavailable" and run their existing PowerShell path - never as an empty
 * (= "clean") answer. `VPNTE_DISABLE_NATIVE_NET=1` forces the PowerShell path.
 */
import { readRawAdapters, readRawIfConfigs, readRawRoutes } from './ipHelperReads'
import {
  toActiveTunnels, toAdapterRows, toIpConfigRows, toPhysicalIpv4Sources, toRouteRows,
  type NativeAdapterRow, type NativeIpConfigRow, type NativePhysicalSource, type NativeRouteRow, type NativeTunnelRow
} from './ipHelperTransforms'

export type { NativeAdapterRow, NativeIpConfigRow, NativePhysicalSource, NativeRouteRow, NativeTunnelRow }

function guard(): void {
  if (process.platform !== 'win32') throw new Error('native network reads are Windows-only')
  if (process.env.VPNTE_DISABLE_NATIVE_NET === '1') throw new Error('native network reads disabled by VPNTE_DISABLE_NATIVE_NET')
}

export function nativePhysicalIpv4Sources(): NativePhysicalSource[] {
  guard()
  return toPhysicalIpv4Sources(readRawAdapters(), readRawIfConfigs())
}

export function nativeActiveTunnels(opts: { vpnteAlias: string; vpnteIpv4Prefix: string }): NativeTunnelRow[] {
  guard()
  return toActiveTunnels(readRawAdapters(), readRawIfConfigs(), opts)
}

export function nativeAdapterRows(): NativeAdapterRow[] {
  guard()
  return toAdapterRows(readRawAdapters())
}

export function nativeIpConfigRows(): NativeIpConfigRow[] {
  guard()
  return toIpConfigRows(readRawAdapters(), readRawIfConfigs())
}

export function nativeRouteRows(prefixes: string[]): NativeRouteRow[] {
  guard()
  return toRouteRows(readRawAdapters(), [...readRawRoutes(4), ...readRawRoutes(6)], prefixes)
}
