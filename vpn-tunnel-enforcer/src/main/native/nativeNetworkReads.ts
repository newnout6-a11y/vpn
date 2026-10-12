/**
 * AT-07-002 / AT-07-012 / AT-08-007: caller-facing native network reads.
 *
 * Each function resolves with data in the same shape the corresponding PowerShell script produced, or REJECTS.
 * The reads run in a separate utility process (nativeHost.ts), so even a fatal koffi error cannot take the
 * application down. Callers must treat a rejection as "native path unavailable" and run their existing
 * PowerShell path - never as an empty (= "clean") answer. `VPNTE_DISABLE_NATIVE_NET=1` forces PowerShell.
 */
import { callNativeHost } from './nativeHost'
import type { NativeAdapterRow, NativeIpConfigRow, NativePhysicalSource, NativeRouteRow, NativeTunnelRow } from './ipHelperTransforms'

export type { NativeAdapterRow, NativeIpConfigRow, NativePhysicalSource, NativeRouteRow, NativeTunnelRow }

export function nativePhysicalIpv4Sources(): Promise<NativePhysicalSource[]> {
  return callNativeHost('physical-sources')
}

export function nativeActiveTunnels(opts: { vpnteAlias: string; vpnteIpv4Prefix: string }): Promise<NativeTunnelRow[]> {
  return callNativeHost('tunnels', opts)
}

export function nativeAdapterRows(): Promise<NativeAdapterRow[]> {
  return callNativeHost('adapters')
}

export function nativeIpConfigRows(): Promise<NativeIpConfigRow[]> {
  return callNativeHost('ipconfig')
}

export function nativeRouteRows(prefixes: string[]): Promise<NativeRouteRow[]> {
  return callNativeHost('routes', { prefixes })
}
