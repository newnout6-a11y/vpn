export interface TunMtuOptions {
  stealthMode?: boolean
  publicWifiCompatibility?: boolean
}

export const DEFAULT_TUN_MTU = 1500
export const PUBLIC_WIFI_TUN_MTU = 1380
export const STEALTH_TUN_MTU = 1280

export function selectTunMtu(options: TunMtuOptions = {}): number {
  if (options.stealthMode === true) return STEALTH_TUN_MTU
  if (options.publicWifiCompatibility === true) return PUBLIC_WIFI_TUN_MTU
  return DEFAULT_TUN_MTU
}
