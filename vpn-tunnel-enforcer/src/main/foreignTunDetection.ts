// AT-02-002 / AT-03-004: synchronous foreign-TUN preflight and runtime warning.
import type { NetworkInterfaceInfo } from 'node:os'
import { TUNNEL_RX } from './native/ipHelperTransforms'

type InterfaceAddress = Pick<NetworkInterfaceInfo, 'address' | 'family' | 'internal'>
export type TunInterfaces = Record<string, readonly InterfaceAddress[] | undefined>

/** Supplied only for the controller's verified, running TUN; an address prefix is not ownership. */
export interface ConfirmedOwnTun { alias: string; ipv4Address: string }

export function findForeignTun(interfaces: TunInterfaces, own?: ConfirmedOwnTun): string | null {
  for (const [name, addresses] of Object.entries(interfaces)) {
    if (!addresses) continue
    // Exempt the whole proved adapter, including its IPv6 address, rather than
    // suppressing unrelated clients that happen to use the same private subnet.
    if (own && name === own.alias && addresses.some(address =>
      address.family === 'IPv4' && !address.internal && address.address === own.ipv4Address)) continue
    if (!TUNNEL_RX.test(name) && !/\bwg\d*\b/i.test(name)) continue
    const address = addresses.find(address => !address.internal &&
      (address.family === 'IPv4' || address.family === 'IPv6'))
    if (address) return `${name} (${address.address})`
  }
  return null
}
