import { networkInterfaces } from 'os'
import { ALL_KNOWN_ALIASES, getTunAdapterAlias, isOwnTunAddress, TUN_IPV6_ADDRESS_CIDR } from './tunAdapter'

// Process exit is proved by the caller. This gate only waits for the old
// active TUN address to disappear before recreating the interface.
export async function waitForTunRelease(
  isCancelled: () => boolean,
  timeoutMs = 5000
): Promise<'released' | 'cancelled' | 'unverified'> {
  const deadline = Date.now() + timeoutMs
  const aliases = new Set<string>([getTunAdapterAlias(), ...ALL_KNOWN_ALIASES])
  const ownedIpv6 = TUN_IPV6_ADDRESS_CIDR.split('/')[0].toLowerCase()
  while (true) {
    if (isCancelled()) return 'cancelled'
    try {
      const interfaces = networkInterfaces()
      const present = [...aliases].some(alias =>
        interfaces[alias]?.some(entry => !entry.internal &&
          (isOwnTunAddress(entry.address) || entry.address.toLowerCase().split('%')[0] === ownedIpv6))
      )
      if (!present) return 'released'
    } catch {
      return 'unverified'
    }
    if (Date.now() >= deadline) return 'unverified'
    await new Promise(resolve => setTimeout(resolve, Math.min(25, deadline - Date.now())))
  }
}
