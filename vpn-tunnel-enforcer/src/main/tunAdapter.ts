/**
 * Single source of truth for the TUN adapter's identity (alias, IP range,
 * gateway). Centralised here so changing it doesn't require touching every
 * file that filters by `Get-NetAdapter -Name` or installs a firewall rule
 * scoped by `-InterfaceAlias`.
 *
 * Why we don't use `'VPNTE-TUN'` literal anymore:
 *   1. The string `VPNTE-TUN` is a strong signal to local "anti-VPN"
 *      software (some games, banking apps, certain Russian state-bank
 *      clients) that the user is on a VPN. They scan `Get-NetAdapter`
 *      output and pattern-match the alias.
 *   2. The default IPv4 `172.19.0.1/30` is also unusual — most home/SOHO
 *      gateways live in `192.168.0.0/16`, so a route through `172.19.x.x`
 *      stands out in `route print`.
 *
 * The new defaults blend in:
 *   - alias `Ethernet 5` mimics the auto-numbered alias Windows assigns to
 *     additional ethernet NICs, and is unlikely to clash on a laptop
 *     (laptops usually have one Ethernet adapter, this slots in past it).
 *   - the IPv4 net `192.168.250.252/30` lives squarely in the RFC1918
 *     home-router space so it reads as "another LAN" rather than "weird
 *     VPN tunnel".
 *
 * Note: any code path that cleans up after a previous run (firewall rules
 * left behind by a crash, orphaned net-adapter, etc.) MUST consult
 * {@link KNOWN_LEGACY_ALIASES} and try each one — older builds shipped
 * `VPNTE-TUN` and crashed users will have rules tagged with that name on
 * their next start.
 */

/** Currently-active alias. Default is the disguised value. */
export const TUN_ADAPTER_ALIAS = 'Ethernet 5'

/** Currently-active IPv4 address (with /30 prefix) handed to sing-box. */
export const TUN_IPV4_ADDRESS_CIDR = '192.168.250.253/30'

/**
 * The IPv4 sing-box assigns to itself inside the TUN. Used by code that
 * needs to recognise "is this address our own tunnel" (foreign-TUN
 * detection, leak diagnostics, etc.).
 */
export const TUN_IPV4_GATEWAY = '192.168.250.253'

/**
 * The other usable IP in the /30 — handed to adapters as their DNS server
 * by physicalAdapterLockdown so DNS queries are intercepted by sing-box's
 * dns-hijack rule.
 */
export const TUN_IPV4_RESOLVER = '192.168.250.254'

/**
 * The /30 network range. Allow-listed by the firewall kill-switch so TUN
 * traffic itself isn't accidentally blocked.
 */
export const TUN_IPV4_NETWORK_CIDR = '192.168.250.252/30'

/**
 * Common /24 prefix our /30 lives under. Used as a fast "is this our TUN's
 * address" check in places that just want to filter out our own adapter
 * from a list of foreign tunnels.
 */
export const TUN_IPV4_PREFIX = '192.168.250.'

/**
 * Legacy /24 prefix from earlier builds (when the adapter was on
 * 172.19.0.x). Kept so detection paths can still recognise stale state
 * left behind by an older binary that crashed mid-run.
 */
export const LEGACY_TUN_IPV4_PREFIX = '172.19.0.'

/**
 * True if the given address belongs to one of our TUN's known prefixes
 * (current or legacy). Used by foreign-TUN detection so we don't mistake
 * our own adapter for a third-party VPN.
 */
export function isOwnTunAddress(address: string): boolean {
  if (!address) return false
  return address.startsWith(TUN_IPV4_PREFIX) || address.startsWith(LEGACY_TUN_IPV4_PREFIX)
}

/** IPv6 address sing-box assigns to its TUN side. Kept v4-only for now. */
export const TUN_IPV6_ADDRESS_CIDR = 'fdfe:dcba:9876::1/126'

/**
 * Aliases shipped by previous builds. Cleanup paths (firewall rule purge,
 * orphaned-adapter sweeper) iterate over this list so a user who crashed
 * on an old build still gets a clean machine after upgrading.
 */
export const KNOWN_LEGACY_ALIASES = ['VPNTE-TUN'] as const

/**
 * The full set of aliases we ever look for, in priority order. The first
 * entry is the live alias we install today; the rest are historical names
 * we still need to clean up after.
 */
export const ALL_KNOWN_ALIASES = [
  TUN_ADAPTER_ALIAS,
  ...KNOWN_LEGACY_ALIASES
] as const
