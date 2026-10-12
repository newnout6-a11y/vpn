// AT-04-002 / F-047: sing-box 1.13 removed the `wireguard` outbound; WireGuard is an `endpoint` now.
// The stored profile keeps the legacy outbound shape (parser, URI export and the server/server_port readers rely on it);
// the translation happens only when the sing-box config is built.
import { isIP } from 'node:net'

export type WireGuardEndpoint = Record<string, unknown>

function asString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : ''
}

/** Integer from a number or a numeric string (hand-written JSON often quotes numbers); NaN otherwise. */
function toInt(value: unknown): number {
  if (typeof value === 'number') return Number.isInteger(value) ? value : NaN
  if (typeof value === 'string' && value.trim() !== '') {
    const parsed = Number(value)
    return Number.isInteger(parsed) ? parsed : NaN
  }
  return NaN
}

/** sing-box wants a validated CIDR; the share-link `ip=10.0.0.2` carries no prefix, so add the host prefix. */
function toPrefix(address: string): string {
  const [host, prefix, ...extra] = address.split('/')
  const family = isIP(host)
  if (family === 0 || extra.length > 0) throw new Error(`WireGuard: некорректный локальный адрес «${address}»`)
  if (prefix === undefined) return family === 4 ? `${host}/32` : `${host}/128`
  const length = /^[0-9]{1,3}$/.test(prefix) ? Number(prefix) : NaN
  if (!(length >= 0 && length <= (family === 4 ? 32 : 128))) throw new Error(`WireGuard: некорректная длина префикса в адресе «${address}»`)
  return address
}

function toPrefixes(value: unknown): string[] {
  const raw: unknown[] = Array.isArray(value) ? value : typeof value === 'string' ? [value] : []
  return raw.map(asString).filter(Boolean).map(toPrefix)
}

/** Cloudflare-style `reserved` bytes: exactly three integers 0-255. Anything else is ignored. */
function validReserved(value: unknown): value is number[] {
  return Array.isArray(value) && value.length === 3 && value.every(byte => Number.isInteger(byte) && byte >= 0 && byte <= 255)
}

/** One peer, from either the endpoint form (address/port) or the legacy form (server/server_port). */
function toEndpointPeer(peer: Record<string, any>, onlyPeer: boolean): Record<string, unknown> {
  const address = asString(peer?.address) || asString(peer?.server)
  const port = toInt(peer?.port ?? peer?.server_port)
  const publicKey = asString(peer?.public_key)
  if (!address) throw new Error('WireGuard: у пира не указан адрес')
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('WireGuard: у пира некорректный порт')
  if (!publicKey) throw new Error('WireGuard: у пира не указан публичный ключ')
  const { pre_shared_key, allowed_ips, persistent_keepalive_interval, reserved } = peer
  // sing-box refuses a peer without allowed_ips. This is a full-tunnel client, so a lone peer defaults to all traffic;
  // with several peers a default would make their routes overlap, so the profile has to say which peer carries what.
  if (allowed_ips !== undefined && !Array.isArray(allowed_ips)) throw new Error('WireGuard: allowed_ips пира должен быть списком')
  // Every given route must be a valid CIDR; a bare address gets the host prefix, anything else is refused here
  // rather than by sing-box at check time.
  const given: string[] = Array.isArray(allowed_ips) ? allowed_ips.map(asString).filter(Boolean).map(toPrefix) : []
  const routes: string[] = given.length > 0 ? given : onlyPeer ? ['0.0.0.0/0', '::/0'] : []
  if (routes.length === 0) throw new Error('WireGuard: у пира не указаны allowed_ips (при нескольких пирах обязательны)')
  return {
    address,
    port,
    public_key: publicKey,
    ...(asString(pre_shared_key) ? { pre_shared_key: asString(pre_shared_key) } : {}),
    allowed_ips: routes,
    ...(toInt(persistent_keepalive_interval) > 0 ? { persistent_keepalive_interval: toInt(persistent_keepalive_interval) } : {}),
    ...(validReserved(reserved) ? { reserved } : {})
  }
}

/**
 * Translates the legacy WireGuard outbound (`server`, `peer_public_key`, `local_address`…) into the 1.13 endpoint.
 * Throws a readable error when the profile cannot describe a working tunnel, so the start is refused instead of
 * handing sing-box a config it rejects at `check`. `dns_servers` has no endpoint counterpart and is dropped.
 */
export function wireguardOutboundToEndpoint(outbound: Record<string, any>): WireGuardEndpoint {
  const tag = asString(outbound.tag) || 'proxy-out'
  if (Array.isArray(outbound.peers)) {
    // Multi-peer profile (hand-written JSON). Peers may still use the legacy keys server/server_port, which the
    // endpoint form does not know: translate every peer instead of copying obsolete fields into the endpoint.
    // Only fields the endpoint knows are carried over: sing-box 1.13 rejects unknown keys (tls, multiplex, detour…).
    const { local_address, domain_resolver, address, peers, private_key, mtu, listen_port, udp_timeout, workers, system, name } = outbound
    const addresses = toPrefixes(Array.isArray(address) ? address : local_address)
    if (addresses.length === 0) throw new Error('WireGuard: не указан локальный адрес туннеля (ip=…)')
    if (peers.length === 0) throw new Error('WireGuard: не указан ни один пир')
    if (!asString(private_key)) throw new Error('WireGuard: не указан приватный ключ')
    return {
      type: 'wireguard',
      tag,
      address: addresses,
      private_key: asString(private_key),
      ...(toInt(mtu) > 0 ? { mtu: toInt(mtu) } : {}),
      ...(toInt(listen_port) > 0 && toInt(listen_port) <= 65535 ? { listen_port: toInt(listen_port) } : {}),
      ...(typeof udp_timeout === 'string' && udp_timeout ? { udp_timeout } : {}),
      ...(toInt(workers) > 0 ? { workers: toInt(workers) } : {}),
      ...(typeof system === 'boolean' ? { system } : {}),
      ...(typeof name === 'string' && name ? { name } : {}),
      ...(domain_resolver ? { domain_resolver } : {}),
      peers: peers.map((peer: Record<string, any>) => toEndpointPeer(peer, peers.length === 1))
    }
  }

  const server = asString(outbound.server)
  const port = toInt(outbound.server_port)
  const privateKey = asString(outbound.private_key)
  const publicKey = asString(outbound.peer_public_key)
  if (!server) throw new Error('WireGuard: не указан адрес сервера')
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('WireGuard: некорректный порт сервера')
  if (!privateKey) throw new Error('WireGuard: не указан приватный ключ')
  if (!publicKey) throw new Error('WireGuard: не указан публичный ключ сервера')

  const addresses = toPrefixes(outbound.local_address)
  if (addresses.length === 0) throw new Error('WireGuard: не указан локальный адрес туннеля (ip=…)')

  const presharedKey = asString(outbound.pre_shared_key)
  const mtu = toInt(outbound.mtu)
  return {
    type: 'wireguard',
    tag,
    address: addresses,
    private_key: privateKey,
    ...(Number.isInteger(mtu) && mtu > 0 ? { mtu } : {}),
    ...(outbound.domain_resolver ? { domain_resolver: outbound.domain_resolver } : {}),
    peers: [{
      address: server,
      port,
      public_key: publicKey,
      ...(presharedKey ? { pre_shared_key: presharedKey } : {}),
      ...(validReserved(outbound.reserved) ? { reserved: outbound.reserved } : {}),
      allowed_ips: ['0.0.0.0/0', '::/0']
    }]
  }
}
