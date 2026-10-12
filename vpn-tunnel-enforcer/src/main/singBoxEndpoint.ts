// AT-04-002 / F-047: sing-box 1.13 removed the `wireguard` outbound; WireGuard is an `endpoint` now.
// The stored profile keeps the legacy outbound shape (parser, URI export and the server/server_port readers rely on it);
// the translation happens only when the sing-box config is built.
import { isIP } from 'node:net'

export type WireGuardEndpoint = Record<string, unknown>

function asString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : ''
}

/** sing-box wants a CIDR prefix; the share-link `ip=10.0.0.2` carries none. */
function toPrefix(address: string): string {
  if (address.includes('/')) return address
  const family = isIP(address)
  if (family === 4) return `${address}/32`
  if (family === 6) return `${address}/128`
  throw new Error(`WireGuard: некорректный локальный адрес «${address}»`)
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
function toEndpointPeer(peer: Record<string, any>): Record<string, unknown> {
  const address = asString(peer?.address) || asString(peer?.server)
  const port = Number(peer?.port ?? peer?.server_port)
  const publicKey = asString(peer?.public_key)
  if (!address) throw new Error('WireGuard: у пира не указан адрес')
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('WireGuard: у пира некорректный порт')
  if (!publicKey) throw new Error('WireGuard: у пира не указан публичный ключ')
  const { server: _s, server_port: _p, address: _a, port: _port, reserved, ...rest } = peer
  return { ...rest, address, port, ...(validReserved(reserved) ? { reserved } : {}) }
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
    const { type: _type, tag: _tag, local_address, dns_servers: _dns, server: _s, server_port: _p, peer_public_key: _k,
      pre_shared_key: _psk, reserved: _r, domain_resolver, address, peers, ...rest } = outbound
    const addresses = toPrefixes(Array.isArray(address) ? address : local_address)
    if (addresses.length === 0) throw new Error('WireGuard: не указан локальный адрес туннеля (ip=…)')
    if (peers.length === 0) throw new Error('WireGuard: не указан ни один пир')
    return {
      type: 'wireguard',
      tag,
      ...rest,
      address: addresses,
      ...(domain_resolver ? { domain_resolver } : {}),
      peers: peers.map(toEndpointPeer)
    }
  }

  const server = asString(outbound.server)
  const port = Number(outbound.server_port)
  const privateKey = asString(outbound.private_key)
  const publicKey = asString(outbound.peer_public_key)
  if (!server) throw new Error('WireGuard: не указан адрес сервера')
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('WireGuard: некорректный порт сервера')
  if (!privateKey) throw new Error('WireGuard: не указан приватный ключ')
  if (!publicKey) throw new Error('WireGuard: не указан публичный ключ сервера')

  const addresses = toPrefixes(outbound.local_address)
  if (addresses.length === 0) throw new Error('WireGuard: не указан локальный адрес туннеля (ip=…)')

  const presharedKey = asString(outbound.pre_shared_key)
  const mtu = Number(outbound.mtu)
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
