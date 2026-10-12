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

/**
 * Translates the legacy WireGuard outbound (`server`, `peer_public_key`, `local_address`…) into the 1.13 endpoint.
 * Throws a readable error when the profile cannot describe a working tunnel, so the start is refused instead of
 * handing sing-box a config it rejects at `check`. `dns_servers` has no endpoint counterpart and is dropped.
 */
export function wireguardOutboundToEndpoint(outbound: Record<string, any>): WireGuardEndpoint {
  const tag = asString(outbound.tag) || 'proxy-out'
  if (Array.isArray(outbound.peers)) {
    // Already in endpoint form (hand-written JSON profile): only make sure it is addressed as an endpoint.
    const { type: _type, tag: _tag, ...rest } = outbound
    return { type: 'wireguard', tag, ...rest }
  }

  const server = asString(outbound.server)
  const port = Number(outbound.server_port)
  const privateKey = asString(outbound.private_key)
  const publicKey = asString(outbound.peer_public_key)
  if (!server) throw new Error('WireGuard: не указан адрес сервера')
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('WireGuard: некорректный порт сервера')
  if (!privateKey) throw new Error('WireGuard: не указан приватный ключ')
  if (!publicKey) throw new Error('WireGuard: не указан публичный ключ сервера')

  const rawAddresses: unknown[] = Array.isArray(outbound.local_address)
    ? outbound.local_address
    : typeof outbound.local_address === 'string' ? [outbound.local_address] : []
  const addresses = rawAddresses.map(asString).filter(Boolean).map(toPrefix)
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
      allowed_ips: ['0.0.0.0/0', '::/0']
    }]
  }
}
