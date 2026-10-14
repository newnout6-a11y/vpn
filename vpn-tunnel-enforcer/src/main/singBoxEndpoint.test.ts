// AT-04-002 / F-047: legacy WireGuard outbound → sing-box 1.13 endpoint.
import { describe, expect, it } from 'vitest'
import { wireguardOutboundToEndpoint } from './singBoxEndpoint'

const base = {
  type: 'wireguard', tag: 'proxy-out', server: '203.0.113.5', server_port: 51820,
  private_key: 'PRIV', peer_public_key: 'PUB', local_address: ['10.0.0.2']
}

describe('wireguardOutboundToEndpoint', () => {
  it('builds a single-peer endpoint with a CIDR address', () => {
    expect(wireguardOutboundToEndpoint(base)).toEqual({
      type: 'wireguard', tag: 'proxy-out', address: ['10.0.0.2/32'], private_key: 'PRIV',
      peers: [{ address: '203.0.113.5', port: 51820, public_key: 'PUB', allowed_ips: ['0.0.0.0/0', '::/0'] }]
    })
  })

  it('adds /128 to a bare IPv6 address and keeps an explicit prefix', () => {
    const endpoint = wireguardOutboundToEndpoint({ ...base, local_address: ['fd00::2', '10.0.0.2/24'] })
    expect(endpoint.address).toEqual(['fd00::2/128', '10.0.0.2/24'])
  })

  it('carries preshared key, mtu and domain_resolver only when present', () => {
    const endpoint = wireguardOutboundToEndpoint({ ...base, pre_shared_key: 'PSK', mtu: 1280, domain_resolver: { server: 'dns-bootstrap' } }) as any
    expect(endpoint.mtu).toBe(1280)
    expect(endpoint.domain_resolver).toEqual({ server: 'dns-bootstrap' })
    expect(endpoint.peers[0].pre_shared_key).toBe('PSK')
    expect(JSON.stringify(wireguardOutboundToEndpoint({ ...base, pre_shared_key: '' }))).not.toContain('pre_shared_key')
  })

  it('drops dns_servers, which an endpoint cannot carry', () => {
    expect(wireguardOutboundToEndpoint({ ...base, dns_servers: ['1.1.1.1'] })).not.toHaveProperty('dns_servers')
  })

  it('keeps an endpoint-form multi-peer profile as it is', () => {
    const peers = [{ address: 'x', port: 1, public_key: 'K', allowed_ips: ['0.0.0.0/0'] }]
    expect(wireguardOutboundToEndpoint({ type: 'wireguard', tag: 'proxy-out', address: ['10.0.0.2/32'], private_key: 'P', peers }))
      .toEqual({ type: 'wireguard', tag: 'proxy-out', address: ['10.0.0.2/32'], private_key: 'P', peers })
  })

  it('translates legacy peers (server/server_port) instead of copying obsolete fields', () => {
    const endpoint = wireguardOutboundToEndpoint({
      type: 'wireguard', tag: 'proxy-out', local_address: ['10.0.0.2'], private_key: 'P',
      peers: [{ server: 'a.example.com', server_port: 51820, public_key: 'K1', allowed_ips: ['0.0.0.0/0'], reserved: [1, 2, 3] }, { server: '203.0.113.9', server_port: 2408, public_key: 'K2', allowed_ips: ['10.1.0.0/16'] }]
    }) as any
    expect(endpoint.address).toEqual(['10.0.0.2/32'])
    expect(endpoint.peers).toEqual([
      { address: 'a.example.com', port: 51820, public_key: 'K1', allowed_ips: ['0.0.0.0/0'], reserved: [1, 2, 3] },
      { address: '203.0.113.9', port: 2408, public_key: 'K2', allowed_ips: ['10.1.0.0/16'] }
    ])
    expect(JSON.stringify(endpoint)).not.toMatch(/server/)
  })

  it('refuses a multi-peer profile with an unusable peer', () => {
    const bad = (peer: object) => () => wireguardOutboundToEndpoint({ type: 'wireguard', local_address: ['10.0.0.2'], private_key: 'P', peers: [peer] })
    expect(bad({ server: '', server_port: 1, public_key: 'K' })).toThrow(/адрес/)
    expect(bad({ server: 'x', server_port: 0, public_key: 'K' })).toThrow(/порт/)
    expect(bad({ server: 'x', server_port: 1 })).toThrow(/публичный ключ/)
  })

  it('validates the interface fields of a multi-peer profile too', () => {
    const peer = { address: 'x', port: 1, public_key: 'K' }
    expect(() => wireguardOutboundToEndpoint({ type: 'wireguard', local_address: ['10.0.0.2'], private_key: '', peers: [peer] })).toThrow(/приватный ключ/)
    const kept = wireguardOutboundToEndpoint({ type: 'wireguard', local_address: ['10.0.0.2'], private_key: 'P', mtu: -5, peers: [peer] })
    expect(kept).not.toHaveProperty('mtu')
  })

  it('drops fields the endpoint does not know (tls, multiplex, detour, udp_fragment…)', () => {
    const endpoint = wireguardOutboundToEndpoint({
      type: 'wireguard', local_address: ['10.0.0.2'], private_key: 'P', tls: { enabled: true }, multiplex: { enabled: true }, detour: 'x', udp_fragment: true,
      peers: [{ address: 'x', port: 1, public_key: 'K', tls: {}, extra: 1, persistent_keepalive_interval: 25 }]
    }) as any
    expect(Object.keys(endpoint).sort()).toEqual(['address', 'peers', 'private_key', 'tag', 'type'])
    expect(endpoint.peers[0]).toEqual({ address: 'x', port: 1, public_key: 'K', allowed_ips: ['0.0.0.0/0', '::/0'], persistent_keepalive_interval: 25 })
  })

  it('never lets a multi-peer profile create a host interface or open a listening port', () => {
    const endpoint = wireguardOutboundToEndpoint({
      type: 'wireguard', local_address: ['10.0.0.2'], private_key: 'P', mtu: 1280, udp_timeout: '5m', workers: 2,
      system: true, name: 'wg-evil', listen_port: 51820,
      peers: [{ address: 'x', port: 1, public_key: 'K' }]
    }) as any
    expect(endpoint).not.toHaveProperty('system')
    expect(endpoint).not.toHaveProperty('name')
    expect(endpoint).not.toHaveProperty('listen_port')
    expect(endpoint).toMatchObject({ mtu: 1280, udp_timeout: '5m', workers: 2 })
  })

  it('coerces numeric strings from hand-written JSON on both paths', () => {
    const multi = wireguardOutboundToEndpoint({
      type: 'wireguard', local_address: ['10.0.0.2'], private_key: 'P', mtu: '1280',
      peers: [{ address: 'x', port: '51820', public_key: 'K' }]
    }) as any
    expect(multi.mtu).toBe(1280)
    expect(multi.peers[0].port).toBe(51820)
    expect((wireguardOutboundToEndpoint({ ...base, server_port: '51820', mtu: '1280' }) as any).mtu).toBe(1280)
  })

  it.each(['x/y', '10.0.0.2/33', '10.0.0.2/-1', '10.0.0.2/24/8', 'fd00::2/129', '10.0.0.2/'])('rejects the malformed local address %j before sing-box does', address => {
    expect(() => wireguardOutboundToEndpoint({ ...base, local_address: [address] })).toThrow(/адрес|префикс/)
  })

  it('accepts valid CIDR addresses as they are', () => {
    expect((wireguardOutboundToEndpoint({ ...base, local_address: ['10.0.0.2/24', 'fd00::2/64'] }) as any).address).toEqual(['10.0.0.2/24', 'fd00::2/64'])
  })

  it('defaults a lone peer without allowed_ips to a full tunnel but demands them with several peers', () => {
    const peer = { address: 'x', port: 1, public_key: 'K' }
    const lone = wireguardOutboundToEndpoint({ type: 'wireguard', local_address: ['10.0.0.2'], private_key: 'P', peers: [peer] }) as any
    expect(lone.peers[0].allowed_ips).toEqual(['0.0.0.0/0', '::/0'])
    expect(() => wireguardOutboundToEndpoint({ type: 'wireguard', local_address: ['10.0.0.2'], private_key: 'P', peers: [peer, { ...peer, address: 'y' }] })).toThrow(/allowed_ips/)
  })

  it('validates allowed_ips entries and normalizes bare addresses', () => {
    const make = (allowed_ips: unknown) => () => wireguardOutboundToEndpoint({ type: 'wireguard', local_address: ['10.0.0.2'], private_key: 'P', peers: [{ address: 'x', port: 1, public_key: 'K', allowed_ips }] })
    expect((make(['10.1.0.0/16', '192.0.2.7', 'fd00::/8'])() as any).peers[0].allowed_ips).toEqual(['10.1.0.0/16', '192.0.2.7/32', 'fd00::/8'])
    expect(make(['not-a-route'])).toThrow(/адрес/)
    expect(make(['10.0.0.0/40'])).toThrow(/префикс/)
    expect(make('0.0.0.0/0')).toThrow(/списком/)
    for (const bad of [[123], [null], [' '], ['10.1.0.0/16', ''], [{}]]) expect(make(bad)).toThrow(/непустой строкой/)
  })

  it('copies valid reserved bytes to the peer and ignores invalid ones', () => {
    expect((wireguardOutboundToEndpoint({ ...base, reserved: [1, 2, 3] }) as any).peers[0].reserved).toEqual([1, 2, 3])
    for (const reserved of [[1, 2], [1, 2, 300], 'abc', [1.5, 2, 3]]) {
      expect((wireguardOutboundToEndpoint({ ...base, reserved }) as any).peers[0]).not.toHaveProperty('reserved')
    }
  })

  it.each([
    ['server', { server: '' }, /адрес сервера/],
    ['port', { server_port: 70000 }, /порт/],
    ['private key', { private_key: '' }, /приватный ключ/],
    ['peer key', { peer_public_key: '' }, /публичный ключ/],
    ['local address', { local_address: [] }, /локальный адрес/],
    ['bad local address', { local_address: ['not-an-ip'] }, /некорректный локальный адрес/]
  ])('refuses a profile without a usable %s instead of producing a config sing-box rejects', (_name, patch, message) => {
    expect(() => wireguardOutboundToEndpoint({ ...base, ...patch })).toThrow(message)
  })
})
