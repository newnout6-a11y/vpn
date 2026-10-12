// AT-04-010 / F-047: legacy WireGuard outbound → sing-box 1.13 endpoint.
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

  it('passes a hand-written endpoint (peers present) through under the proxy tag', () => {
    const peers = [{ address: 'x', port: 1, public_key: 'K', allowed_ips: ['0.0.0.0/0'] }]
    expect(wireguardOutboundToEndpoint({ type: 'wireguard', tag: 'proxy-out', address: ['10.0.0.2/32'], private_key: 'P', peers }))
      .toEqual({ type: 'wireguard', tag: 'proxy-out', address: ['10.0.0.2/32'], private_key: 'P', peers })
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
