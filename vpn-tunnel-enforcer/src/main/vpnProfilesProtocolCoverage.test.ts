import { describe, expect, it } from 'vitest'
import { describeVpnProfileCapabilities, exportOutboundToUri, parseVpnProfiles } from './vpnProfiles'

describe('phase 3 protocol URI coverage', () => {
  it('parses naive:// links into sing-box naive outbounds', () => {
    const [profile] = parseVpnProfiles('naive://user:pass@naive.example.com:443?sni=front.example.com#Naive%20Node')

    expect(profile.protocol).toBe('naive')
    expect(profile.name).toBe('Naive Node')
    expect(profile.outbound).toMatchObject({
      type: 'naive',
      tag: 'proxy-out',
      server: 'naive.example.com',
      server_port: 443,
      username: 'user',
      password: 'pass'
    })
    expect(profile.outbound.tls.server_name).toBe('front.example.com')
  })

  it('strips tls.insecure from naive outbounds because sing-box rejects it', () => {
    const [profile] = parseVpnProfiles('naive://user:pass@naive.example.com:443?sni=front.example.com&allowInsecure=1#Naive')

    expect(profile.outbound.tls.insecure).toBeUndefined()
  })

  it('parses ECH params on TLS-capable links', () => {
    const [profile] = parseVpnProfiles(
      'naive://user:pass@naive.example.com:443?sni=front.example.com&ech=1&echConfig=abc,def&echQueryServerName=cloudflare-ech.com#Naive%20ECH'
    )

    expect(profile.outbound.tls.ech).toEqual({
      enabled: true,
      config: ['abc', 'def'],
      query_server_name: 'cloudflare-ech.com'
    })
  })

  it('parses anytls:// links into sing-box anytls outbounds', () => {
    const [profile] = parseVpnProfiles('anytls://secret@any.example.com:443?sni=front.example.com#AnyTLS')

    expect(profile.protocol).toBe('anytls')
    expect(profile.outbound).toMatchObject({
      type: 'anytls',
      server: 'any.example.com',
      server_port: 443,
      password: 'secret'
    })
    expect(profile.outbound.tls.server_name).toBe('front.example.com')
  })

  it('parses shadowtls:// links with version', () => {
    const [profile] = parseVpnProfiles('shadowtls://secret@shadow.example.com:443?version=3&sni=front.example.com#ShadowTLS')

    expect(profile.protocol).toBe('shadowtls')
    expect(profile.outbound).toMatchObject({
      type: 'shadowtls',
      server: 'shadow.example.com',
      server_port: 443,
      password: 'secret',
      version: 3
    })
  })

  it('parses tuic:// links with congestion options', () => {
    const [profile] = parseVpnProfiles('tuic://550e8400-e29b-41d4-a716-446655440000:secret@tuic.example.com:443?sni=front.example.com&congestion_control=bbr&udp_relay_mode=native#TUIC')

    expect(profile.protocol).toBe('tuic')
    expect(profile.outbound).toMatchObject({
      type: 'tuic',
      server: 'tuic.example.com',
      server_port: 443,
      uuid: '550e8400-e29b-41d4-a716-446655440000',
      password: 'secret',
      congestion_control: 'bbr',
      udp_relay_mode: 'native'
    })
  })

  it('extracts new protocol URIs from mixed subscription text', () => {
    const profiles = parseVpnProfiles([
      'vless://00000000-0000-4000-8000-000000000000@vless.example.com:443?security=tls#VLESS',
      'tuic://550e8400-e29b-41d4-a716-446655440000:secret@tuic.example.com:443?sni=front.example.com#TUIC',
      'naive://user:pass@naive.example.com:443?sni=front.example.com#Naive'
    ].join('\n'))

    expect(profiles.map((profile) => profile.protocol)).toEqual(['vless', 'tuic', 'naive'])
  })

  it('does not force imported VLESS links into tcp-only mode', () => {
    const [profile] = parseVpnProfiles(
      'vless://00000000-0000-4000-8000-000000000000@vless.example.com:443?security=tls&sni=front.example.com#VLESS'
    )

    expect(profile.protocol).toBe('vless')
    expect(profile.outbound.type).toBe('vless')
    expect(profile.outbound.network).toBeUndefined()
  })

  it('does not force imported Trojan links into tcp-only mode', () => {
    const [profile] = parseVpnProfiles(
      'trojan://secret@trojan.example.com:443?sni=front.example.com#Trojan'
    )

    expect(profile.protocol).toBe('trojan')
    expect(profile.outbound.type).toBe('trojan')
    expect(profile.outbound.network).toBeUndefined()
  })

  it('does not force imported VMess links into tcp-only mode', () => {
    const payload = Buffer.from(JSON.stringify({
      add: 'vmess.example.com',
      port: '443',
      id: '00000000-0000-4000-8000-000000000000',
      aid: '0',
      scy: 'auto',
      tls: 'tls',
      ps: 'VMess'
    })).toString('base64')
    const [profile] = parseVpnProfiles(`vmess://${payload}`)

    expect(profile.protocol).toBe('vmess')
    expect(profile.outbound.type).toBe('vmess')
    expect(profile.outbound.network).toBeUndefined()
  })

  it('round-trips exportable new protocol outbounds', () => {
    const profile = parseVpnProfiles('tuic://550e8400-e29b-41d4-a716-446655440000:secret@tuic.example.com:443?sni=front.example.com&congestion_control=bbr#TUIC')[0]
    const exported = exportOutboundToUri(profile)

    expect(exported).toMatch(/^tuic:\/\//)
    expect(exported).toContain('congestion_control=bbr')
    expect(parseVpnProfiles(exported || '')[0].outbound).toMatchObject({
      type: 'tuic',
      server: 'tuic.example.com',
      server_port: 443,
      uuid: '550e8400-e29b-41d4-a716-446655440000',
      password: 'secret'
    })
  })

  it('round-trips ECH params during URI export', () => {
    const profile = parseVpnProfiles(
      'naive://user:pass@naive.example.com:443?sni=front.example.com&ech=1&echConfig=abc,def&echQueryServerName=cloudflare-ech.com#Naive%20ECH'
    )[0]
    const exported = exportOutboundToUri(profile)
    const reparsed = parseVpnProfiles(exported || '')[0]

    expect(exported).toContain('ech=1')
    expect(exported).toContain('echConfig=abc%2Cdef')
    expect(reparsed.outbound.tls.ech).toMatchObject({
      enabled: true,
      config: ['abc', 'def'],
      query_server_name: 'cloudflare-ech.com'
    })
  })

  it('summarizes stealth capabilities for Naive ECH profiles', () => {
    const profile = parseVpnProfiles(
      'naive://user:pass@naive.example.com:443?sni=front.example.com&ech=1&echConfig=abc#Naive%20ECH'
    )[0]

    expect(describeVpnProfileCapabilities(profile)).toMatchObject({
      protocol: 'naive',
      stealthPreset: 'naive-ech',
      tlsConfigured: true,
      echConfigured: true,
      warnings: []
    })
  })

  it('preserves Hysteria2 advanced stable options', () => {
    const [profile] = parseVpnProfiles(
      'hy2://secret@hy2.example.com:443?sni=front.example.com&obfs=salamander&obfs-password=pepper&mport=8443-8450&hop_interval=30s&upmbps=80&downmbps=200#HY2'
    )
    const exported = exportOutboundToUri(profile)
    const reparsed = parseVpnProfiles(exported || '')[0]

    expect(profile.outbound).toMatchObject({
      type: 'hysteria2',
      server: 'hy2.example.com',
      server_port: 443,
      password: 'secret',
      obfs: { type: 'salamander', password: 'pepper' },
      server_ports: '8443:8450',
      hop_interval: '30s',
      up_mbps: 80,
      down_mbps: 200
    })
    expect(profile.outbound.network).toBeUndefined()
    expect(exported).toContain('mport=8443-8450')
    expect(reparsed.outbound).toMatchObject({
      obfs: { type: 'salamander', password: 'pepper' },
      server_ports: '8443:8450',
      hop_interval: '30s',
      up_mbps: 80,
      down_mbps: 200
    })
  })

  it('summarizes Hysteria2 obfs and unsafe imported tcp-only routing', () => {
    const profile = {
      name: 'HY2',
      protocol: 'hysteria2',
      outbound: {
        type: 'hysteria2',
        server: 'hy2.example.com',
        server_port: 443,
        password: 'secret',
        network: 'tcp',
        obfs: { type: 'salamander', password: 'pepper' }
      }
    }

    expect(describeVpnProfileCapabilities(profile)).toMatchObject({
      protocol: 'hysteria2',
      stealthPreset: 'hysteria2-obfs',
      tlsConfigured: false,
      echConfigured: false
    })
    expect(describeVpnProfileCapabilities(profile).warnings).toContain(
      'Hysteria2 uses QUIC/UDP; tcp-only routing can block it'
    )
  })
})
