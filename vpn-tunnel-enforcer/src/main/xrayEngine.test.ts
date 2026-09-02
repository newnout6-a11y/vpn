import { describe, it, expect } from 'vitest'
import { resolveProxyEngine } from './proxyEngine'
import {
  toXrayOutbound,
  buildXrayConfig,
  buildXrayProbeConfig,
  readRecentXrayOutboundFault
} from './xrayEngine'
import { writeFile, rm } from 'fs/promises'
import { join } from 'path'
import { tmpdir } from 'os'

describe('resolveProxyEngine', () => {
  it('defaults to xray for reality in auto mode', () => {
    const outbound = {
      type: 'vless',
      server: '1.2.3.4',
      server_port: 443,
      tls: {
        enabled: true,
        reality: {
          enabled: true,
          public_key: 'abc'
        }
      }
    }
    expect(resolveProxyEngine(outbound, 'auto')).toBe('xray')
  })

  it('keeps non-reality TLS on sing-box in auto mode', () => {
    const outbound = {
      type: 'vless',
      server: '1.2.3.4',
      server_port: 443,
      tls: {
        enabled: true,
        server_name: 'example.com'
      }
    }
    expect(resolveProxyEngine(outbound, 'auto')).toBe('sing-box')
  })

  it('keeps hysteria2 on sing-box even if setting is xray', () => {
    const outbound = {
      type: 'hysteria2',
      server: '1.2.3.4',
      server_port: 443
    }
    expect(resolveProxyEngine(outbound, 'xray')).toBe('sing-box')
  })

  it('respects explicit sing-box setting even for reality', () => {
    const outbound = {
      type: 'vless',
      server: '1.2.3.4',
      server_port: 443,
      tls: {
        reality: {
          enabled: true,
          public_key: 'abc'
        }
      }
    }
    expect(resolveProxyEngine(outbound, 'sing-box')).toBe('sing-box')
  })

  it('allows explicit xray for standard vmess', () => {
    const outbound = {
      type: 'vmess',
      server: '1.2.3.4',
      server_port: 443
    }
    expect(resolveProxyEngine(outbound, 'xray')).toBe('xray')
  })
})

describe('toXrayOutbound', () => {
  it('translates VLESS + REALITY over TCP correctly', () => {
    const sbOutbound = {
      type: 'vless',
      server: 'nl.cloudrynth.com',
      server_port: 443,
      uuid: '11111111-2222-3333-4444-555555555555',
      flow: 'xtls-rprx-vision',
      tls: {
        enabled: true,
        server_name: 'yahoo.com',
        reality: {
          enabled: true,
          public_key: 'abcdef123456',
          short_id: '01234567'
        }
      }
    }

    const xrayOut = toXrayOutbound(sbOutbound, { resolvedIp: '185.1.2.3' })
    expect(xrayOut.protocol).toBe('vless')
    expect(xrayOut.settings.vnext[0].address).toBe('185.1.2.3')
    expect(xrayOut.settings.vnext[0].port).toBe(443)
    expect(xrayOut.settings.vnext[0].users[0].id).toBe('11111111-2222-3333-4444-555555555555')
    expect(xrayOut.settings.vnext[0].users[0].flow).toBe('xtls-rprx-vision')
    expect(xrayOut.streamSettings.security).toBe('reality')
    expect(xrayOut.streamSettings.realitySettings.serverName).toBe('yahoo.com')
    expect(xrayOut.streamSettings.realitySettings.publicKey).toBe('abcdef123456')
  })

  it('strips flow on non-TCP transport to avoid Xray config validation crash', () => {
    const sbOutbound = {
      type: 'vless',
      server: '1.2.3.4',
      server_port: 443,
      uuid: '11111111-2222-3333-4444-555555555555',
      flow: 'xtls-rprx-vision',
      transport: {
        type: 'ws',
        path: '/vless-ws'
      },
      tls: {
        enabled: true,
        reality: {
          enabled: true,
          public_key: 'abc'
        }
      }
    }

    const xrayOut = toXrayOutbound(sbOutbound)
    expect(xrayOut.streamSettings.network).toBe('ws')
    expect(xrayOut.settings.vnext[0].users[0].flow).toBeUndefined()
  })

  it('translates VMess + WS + TLS', () => {
    const sbOutbound = {
      type: 'vmess',
      server: 'example.com',
      server_port: 443,
      uuid: '22222222-2222-2222-2222-222222222222',
      alter_id: 0,
      transport: {
        type: 'ws',
        path: '/ws'
      },
      tls: {
        enabled: true,
        server_name: 'example.com'
      }
    }

    const xrayOut = toXrayOutbound(sbOutbound)
    expect(xrayOut.protocol).toBe('vmess')
    expect(xrayOut.streamSettings.network).toBe('ws')
    expect(xrayOut.streamSettings.security).toBe('tls')
    expect(xrayOut.streamSettings.wsSettings.path).toBe('/ws')
  })

  it('translates Trojan + TLS', () => {
    const sbOutbound = {
      type: 'trojan',
      server: '1.2.3.4',
      server_port: 443,
      password: 'secretpassword',
      tls: {
        enabled: true,
        server_name: 'tr.example.com'
      }
    }

    const xrayOut = toXrayOutbound(sbOutbound)
    expect(xrayOut.protocol).toBe('trojan')
    expect(xrayOut.settings.servers[0].password).toBe('secretpassword')
    expect(xrayOut.streamSettings.security).toBe('tls')
  })

  it('supports dialerProxy for key probe routing', () => {
    const sbOutbound = {
      type: 'vless',
      server: '1.2.3.4',
      server_port: 443,
      uuid: 'abc'
    }

    const xrayOut = toXrayOutbound(sbOutbound, { dialerProxy: 'probe-direct-out' })
    expect(xrayOut.streamSettings.sockopt?.dialerProxy).toBe('probe-direct-out')
  })
})

describe('buildXrayConfig', () => {
  it('constructs a valid config with SOCKS inbound and routing', () => {
    const outbound = { protocol: 'freedom', tag: 'proxy' }
    const config = buildXrayConfig(outbound, 19999, { logPath: 'C:\\test\\xray.log' })

    expect(config.log.loglevel).toBe('warning')
    expect(config.inbounds[0].protocol).toBe('socks')
    expect(config.inbounds[0].port).toBe(19999)
    expect(config.inbounds[0].listen).toBe('127.0.0.1')
    expect(config.outbounds.some((o: any) => o.tag === 'proxy')).toBe(true)
    expect(config.outbounds.some((o: any) => o.tag === 'direct')).toBe(true)
    expect(config.routing.rules.some((r: any) => r.ip?.includes('geoip:private'))).toBe(true)
  })
})

describe('buildXrayProbeConfig', () => {
  it('attaches probe-direct-out when directProxy is provided', () => {
    const sbOutbound = {
      type: 'vless',
      server: '1.2.3.4',
      server_port: 443,
      uuid: 'abc'
    }

    const config = buildXrayProbeConfig(sbOutbound, 19998, {
      directProxy: { host: '127.0.0.1', port: 18000 }
    })

    const probeDirect = config.outbounds.find((o: any) => o.tag === 'probe-direct-out')
    expect(probeDirect).toBeDefined()
    expect(probeDirect.protocol).toBe('socks')
    expect(probeDirect.settings.servers[0].port).toBe(18000)
    expect(config.outbounds[0].streamSettings.sockopt.dialerProxy).toBe('probe-direct-out')
  })
})

describe('readRecentXrayOutboundFault', () => {
  it('detects REALITY verification failure from log', async () => {
    const tmp = join(tmpdir(), 'test-xray-log-fault1.log')
    const logContent = [
      '2026/09/02 12:00:00 [Warning] [12345] proxy: REALITY: processed invalid connection',
      '2026/09/02 12:00:01 [Warning] [12345] proxy: REALITY verification failed'
    ].join('\n')

    await writeFile(tmp, logContent, 'utf8')
    try {
      const fault = await readRecentXrayOutboundFault(tmp)
      expect(fault).toBe('reality-key-mismatch')
    } finally {
      await rm(tmp).catch(() => undefined)
    }
  })

  it('detects upstream unreachable from timeout log', async () => {
    const tmp = join(tmpdir(), 'test-xray-log-fault2.log')
    const logContent = [
      '2026/09/02 12:00:00 [Warning] [12345] dial tcp 1.2.3.4:443: i/o timeout',
      '2026/09/02 12:00:01 [Warning] [12345] dial tcp 1.2.3.4:443: connect: connection refused'
    ].join('\n')

    await writeFile(tmp, logContent, 'utf8')
    try {
      const fault = await readRecentXrayOutboundFault(tmp)
      expect(fault).toBe('upstream-unreachable')
    } finally {
      await rm(tmp).catch(() => undefined)
    }
  })
})
