/**
 * Tests for keyHealthChecker.describeProbeTarget — specifically the
 * tlsLeaksSni classification (D4). A TLS handshake to a plain-TLS key would
 * leak the provider's real front SNI on a direct path; Reality keys carry a
 * camouflage SNI and are safe. The probe must only run the TLS rung when it
 * won't leak.
 */

import { describe, it, expect, vi } from 'vitest'

vi.mock('electron-store', () => ({ default: class { get() { return [] } set() {} } }))
vi.mock('socks', () => ({ SocksClient: { createConnection: vi.fn() } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./tunController', () => ({
  tunController: { getStatus: () => ({ running: false }) },
  getDirectProxyPort: () => null
}))

import { describeProbeTarget } from './keyHealthChecker'
import type { ServerProfile } from '../shared/ipc-types'

function profile(outbound: Record<string, any>): ServerProfile {
  return {
    id: 'p', name: 'p', protocol: 'vless',
    server: outbound.server, port: outbound.server_port,
    status: 'unknown', ping: null, outbound
  } as unknown as ServerProfile
}

describe('describeProbeTarget tlsLeaksSni', () => {
  it('plain TLS leaks SNI → tlsLeaksSni true, needsTls true', () => {
    const t = describeProbeTarget(profile({
      server: 'real.feodorn.com', server_port: 443,
      tls: { enabled: true, server_name: 'real.feodorn.com' }
    }))!
    expect(t.needsTls).toBe(true)
    expect(t.tlsLeaksSni).toBe(true)
  })

  it('Reality SNI is camouflage → tlsLeaksSni false', () => {
    const t = describeProbeTarget(profile({
      server: 'vpn.example.com', server_port: 443,
      tls: { enabled: true, server_name: 'www.microsoft.com', reality: { enabled: true, public_key: 'k' } }
    }))!
    expect(t.needsTls).toBe(true)
    expect(t.tlsLeaksSni).toBe(false)
  })

  it('no TLS (shadowsocks) → needsTls false, tlsLeaksSni false', () => {
    const t = describeProbeTarget(profile({
      server: '1.2.3.4', server_port: 8388, method: 'aes-256-gcm', password: 'x'
    }))!
    expect(t.needsTls).toBe(false)
    expect(t.tlsLeaksSni).toBe(false)
  })

  it('picks Reality server_name from tls.server_name', () => {
    const t = describeProbeTarget(profile({
      server: 'vpn.example.com', server_port: 443,
      tls: { enabled: true, server_name: 'cdn.cloudflare.com', reality: { enabled: true } }
    }))!
    expect(t.serverName).toBe('cdn.cloudflare.com')
  })

  it('returns null when host/port missing', () => {
    expect(describeProbeTarget(profile({ server: '', server_port: 0 }))).toBeNull()
  })
})
