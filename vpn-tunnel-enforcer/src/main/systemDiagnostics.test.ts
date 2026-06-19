import { describe, it, expect, vi } from 'vitest'
import type { ServerProfile } from '../shared/ipc-types'

vi.mock('electron', () => ({
  app: {
    getVersion: () => '1.1.0-test',
    getPath: () => '/tmp/vpnte-test',
    isPackaged: false
  }
}))
vi.mock('./admin', () => ({ isProcessElevated: vi.fn(async () => false) }))
vi.mock('./appLogger', () => ({
  getAppLogPath: () => '/tmp/vpnte-test/app.log',
  getLogDir: () => '/tmp/vpnte-test/logs',
  logEvent: vi.fn()
}))
vi.mock('./connectionPlanner', () => ({ getRoutingPlan: vi.fn(() => ({ verdict: 'unknown' })) }))
vi.mock('./leakDiagnostics', () => ({ runLeakCheck: vi.fn(async () => ({ items: [] })) }))
vi.mock('./settings', () => ({ settingsStore: { get: () => ({ proxyOverride: '', proxyType: 'socks5' }) } }))
vi.mock('./storeDiagnostics', () => ({ runStoreDiagnostics: vi.fn(async () => ({ items: [] })) }))
vi.mock('./ruleSetManager', () => ({ getSmartRouteRuleSetState: vi.fn() }))
vi.mock('./tunController', () => ({
  getTunRuntimeDir: () => '/tmp/vpnte-test/tun',
  parseProxyAddress: vi.fn(),
  probeTcp: vi.fn(),
  tunController: { getStatus: () => ({ running: false }) }
}))
vi.mock('./serverPicker', () => ({ getActiveProfile: vi.fn(() => null) }))

import { buildActiveProfileDiagnosticItems } from './systemDiagnostics'

function profile(partial: Partial<ServerProfile> & { outbound?: Record<string, any> }): ServerProfile {
  return {
    id: 'p1',
    name: 'test profile',
    protocol: partial.protocol || String(partial.outbound?.type || 'vless'),
    server: partial.server || String(partial.outbound?.server || 'example.com'),
    port: partial.port || Number(partial.outbound?.server_port || 443),
    status: 'unknown',
    outbound: partial.outbound,
    ...partial
  } as ServerProfile
}

describe('buildActiveProfileDiagnosticItems', () => {
  it('reports missing active profile without warning', () => {
    const [item] = buildActiveProfileDiagnosticItems(null)
    expect(item.id).toBe('active-profile-capabilities')
    expect(item.status).toBe('info')
    expect(item.value).toBe('no active profile')
  })

  it('reports Naive ECH stealth details', () => {
    const [item] = buildActiveProfileDiagnosticItems(profile({
      protocol: 'naive',
      outbound: {
        type: 'naive',
        server: 'naive.example.com',
        server_port: 443,
        tls: {
          enabled: true,
          server_name: 'front.example.com',
          ech: { enabled: true, config: ['abc'] }
        }
      }
    }))

    expect(item.status).toBe('info')
    expect(item.value).toContain('naive, stealth=naive-ech')
    expect(item.details).toContain('echConfigured=true')
  })

  it('warns for Hysteria2 profiles that need operator attention', () => {
    const [item] = buildActiveProfileDiagnosticItems(profile({
      protocol: 'hysteria2',
      outbound: {
        type: 'hysteria2',
        server: 'hy2.example.com',
        server_port: 443,
        network: 'tcp',
        server_ports: '8443:8450',
        hop_interval: '30s'
      }
    }))

    expect(item.status).toBe('warn')
    expect(item.value).toContain('hysteria2')
    expect(item.details).toContain('hy2Transport=QUIC/UDP')
    expect(item.details).toContain('hy2ServerPorts=8443:8450')
    expect(item.details).toContain('warning=Hysteria2 obfs is not configured')
    expect(item.details).toContain('warning=Hysteria2 uses QUIC/UDP; tcp-only routing can block it')
  })
})
