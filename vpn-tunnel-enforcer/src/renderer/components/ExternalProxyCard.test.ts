import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  EXTERNAL_PROXY_HEALTHY_REFRESH_INTERVAL_MS,
  EXTERNAL_PROXY_IDLE_REFRESH_INTERVAL_MS,
  EXTERNAL_PROXY_UNSTABLE_REFRESH_INTERVAL_MS,
  externalProxyRefreshIntervalMs
} from './ExternalProxyCard'
import type { ExternalProxyInstanceStatus, ExternalProxyStatus } from '../../shared/ipc-types'

function statusFor(instances: ExternalProxyInstanceStatus[]): ExternalProxyStatus {
  return { instances } as ExternalProxyStatus
}

function instanceFor(overrides: Partial<ExternalProxyInstanceStatus>): ExternalProxyInstanceStatus {
  return {
    slot: 1,
    running: true,
    processRunning: true,
    ready: true,
    health: 'healthy',
    state: 'healthy',
    generation: 1,
    egressIp: '203.0.113.10',
    latencyMs: 50,
    lastCheckedAt: Date.now(),
    lastSuccessAt: Date.now(),
    egressCheckedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    lastError: null,
    lastErrorAt: null,
    degradationReason: null,
    consecutiveFailures: 0,
    nextCheckAt: new Date().toISOString(),
    lastRotateReason: null,
    autoDisabled: false,
    host: '127.0.0.1',
    port: 17990,
    proxyUrl: 'socks5://127.0.0.1:17990',
    profileId: 'profile-1',
    profileName: 'profile-1',
    country: 'DE',
    pid: 1234,
    startedAt: new Date().toISOString(),
    ...overrides
  }
}

describe('external proxy UI refresh policy', () => {
  it('backs off while no proxy instance is running', () => {
    expect(externalProxyRefreshIntervalMs(statusFor([]))).toBe(EXTERNAL_PROXY_IDLE_REFRESH_INTERVAL_MS)
  })

  it('keeps healthy running routes visibly fresh without polling every five seconds', () => {
    expect(externalProxyRefreshIntervalMs(statusFor([instanceFor({})]))).toBe(EXTERNAL_PROXY_HEALTHY_REFRESH_INTERVAL_MS)
  })

  it('refreshes a starting or unhealthy route more quickly', () => {
    expect(externalProxyRefreshIntervalMs(statusFor([
      instanceFor({ ready: false, health: 'starting', state: 'starting' })
    ]))).toBe(EXTERNAL_PROXY_UNSTABLE_REFRESH_INTERVAL_MS)
  })

  it('keeps disabled routes on the slower health refresh cadence', () => {
    expect(externalProxyRefreshIntervalMs(statusFor([
      instanceFor({ processRunning: false, running: false, autoDisabled: true, health: 'failed', state: 'failed' })
    ]))).toBe(EXTERNAL_PROXY_HEALTHY_REFRESH_INTERVAL_MS)
  })
})

describe('explicit external proxy assignment', () => {
  const cardSource = readFileSync(join(process.cwd(), 'src', 'renderer', 'components', 'ExternalProxyCard.tsx'), 'utf8')
  const serversSource = readFileSync(join(process.cwd(), 'src', 'renderer', 'pages', 'Servers.tsx'), 'utf8')

  it('requires a selected profile when starting a new proxy slot', () => {
    expect(cardSource).toContain('label="Сервер для нового прокси"')
    expect(cardSource).toContain('externalProxyStart({ slot, profileId })')
    expect(cardSource).not.toContain('externalProxyStart({ slot })')
  })

  it('starts exactly one selected server from its row action', () => {
    expect(serversSource).toContain('externalProxyStartProfiles([profile.id])')
    expect(serversSource).toContain('Запустить этот сервер как внешний прокси')
  })

  it('separates removed subscription servers and excludes them from group proxy starts', () => {
    expect(serversSource).toContain("t('servers.groups.removedServers')")
    expect(serversSource).toContain('profile.removedFromSubscriptionAt')
    expect(serversSource).toContain('externalProxyStartProfiles(availableProfiles.map')
    expect(serversSource).toContain('startingProxy || isActive || staleFromSub')
  })
})

describe('dashboard rendering regressions', () => {
  const source = readFileSync(join(process.cwd(), 'src', 'renderer', 'pages', 'Dashboard.tsx'), 'utf8')

  it('keeps the uptime timer inside a dedicated child instead of rerendering Dashboard every second', () => {
    const dashboardStart = source.indexOf('export function Dashboard')
    const dashboardSource = source.slice(dashboardStart)

    expect(source).toContain('function UptimeLabel')
    expect(dashboardSource).toContain('<UptimeLabel startedAt={tunStartedAt} />')
    expect(dashboardSource).not.toContain('const [now, setNow]')
  })

  it('uses a one-shot connected state animation rather than an infinite pulse', () => {
    expect(source).toContain("transition={{ duration: 0.6, ease: 'easeOut' }}")
    expect(source).not.toContain("duration: 2, repeat: Infinity, ease: 'easeOut'")
  })
})
