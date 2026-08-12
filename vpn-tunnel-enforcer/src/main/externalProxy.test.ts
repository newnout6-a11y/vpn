import { EventEmitter } from 'node:events'
import { createServer } from 'node:net'
import { describe, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import type { ServerProfile } from '../shared/ipc-types'

const ensureKillSwitchProgramAllowedMock = vi.hoisted(() => vi.fn(async () => ({ success: true, message: 'ok' })))
const spawnMock = vi.hoisted(() => vi.fn())
const probeExternalProxyMock = vi.hoisted(() => vi.fn())
const createHttpServerMock = vi.hoisted(() => vi.fn(() => ({
  once: vi.fn().mockReturnThis(),
  close: vi.fn((callback?: (error?: Error) => void) => callback?.()),
  listen: vi.fn((_port: number, _host: string, callback?: () => void) => callback?.())
})))
const fsPromisesMock = vi.hoisted(() => ({
  access: vi.fn(async () => undefined),
  copyFile: vi.fn(async () => undefined),
  mkdir: vi.fn(async () => undefined),
  stat: vi.fn(async () => { throw new Error('not staged') }),
  writeFile: vi.fn(async () => undefined)
}))

vi.mock('child_process', () => ({
  default: { spawn: spawnMock },
  spawn: spawnMock
}))

vi.mock('http', () => ({
  createServer: createHttpServerMock,
  default: { createServer: createHttpServerMock }
}))

vi.mock('fs/promises', () => ({ ...fsPromisesMock, default: fsPromisesMock }))

vi.mock('./managedChildProcess', () => ({
  cleanupManagedChildPidFile: vi.fn(async () => true),
  removeManagedChildPidFile: vi.fn(async () => undefined),
  writeManagedChildPidFile: vi.fn(async () => undefined)
}))

vi.mock('electron', () => ({
  app: {
    getPath: () => '/tmp/vpnte-test',
    getAppPath: () => '/tmp/vpnte-test/app',
    isPackaged: false
  }
}))

vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))

vi.mock('./firewallKillSwitch', () => ({
  ensureKillSwitchProgramAllowed: ensureKillSwitchProgramAllowedMock
}))

vi.mock('./externalProxyHealth', () => ({
  probeExternalProxy: probeExternalProxyMock,
  externalProxyHealthErrorMessage: (error: unknown) => error instanceof Error ? error.message : String(error),
  isRecoverableExternalProxyTransportError: (error: unknown) => /timeout|timed out|eof/i.test(error instanceof Error ? error.message : String(error))
}))

vi.mock('./serverPicker', () => ({
  serverPicker: {
    getProfiles: vi.fn(() => []),
    getActiveProfileId: vi.fn(() => null),
    getActiveProfile: vi.fn(() => null),
    selectProfile: vi.fn()
  }
}))

import {
  buildExternalProxyConfig,
  checkExternalProxyHealth,
  externalProxyPortForSlot,
  externalProxy,
  getExternalProxyAggregate,
  getExternalProxyStatus,
  isExternalProxyMutationPath,
  isValidExternalProxyControlToken,
  listExternalProxyProfiles,
  MAX_EXTERNAL_PROXY_SLOT,
  pickExternalProxyProfile,
  releaseExternalProxyReservation,
  renewExternalProxyReservation,
  reserveExternalProxy
} from './externalProxy'
import { serverPicker } from './serverPicker'

const source = readFileSync(join(process.cwd(), 'src/main/externalProxy.ts'), 'utf8')

function sampleProfile(): ServerProfile {
  return {
    id: 'profile-1',
    name: 'sample',
    country: 'Netherlands',
    protocol: 'vless',
    server: '203.0.113.10',
    port: 443,
    status: 'unknown',
    outbound: {
      type: 'vless',
      tag: 'original-tag',
      server: '203.0.113.10',
      server_port: 443,
      uuid: '00000000-0000-4000-8000-000000000000',
      tls: { enabled: true }
    }
  } as ServerProfile
}

function sampleProfiles(count: number): ServerProfile[] {
  return Array.from({ length: count }, (_, index) => ({
    ...sampleProfile(),
    id: `profile-${index + 1}`,
    name: `profile-${index + 1}`
  }))
}

function fakeChild(pid: number, check: boolean) {
  const process = new EventEmitter() as any
  process.pid = pid
  process.killed = false
  process.stdout = new EventEmitter()
  process.stderr = new EventEmitter()
  process.kill = vi.fn(() => {
    process.killed = true
    queueMicrotask(() => process.emit('exit', 0, null))
    return true
  })
  if (check) queueMicrotask(() => process.emit('exit', 0, null))
  return process
}

async function freeLoopbackPort(): Promise<number> {
  const server = createServer()
  const port = await new Promise<number>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      resolve(typeof address === 'object' && address ? address.port : 0)
    })
  })
  await new Promise<void>((resolve, reject) => server.close((err) => err ? reject(err) : resolve()))
  return port
}

describe('buildExternalProxyConfig', () => {
  it('uses sing-box 1.13 sniff route actions instead of legacy inbound sniff fields', () => {
    const config = buildExternalProxyConfig(sampleProfile(), 17990) as any
    const inbound = config.inbounds.find((item: any) => item.tag === 'external-mixed-in')

    expect(inbound).toMatchObject({
      type: 'mixed',
      listen: '127.0.0.1',
      listen_port: 17990
    })
    expect(inbound).not.toHaveProperty('sniff')
    expect(inbound).not.toHaveProperty('sniff_override_destination')
    expect(config.route.rules[0]).toEqual({ action: 'sniff' })
    expect(config.route.rules).toContainEqual({ domain: ['localhost'], outbound: 'direct-out' })
    expect(config.route.rules).toContainEqual({ domain_suffix: ['localhost'], outbound: 'direct-out' })
    expect(config.route.rules).toContainEqual({ ip_cidr: ['127.0.0.0/8', '::1/128'], outbound: 'direct-out' })
    expect(config.route.rules).toContainEqual({ ip_is_private: true, outbound: 'direct-out' })
    expect(config.route.rules).toContainEqual({
      inbound: 'external-mixed-in',
      protocol: 'dns',
      outbound: 'proxy-out'
    })
    expect(config.route.final).toBe('block-out')
    expect(config.outbounds[0].tag).toBe('proxy-out')
  })

  it('bootstraps hostname endpoints directly without changing proxied DNS routing or TLS SNI', () => {
    const profile = sampleProfile()
    profile.outbound = {
      ...profile.outbound,
      server: 'nl9.netfix.app',
      domain_strategy: 'prefer_ipv4',
      tls: { enabled: true, server_name: 'cdn.example.test' }
    }

    const config = buildExternalProxyConfig(profile, 17990) as any
    const outbound = config.outbounds[0]

    expect(config.dns.strategy).toBe('ipv4_only')
    expect(config.dns.final).toBe('dns-bootstrap')
    expect(config.dns.servers).toEqual(expect.arrayContaining([
      { type: 'udp', tag: 'dns-bootstrap', server: '1.1.1.1' }
    ]))
    expect(config.route.default_domain_resolver).toBe('dns-bootstrap')
    expect(config.route.rules).toContainEqual({
      inbound: 'external-mixed-in',
      protocol: 'dns',
      outbound: 'proxy-out'
    })
    expect(outbound.domain_resolver).toEqual({ server: 'dns-bootstrap', strategy: 'prefer_ipv4' })
    expect(outbound.tls.server_name).toBe('cdn.example.test')
    expect(profile.outbound.server).toBe('nl9.netfix.app')
    expect((profile.outbound as any).domain_strategy).toBe('prefer_ipv4')
  })

  it('does not add a DNS bootstrap block for IP endpoints', () => {
    const config = buildExternalProxyConfig(sampleProfile(), 17990) as any

    expect(config.dns).toBeUndefined()
    expect(config.route.default_domain_resolver).toBeUndefined()
    expect(config.outbounds[0].domain_resolver).toBeUndefined()
  })
})

describe('listExternalProxyProfiles', () => {
  it('does not treat the main active VPN profile as the external proxy selection', () => {
    vi.mocked(serverPicker.getProfiles).mockReturnValue([sampleProfile()])
    vi.mocked(serverPicker.getActiveProfileId).mockReturnValue('profile-1')

    expect(listExternalProxyProfiles()).toMatchObject([
      {
        id: 'profile-1',
        status: 'unknown',
        pingMs: null,
        lastCheckedAt: null,
        selectedForVpn: true,
        active: false
      }
    ])
  })

  it('excludes profiles removed from their source subscription', () => {
    const removed = sampleProfile()
    removed.removedFromSubscriptionAt = Date.now()
    removed.enabled = true
    vi.mocked(serverPicker.getProfiles).mockReturnValue([removed])

    expect(listExternalProxyProfiles()).toEqual([])
    expect(pickExternalProxyProfile([removed], { profileId: removed.id })).toBeNull()
  })
})

describe('external proxy slots', () => {
  it('assigns a distinct default port beyond the old ten-slot boundary', () => {
    const ports = Array.from({ length: 100 }, (_, index) => externalProxyPortForSlot(index + 1))

    expect(ports[0]).toBe(17990)
    expect(ports[9]).toBe(17999)
    expect(ports[99]).toBe(18089)
    expect(new Set(ports)).toHaveLength(100)
    expect(() => externalProxyPortForSlot(0)).toThrow(RangeError)
    expect(() => externalProxyPortForSlot(MAX_EXTERNAL_PROXY_SLOT + 1)).toThrow(RangeError)
  })

  it('keeps the legacy primary instance without allocating placeholder slots', () => {
    const status = getExternalProxyStatus()

    expect(status.slot).toBe(1)
    expect(status.maxInstances).toBeNull()
    expect(status.instances).toEqual([])
  })

  it('keeps separate slots in independent sing-box processes', async () => {
    vi.mocked(serverPicker.getProfiles).mockReturnValue([sampleProfile()])
    let pid = 31000
    spawnMock.mockImplementation((_exe: string, args: string[]) => fakeChild(pid++, args[0] === 'check'))
    const [firstPort, secondPort] = await Promise.all([freeLoopbackPort(), freeLoopbackPort()])

    const first = await externalProxy.start({ slot: 1, port: firstPort, action: 'start' })
    const second = await externalProxy.start({ slot: 2, port: secondPort, action: 'start' })
    const runningConfigs = spawnMock.mock.calls
      .filter(([, args]) => args[0] === 'run')
      .map(([, args]) => args[2])

    expect(first).toMatchObject({ slot: 1, processRunning: true, running: false, health: 'starting', port: firstPort })
    expect(second).toMatchObject({ slot: 2, processRunning: true, running: false, health: 'starting', port: secondPort })
    expect(second.instances.filter((instance) => instance.processRunning)).toMatchObject([
      { slot: 1, port: firstPort },
      { slot: 2, port: secondPort }
    ])
    expect(first.pid).not.toBe(second.pid)
    expect(second.instances.map((instance) => instance.pid)).toEqual([first.pid, second.pid])
    expect(runningConfigs).toEqual([
      expect.stringContaining('external-proxy.json'),
      expect.stringContaining('external-proxy-2.json')
    ])

    await externalProxy.stop(1, 'test cleanup')
    await externalProxy.stop(2, 'test cleanup')
  })

  it('reports data-plane health separately from a live child process', async () => {
    const profile = sampleProfile()
    vi.mocked(serverPicker.getProfiles).mockReturnValue([profile])
    spawnMock.mockImplementation((_exe: string, args: string[]) => fakeChild(32000, args[0] === 'check'))
    probeExternalProxyMock.mockResolvedValueOnce({ egressIp: '198.51.100.42', latencyMs: 123 })
    const port = await freeLoopbackPort()

    const starting = await externalProxy.start({ slot: 1, port, action: 'start' })
    expect(starting).toMatchObject({ processRunning: true, running: false, health: 'starting' })

    const healthy = await checkExternalProxyHealth(1)
    expect(healthy).toMatchObject({
      processRunning: true,
      running: true,
      health: 'healthy',
      egressIp: '198.51.100.42',
      latencyMs: 123
    })
    expect(healthy.lastCheckedAt).toEqual(expect.any(Number))
    expect(healthy.lastSuccessAt).toEqual(expect.any(Number))

    await externalProxy.stop(1, 'test cleanup')
  })

  it('keeps a failed proxy controllable and reports its transport error', async () => {
    const profile = sampleProfile()
    vi.mocked(serverPicker.getProfiles).mockReturnValue([profile])
    spawnMock.mockImplementation((_exe: string, args: string[]) => fakeChild(32500, args[0] === 'check'))
    probeExternalProxyMock.mockRejectedValueOnce(new Error('ConnectTimeout after 10000ms'))
    const port = await freeLoopbackPort()

    await externalProxy.start({ slot: 1, port, action: 'start' })
    const unhealthy = await checkExternalProxyHealth(1)

    expect(unhealthy).toMatchObject({
      processRunning: true,
      running: false,
      health: 'degraded',
      proxyUrl: `http://127.0.0.1:${port}`
    })
    expect(unhealthy.lastError).toContain('ConnectTimeout')

    await externalProxy.stop(1, 'test cleanup')
  })

  it('does not let repeated runtime timeouts bypass a degraded route cooldown', async () => {
    vi.useFakeTimers()
    let started = false
    try {
      const profile = sampleProfile()
      vi.mocked(serverPicker.getProfiles).mockReturnValue([profile])
      spawnMock.mockClear()
      probeExternalProxyMock.mockReset()
      spawnMock.mockImplementation((_exe: string, args: string[]) => fakeChild(32550, args[0] === 'check'))
      probeExternalProxyMock.mockRejectedValue(new Error('ConnectTimeout after 10000ms'))

      await externalProxy.start({ slot: 1, port: 17990, action: 'start' })
      started = true
      await checkExternalProxyHealth(1)

      const runCall = spawnMock.mock.calls.findIndex(([, args]) => args[0] === 'run')
      const child = spawnMock.mock.results[runCall]?.value as ReturnType<typeof fakeChild>
      for (let index = 0; index < 20; index += 1) {
        child.stderr.emit('data', 'context deadline exceeded')
      }

      expect(probeExternalProxyMock).toHaveBeenCalledTimes(1)
      await vi.advanceTimersByTimeAsync(14_999)
      expect(probeExternalProxyMock).toHaveBeenCalledTimes(1)
    } finally {
      if (started) await externalProxy.stop(1, 'test cleanup')
      vi.useRealTimers()
    }
  })

  it('uses an exponential cooldown without restarting a dead route', async () => {
    vi.useFakeTimers()
    let started = false
    try {
      const profile = sampleProfile()
      vi.mocked(serverPicker.getProfiles).mockReturnValue([profile])
      let pid = 32600
      spawnMock.mockClear()
      spawnMock.mockImplementation((_exe: string, args: string[]) => fakeChild(pid++, args[0] === 'check'))
      probeExternalProxyMock.mockRejectedValue(new Error('ConnectTimeout after 10000ms'))

      await externalProxy.start({ slot: 1, port: 17990, action: 'start' })
      started = true
      await checkExternalProxyHealth(1)
      await checkExternalProxyHealth(1)
      await checkExternalProxyHealth(1)

      const degraded = externalProxy.status(1)
      expect(degraded).toMatchObject({
        processRunning: true,
        health: 'degraded',
        consecutiveFailures: 3
      })
      expect(degraded.nextCheckAt).toEqual(expect.any(String))

      await vi.advanceTimersByTimeAsync(59_999)

      expect(spawnMock.mock.calls.filter(([, args]) => args[0] === 'run')).toHaveLength(1)

    } finally {
      if (started) await externalProxy.stop(1, 'test cleanup')
      vi.useRealTimers()
    }
  })

  it('disables a slot after the bounded health-failure budget without restarting it', async () => {
    vi.useFakeTimers()
    let started = false
    try {
      const profile = sampleProfile()
      vi.mocked(serverPicker.getProfiles).mockReturnValue([profile])
      let pid = 32700
      spawnMock.mockClear()
      spawnMock.mockImplementation((_exe: string, args: string[]) => fakeChild(pid++, args[0] === 'check'))
      probeExternalProxyMock.mockRejectedValue(new Error('EOF'))

      await externalProxy.start({ slot: 1, port: 17990, action: 'start' })
      started = true
      await checkExternalProxyHealth(1)
      await checkExternalProxyHealth(1)
      await checkExternalProxyHealth(1)
      await checkExternalProxyHealth(1)
      await vi.advanceTimersByTimeAsync(0)

      const disabled = externalProxy.status(1)
      expect(disabled).toMatchObject({
        processRunning: false,
        running: false,
        health: 'failed',
        autoDisabled: true,
        profileId: profile.id
      })
      expect(disabled.lastError).toContain('EOF')
      expect(spawnMock.mock.calls.filter(([, args]) => args[0] === 'run')).toHaveLength(1)
    } finally {
      if (started) await externalProxy.stop(1, 'test cleanup')
      vi.useRealTimers()
    }
  })

  it('starts one proxy per selected usable profile and leaves the active VPN profile alone', async () => {
    const primary = sampleProfile()
    const second = { ...sampleProfile(), id: 'profile-2', name: 'second' }
    const third = { ...sampleProfile(), id: 'profile-3', name: 'third' }
    vi.mocked(serverPicker.getProfiles).mockReturnValue([primary, second, third])
    vi.mocked(serverPicker.getActiveProfileId).mockReturnValue(primary.id)
    let pid = 33000
    spawnMock.mockClear()
    fsPromisesMock.writeFile.mockClear()
    spawnMock.mockImplementation((_exe: string, args: string[]) => fakeChild(pid++, args[0] === 'check'))

    const result = await externalProxy.startProfiles([primary.id, second.id, third.id])

    expect(result.started).toMatchObject([
      { slot: 1, profileId: second.id, port: 17990 },
      { slot: 2, profileId: third.id, port: 17991 }
    ])
    expect(result.skipped).toEqual([{ profileId: primary.id, reason: 'active-vpn' }])
    expect(result.failed).toEqual([])
    expect(spawnMock.mock.calls.filter(([, args]) => args[0] === 'run')).toHaveLength(2)
    expect(result.started[0].pid).not.toBe(result.started[1].pid)
    const runtimeWrites = fsPromisesMock.writeFile.mock.calls as unknown as Array<[string, string]>
    const firstConfigWrite = runtimeWrites.find(([path]) => String(path).endsWith('external-proxy.json'))
    const secondConfigWrite = runtimeWrites.find(([path]) => String(path).endsWith('external-proxy-2.json'))
    expect(firstConfigWrite).toBeDefined()
    expect(secondConfigWrite).toBeDefined()
    expect(JSON.parse(String(firstConfigWrite?.[1])).inbounds).toMatchObject([
      { tag: 'external-mixed-in', listen_port: 17990 }
    ])
    expect(JSON.parse(String(secondConfigWrite?.[1])).inbounds).toMatchObject([
      { tag: 'external-mixed-in', listen_port: 17991 }
    ])

    await externalProxy.stop(1, 'test cleanup')
    await externalProxy.stop(2, 'test cleanup')
  })

  it('stops every running external proxy in one batch operation', async () => {
    const first = sampleProfile()
    const second = { ...sampleProfile(), id: 'profile-stop-all-2', name: 'second' }
    const third = { ...sampleProfile(), id: 'profile-stop-all-3', name: 'third' }
    vi.mocked(serverPicker.getProfiles).mockReturnValue([first, second, third])
    vi.mocked(serverPicker.getActiveProfileId).mockReturnValue(null)
    let pid = 34000
    spawnMock.mockImplementation((_exe: string, args: string[]) => fakeChild(pid++, args[0] === 'check'))

    const started = await externalProxy.startProfiles([first.id, second.id, third.id])
    expect(started.started).toHaveLength(3)

    const stopped = await externalProxy.stopAll('test stop all')

    expect(stopped.instances).toEqual([])
    expect(stopped.running).toBe(false)
    expect(spawnMock.mock.results.length).toBeGreaterThanOrEqual(6)
  })

  it('counts capacity only after 30 distinct instances pass fresh unique egress checks', async () => {
    const profiles = sampleProfiles(30)
    vi.mocked(serverPicker.getProfiles).mockReturnValue(profiles)
    vi.mocked(serverPicker.getActiveProfileId).mockReturnValue(null)
    let pid = 35000
    spawnMock.mockClear()
    spawnMock.mockImplementation((_exe: string, args: string[]) => fakeChild(pid++, args[0] === 'check'))
    probeExternalProxyMock.mockImplementation(async (proxyUrl: string) => ({
      egressIp: `198.51.100.${Number(new URL(proxyUrl).port) - 17989}`,
      latencyMs: 1
    }))

    const prewarmed = await externalProxy.prewarm(30)

    expect(prewarmed.ready).toBe(true)
    expect(prewarmed.aggregate).toMatchObject({
      total: 30,
      running: 30,
      ready: 30,
      healthy: 30,
      uniqueEgress: 30,
      duplicateEgress: 0,
      starting: 0,
      degraded: 0,
      quarantined: 0
    })
    expect(new Set(prewarmed.instances.map((instance) => instance.proxyUrl)).size).toBe(30)
    expect(new Set(prewarmed.instances.map((instance) => instance.egressIp)).size).toBe(30)
    expect(prewarmed.instances.every((instance) => instance.ready && instance.health === 'healthy' && instance.egressCheckedAt)).toBe(true)

    const reservations = await Promise.all(Array.from({ length: 30 }, (_, index) => reserveExternalProxy({
      owner: `buyer-worker-${index + 1}`,
      ttlSeconds: 120
    })))
    expect(new Set(reservations.map((reservation) => reservation.instance.slot)).size).toBe(30)
    expect(new Set(reservations.map((reservation) => reservation.leaseToken)).size).toBe(30)
    await Promise.all(reservations.map((reservation) => releaseExternalProxyReservation(reservation.leaseToken)))
    await externalProxy.stopAll('test cleanup')
  })

  it('falls back from an occupied signup IP and enforces lease tokens atomically', async () => {
    const profiles = sampleProfiles(3)
    vi.mocked(serverPicker.getProfiles).mockReturnValue(profiles)
    vi.mocked(serverPicker.getActiveProfileId).mockReturnValue(null)
    let pid = 36000
    spawnMock.mockImplementation((_exe: string, args: string[]) => fakeChild(pid++, args[0] === 'check'))
    probeExternalProxyMock.mockImplementation(async (proxyUrl: string) => ({
      egressIp: `198.51.100.${Number(new URL(proxyUrl).port) - 17989}`,
      latencyMs: 1
    }))

    await externalProxy.prewarm(3)
    const preferred = await reserveExternalProxy({
      owner: 'buyer-worker-1',
      preferredEgressIp: '198.51.100.2',
      ttlSeconds: 120
    })
    expect(preferred.instance.egressIp).toBe('198.51.100.2')
    await expect(externalProxy.rotate({ slot: preferred.instance.slot, idempotencyKey: 'leased-rotation' }))
      .rejects.toMatchObject({ statusCode: 409 })
    expect(getExternalProxyStatus(preferred.instance.slot)).toMatchObject({
      generation: preferred.instance.generation,
      proxyUrl: preferred.instance.proxyUrl,
      egressIp: preferred.instance.egressIp
    })

    const fallback = await reserveExternalProxy({
      owner: 'buyer-worker-2',
      preferredEgressIp: '198.51.100.2',
      preferredSlot: preferred.instance.slot,
      allowFallback: true,
      ttlSeconds: 120
    })
    expect(fallback.instance.slot).not.toBe(preferred.instance.slot)
    expect(fallback.instance.egressIp).not.toBe(preferred.instance.egressIp)
    await expect(reserveExternalProxy({
      owner: 'buyer-worker-3',
      slot: preferred.instance.slot,
      allowFallback: false
    })).rejects.toMatchObject({ statusCode: 409 })
    await expect(releaseExternalProxyReservation('wrong-token')).rejects.toMatchObject({ statusCode: 403 })

    const renewed = await renewExternalProxyReservation(preferred.leaseToken, 120)
    expect(renewed.leaseToken).toBe(preferred.leaseToken)
    await releaseExternalProxyReservation(preferred.leaseToken)
    const restored = await reserveExternalProxy({ owner: 'buyer-worker-1', ttlSeconds: 120 })
    expect(restored.instance.slot).toBe(preferred.instance.slot)
    await Promise.all([fallback, restored].map((reservation) => releaseExternalProxyReservation(reservation.leaseToken)))
    await externalProxy.stopAll('test cleanup')
  })

  it('automatically frees an expired lease before the next reservation', async () => {
    vi.useFakeTimers()
    let activeLeaseToken: string | null = null
    try {
      const profile = sampleProfile()
      vi.mocked(serverPicker.getProfiles).mockReturnValue([profile])
      vi.mocked(serverPicker.getActiveProfileId).mockReturnValue(null)
      spawnMock.mockImplementation((_exe: string, args: string[]) => fakeChild(36500, args[0] === 'check'))
      probeExternalProxyMock.mockResolvedValue({ egressIp: '198.51.100.50', latencyMs: 1 })
      await externalProxy.start({ slot: 1, profileId: profile.id, action: 'start' })
      await checkExternalProxyHealth(1)

      const first = await reserveExternalProxy({ owner: 'expiry-owner', slot: 1, ttlSeconds: 1, allowFallback: false })
      activeLeaseToken = first.leaseToken
      await vi.advanceTimersByTimeAsync(1_001)
      const second = await reserveExternalProxy({ owner: 'next-owner', slot: 1, ttlSeconds: 120, allowFallback: false })
      expect(second.instance.slot).toBe(1)
      activeLeaseToken = second.leaseToken
    } finally {
      if (activeLeaseToken) await releaseExternalProxyReservation(activeLeaseToken).catch(() => undefined)
      await externalProxy.stop(1, 'test cleanup').catch(() => undefined)
      vi.useRealTimers()
    }
  })

  it('quarantines duplicate egress and rotates only the requested slot', async () => {
    const profiles = sampleProfiles(3)
    vi.mocked(serverPicker.getProfiles).mockReturnValue(profiles)
    vi.mocked(serverPicker.getActiveProfileId).mockReturnValue(null)
    let pid = 37000
    spawnMock.mockClear()
    spawnMock.mockImplementation((_exe: string, args: string[]) => fakeChild(pid++, args[0] === 'check'))

    probeExternalProxyMock.mockResolvedValueOnce({ egressIp: '198.51.100.10', latencyMs: 1 })
    probeExternalProxyMock.mockResolvedValueOnce({ egressIp: '198.51.100.10', latencyMs: 1 })
    await externalProxy.start({ slot: 1, profileId: profiles[0].id, action: 'start' })
    await externalProxy.start({ slot: 2, profileId: profiles[1].id, action: 'start' })
    await checkExternalProxyHealth(1)
    const duplicate = await checkExternalProxyHealth(2)
    expect(duplicate).toMatchObject({ ready: false, health: 'quarantined', state: 'quarantined', degradationReason: 'duplicate-egress-ip' })
    expect(getExternalProxyAggregate()).toMatchObject({ ready: 1, uniqueEgress: 1, duplicateEgress: 1, quarantined: 1 })
    await externalProxy.stop(1, 'test cleanup')
    await externalProxy.stop(2, 'test cleanup')

    probeExternalProxyMock.mockResolvedValueOnce({ egressIp: '198.51.100.21', latencyMs: 1 })
    probeExternalProxyMock.mockResolvedValueOnce({ egressIp: '198.51.100.22', latencyMs: 1 })
    probeExternalProxyMock.mockResolvedValueOnce({ egressIp: '198.51.100.23', latencyMs: 1 })
    await externalProxy.start({ slot: 1, profileId: profiles[0].id, action: 'start' })
    await externalProxy.start({ slot: 2, profileId: profiles[1].id, action: 'start' })
    await checkExternalProxyHealth(1)
    await checkExternalProxyHealth(2)
    const untouchedBefore = getExternalProxyStatus(2)
    const runCountBeforeRotation = spawnMock.mock.calls.filter(([, args]) => args[0] === 'run').length

    const rotated = await externalProxy.rotate({ slot: 1, idempotencyKey: 'rotation-1', rotateReason: 'test' })
    const untouchedAfter = getExternalProxyStatus(2)
    expect(rotated).toMatchObject({ ready: true, health: 'healthy', egressIp: '198.51.100.23', lastRotateReason: 'test' })
    expect(rotated.generation).toBeGreaterThan(1)
    expect(untouchedAfter.instances.find((instance) => instance.slot === 2)).toMatchObject({
      slot: untouchedBefore.slot,
      proxyUrl: untouchedBefore.proxyUrl,
      egressIp: untouchedBefore.egressIp,
      generation: untouchedBefore.generation,
      profileId: untouchedBefore.profileId,
      port: untouchedBefore.port,
      pid: untouchedBefore.pid
    })
    await externalProxy.rotate({ slot: 1, idempotencyKey: 'rotation-1', rotateReason: 'ignored' })
    expect(spawnMock.mock.calls.filter(([, args]) => args[0] === 'run')).toHaveLength(runCountBeforeRotation + 1)
    await externalProxy.stop(1, 'test cleanup')
    await externalProxy.stop(2, 'test cleanup')
  })
})

describe('external proxy control auth helpers', () => {
  it('classifies state-changing control paths', () => {
    expect(isExternalProxyMutationPath('/start')).toBe(true)
    expect(isExternalProxyMutationPath('/rotate')).toBe(true)
    expect(isExternalProxyMutationPath('/connect')).toBe(true)
    expect(isExternalProxyMutationPath('/connect-profiles')).toBe(true)
    expect(isExternalProxyMutationPath('/trigger')).toBe(true)
    expect(isExternalProxyMutationPath('/stop')).toBe(true)
    expect(isExternalProxyMutationPath('/healthcheck')).toBe(true)
    expect(isExternalProxyMutationPath('/profiles/healthcheck')).toBe(true)
    expect(isExternalProxyMutationPath('/instances/prewarm')).toBe(true)
    expect(isExternalProxyMutationPath('/instances/status-batch')).toBe(true)
    expect(isExternalProxyMutationPath('/instances/reserve')).toBe(true)
    expect(isExternalProxyMutationPath('/instances/renew')).toBe(true)
    expect(isExternalProxyMutationPath('/instances/release')).toBe(true)
    expect(isExternalProxyMutationPath('/status')).toBe(false)
    expect(isExternalProxyMutationPath('/list')).toBe(false)
  })

  it('requires an exact session token for protected control calls', () => {
    expect(isValidExternalProxyControlToken('abc123', 'abc123')).toBe(true)
    expect(isValidExternalProxyControlToken('abc123', 'abc124')).toBe(false)
    expect(isValidExternalProxyControlToken('abc123', '')).toBe(false)
    expect(isValidExternalProxyControlToken(null, 'abc123')).toBe(false)
  })
})

describe('external proxy runtime isolation', () => {
  it('ensures a kill-switch bypass before replacing one instance process', () => {
    const bypassIndex = source.indexOf('const firewallBypass = await ensureExternalProxyFirewallAllowed')
    const stopIndex = source.indexOf('await stopExternalProxyProcessUnlocked(state, `${reason}: replace`)')
    expect(bypassIndex).toBeGreaterThan(0)
    expect(stopIndex).toBeGreaterThan(bypassIndex)
    expect(source).toContain("'external-proxy'")
    expect(source).toContain('allow external proxy sing-box outbound')
  })

  it('returns the actual control URL in status so local clients can survive control-port fallback', () => {
    expect(source).toContain('let controlServerPort: number | null = null')
    expect(source).toContain('controlUrl: controlServerPort ? `http://${CONTROL_HOST}:${controlServerPort}` : null')
    expect(source).toContain('controlServerPort = actualPort')
  })

  it('writes PSR-compatible discovery files outside Electron userData name drift', () => {
    expect(source).toContain("join(app.getPath('appData'), 'VPN Tunnel Enforcer')")
    expect(source).toContain('function controlDiscoveryDirs')
    expect(source).toContain('writeControlTokenFiles(controlToken)')
    expect(source).toContain('failed to write compatibility control endpoint file')
  })

  it('keeps /start idempotent and returns structured JSON errors for PSR clients', () => {
    expect(source).toContain("if (action === 'start' && state.configured)")
    expect(source).toContain('function controlError')
    expect(source).toContain("controlError('external-proxy-error', detail)")
  })

  it('exposes a stop-all operation without changing the individual stop endpoint', () => {
    expect(source).toContain('async function stopAllExternalProxies')
    expect(source).toContain('stopAll: stopAllExternalProxies')
    expect(source).toContain("async function stopExternalProxy(slot: number | null | undefined = DEFAULT_PROXY_SLOT")
    expect(source).toContain("path === '/stop'")
  })

  it('uses isolated runtime configurations and preserves per-slot ports', () => {
    expect(source).toContain('external-proxy-${slot}.pid')
    expect(source).toContain('function stageExternalProxyRuntime')
    expect(source).toContain('function startExternalProxyProcessUnlocked')
    expect(source).toContain('function stopExternalProxyProcessUnlocked')
    expect(source).toContain('MAX_EXTERNAL_PROXY_SLOT = 65535 - DEFAULT_EXTERNAL_PROXY_PORT + 1')
    expect(source).toContain('startExternalProxyProfiles')
    expect(source).toContain("if (path === '/instances')")
  })
})
