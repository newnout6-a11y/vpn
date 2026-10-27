// AT-00-003/005; AT-07-003/006/012: real OS sockets, synthetic DNS and loopback TLS only.
import https from 'node:https'
import net from 'node:net'
import type { Socket } from 'node:net'
import type { Server } from 'node:net'
import { EventEmitter } from 'node:events'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { LOOPBACK_KEY } from '../../scripts/fixtures/socks-upstream-certificate'
import { IP_MONITOR_CERT } from '../../scripts/fixtures/ip-monitor-certificate'
import { publicIpTransport } from './ipMonitorTransport'

vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
let module: typeof import('./ipMonitor')
const servers: Server[] = [], sockets = new Set<Socket>()
async function listen(server: Server): Promise<number> {
  servers.push(server)
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)) })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  return (server.address() as net.AddressInfo).port
}
function urls(url: string): void {
  module.IP_CHECK_URLS.splice(0, 4, url, 'https://dns-failure.invalid/1', 'https://dns-failure.invalid/2', 'https://dns-failure.invalid/3')
}
beforeEach(async () => {
  vi.resetModules()
  vi.clearAllMocks()
  vi.stubEnv('HTTPS_PROXY', 'http://127.0.0.1:1')
  module = await import('./ipMonitor')
  module.noKeepAliveHttpsAgent.options.ca = IP_MONITOR_CERT
  module.noKeepAliveHttpsAgent.options.lookup = (_hostname, _options, callback) => {
    queueMicrotask(() => callback(Object.assign(new Error('PRIVATE_DNS_MESSAGE'), { code: 'ENOTFOUND' }), '', 4))
  }
})
afterEach(async () => {
  module.ipMonitor.clearVpnIp()
  module.noKeepAliveHttpAgent.destroy(); module.noKeepAliveHttpsAgent.destroy()
  for (const socket of sockets) socket.destroy()
  await Promise.all(servers.splice(0).map(server => new Promise<void>(resolve => server.close(() => resolve()))))
  sockets.clear(); vi.unstubAllEnvs(); vi.restoreAllMocks()
})

describe('public IP transport over real loopback HTTPS', () => {
  it('gets a fresh validated TLS IP literal when every hostname lookup fails, ignoring proxy env', async () => {
    const requests: string[] = [], connections: string[] = []
    const server = https.createServer({ key: LOOPBACK_KEY, cert: IP_MONITOR_CERT }, (request, response) => {
      requests.push(request.headers.connection ?? '')
      response.end('ip=198.51.100.10\n')
    })
    server.on('secureConnection', socket => connections.push(String(socket.remotePort)))
    urls(`https://127.0.0.1:${await listen(server)}/cdn-cgi/trace`)
    expect(await module.fetchPublicIp()).toBe('198.51.100.10')
    expect(await module.fetchPublicIp()).toBe('198.51.100.10')
    expect(requests).toEqual(['close', 'close'])
    expect(new Set(connections).size).toBe(2)
    const { logEvent } = await import('./appLogger')
    const telemetry = vi.mocked(logEvent).mock.calls.filter(call => call[2] === 'public IP provider timing')
    expect(telemetry).toEqual(expect.arrayContaining([
      ['debug', 'ip-monitor', 'public IP provider timing', expect.objectContaining({ providerIndex: 0, code: 'OK', stage: 'body', closeFailed: false,
        stagesMs: expect.objectContaining({ tcp: expect.any(Number), tls: expect.any(Number), http: expect.any(Number), body: expect.any(Number), closed: expect.any(Number) }) })],
      ['debug', 'ip-monitor', 'public IP provider timing', expect.objectContaining({ providerIndex: 1, code: 'ENOTFOUND', stage: 'dns' })]
    ]))
    expect(JSON.stringify(telemetry)).not.toMatch(/PRIVATE|127\.0|198\.51|https?:/)
  })

  it('rejects untrusted TLS instead of treating a literal endpoint as a bypass', async () => {
    const server = https.createServer({ key: LOOPBACK_KEY, cert: IP_MONITOR_CERT }, (_request, response) => response.end('198.51.100.10'))
    urls(`https://127.0.0.1:${await listen(server)}/`)
    module.noKeepAliveHttpsAgent.options.ca = undefined
    expect(await module.fetchPublicIp()).toBeNull()
    expect(module.ipMonitor.getLastSuccessAt()).toBe(0)
    const { logEvent } = await import('./appLogger')
    expect(vi.mocked(logEvent).mock.calls).toEqual(expect.arrayContaining([
      ['debug', 'ip-monitor', 'public IP provider timing', expect.objectContaining({ providerIndex: 0, stage: 'tls', code: 'DEPTH_ZERO_SELF_SIGNED_CERT' })]
    ]))
  })

  it('closes all stalled native loser sockets before releasing a successful wave (AT-00-003)', async () => {
    let requests = 0
    const server = https.createServer({ key: LOOPBACK_KEY, cert: IP_MONITOR_CERT }, (_request, response) => {
      if (++requests === 4) response.end('198.51.100.10')
    })
    const port = await listen(server)
    module.IP_CHECK_URLS.splice(0, 4, ...Array.from({ length: 4 }, (_, i) => `https://127.0.0.1:${port}/${i}`))
    expect(await module.fetchPublicIp()).toBe('198.51.100.10')
    expect(requests).toBe(4)
    expect(module.ipMonitor.getLastSuccessAt()).toBeGreaterThan(0)
    const { logEvent } = await import('./appLogger')
    const timings = vi.mocked(logEvent).mock.calls.filter(call => call[2] === 'public IP provider timing')
    expect(timings).toHaveLength(4)
    for (const timing of timings) expect(timing[3]).toMatchObject({ closeFailed: false, stagesMs: { closed: expect.any(Number) } })
  })

  it.each(['tls', 'http', 'body'] as const)('bounds a stalled %s stage within the caller budget and closes every client socket', async stalled => {
    const server = stalled === 'tls' ? net.createServer() : https.createServer({ key: LOOPBACK_KEY, cert: IP_MONITOR_CERT }, (_request, response) => {
      if (stalled === 'body') { response.writeHead(200); response.write('ip=') }
    })
    urls(`https://127.0.0.1:${await listen(server)}/`)
    const began = performance.now()
    expect(await module.fetchPublicIp(undefined, undefined, { timeoutMs: 600 })).toBeNull()
    expect(performance.now() - began).toBeLessThan(1000)
    const { logEvent } = await import('./appLogger')
    expect(vi.mocked(logEvent).mock.calls).toEqual(expect.arrayContaining([
      ['debug', 'ip-monitor', 'public IP provider timing', expect.objectContaining({ providerIndex: 0, stage: stalled, outcome: 'timeout', code: 'DEADLINE', closeFailed: false, stagesMs: expect.objectContaining({ closed: expect.any(Number) }) })]
    ]))
    expect(module.ipMonitor.getLastSuccessAt()).toBe(0)
  })

  it('cancels a stalled native request and never publishes a baseline, health or callbacks', async () => {
    let received!: () => void
    const requestReceived = new Promise<void>(resolve => { received = resolve })
    const server = https.createServer({ key: LOOPBACK_KEY, cert: IP_MONITOR_CERT }, () => received())
    urls(`https://127.0.0.1:${await listen(server)}/`)
    const controller = new AbortController(), notify = vi.fn(), recovered = vi.fn()
    module.ipMonitor.onIpChange(notify); module.ipMonitor.setRecoveryCallback(recovered)
    const result = module.ipMonitor.recheck(true, () => true, '198.51.100.10', { timeoutMs: 1000, signal: controller.signal })
    await requestReceived
    const began = performance.now()
    controller.abort()
    expect(await result).toEqual({ ip: null, vpnIp: null, isLeak: false })
    expect(performance.now() - began).toBeLessThan(500)
    expect(module.ipMonitor.getLastSuccessAt()).toBe(0)
    expect(notify).not.toHaveBeenCalled(); expect(recovered).not.toHaveBeenCalled()
  })
  it('drains an immediate abort before Node assigns the request socket (AT-00-003)', async () => {
    const server = https.createServer({ key: LOOPBACK_KEY, cert: IP_MONITOR_CERT })
    urls(`https://127.0.0.1:${await listen(server)}/`)
    const controller = new AbortController()
    const result = module.fetchPublicIp(() => true, controller.signal)
    controller.abort()
    expect(await result).toBeNull()
    const { logEvent } = await import('./appLogger')
    const timings = vi.mocked(logEvent).mock.calls.filter(call => call[2] === 'public IP provider timing')
    expect(timings).toHaveLength(4)
    for (const timing of timings) expect(timing[3]).toMatchObject({ code: 'CANCELLED', closeFailed: false, stagesMs: { closed: expect.any(Number) } })
    expect(module.ipMonitor.getLastSuccessAt()).toBe(0)
  })
  it('retains ownership past a close deadline until a late-assigned socket actually closes (AT-00-003)', async () => {
    vi.useFakeTimers()
    try {
      const request = Object.assign(new EventEmitter(), { destroy: vi.fn() })
      const socket = Object.assign(new EventEmitter(), { destroy: vi.fn() })
      vi.spyOn(https, 'request').mockReturnValue(request as any)
      const owned = publicIpTransport()
      owned.transport.request({ protocol: 'https:', hostname: '127.0.0.1' }, () => undefined)
      let settled = false
      const close = owned.close().catch(error => { settled = true; return error })
      request.emit('socket', socket)
      expect(socket.destroy).toHaveBeenCalledOnce()
      request.emit('close')
      await vi.advanceTimersByTimeAsync(201)
      expect(settled).toBe(false)
      expect(owned.diagnostics().closeFailed).toBe(true)
      socket.emit('close')
      expect(await close).toEqual(new Error('IP_SOCKET_CLOSE_UNCONFIRMED'))
    } finally { vi.useRealTimers() }
  })
})
