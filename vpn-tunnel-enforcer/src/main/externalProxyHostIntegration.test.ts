// AT-01-005; F-038: real HTTP transport, production Host and token enforcement.
import { createServer, request } from 'http'
import { once } from 'events'
import { afterEach, describe, expect, it, vi } from 'vitest'
vi.mock('electron', () => ({ app: { getPath: () => '/tmp/vpnte-test', isPackaged: false }, ipcMain: { handle: vi.fn() } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
import { handleControlRequest } from './externalProxy'
import { logEvent } from './appLogger'
let server: ReturnType<typeof createServer> | undefined
afterEach(async () => { if (server) await new Promise<void>(resolve => server!.close(() => resolve())) })
describe('HTTP control Host allow-list', () => {
  it('denies decimal IP, IPv6, external and missing Host before any action', async () => {
    server = createServer((req, res) => { void handleControlRequest(req, res) })
    server.listen(0, '127.0.0.1'); await once(server, 'listening')
    const port = (server.address() as { port: number }).port
    const send = (host: string | null) => new Promise<{ status: number; body: string }>((resolve, reject) => {
      const req = request({ host: '127.0.0.1', port, path: '/api/external-proxy/start', method: 'POST',
        setHost: false, headers: host === null ? {} : { Host: host } }, res => {
        let body = ''; res.on('data', bytes => { body += bytes }); res.on('end', () => resolve({ status: res.statusCode!, body }))
      }); req.on('error', reject); req.end()
    })
    for (const host of [`evil.attacker.tld:${port}`, `2130706433:${port}`, `[::1]:${port}`, null]) {
      const result = await send(host)
      // Node's HTTP parser rejects a missing HTTP/1.1 Host before dispatch.
      expect(result.status).toBe(host === null ? 400 : 421); expect(result.body).not.toContain('FAKE-')
    }
    for (const host of [`localhost:${port}`, `127.0.0.1:${port}`]) expect((await send(host)).status).toBe(401)
    expect(logEvent).toHaveBeenCalledWith('warn', 'external-proxy', 'control request rejected', { reason: 'untrusted-host', status: 'error' })
  })
})
