// AT-00-003: native SOCKS negotiation settles after abort destroys its transport.
import * as net from 'node:net'
import { describe, expect, it, vi } from 'vitest'
vi.mock('electron', () => ({ ipcMain: { handle: vi.fn() } }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./tunController', () => ({ tunController: { getStatus: () => ({ running: false }) } }))
import { openTcpViaSocks } from './keyHealthChecker'
describe('native owned SOCKS transport', () => {
  it.each(['cancel', 'timeout'])('closes a real blackholed negotiation on %s', async boundary => {
    let greeted!: () => void
    const greeting = new Promise<void>(resolve => { greeted = resolve })
    const peers = new Set<net.Socket>(), server = net.createServer(socket => {
      peers.add(socket); socket.on('data', greeted); socket.once('close', () => peers.delete(socket))
    })
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const owner = new AbortController(), drains: Promise<unknown>[] = []
    const task = openTcpViaSocks({ host: '127.0.0.1', port: (server.address() as net.AddressInfo).port }, 'fixture.example', 443, 500, owner.signal, value => { drains.push(value) }).catch(error => error)
    try {
      await greeting
      if (boundary === 'cancel') owner.abort()
      expect((await task).message).toBe(boundary === 'cancel' ? 'Cancelled' : 'timeout')
      await Promise.all(drains)
      expect(drains.length).toBeGreaterThanOrEqual(2)
    } finally { owner.abort(); for (const peer of peers) peer.destroy(); await task; await Promise.all(drains); await new Promise<void>(resolve => server.close(() => resolve())) }
  }, 5000)
  it('preserves a successful native SOCKS connection until the caller closes it', async () => {
    const peers = new Set<net.Socket>(), server = net.createServer(socket => {
      peers.add(socket); socket.once('close', () => peers.delete(socket))
      let greeted = false, buffer = Buffer.alloc(0)
      socket.on('data', chunk => {
        buffer = Buffer.concat([buffer, chunk])
        if (!greeted && buffer.length >= 3) { greeted = true; buffer = Buffer.alloc(0); socket.write(Buffer.from([5, 0])); return }
        if (greeted && buffer.length >= 7) { buffer = Buffer.alloc(0); socket.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 80])) }
      })
    })
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
    const drains: Promise<unknown>[] = [], owner = new AbortController()
    let socket: net.Socket | undefined
    try {
      socket = await openTcpViaSocks({ host: '127.0.0.1', port: (server.address() as net.AddressInfo).port }, 'fixture.example', 443, 1000, owner.signal, value => { drains.push(value) })
      expect(socket.destroyed).toBe(false)
      let drained = false; const drain = Promise.all(drains).then(() => { drained = true })
      await Promise.resolve(); expect(drained).toBe(false)
      socket.destroy(); await drain
      expect(socket.closed).toBe(true)
    } finally { owner.abort(); socket?.destroy(); for (const peer of peers) peer.destroy(); await Promise.all(drains); await new Promise<void>(resolve => server.close(() => resolve())) }
  }, 5000)
})
