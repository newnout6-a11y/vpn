import { createServer } from 'net'
import { afterEach, describe, expect, it } from 'vitest'
import { socksTcpConnectPing } from './socksPing'

const servers: ReturnType<typeof createServer>[] = []

afterEach(async () => {
  await Promise.all(servers.splice(0).map(server => new Promise<void>(resolve => server.close(() => resolve()))))
})

async function fakeSocksServer(replyCode = 0): Promise<number> {
  const server = createServer(socket => {
    socket.once('data', () => {
      socket.write(Buffer.from([0x05, 0x00]))
      socket.once('data', () => {
        socket.write(Buffer.from([0x05, replyCode, 0x00, 0x01, 127, 0, 0, 1, 0, 80]))
      })
    })
  })
  servers.push(server)
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  return (server.address() as { port: number }).port
}

describe('SOCKS direct ping', () => {
  it('measures a successful CONNECT handshake', async () => {
    const proxyPort = await fakeSocksServer()
    expect(await socksTcpConnectPing(proxyPort, 'example.com', 443, 1000)).toBeGreaterThan(0)
  })

  it('rejects a failed CONNECT reply', async () => {
    const proxyPort = await fakeSocksServer(5)
    expect(await socksTcpConnectPing(proxyPort, '203.0.113.1', 443, 1000)).toBeNull()
  })
})
