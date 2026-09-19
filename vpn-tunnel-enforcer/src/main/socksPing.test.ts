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

  it('rejects invalid or out-of-range ports and timeouts immediately without socket activity', async () => {
    // Invalid target port
    expect(await socksTcpConnectPing(10808, 'example.com', 0, 1000)).toBeNull()
    expect(await socksTcpConnectPing(10808, 'example.com', -1, 1000)).toBeNull()
    expect(await socksTcpConnectPing(10808, 'example.com', 65536, 1000)).toBeNull()
    expect(await socksTcpConnectPing(10808, 'example.com', 443.5, 1000)).toBeNull()
    expect(await socksTcpConnectPing(10808, 'example.com', NaN, 1000)).toBeNull()

    // Invalid proxy port
    expect(await socksTcpConnectPing(0, 'example.com', 443, 1000)).toBeNull()
    expect(await socksTcpConnectPing(-5, 'example.com', 443, 1000)).toBeNull()
    expect(await socksTcpConnectPing(70000, 'example.com', 443, 1000)).toBeNull()

    // Invalid timeout
    expect(await socksTcpConnectPing(10808, 'example.com', 443, 0)).toBeNull()
    expect(await socksTcpConnectPing(10808, 'example.com', 443, -100)).toBeNull()
    expect(await socksTcpConnectPing(10808, 'example.com', 443, NaN)).toBeNull()
    expect(await socksTcpConnectPing(10808, 'example.com', 443, Infinity)).toBeNull()

    // Invalid host
    expect(await socksTcpConnectPing(10808, '', 443, 1000)).toBeNull()
  })
})
