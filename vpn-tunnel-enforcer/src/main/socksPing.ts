import { isIP, Socket } from 'net'
import { performance } from 'perf_hooks'

function socksAddress(host: string): Buffer | null {
  if (isIP(host) === 4) {
    return Buffer.from([0x01, ...host.split('.').map(part => Number(part))])
  }
  const encoded = Buffer.from(host, 'utf8')
  if (encoded.length === 0 || encoded.length > 255) return null
  return Buffer.concat([Buffer.from([0x03, encoded.length]), encoded])
}

function replyLength(buffer: Buffer): number | null {
  if (buffer.length < 5) return null
  if (buffer[3] === 0x01) return 10
  if (buffer[3] === 0x04) return 22
  if (buffer[3] === 0x03) return 7 + buffer[4]
  return -1
}

export function socksTcpConnectPing(
  proxyPort: number,
  host: string,
  port: number,
  timeoutMs: number
): Promise<number | null> {
  return new Promise(resolve => {
    const address = socksAddress(host)
    if (!address) {
      resolve(null)
      return
    }

    const socket = new Socket()
    const startedAt = performance.now()
    let stage: 'greeting' | 'connect' = 'greeting'
    let buffer = Buffer.alloc(0)
    let settled = false
    const finish = (latency: number | null) => {
      if (settled) return
      settled = true
      socket.destroy()
      resolve(latency)
    }

    socket.setTimeout(timeoutMs)
    socket.once('connect', () => socket.write(Buffer.from([0x05, 0x01, 0x00])))
    socket.on('data', chunk => {
      buffer = Buffer.concat([buffer, chunk])
      if (stage === 'greeting') {
        if (buffer.length < 2) return
        if (buffer[0] !== 0x05 || buffer[1] !== 0x00) {
          finish(null)
          return
        }
        buffer = buffer.subarray(2)
        stage = 'connect'
        socket.write(Buffer.concat([
          Buffer.from([0x05, 0x01, 0x00]),
          address,
          Buffer.from([(port >> 8) & 0xff, port & 0xff])
        ]))
      }

      if (stage === 'connect') {
        const expected = replyLength(buffer)
        if (expected == null) return
        if (expected < 0 || buffer[0] !== 0x05 || buffer[1] !== 0x00) {
          finish(null)
          return
        }
        if (buffer.length >= expected) {
          finish(Math.max(1, Math.round(performance.now() - startedAt)))
        }
      }
    })
    socket.once('timeout', () => finish(null))
    socket.once('error', () => finish(null))
    socket.connect(proxyPort, '127.0.0.1')
  })
}

export async function reliableSocksTcpPing(
  proxyPort: number,
  host: string,
  port: number,
  timeoutMs: number,
  attempts = 3
): Promise<number | null> {
  const samples = await Promise.all(
    Array.from({ length: attempts }, () => socksTcpConnectPing(proxyPort, host, port, timeoutMs))
  )
  const values = samples.filter((value): value is number => value != null).sort((a, b) => a - b)
  if (!values.length) return null
  return values[Math.floor(values.length / 2)]
}
