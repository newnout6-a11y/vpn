// @vitest-environment node
// AT-00-003: native Resolver cancellation with a local UDP DNS fixture only.
import { createSocket, type RemoteInfo, type Socket } from 'node:dgram'
import { promises as dns } from 'node:dns'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { resolveXrayEndpoint } from './xrayDns'

let socket: Socket, originalServers: string[]
const owners: AbortController[] = []
const queries = new Map<string, { bytes: Buffer; peer: RemoteInfo; questionEnd: number }>()
beforeEach(async () => {
  queries.clear()
  originalServers = dns.getServers()
  socket = createSocket('udp4')
  socket.on('message', (bytes, peer) => {
    let offset = 12
    const labels: string[] = []
    while (bytes[offset] > 0 && offset < bytes.length) {
      const length = bytes[offset++]
      labels.push(bytes.subarray(offset, offset + length).toString('ascii'))
      offset += length
    }
    queries.set(labels.join('.'), { bytes, peer, questionEnd: offset + 5 })
  })
  await new Promise<void>(done => socket.bind(0, '127.0.0.1', done))
  const address = socket.address()
  if (typeof address === 'string') throw new Error('Expected UDP address')
  // Only this test worker's Node DNS list changes; Windows DNS is untouched.
  dns.setServers([`127.0.0.1:${address.port}`])
})
afterEach(async () => {
  owners.forEach(owner => owner.abort())
  owners.length = 0
  dns.setServers(originalServers)
  await new Promise<void>(done => socket.close(done))
})
function owner() { const value = new AbortController(); owners.push(value); return value }
async function received(host: string) {
  const deadline = performance.now() + 3000
  while (performance.now() < deadline) {
    if (queries.has(host)) return queries.get(host)!
    await new Promise(done => setTimeout(done, 10))
  }
  throw new Error('Local DNS fixture received no query')
}
async function answer(host: string) {
  const query = await received(host)
  const header = Buffer.from(query.bytes.subarray(0, 12))
  header.writeUInt16BE(0x8180, 2)
  header.writeUInt16BE(1, 4)
  header.writeUInt16BE(1, 6)
  header.writeUInt16BE(0, 8)
  header.writeUInt16BE(0, 10)
  const response = Buffer.concat([header, query.bytes.subarray(12, query.questionEnd), Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 51, 100, 42])])
  await new Promise<void>((done, reject) => socket.send(response, query.peer.port, query.peer.address, error => error ? reject(error) : done()))
}

describe('native scoped Xray DNS (local fixture, no public requests)', () => {
  it('bypasses a 3025 ms held DNS reply through real OS localhost resolution (AT-02-002)', async () => {
    const previousStarted = performance.now()
    const previous = dns.resolve4('localhost')
    await received('localhost')
    await new Promise(done => setTimeout(done, 3025))
    await answer('localhost')
    expect(await previous).toEqual(['198.51.100.42'])
    const previousMs = Math.round(performance.now() - previousStarted)
    queries.clear()

    const report: Record<string, unknown>[] = [], started = performance.now()
    expect(await resolveXrayEndpoint('localhost', owner().signal, details => report.push(details))).toBe('127.0.0.1')
    const hedgedMs = Math.round(performance.now() - started)
    expect(queries.has('localhost')).toBe(true)
    expect(report).toEqual([expect.objectContaining({ method: 'system-lookup', ok: true, hedged: true })])
    expect(hedgedMs).toBeLessThan(1000)
    console.info(JSON.stringify({ fixture: 'local-held-DNS', previousMs, hedgedMs }))
  }, 8000)
  it('reacts to a held real DNS query cancellation within one second', async () => {
    const current = owner()
    const pending = resolveXrayEndpoint('held.fixture.invalid', current.signal)
    const cancelled = expect(pending).rejects.toMatchObject({ name: 'AbortError' })
    await received('held.fixture.invalid')
    const started = performance.now()
    current.abort()
    await cancelled
    expect(performance.now() - started).toBeLessThan(1000)
  }, 5000)
  it('cancels one real resolver without cancelling another operation query', async () => {
    const old = owner(), fresh = owner()
    const first = resolveXrayEndpoint('old.fixture.invalid', old.signal)
    const cancelled = expect(first).rejects.toThrow('cancelled')
    await received('old.fixture.invalid')
    const second = resolveXrayEndpoint('fresh.fixture.invalid', fresh.signal)
    // Attach a rejection handler immediately, including fixture setup failures.
    void second.catch(() => undefined)
    await received('fresh.fixture.invalid')
    old.abort()
    await cancelled
    await answer('fresh.fixture.invalid')
    expect(await second).toBe('198.51.100.42')
  }, 5000)
})
