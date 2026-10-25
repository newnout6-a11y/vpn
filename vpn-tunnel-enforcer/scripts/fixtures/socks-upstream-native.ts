// AT-02-004; AT-10-004: actual Electron/BoringSSL + bundled Xray, confined to loopback.
import { app } from 'electron'
import { strict as assert } from 'node:assert'
import { connect, type Socket } from 'node:net'
import { createServer } from 'node:https'
import { getCACertificates, setDefaultCACertificates } from 'node:tls'
import { mkdir } from 'node:fs/promises'
import { join } from 'node:path'
import { probeSocksUpstream } from '../../src/main/socksUpstreamProbe'
import { LOOPBACK_CERT, LOOPBACK_KEY } from './socks-upstream-certificate'

const directory = process.env.VPNTE_SOCKS_FIXTURE_DIR!
app.setPath('userData', join(directory, 'user-data'))
app.on('window-all-closed', () => {})
const wait = (ms: number) => new Promise<void>(done => setTimeout(done, ms))

app.whenReady().then(async () => {
  await mkdir(directory, { recursive: true })
  assert(process.versions.electron, 'This fixture must use real Electron')
  if (process.env.VPNTE_SOCKS_FORCE_HANG === '1') await new Promise(() => setInterval(() => {}, 1000))
  const originalCAs = getCACertificates('default')
  const peers = new Set<Socket>(), requests: Array<() => void> = []
  let hold = false, primaryFailure = false
  const backupHosts = new Set<string>()
  const endpoint = createServer({ key: LOOPBACK_KEY, cert: LOOPBACK_CERT }, (request, response) => {
    for (const notify of requests.splice(0)) notify()
    const host = String(request.headers.host || '').split(':')[0]
    if (primaryFailure) backupHosts.add(host)
    const body = host === 'cloudflare.com' ? 'ip=8.8.8.8\n' : host === 'icanhazip.com' ? '8.8.8.8\n'
      : JSON.stringify({ ip: '8.8.8.8', country: 'ZZ' })
    if (!hold) response.writeHead(primaryFailure && ['cloudflare.com', 'api.ipify.org'].includes(host) ? 503 : 200,
      { 'Content-Type': 'text/plain' }).end(body)
  })
  endpoint.on('tlsClientError', () => {})
  endpoint.on('connection', socket => {
    peers.add(socket); socket.on('error', () => {}); socket.once('close', () => peers.delete(socket))
  })
  const port = Number(process.env.VPNTE_SOCKS_UPSTREAM_PORT)
  await new Promise<void>(done => endpoint.listen(Number(process.env.VPNTE_SOCKS_ENDPOINT_PORT), '127.0.0.1', done))
  const upstream = { port, username: 'loopback-user', password: 'loopback-password' }
  const drained = async () => {
    const deadline = Date.now() + 1000
    while (peers.size && Date.now() < deadline) await wait(10)
    assert.equal(peers.size, 0, 'Probe must close the actual TLS peer before reuse')
  }
  try {
    // Listener startup has its own budget; the production probe keeps its 2 s deadline.
    const readyBy = Date.now() + 5000
    while (true) {
      try {
        await new Promise<void>((done, fail) => {
          const socket = connect(port, '127.0.0.1')
          let failure: Error | undefined
          socket.once('connect', () => socket.destroy())
          socket.once('error', error => { failure = error })
          socket.once('close', () => { if (failure) fail(failure); else done() })
          socket.setTimeout(100, () => socket.destroy(new Error('Loopback listener not ready')))
        })
        break
      }
      catch (error) { if (Date.now() >= readyBy) throw error; await wait(20) }
    }
    setDefaultCACertificates([LOOPBACK_CERT]) // This isolated fixture alone trusts its public test CA.
    assert.equal(await probeSocksUpstream(upstream), '8.8.8.8')
    await drained()
    primaryFailure = true
    assert.equal(await probeSocksUpstream(upstream), '8.8.8.8', 'Backup provider must survive primary HTTP failure')
    assert([...backupHosts].some(host => ['icanhazip.com', 'api.myip.com'].includes(host)))
    await drained(); primaryFailure = false
    setDefaultCACertificates(originalCAs)
    await assert.rejects(probeSocksUpstream(upstream), (error: any) => error.category === 'network')
    await drained()
    setDefaultCACertificates([LOOPBACK_CERT])
    await assert.rejects(probeSocksUpstream({ ...upstream, password: 'incorrect-test-password' }),
      (error: any) => error.category === 'network')
    await drained()
    hold = true
    const controller = new AbortController()
    const requested = new Promise<void>(done => requests.push(done))
    const cancelled = probeSocksUpstream(upstream, controller.signal).catch(error => error)
    let requestDeadline: ReturnType<typeof setTimeout> | undefined
    try {
      await Promise.race([requested, cancelled.then(error => { throw error }), new Promise<never>((_done, fail) => {
        requestDeadline = setTimeout(() => fail(new Error('Loopback HTTPS request was not observed')), 2000)
      })]).finally(() => clearTimeout(requestDeadline))
      controller.abort()
      assert.equal((await cancelled).category, 'cancelled')
    } finally { controller.abort(); await cancelled }
    await drained()
    console.log('SOCKS_UPSTREAM_NATIVE_PASS', JSON.stringify({ electron: process.versions.electron,
      checks: ['actual bundled Xray RFC1929', 'verified TLS and HTTPS', 'backup provider',
        'untrusted certificate rejected', 'wrong credentials rejected', 'cancellation closes native transports'] }))
  } finally {
    setDefaultCACertificates(originalCAs)
    for (const peer of peers) peer.destroy()
    await new Promise<void>(done => endpoint.close(() => done()))
  }
  app.exit(0)
}).catch(error => { console.error('SOCKS_UPSTREAM_NATIVE_FAILED', error); app.exit(1) })
