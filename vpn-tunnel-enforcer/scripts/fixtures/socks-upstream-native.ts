// AT-02-004; AT-10-004: actual Electron/BoringSSL + bundled Xray, confined to loopback.
import { app } from 'electron'
import { strict as assert } from 'node:assert'
import { spawn } from 'node:child_process'
import { createServer as createTcpServer, type AddressInfo, type Socket } from 'node:net'
import { createServer } from 'node:https'
import { getCACertificates, setDefaultCACertificates } from 'node:tls'
import { mkdir, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { probeSocksUpstream } from '../../src/main/socksUpstreamProbe'
import { LOOPBACK_CERT, LOOPBACK_KEY } from './socks-upstream-certificate'

const directory = process.env.VPNTE_SOCKS_FIXTURE_DIR!
app.setPath('userData', join(directory, 'user-data'))
app.on('window-all-closed', () => {})
const wait = (ms: number) => new Promise<void>(done => setTimeout(done, ms))

app.whenReady().then(async () => {
  await mkdir(directory, { recursive: true })
  assert(process.versions.electron, 'This fixture must use real Electron')
  const originalCAs = getCACertificates('default')
  const peers = new Set<Socket>(), requests: Array<() => void> = []
  let hold = false, primaryFailure = false
  const endpoint = createServer({ key: LOOPBACK_KEY, cert: LOOPBACK_CERT }, (request, response) => {
    for (const notify of requests.splice(0)) notify()
    if (!hold) response.writeHead(primaryFailure && request.headers.host === 'api.ipify.org' ? 503 : 200,
      { 'Content-Type': 'text/plain' }).end('8.8.8.8\n')
  })
  endpoint.on('tlsClientError', () => {})
  endpoint.on('connection', socket => {
    peers.add(socket); socket.on('error', () => {}); socket.once('close', () => peers.delete(socket))
  })
  await new Promise<void>(done => endpoint.listen(0, '127.0.0.1', done))
  const endpointPort = (endpoint.address() as AddressInfo).port
  const reservation = createTcpServer()
  await new Promise<void>(done => reservation.listen(0, '127.0.0.1', done))
  const port = (reservation.address() as AddressInfo).port
  await new Promise<void>(done => reservation.close(() => done()))
  const upstream = { port, username: 'loopback-user', password: 'loopback-password' }
  const config = join(directory, 'xray.json')
  await writeFile(config, JSON.stringify({ log: { loglevel: 'none' },
    inbounds: [{ listen: '127.0.0.1', port, protocol: 'socks', settings: {
      auth: 'password', accounts: [{ user: upstream.username, pass: upstream.password }], udp: false } }],
    outbounds: [{ protocol: 'freedom', settings: { redirect: `127.0.0.1:${endpointPort}` } }]
  }))
  const xray = spawn(resolve('resources/xray.exe'), ['run', '-c', config], { windowsHide: true, stdio: 'ignore' })
  const exited = new Promise<void>(done => xray.once('close', () => done()))
  const drained = async () => {
    const deadline = Date.now() + 1000
    while (peers.size && Date.now() < deadline) await wait(10)
    assert.equal(peers.size, 0, 'Probe must close the actual TLS peer before reuse')
  }
  try {
    await new Promise<void>((done, fail) => { xray.once('spawn', () => done()); xray.once('error', fail) })
    setDefaultCACertificates([LOOPBACK_CERT]) // This isolated fixture alone trusts its public test CA.
    const readyBy = Date.now() + 2000
    while (true) {
      assert.equal(xray.exitCode, null, 'Loopback Xray exited before readiness')
      try { assert.equal(await probeSocksUpstream(upstream), '8.8.8.8'); break }
      catch (error) { if (Date.now() >= readyBy) throw error; await wait(20) }
    }
    await drained()
    primaryFailure = true
    assert.equal(await probeSocksUpstream(upstream), '8.8.8.8', 'Backup provider must survive primary HTTP failure')
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
    if (xray.exitCode === null && xray.signalCode === null) xray.kill()
    let timer: ReturnType<typeof setTimeout> | undefined
    await Promise.race([exited, new Promise<never>((_done, fail) => {
      timer = setTimeout(() => fail(new Error('Loopback Xray exit was not confirmed')), 2000)
    })]).finally(() => clearTimeout(timer))
    await new Promise<void>(done => endpoint.close(() => done()))
  }
  app.exit(0)
}).catch(error => { console.error('SOCKS_UPSTREAM_NATIVE_FAILED', error); app.exit(1) })
