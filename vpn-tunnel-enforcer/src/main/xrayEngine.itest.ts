/**
 * Live acceptance: generate an xray config through the real code path and run
 * `xray run -test -c` against the bundled `resources/xray.exe`. When
 * VPNTE_LIVE_XRAY_URI is set to a `vless://…reality…` key, also spawn xray for
 * real and confirm a request tunnels through the loopback SOCKS.
 *
 * Skipped entirely when `resources/xray.exe` is absent, like
 * keyHealthChecker.live.test.ts.
 */
import { describe, it, expect } from 'vitest'
import { existsSync } from 'fs'
import { writeFile, mkdtemp, mkdir, readFile, rm } from 'fs/promises'
import { spawn } from 'child_process'
import { tmpdir } from 'os'
import { join } from 'path'
import { createServer, Socket, type AddressInfo } from 'net'
import { once } from 'events'
import { SocksClient } from 'socks'
import { toXrayOutbound, buildXrayConfig } from './xrayEngine'

const XRAY = join(process.cwd(), 'resources', 'xray.exe')
const HAVE_XRAY = existsSync(XRAY)
const d = HAVE_XRAY ? describe : describe.skip

function runXray(args: string[], cwd: string, timeoutMs = 15000): Promise<{ code: number | null; out: string }> {
  return new Promise((resolve) => {
    const p = spawn(XRAY, args, { cwd, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] })
    let out = ''
    p.stdout?.on('data', (c) => { out += c })
    p.stderr?.on('data', (c) => { out += c })
    const t = setTimeout(() => { try { p.kill() } catch {} resolve({ code: null, out }) }, timeoutMs)
    p.on('exit', (code) => { clearTimeout(t); resolve({ code, out }) })
    p.on('error', (e) => { clearTimeout(t); resolve({ code: -1, out: out + String(e) }) })
  })
}

const SAMPLE = {
  vlessReality: {
    type: 'vless', server: 'example.com', server_port: 443, uuid: '6184aeb4-9080-494f-b9f9-df87c417166a',
    tls: { enabled: true, server_name: 'cloudrynth.com', utls: { enabled: true, fingerprint: 'chrome' },
      reality: { enabled: true, public_key: 'G2i-nsQgWiVf52tdCUV-G_VeuCJ3hggwDnTaEAgvg0Y', short_id: '' } }
  },
  vmessWsTls: {
    type: 'vmess', server: 'example.com', server_port: 443, uuid: '22222222-2222-2222-2222-222222222222',
    alter_id: 0, transport: { type: 'ws', path: '/ws' }, tls: { enabled: true, server_name: 'example.com' }
  },
  trojan: { type: 'trojan', server: 'example.com', server_port: 443, password: 'p', tls: { enabled: true, server_name: 'example.com' } },
  ss: { type: 'shadowsocks', server: 'example.com', server_port: 8388, method: 'aes-256-gcm', password: 'p' }
} as const

d('xrayEngine live — config validity', () => {
  it.each(Object.entries(SAMPLE))('xray run -test accepts generated config: %s', async (_name, ob) => {
    const dir = await mkdtemp(join(tmpdir(), 'vpnte-xray-live-'))
    try {
      const cfg = buildXrayConfig(toXrayOutbound(ob as any, {}), 45999, { logPath: join(dir, 'xray.log') })
      const cfgPath = join(dir, 'xray.json')
      await writeFile(cfgPath, JSON.stringify(cfg, null, 2))
      const { code, out } = await runXray(['run', '-test', '-c', cfgPath], dir)
      expect(code, out).toBe(0)
    } finally {
      await rm(dir, { recursive: true, force: true })
    }
  })
})

// A synthetic ClientHello is enough to exercise Xray's TLS sniffer. This test
// only forwards bytes between loopback sockets; it does not bypass TLS checks.
function clientHelloWithSni(name: string): Buffer {
  const u16 = (n: number) => Buffer.from([n >> 8, n & 255])
  const host = Buffer.from(name)
  const entry = Buffer.concat([Buffer.from([0]), u16(host.length), host])
  const sni = Buffer.concat([u16(entry.length), entry])
  const extensions = Buffer.concat([u16(0), u16(sni.length), sni])
  const body = Buffer.concat([
    Buffer.from([3, 3]), Buffer.alloc(32), Buffer.from([0]),
    u16(2), Buffer.from([0, 0x2f, 1, 0]), u16(extensions.length), extensions
  ])
  const handshake = Buffer.concat([Buffer.from([1, 0]), u16(body.length), body])
  return Buffer.concat([Buffer.from([22, 3, 1]), u16(handshake.length), handshake])
}

d('AT-02-008 / AT-06-001: real Xray sniffing preserves the requested endpoint', () => {
  it.each(['http', 'tls'] as const)('routes by %s domain but retains the original IP and nonstandard port', async (protocol) => {
    const name = 'search.vpnte-sniff.invalid'
    const payload = protocol === 'tls' ? clientHelloWithSni(name)
      : Buffer.from(`GET /search HTTP/1.1\r\nHost: ${name}\r\nConnection: close\r\n\r\n`)
    const peers = new Set<Socket>()
    let received = Buffer.alloc(0)
    const endpoint = createServer(peer => {
      peers.add(peer)
      peer.once('close', () => peers.delete(peer))
      peer.on('data', chunk => {
        received = Buffer.concat([received, chunk])
        if (received.length >= payload.length) peer.end('original-endpoint')
      })
    })
    const root = join(process.cwd(), '.tmp')
    await mkdir(root, { recursive: true })
    const dir = await mkdtemp(join(root, 'xray-sniff-'))
    const reservation = createServer()
    let proc: ReturnType<typeof spawn> | undefined
    let tunnel: Socket | undefined
    try {
      endpoint.listen(0, '127.0.0.1')
      await once(endpoint, 'listening')
      const destinationPort = (endpoint.address() as AddressInfo).port
      reservation.listen(0, '127.0.0.1')
      await once(reservation, 'listening')
      const socksPort = (reservation.address() as AddressInfo).port
      await new Promise<void>(resolve => reservation.close(() => resolve()))
      const logPath = join(dir, 'xray.log')
      // The fixture egress is local. Both tags use freedom, and the domain
      // rule proves sniffing still selects proxy instead of the private-IP rule.
      const config = buildXrayConfig({ protocol: 'freedom' }, socksPort, { logPath })
      config.routing.rules.unshift({ type: 'field', domain: [`full:${name}`], outboundTag: 'proxy' })
      const configPath = join(dir, 'xray.json')
      await writeFile(configPath, JSON.stringify(config))
      proc = spawn(XRAY, ['run', '-c', configPath], { cwd: dir, windowsHide: true, stdio: 'ignore' })
      for (let attempt = 0; attempt < 40; attempt++) {
        const ready = await new Promise<boolean>(resolve => {
          const probe = new Socket()
          const done = (ok: boolean) => { probe.destroy(); resolve(ok) }
          probe.setTimeout(100)
          probe.once('connect', () => done(true))
          probe.once('error', () => done(false))
          probe.once('timeout', () => done(false))
          probe.connect(socksPort, '127.0.0.1')
        })
        if (ready) break
        await new Promise(resolve => setTimeout(resolve, 50))
      }
      const connected = await SocksClient.createConnection({
        proxy: { host: '127.0.0.1', port: socksPort, type: 5 }, command: 'connect', timeout: 3000,
        destination: { host: '127.0.0.1', port: destinationPort }
      })
      tunnel = connected.socket
      const response = await new Promise<string>((resolve, reject) => {
        let data = ''
        tunnel!.setTimeout(3000)
        tunnel!.on('data', chunk => { data += chunk.toString() })
        tunnel!.once('end', () => resolve(data))
        tunnel!.once('error', reject)
        tunnel!.once('timeout', () => reject(new Error('original endpoint did not respond')))
        tunnel!.write(payload)
      })
      expect(response).toBe('original-endpoint')
      expect(received).toEqual(payload)
      const log = await readFile(logPath, 'utf8')
      expect(log).toContain(`sniffed domain: ${name}`)
      expect(log).toContain('taking detour [proxy]')
    } finally {
      tunnel?.destroy()
      for (const peer of peers) peer.destroy()
      if (proc && proc.exitCode === null && proc.signalCode === null) {
        const closed = once(proc, 'close')
        proc.kill()
        await closed
      }
      await new Promise<void>(resolve => endpoint.close(() => resolve()))
      if (reservation.listening) await new Promise<void>(resolve => reservation.close(() => resolve()))
      await rm(dir, { recursive: true, force: true })
    }
  }, 15000)
})

const LIVE_URI = process.env.VPNTE_LIVE_XRAY_URI
const dl = HAVE_XRAY && LIVE_URI ? describe : describe.skip

dl('xrayEngine live — real REALITY handshake', () => {
  it('tunnels a request through xray to the real server', async () => {
    // parse vless://uuid@host:port?security=reality&sni=..&pbk=..&sid=..
    const u = new URL(LIVE_URI!)
    const q = u.searchParams
    const ob: Record<string, any> = {
      type: 'vless', server: u.hostname, server_port: Number(u.port || 443), uuid: decodeURIComponent(u.username),
      flow: q.get('flow') || undefined,
      tls: { enabled: true, server_name: q.get('sni') || u.hostname, utls: { enabled: true, fingerprint: q.get('fp') || 'chrome' },
        reality: { enabled: true, public_key: q.get('pbk') || '', short_id: q.get('sid') || '' } }
    }
    const dir = await mkdtemp(join(tmpdir(), 'vpnte-xray-live-real-'))
    const port = 45888
    const cfgPath = join(dir, 'xray.json')
    await writeFile(cfgPath, JSON.stringify(buildXrayConfig(toXrayOutbound(ob, {}), port, { logPath: join(dir, 'xray.log') }), null, 2))
    const proc = spawn(XRAY, ['run', '-c', cfgPath], { cwd: dir, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] })
    let log = ''
    proc.stdout?.on('data', (c) => { log += c }); proc.stderr?.on('data', (c) => { log += c })
    try {
      // wait for socks
      for (let i = 0; i < 40; i++) {
        const ok = await new Promise<boolean>((res) => {
          const s = new Socket(); s.setTimeout(250)
          s.once('connect', () => { s.destroy(); res(true) })
          s.once('error', () => { s.destroy(); res(false) })
          s.once('timeout', () => { s.destroy(); res(false) })
          s.connect(port, '127.0.0.1')
        })
        if (ok) break
        await new Promise((r) => setTimeout(r, 150))
      }
      const { socket } = await SocksClient.createConnection({
        proxy: { host: '127.0.0.1', port, type: 5 }, command: 'connect',
        destination: { host: 'api.ipify.org', port: 80 }
      })
      const body = await new Promise<string>((resolve, reject) => {
        let buf = ''
        socket.setTimeout(10000)
        socket.on('data', (d2) => { buf += d2.toString() })
        socket.once('timeout', () => reject(new Error('timeout: ' + log.slice(-400))))
        socket.once('close', () => resolve(buf))
        socket.once('error', reject)
        socket.write('GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n')
      })
      // eslint-disable-next-line no-console
      console.log('LIVE xray response body:', body.split('\r\n\r\n')[1]?.trim() || body.slice(-200))
      expect(body, log.slice(-400)).toMatch(/\b\d{1,3}(\.\d{1,3}){3}\b/)
    } finally {
      try { proc.kill() } catch {}
      await new Promise((r) => setTimeout(r, 1500))
      await rm(dir, { recursive: true, force: true }).catch(() => undefined)
    }
  }, 30000)
})
