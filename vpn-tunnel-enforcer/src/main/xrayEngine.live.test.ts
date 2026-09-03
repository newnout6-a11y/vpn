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
import { writeFile, mkdtemp, rm } from 'fs/promises'
import { spawn } from 'child_process'
import { tmpdir } from 'os'
import { join } from 'path'
import { Socket } from 'net'
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
