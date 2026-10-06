// AT-08-001: real bundled engines must append after in-place size rotation.
// Loopback-only fixtures; no installed client, routes, DNS, or firewall changes.
import { existsSync } from 'fs'
import { mkdir, mkdtemp, writeFile, appendFile, readFile, stat, rm } from 'fs/promises'
import { spawn } from 'child_process'
import { createServer, Socket, type AddressInfo } from 'net'
import { once } from 'events'
import { join } from 'path'
import { describe, expect, it } from 'vitest'
import { SocksClient } from 'socks'
import { maintainEngineLog } from './engineLogRetention'

const wait = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))
describe.skipIf(process.platform !== 'win32')('real engine log append after rotation', () => {
  it.each(['xray', 'sing-box'])('%s', async engine => {
    const binary = join(process.cwd(), 'resources', `${engine}.exe`)
    expect(existsSync(binary)).toBe(true)
    const root = join(process.cwd(), '.tmp')
    await mkdir(root, { recursive: true })
    const dir = await mkdtemp(join(root, 'engine-log-live-'))
    const endpoint = createServer(peer => { peer.on('data', () => peer.end('OK')) })
    const reservation = createServer()
    let proc: ReturnType<typeof spawn> | undefined
    let tunnel: Socket | undefined
    try {
      endpoint.listen(0, '127.0.0.1')
      await once(endpoint, 'listening')
      reservation.listen(0, '127.0.0.1')
      await once(reservation, 'listening')
      const port = (reservation.address() as AddressInfo).port
      await new Promise<void>(resolve => reservation.close(() => resolve()))
      const log = join(dir, `${engine}.log`)
      const previous = join(dir, `${engine}.prev.log`)
      const config = engine === 'xray' ? {
        log: { loglevel: 'info', error: log.replace(/\\/g, '/'), access: 'none' },
        inbounds: [{ listen: '127.0.0.1', port, protocol: 'socks', settings: { udp: false } }],
        outbounds: [{ protocol: 'freedom' }]
      } : {
        log: { level: 'info', timestamp: true, output: log },
        inbounds: [{ type: 'mixed', tag: 'fixture', listen: '127.0.0.1', listen_port: port }],
        outbounds: [{ type: 'direct', tag: 'direct' }]
      }
      const configPath = join(dir, 'config.json')
      await writeFile(configPath, JSON.stringify(config))
      proc = spawn(binary, ['run', '-c', configPath], { cwd: dir, windowsHide: true, stdio: 'ignore' })
      await once(proc, 'spawn')
      for (let attempt = 0; attempt < 60; attempt++) {
        const ready = await new Promise<boolean>(resolve => {
          const peer = new Socket()
          const done = (ok: boolean) => { peer.destroy(); resolve(ok) }
          peer.once('connect', () => done(true)); peer.once('error', () => done(false))
          peer.setTimeout(100, () => done(false)); peer.connect(port, '127.0.0.1')
        })
        if (ready) break
        await wait(50)
      }
      await appendFile(log, 'fixture history\n'.repeat(1000))
      await maintainEngineLog(log, previous, 1024)
      expect((await stat(log)).size).toBeLessThanOrEqual(1024)
      expect((await stat(previous)).size).toBeLessThanOrEqual(1024)
      const connection = await SocksClient.createConnection({
        proxy: { host: '127.0.0.1', port, type: 5 }, command: 'connect', timeout: 3000,
        destination: { host: '127.0.0.1', port: (endpoint.address() as AddressInfo).port }
      })
      tunnel = connection.socket
      const response = new Promise<string>((resolve, reject) => {
        let text = ''
        tunnel!.on('data', chunk => { text += chunk.toString() })
        tunnel!.once('end', () => resolve(text)); tunnel!.once('error', reject)
        tunnel!.setTimeout(3000, () => reject(new Error('Loopback request timed out')))
      })
      tunnel.write('after rotation')
      expect(await response).toBe('OK')
      for (let attempt = 0; attempt < 40 && (await stat(log)).size === 0; attempt++) await wait(50)
      const content = await readFile(log, 'utf8')
      expect(content.length).toBeGreaterThan(0)
      expect(content).not.toContain('\0')
      expect(proc.exitCode).toBeNull()
    } finally {
      tunnel?.destroy()
      if (proc && proc.exitCode === null) {
        const closed = once(proc, 'close')
        proc.kill()
        await closed
      }
      if (reservation.listening) await new Promise<void>(resolve => reservation.close(() => resolve()))
      await new Promise<void>(resolve => endpoint.close(() => resolve()))
      await rm(dir, { recursive: true, force: true })
    }
  }, 15000)
})
