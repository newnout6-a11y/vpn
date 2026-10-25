// AT-02-004; AT-10-004: Node mocks cannot establish Electron/BoringSSL compatibility.
import { spawn, spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { createServer, type AddressInfo } from 'node:net'
import { dirname, join, resolve } from 'node:path'
import { build } from 'esbuild'
import { describe, expect, it } from 'vitest'

describe.skipIf(process.platform !== 'win32')('SOCKS egress probe under actual Electron', () => {
  it.each([false, true])('owns bundled Xray through Electron probe completion or timeout=%s (AT-02-004)', async timeout => {
    const tempRoot = resolve('.tmp')
    mkdirSync(tempRoot, { recursive: true })
    const directory = mkdtempSync(join(tempRoot, 'socks-electron-'))
    const reservations = [createServer(), createServer()]
    let xray: ReturnType<typeof spawn> | undefined
    let exited: Promise<void> | undefined
    try {
      const main = join(directory, 'main.cjs')
      await build({ entryPoints: [resolve('scripts/fixtures/socks-upstream-native.ts')], outfile: main,
        bundle: true, platform: 'node', format: 'cjs', external: ['electron', 'socks'], logLevel: 'silent',
        plugins: [{ name: 'isolated-probe-logger', setup(builder) {
          builder.onResolve({ filter: /^\.\/appLogger$/ }, args => args.importer.endsWith('socksUpstreamProbe.ts')
            ? { path: 'logger', namespace: 'socks-native' } : undefined)
          builder.onLoad({ filter: /.*/, namespace: 'socks-native' }, () => ({ loader: 'js', contents:
            'export const logEvent=(_level,_scope,_message,details)=>console.log("SOCKS_NATIVE_DIAGNOSTIC",JSON.stringify(details))' }))
        } }] })
      const ports = await Promise.all(reservations.map(server => new Promise<number>((done, fail) => {
        server.once('error', fail)
        server.listen(0, '127.0.0.1', () => done((server.address() as AddressInfo).port))
      })))
      const config = join(directory, 'xray.json')
      writeFileSync(config, JSON.stringify({ log: { loglevel: 'none' },
        // This fixture intentionally holds a remote response forever. Avoid
        // racing its 1s peer assertion against Xray's default 1s half-close grace.
        policy: { levels: { '0': { uplinkOnly: 0, downlinkOnly: 0 } } },
        inbounds: [{ listen: '127.0.0.1', port: ports[0], protocol: 'socks', settings: {
          auth: 'password', accounts: [{ user: 'loopback-user', pass: 'loopback-password' }], udp: false } }],
        outbounds: [{ protocol: 'freedom', settings: { redirect: `127.0.0.1:${ports[1]}` } }]
      }))
      await Promise.all(reservations.map(server => new Promise<void>(done => server.close(() => done()))))
      // The outer test owns Xray even if Electron is forcibly terminated before its finally.
      xray = spawn(resolve('resources/xray.exe'), ['run', '-c', config], { windowsHide: true, stdio: 'ignore' })
      exited = new Promise<void>(done => xray!.once('close', () => done()))
      await new Promise<void>((done, fail) => { xray!.once('spawn', () => done()); xray!.once('error', fail) })
      const env: NodeJS.ProcessEnv = { ...process.env, VPNTE_SOCKS_FIXTURE_DIR: directory,
        VPNTE_SOCKS_UPSTREAM_PORT: String(ports[0]), VPNTE_SOCKS_ENDPOINT_PORT: String(ports[1]),
        VPNTE_SOCKS_FORCE_HANG: timeout ? '1' : '0' }
      delete env.ELECTRON_RUN_AS_NODE
      delete env.NODE_ENV
      const require = createRequire(import.meta.url)
      const result = spawnSync(require('electron'), [main, '--disable-gpu'], {
        cwd: process.cwd(), env, windowsHide: true, encoding: 'utf8', timeout: timeout ? 1000 : 20_000
      })
      if (timeout) {
        expect(result.error).toMatchObject({ code: 'ETIMEDOUT' })
        expect(xray.exitCode).toBeNull()
        return
      }
      expect(result.error, String(result.error)).toBeUndefined()
      expect(result.status, result.stdout + result.stderr).toBe(0)
      expect(result.stdout).toContain('SOCKS_UPSTREAM_NATIVE_PASS')
      expect(result.stdout).toContain('DEPTH_ZERO_SELF_SIGNED_CERT')
      expect(result.stdout).not.toContain('loopback-password')
    } finally {
      await Promise.all(reservations.map(server => new Promise<void>(done => server.close(() => done()))))
      if (xray) {
        if (xray.exitCode === null && xray.signalCode === null) xray.kill()
        let timer: ReturnType<typeof setTimeout> | undefined
        await Promise.race([exited, new Promise<never>((_done, fail) => {
          timer = setTimeout(() => fail(new Error('Outer fixture did not confirm Xray exit')), 2000)
        })]).finally(() => clearTimeout(timer))
        expect(xray.exitCode !== null || xray.signalCode !== null).toBe(true)
      }
      if (dirname(directory) !== tempRoot) throw new Error('Unexpected Electron fixture cleanup target')
      rmSync(directory, { recursive: true, force: true })
    }
  }, 30_000)
})
