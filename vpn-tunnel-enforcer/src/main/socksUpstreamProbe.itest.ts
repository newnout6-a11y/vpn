// AT-02-004; AT-10-004: Node mocks cannot establish Electron/BoringSSL compatibility.
import { spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join, resolve } from 'node:path'
import { build } from 'esbuild'
import { describe, expect, it } from 'vitest'

describe.skipIf(process.platform !== 'win32')('SOCKS egress probe under actual Electron', () => {
  it('uses bundled Xray, strict TLS, provider fallback and complete cancellation on loopback', async () => {
    const tempRoot = resolve('.tmp')
    mkdirSync(tempRoot, { recursive: true })
    const directory = mkdtempSync(join(tempRoot, 'socks-electron-'))
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
      const env: NodeJS.ProcessEnv = { ...process.env, VPNTE_SOCKS_FIXTURE_DIR: directory }
      delete env.ELECTRON_RUN_AS_NODE
      delete env.NODE_ENV
      const require = createRequire(import.meta.url)
      const result = spawnSync(require('electron'), [main, '--disable-gpu'], {
        cwd: process.cwd(), env, windowsHide: true, encoding: 'utf8', timeout: 20_000
      })
      expect(result.error, String(result.error)).toBeUndefined()
      expect(result.status, result.stdout + result.stderr).toBe(0)
      expect(result.stdout).toContain('SOCKS_UPSTREAM_NATIVE_PASS')
      expect(result.stdout).toContain('DEPTH_ZERO_SELF_SIGNED_CERT')
      expect(result.stdout).not.toContain('loopback-password')
    } finally {
      if (dirname(directory) !== tempRoot) throw new Error('Unexpected Electron fixture cleanup target')
      rmSync(directory, { recursive: true, force: true })
    }
  }, 30_000)
})
