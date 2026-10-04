import { spawnSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { mkdirSync, mkdtempSync, writeFileSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { build } from 'esbuild'
import { runWithCleanup, removeWp1WorkDirectory } from './wp1-test-cleanup.mjs'
const require = createRequire(import.meta.url)
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
if (process.platform !== 'win32') throw new Error('Windows native acceptance cannot PASS on this platform')
const tempRoot = join(root, '.tmp'); mkdirSync(tempRoot, { recursive: true })
const work = mkdtempSync(join(tempRoot, 'wp1-native-'))
const stdout = await runWithCleanup(async () => {
  const output = readFileSync(join(root, 'out/renderer/index.html'), 'utf8')
  const meta = output.match(/<meta\s+http-equiv="Content-Security-Policy"[\s\S]*?>/i)?.[0]
  if (!meta) throw new Error('Production CSP meta missing; run npm run build first')
  writeFileSync(join(work, 'renderer.html'), `<!doctype html>${meta}<title>WP1 production CSP</title>`)
  // The hostile-frame fixture needs a local frame; production CSP is tested
  // separately and is never weakened to make the hostile IPC test pass.
  writeFileSync(join(work, 'hostile.html'), `<!doctype html>${meta.replace('frame-src https://www.openstreetmap.org', "frame-src 'self'")}<title>Hostile IPC fixture</title>`)
  writeFileSync(join(work, 'child.html'), '<!doctype html><title>Hostile subframe</title>')
  writeFileSync(join(work, 'eval.js'), `eval('window.EVAL_RAN=true')`)
  writeFileSync(join(work, 'hostile-preload.cjs'), `const { ipcRenderer } = require('electron'); if (!process.isMainFrame) ipcRenderer.invoke('save-settings', {}).then(() => 'accepted', error => error.message).then(result => ipcRenderer.send('wp1:subframe-result', result));`)
  await build({ entryPoints: [join(root, 'scripts/fixtures/wp1-native.ts')], outfile: join(work, 'main.cjs'),
    bundle: true, platform: 'node', format: 'cjs', external: ['electron'], plugins: [{
      name: 'isolated-diagnostics-boundaries', setup(build) {
        // This host is not elevated. Use declared L2 system boundaries for the
        // ZIP pipeline; retain real redaction, filesystem and Compress-Archive.
        // Runtime-path reads in this L2 ZIP fixture stay in isolated userData.
        // This does not test trusted ProgramData bootstrap or elevated launch.
        build.onResolve({ filter: /^\.\/runtimePaths$/ }, () => ({ path: 'runtimePaths', namespace: 'wp1-runtime-fixture' }))
        build.onLoad({ filter: /.*/, namespace: 'wp1-runtime-fixture' }, () => ({
          contents: `import {app} from 'electron'; import {join} from 'node:path'; export const getPrivilegedRuntimeDir = name => join(app.getPath('userData'), name)`, loader: 'js'
        }))
        build.onResolve({ filter: /^\.\/(systemDiagnostics|recoveryManifest)$/ }, args => {
          if (args.importer.endsWith('diagnosticsExport.ts')) return { path: args.path, namespace: 'wp1-system-fixture' }
        })
        build.onLoad({ filter: /.*/, namespace: 'wp1-system-fixture' }, args => ({ contents: args.path.endsWith('systemDiagnostics')
          ? `export async function runSystemDiagnostics(){return {password:'FAKE-WP1-NATIVE-SECRET', environment:{HTTP_PROXY:'http://user:FAKE-WP1-NATIVE-SECRET@proxy.test'}}}`
          : `export async function readRecoveryManifest(){return null}; export const validateBootRecoveryReport = value => value`, loader: 'js' }))
      }
    }] })
  const env = { ...process.env, VPNTE_WP1_WORK: work, VPNTE_WP1_PRELOAD: join(root, 'out/preload/index.js'),
    VPNTE_WP1_CLIPBOARD: process.argv.includes('--clipboard') ? '1' : '0' }
  delete env.NODE_ENV; delete env.ELECTRON_RUN_AS_NODE
  const result = spawnSync(require('electron'), [join(work, 'main.cjs')], { cwd: root, env,
    encoding: 'utf8', windowsHide: true, timeout: 180_000, maxBuffer: 4 * 1024 * 1024 })
  if (result.status !== 0 || !result.stdout?.includes('WP1_NATIVE_PASS')) {
    if (result.stderr) process.stderr.write(result.stderr)
    throw result.error ?? new Error(`Native WP1 failed (exit ${result.status})`)
  }
  return result.stdout
}, () => removeWp1WorkDirectory(work, tempRoot))
// A child PASS marker is not an overall PASS until the owned work directory is removed.
if (stdout) process.stdout.write(stdout)
