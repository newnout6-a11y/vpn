// WP-11 Electron migration; AT-01-001/003/004/007/010, F-166/F-167.
// Runs real Electron with the production preload and security modules, using
// isolated userData. Does not start VPN runtimes or change network/clipboard state.
import { spawnSync } from 'node:child_process'
import { createRequire } from 'node:module'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { build } from 'esbuild'

const require = createRequire(import.meta.url)
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const tempRoot = join(root, '.tmp')
mkdirSync(tempRoot, { recursive: true })
const work = mkdtempSync(join(tempRoot, 'electron-smoke-'))
try {
  writeFileSync(join(work, 'renderer.html'), '<!doctype html><meta http-equiv="Content-Security-Policy" content="default-src \'none\'"><title>Electron migration smoke</title>')
  writeFileSync(join(work, 'other.html'), '<!doctype html><title>Untrusted entry</title>')
  await build({
    entryPoints: [join(root, 'scripts/fixtures/electron-runtime-smoke.ts')],
    outfile: join(work, 'main.cjs'), bundle: true, platform: 'node',
    format: 'cjs', external: ['electron']
  })
  await build({ entryPoints: [join(root, 'scripts/fixtures/request-document-native.ts')],
    outfile: join(work, 'requester.cjs'), bundle: true, platform: 'node',
    format: 'cjs', external: ['electron'] })
  await build({ entryPoints: [join(root, 'scripts/fixtures/config-request-native.ts')],
    outfile: join(work, 'config-request.cjs'), bundle: true, platform: 'node',
    format: 'cjs', external: ['electron', 'koffi'] })
  await build({ entryPoints: [join(root, 'scripts/fixtures/diagnostics-request-native.ts')],
    outfile: join(work, 'diagnostics-request.cjs'), bundle: true, platform: 'node', format: 'cjs', external: ['electron', 'koffi'],
    plugins: [{ name: 'controlled-diagnostic-collection', setup(builder) {
      const boundaries = {
        './systemSnapshot': 'export const captureSnapshot=(...args)=>globalThis.vpnteDiagnosticSnapshot(...args)',
        './systemDiagnostics': 'export const runSystemDiagnostics=async()=>({fixture:true})',
        './trafficForensics': 'export const stageTrafficForensicsArtifacts=async()=>false',
        './tunController': 'export const getTunRuntimeDir=()=>"missing-native-diagnostics-runtime"',
        './systemNetwork': 'export const validateNetworkBackupManifest=value=>value',
        './firewallKillSwitch': 'export const validateFirewallManifest=value=>value',
        './physicalAdapterLockdown': 'export const validateLockdownManifest=value=>value',
        './recoveryManifest': 'export const readRecoveryManifest=async()=>null;export const validateBootRecoveryReport=value=>value'
      }
      builder.onResolve({ filter: /^\.\// }, args => args.importer.endsWith('diagnosticsExport.ts') && boundaries[args.path]
        ? { path: args.path, namespace: 'diagnostics-native' } : undefined)
      builder.onLoad({ filter: /.*/, namespace: 'diagnostics-native' }, ({ path }) => ({ loader: 'js', contents: boundaries[path] }))
    } }]
  })
  await build({ entryPoints: [join(root, 'scripts/fixtures/server-request-native.ts')],
    outfile: join(work, 'server-request.cjs'), bundle: true, platform: 'node', format: 'cjs', external: ['electron', 'koffi'],
    plugins: [{ name: 'controlled-profile-boundaries', setup(builder) {
      builder.onResolve({ filter: /^\.\/vpnProfiles$/ }, () => ({ path: 'profiles', namespace: 'server-native' }))
      builder.onResolve({ filter: /^\.\/tunController$/ }, () => ({ path: 'tunnel', namespace: 'server-native' }))
      builder.onResolve({ filter: /^\.\/adaptiveBypass$/ }, () => ({ path: 'adaptive', namespace: 'server-native' }))
      builder.onResolve({ filter: /^\.\/ipMonitor$/ }, () => ({ path: 'monitor', namespace: 'server-native' }))
      builder.onResolve({ filter: /^\.\/keyHealthChecker$/ }, () => ({ path: 'health', namespace: 'server-native' }))
      builder.onLoad({ filter: /.*/, namespace: 'server-native' }, ({ path }) => ({ loader: 'js', resolveDir: root, contents:
        path === 'profiles' ? `export * from ${JSON.stringify(join(root, 'src/main/vpnProfiles.ts'))}; export const resolveVpnProfiles=(...args)=>globalThis.vpnteProfileBoundary(...args)`
          : path === 'tunnel' ? 'const unexpected=()=>{throw new Error("Unexpected runtime access in import fixture")}; export const getDirectProxyPort=()=>1080; export const getTunRuntimeDir=unexpected,getBundledResource=unexpected,pickFreeLocalPort=unexpected,copyResourceIfStale=unexpected; export const tunController={getStatus:()=>({running:false}),setWatchdogProbeConfirmationChecker:()=>{}}'
            : path === 'adaptive' ? 'export const beginAdaptiveConnection=()=>{}; export const readAdaptiveNetworkFingerprint=()=>{}'
              : path === 'health' ? 'export const checkGroupHealth=()=>{throw new Error("Unexpected health check in import fixture")}'
                : 'export const ipMonitor={}' }))
    } }]
  })
  await build({
    entryPoints: [join(root, 'scripts/fixtures/speed-test-ui-native.ts')],
    outfile: join(work, 'speed-ui.cjs'), bundle: true, platform: 'node', format: 'cjs', external: ['electron'],
    plugins: [{ name: 'controlled-speed-boundaries', setup(builder) {
      builder.onResolve({ filter: /^\.\/tunController$/ }, () => ({ path: 'vpn-ready', namespace: 'speed-native' }))
      builder.onResolve({ filter: /^axios$/ }, () => ({ path: 'http', namespace: 'speed-native' }))
      builder.onLoad({ filter: /.*/, namespace: 'speed-native' }, ({ path }) => ({ loader: 'js', contents: path === 'vpn-ready'
        ? 'export const tunController={getStatus:()=>({running:true,vpnProfileName:"Native fixture"})}'
        : 'export default {get:(...args)=>globalThis.vpnteSpeedBoundary(...args)}' }))
    } }]
  })
  await build({ entryPoints: [join(root, 'scripts/fixtures/url-probe-native.ts')],
    outfile: join(work, 'url-probe.cjs'), bundle: true, platform: 'node', format: 'cjs', external: ['electron'],
    plugins: [{ name: 'controlled-url-store-boundaries', setup(builder) {
      const boundaries = {
        './versionedStore': 'export default class {get(){return []}set(){}}',
        './appLogger': 'export const logEvent=()=>{}',
        './settings': 'export const settingsStore={get:()=>({})}',
        './tunController': 'export const tunController={getStatus:()=>({running:false})};export const getDirectProxyPort=()=>null,getClashApiInfo=()=>null'
      }
      builder.onResolve({ filter: /^\.\// }, args => boundaries[args.path] ? { path: args.path, namespace: 'url-native' } : undefined)
      builder.onLoad({ filter: /.*/, namespace: 'url-native' }, ({ path }) => ({ loader: 'js', contents: boundaries[path] }))
    } }]
  })
  await build({ entryPoints: [join(root, 'scripts/fixtures/notifications-native.ts')],
    outfile: join(work, 'notifications.cjs'), bundle: true, platform: 'node', format: 'cjs', external: ['electron', 'koffi'],
    plugins: [{ name: 'controlled-notification-registry', setup(builder) {
      builder.onResolve({ filter: /^child_process$/ }, args => args.importer.endsWith('notifications.ts')
        ? { path: 'reg', namespace: 'notifications-native' } : undefined)
      builder.onLoad({ filter: /.*/, namespace: 'notifications-native' }, () => ({ loader: 'js', contents:
        'export const execFile=()=>{throw new Error("Use promisified registry boundary")};execFile[Symbol.for("nodejs.util.promisify.custom")]=(...args)=>globalThis.vpnteNotificationReg(...args)' }))
    } }]
  })
  const env = { ...process.env }
  delete env.ELECTRON_RUN_AS_NODE
  delete env.NODE_ENV // No unit-test escape or test cipher in this native smoke.
  env.VPNTE_SMOKE_DIR = work
  env.VPNTE_SMOKE_PRELOAD = join(root, 'out/preload/index.js')
  env.VPNTE_SMOKE_VERSION = require('../package.json').devDependencies.electron
  for (const [fixture, marker] of [['main.cjs', 'ELECTRON_SMOKE_PASS'], ['notifications.cjs', 'NOTIFICATIONS_NATIVE_PASS'], ['speed-ui.cjs', 'SPEED_UI_NATIVE_PASS'], ['requester.cjs', 'REQUEST_DOCUMENT_NATIVE_PASS'], ['config-request.cjs', 'CONFIG_REQUEST_NATIVE_PASS'], ['server-request.cjs', 'SERVER_REQUEST_NATIVE_PASS'], ['diagnostics-request.cjs', 'DIAGNOSTICS_REQUEST_NATIVE_PASS'], ['url-probe.cjs', 'URL_PROBE_NATIVE_PASS']]) {
    const result = spawnSync(require('electron'), [join(work, fixture)], {
      cwd: root, env, encoding: 'utf8', windowsHide: true, timeout: 60_000
    })
    if (result.stdout) process.stdout.write(result.stdout)
    if (result.status !== 0 || !result.stdout?.includes(marker)) {
      if (result.stderr) process.stderr.write(result.stderr)
      throw result.error ?? new Error(`Electron smoke failed (exit ${result.status})`)
    }
  }
} finally {
  // Only this run's newly created directory is removed.
  if (dirname(work) !== tempRoot) throw new Error('Unexpected smoke cleanup path')
  rmSync(work, { recursive: true, force: true })
}
