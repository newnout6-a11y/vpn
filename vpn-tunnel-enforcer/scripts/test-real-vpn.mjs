// Real production IPC/TUN test, restricted to a disposable GitHub-hosted Windows machine.
import assert from 'node:assert/strict'
import { spawn, execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readFile, writeFile, mkdir, stat } from 'node:fs/promises'
import { createServer } from 'node:net'
import { dirname, join, resolve, win32 } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify, parseArgs } from 'node:util'
import { test } from 'node:test'
import { createInterface } from 'node:readline'
import { setTimeout as delay } from 'node:timers/promises'
import { performance } from 'node:perf_hooks'
import { assertStable, deadline, runScenario } from './real-vpn-scenario.mjs'
import { connectInspector } from './real-vpn-inspector.mjs'
import { requireHostedWindows, readScenarioSecret, seedScenario, hostedLaunchArgs, verifyNativeTunOwnership, verifySelectorTlsFlow, safeWindowsOracleError, snapshotRuntimeLogs, inspectRuntimeFailures } from './real-vpn-runner.mjs'
import { createProgressLog, safeAppEvent, safeSnapshot, safeElectronDiagnostic } from './real-vpn-log.mjs'
import { runWithCleanup } from './wp1-test-cleanup.mjs'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const powershell = join(process.env.SystemRoot || 'C:\\Windows', 'System32/WindowsPowerShell/v1.0/powershell.exe')
const exec = promisify(execFile)
const quote = value => "'" + String(value).replaceAll("'", "''") + "'"
const ps = async (source, timeout = 30_000) => {
  try {
    return (await exec(powershell, ['-NoProfile', '-NonInteractive', '-EncodedCommand',
      Buffer.from("$ErrorActionPreference='Stop';\n" + source, 'utf16le').toString('base64')],
    { windowsHide: true, maxBuffer: 1024 * 1024, timeout })).stdout.trim()
  } catch (error) { throw safeWindowsOracleError(error) }
}
const hash = value => createHash('sha256').update(value).digest('hex')
const adminCheck = "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)"
async function run(config, seed) {
  const report = { schemaVersion: 1, startedAt: new Date().toISOString(), status: 'FAIL', steps: [],
    runner: { os: process.env.RUNNER_OS, image: process.env.ImageOS, commit: process.env.GITHUB_SHA },
    limits: ['Real production Direct VPN IPC/runtime, without UI clicks.',
      'Windows Server/cloud network timings differ from the user PC.',
      'Not a packet-leak oracle, OS matrix, or p95 acceptance run.'] }
  const save = () => writeFile(join(config.output, 'report.json'), JSON.stringify(report, null, 2) + '\n')
  const scenarioDeadline = performance.now() + 300_000
  let cleaningUp = false
  const progress = createProgressLog(join(config.output, 'progress.log'), { admit: action => {
    if (!cleaningUp && !['ipc/cancelTun', 'ipc/serversCancelSwitch'].includes(action)) {
      assert.ok(performance.now() < scenarioDeadline, 'Run budget exhausted; proceed to cleanup')
    }
  } })
  report.budgets = { admissionMs: 300_000, operationMs: config.timeoutMs, shutdownMs: 135_000 }
  progress.record('runner-started')
  let inspector, application, originalId, runtimeDir, userData, tunAlias = '', renderer, invoke, settingsDigest
  let eventCursor = 0, eventsReady = false, refreshing = false, lastWindows = ''
  report.appEvents = []
  const seen = new Set()
  const refresh = async () => {
    if (refreshing) return
    refreshing = true
    try {
      if (userData) for (const name of ['app.prev.log', 'app.log']) {
        let content
        try { content = await readFile(join(userData, 'logs', name), 'utf8') } catch { continue }
        for (const line of content.split(/\r?\n/)) {
          let event
          try { event = JSON.parse(line) } catch { continue }
          if (!event || event.ts < report.startedAt) continue
          const safe = safeAppEvent(event)
          if (!safe || seen.has(JSON.stringify(event))) continue
          seen.add(JSON.stringify(event))
          report.appEvents.push(safe)
          progress.record('app', safe)
        }
      }
      if (inspector) {
        const windows = await inspector.evaluate(`__realVpnElectron.BrowserWindow.getAllWindows().filter(w => !w.isDestroyed()).map(w => ({
          id:w.id, loading:w.webContents.isLoadingMainFrame(), crashed:w.webContents.isCrashed(),
          appPage:w.webContents.getURL().endsWith('/renderer/index.html'), visible:w.isVisible()
        }))`)
        if (JSON.stringify(windows) !== lastWindows) {
          lastWindows = JSON.stringify(windows)
          progress.record('renderer-windows', { windows })
        }
      }
      if (eventsReady && inspector) for (const event of await renderer(`window.__realVpnEvents.slice(${eventCursor})`) ?? []) {
        eventCursor++
        progress.record('state', event)
      }
    } finally { refreshing = false }
  }
  const monitor = setInterval(() => { void refresh().catch(() => {}) }, 1000)
  monitor.unref()
  const proof = (expectedPid, { requireEndpointPair = false } = {}) => progress.run('oracle/windows', async () => {
    const until = performance.now() + 30000
    const remaining = () => {
      const ms = Math.floor(until - performance.now())
      assert.ok(ms > 0, 'Independent Windows oracle deadline exceeded')
      return ms
    }
    const result = JSON.parse(await ps(`& ${quote(join(root, 'scripts/real-vpn-windows.ps1'))} -RuntimeDir ${quote(runtimeDir)} -ExpectedPid ${expectedPid} -TunAlias ${quote(tunAlias)}${requireEndpointPair ? ' -RequireEndpointPair' : ''}`, remaining()))
    tunAlias = result.tunAlias
    progress.record('os', { runtimeProcessCount: result.runtimeProcessCount, tunProcessCount: result.tunProcessCount,
      matchingPid: result.matchingPid, adapterUp: result.adapterUp, interfaceAddressCount: result.interfaceAddressCount })
    if (result.endpointOsRoutes?.applicable) {
      assert.ok(result.endpointOsRoutes.allViaOwnedTun === true && Number.isInteger(result.endpointOsRoutes.endpointCount)
        && result.endpointOsRoutes.endpointCount > 0 && result.endpointOsRoutes.tunRouteCount === result.endpointOsRoutes.endpointCount
        && Number.isInteger(result.endpointOsRoutes.configuredSlots) && result.endpointOsRoutes.configuredSlots >= 1
        && result.endpointOsRoutes.configuredSlots <= 2 && (!requireEndpointPair || result.endpointOsRoutes.configuredSlots === 2), 'Endpoint OS routes were not confirmed')
      progress.record('endpoint-os-routes', result.endpointOsRoutes)
      result.selectorTlsFlow = await progress.run('oracle/selector-ordinary-tls-flow', async () => {
        let config
        try { config = JSON.parse(await readFile(join(runtimeDir, 'sing-box.json'), 'utf8')) }
        catch { throw new Error('Selector configuration unavailable; private details omitted') }
        return verifySelectorTlsFlow(config, { timeoutMs: Math.min(5000, remaining()) })
      })
      assert.equal(result.selectorTlsFlow.applicable, true, 'Selector disappeared during ordinary TLS proof')
      progress.record('selector-ordinary-tls-flow', result.selectorTlsFlow)
    }
    if (expectedPid && !report.nativeTunOwnership) {
      report.nativeTunOwnership = await progress.run('oracle/native-tun-ownership', () => verifyNativeTunOwnership(async (args, envPatch) =>
        (await exec(process.execPath, [join(root, 'node_modules/vitest/vitest.mjs'), ...args], {
          cwd: root, env: { ...process.env, ...envPatch }, windowsHide: true, timeout: remaining(), maxBuffer: 1024 * 1024
        })).stdout))
      progress.record('native-tun-ownership', report.nativeTunOwnership)
    }
    return result
  })
  await test('AT-00-003/005/007, AT-02-002/009 real connection sequence (partial coverage)', async t => {
    try {
      await runWithCleanup(async () => {
        const admin = await progress.run('prepare/admin', () => ps(adminCheck))
        assert.equal(admin, 'True', 'GitHub runner must already be elevated; no UAC/relaunch is attempted')
        // Reject reuse before launch. Never shut down an existing client or use its DPAPI stores.
        assert.equal(await progress.run('prepare/processes', () => ps(`@(Get-CimInstance Win32_Process -Filter "Name='VPN Tunnel Enforcer.exe' OR Name='vpnte-sing-box.exe' OR Name='vpnte-xray.exe'").Count`)), '0', 'Existing VPN process found; run refused')
        userData = win32.join(process.env.APPDATA, 'vpn-tunnel-enforcer')
        await progress.run('prepare/fresh-profile', () => assert.rejects(stat(userData), { code: 'ENOENT' }, 'Existing application profile found; run refused'))
        const server = createServer()
        await new Promise((ok, no) => { server.once('error', no); server.listen(0, '127.0.0.1', ok) })
        const port = server.address().port
        await new Promise(ok => server.close(ok))
        report.build = { asarSha256: hash(await readFile(join(dirname(config.exe), 'resources/app.asar'))) }
        const env = { ...process.env }
        delete env.VPNTE_REAL_SCENARIO
        // Manual spawn: a transport failure must never force-kill a live VPN runtime.
        application = await progress.run('prepare/launch', () => spawn(config.exe, hostedLaunchArgs(port), {
          cwd: dirname(config.exe), env, windowsHide: true, stdio: ['ignore', 'ignore', 'pipe'] }))
        report.electronDiagnostics = []
        createInterface({ input: application.stderr }).on('line', line => {
          const diagnostic = safeElectronDiagnostic(line)
          if (diagnostic) {
            report.electronDiagnostics.push(diagnostic)
            progress.record('electron-diagnostic', diagnostic)
          }
        })
        application.once('exit', (code, signal) => {
          report.applicationExit = { code, signal }
          progress.record('application-exit', report.applicationExit)
        })
        const launchError = new Promise((_, reject) => application.once('error', () => reject(new Error('Application launch failed'))))
        inspector = await progress.run('prepare/inspector', () => Promise.race([connectInspector(port, application.pid, config.timeoutMs), launchError]))
        await progress.run('prepare/window-hooks', () => inspector.evaluate(`(() => {
          const e = globalThis.__realVpnElectron;
          const hide = w => { w.hide(); w.on('show', () => w.hide()); };
          e.BrowserWindow.getAllWindows().forEach(hide);
          e.app.on('browser-window-created', (_event, w) => hide(w));
          return true;
        })()`))
        const identity = await inspector.evaluate(`({packaged:__realVpnElectron.app.isPackaged, version:__realVpnElectron.app.getVersion(), userData:__realVpnElectron.app.getPath('userData')})`)
        assert.equal(identity.packaged, true, 'Use a packaged production executable')
        assert.equal(win32.resolve(identity.userData).toLowerCase(), win32.resolve(userData).toLowerCase(), 'Unexpected user profile')
        report.build.version = identity.version
        report.build.executionLevel = 'asInvoker (CI artifact only)'
        const mainElevated = await progress.run('prepare/application-admin', () => inspector.evaluate(`new Promise((resolve, reject) => {
          process.mainModule.require('node:child_process').execFile(${JSON.stringify(powershell)},
            ['-NoProfile', '-NonInteractive', '-EncodedCommand', ${JSON.stringify(Buffer.from(adminCheck, 'utf16le').toString('base64'))}],
            {windowsHide:true, timeout:10000}, (error, stdout) => error ? reject(new Error('Admin readback failed')) : resolve(stdout.trim() === 'True'));
        })`))
        assert.equal(mainElevated, true, 'The actual Electron main process must be elevated')
        report.runner.elevatedMain = mainElevated
        const instance = hash(win32.resolve(userData).toLowerCase()).slice(0, 32)
        runtimeDir = win32.join(process.env.ProgramData || 'C:\\ProgramData', 'VPNTE/runtime', instance, 'tun-runtime')
        renderer = inspector.renderer
        await progress.run('prepare/preload', async () => {
          const until = Date.now() + config.timeoutMs
          while (!await renderer('Boolean(window.electronAPI?.getTunStatus)')) {
            assert.ok(Date.now() < until, 'Production preload did not become ready'); await delay(100)
          }
        })
        invoke = (method, ...args) => progress.run(`ipc/${method}`, () => renderer(`window.electronAPI[${JSON.stringify(method)}](...${JSON.stringify(args)})`))
        assertStable(await invoke('getTunStatus'), false)
        const pair = await progress.run('prepare/settings-and-profiles', () => seedScenario(invoke, seed))
        originalId = pair.original.id
        settingsDigest = hash(JSON.stringify(pair.settings))
        report.settings = { sha256: settingsDigest, connectionMode: pair.settings.connectionMode,
          routingMode: pair.settings.routingMode, firewallKillSwitch: pair.settings.firewallKillSwitch,
          smartRuSplit: pair.settings.smartRuSplit, strictAdapterLockdown: pair.settings.strictAdapterLockdown,
          adaptiveBypassEnabled: pair.settings.adaptiveBypassEnabled, autoPilotEnabled: pair.settings.autoPilotEnabled }
        report.profiles = { A: { id: pair.original.id, protocol: pair.original.protocol },
          B: { id: pair.target.id, protocol: pair.target.protocol } }
        await renderer(`(() => {
          window.__realVpnEvents = [];
          window.electronAPI.onTunnelStateChanged(s => window.__realVpnEvents.push((${safeSnapshot.toString()})(s)));
          return true;
        })()`)
        eventsReady = true
        const driver = { invoke, proof, waitTransition: async (kind, revision) => {
          const until = Date.now() + config.timeoutMs
          while (Date.now() < until) {
            if (await renderer(`window.__realVpnEvents.some(s => s.revision > ${revision} && s.transition === ${JSON.stringify(kind)})`)) return
            await delay(50)
          }
          throw new Error('No admitted backend transition observed for cancellation')
        } }
        await runScenario(driver, { ...pair, ...config, scenarioTimeoutMs: Math.max(0, scenarioDeadline - performance.now()) }, async (name, action) => {
          let failure
          const runtimeLogBaseline = runtimeDir ? await snapshotRuntimeLogs(runtimeDir) : undefined
          await t.test(name, async () => {
            try {
              const result = await progress.run(`scenario/${name}`, action)
              report.steps.push({ name, status: 'PASS', ...result })
              progress.record('step-pass', { action: name, elapsedMs: result.elapsedMs,
                acknowledgementMs: result.acknowledgementMs, cancelToSettledMs: result.cancelToSettledMs })
            } catch (error) {
              failure = error
              report.steps.push({ name, status: 'FAIL', reason: 'Action or oracle failed; see test result' })
              if (runtimeDir) {
                report.runtimeFailureKinds = await inspectRuntimeFailures(runtimeDir, runtimeLogBaseline)
                progress.record('runtime-failure-kinds', { files: report.runtimeFailureKinds })
              }
              progress.record('step-fail', { action: name })
              throw error
            } finally { await save() }
          })
          if (failure) throw failure
        })
        report.ipVerification = await progress.run('oracle/vpn-egress', () => renderer(`window.electronAPI.getPublicIp().then(p => ({verdict:p.verdict, isLeak:p.isLeak}))`))
        assert.equal(report.ipVerification.isLeak, false, 'Application detected an IP leak')
        assert.equal(report.ipVerification.verdict, 'passed', 'VPN egress has not been verified by the application')
        report.status = 'PASS'
      }, async () => {
        cleaningUp = true
        progress.record('cleanup-started')
        await runWithCleanup(async () => { if (invoke) {
          assert.equal((await deadline(invoke('stopTun'), config.timeoutMs, 'cleanup stop')).success, true)
          assertStable(await invoke('getTunStatus'), false)
          const os = await proof(0)
          assert.equal(os.runtimeProcessCount, 0)
          assert.equal(os.adapterUp, false)
          if (originalId) await invoke('serversSelect', originalId)
          if (settingsDigest) assert.ok(hash(JSON.stringify(await invoke('getSettings'))) === settingsDigest, 'Settings changed during test')
          report.cleanup = { status: 'PASS', state: 'disconnected', os, settingsUnchanged: true }
          report.transitions = await renderer('window.__realVpnEvents ?? []')
        } }, async () => {
          inspector?.close()
          if (application?.pid) {
            await progress.run('cleanup/shutdown', () => ps(`& ${quote(join(root, 'build/shutdown-for-update.ps1'))} -InstallDir ${quote(dirname(config.exe))}; if ($LASTEXITCODE -ne 0) { throw 'Acknowledged shutdown failed' }`, 135_000))
            report.debugInstanceClosed = true
          }
        })
      })
    } catch (error) {
      inspector?.close()
      report.status = 'FAIL'
      report.reason = 'Scenario or cleanup failed; see test result'
      if (report.cleanup?.status !== 'PASS' || !report.debugInstanceClosed) report.cleanup = { status: 'FAIL', reason: 'Cleanup not confirmed; no process was force-killed' }
      throw error
    } finally {
      report.finishedAt = new Date().toISOString()
      clearInterval(monitor)
      inspector = undefined
      await refresh()
      report.ipc = report.appEvents.filter(event => event.scope === 'ipc')
      progress.record('runner-finished', { status: report.status, cleanup: report.cleanup?.status ?? 'NOT VERIFIED' })
      progress.close()
      await save()
      if (process.env.GITHUB_STEP_SUMMARY) {
        const rows = report.steps.map(s => `| ${s.name} | ${s.status} | ${s.elapsedMs ?? '-'} | ${s.acknowledgementMs ?? '-'} | ${s.cancelToSettledMs ?? '-'} |`)
        await writeFile(process.env.GITHUB_STEP_SUMMARY, `Real VPN: **${report.status}**\n\n| Action | Result | ms | Cancel ack ms | Cancel settled ms |\n|---|---|---:|---:|---:|\n${rows.join('\n')}\n\nCleanup: ${report.cleanup?.status ?? 'NOT VERIFIED'}\n`, { flag: 'a' })
      }
    }
  })
}

const { values } = parseArgs({ options: { exe: { type: 'string' },
  'cancel-after-ms': { type: 'string', default: process.env.VPNTE_CANCEL_AFTER_MS || '500' },
  'timeout-ms': { type: 'string', default: '90000' }, help: { type: 'boolean' } } })
if (values.help) {
  console.log('Manual GitHub-hosted Windows workflow only; local VPN execution is blocked.\n--exe "packaged app.exe" [--cancel-after-ms 500] [--timeout-ms 90000]\nSecret: VPNTE_REAL_SCENARIO; report: .tmp/real-vpn/report.json. See docs/real-vpn-integration.md.')
} else {
  // Gate before profile reads, PowerShell, filesystem writes, elevation or process creation.
  requireHostedWindows()
  const seed = readScenarioSecret(process.env.VPNTE_REAL_SCENARIO)
  delete process.env.VPNTE_REAL_SCENARIO
  const cancelAfterMs = Number(values['cancel-after-ms']), timeoutMs = Number(values['timeout-ms'])
  assert.ok(Number.isInteger(cancelAfterMs) && cancelAfterMs >= 0 && cancelAfterMs <= 10_000, 'Invalid cancellation delay')
  assert.ok(Number.isInteger(timeoutMs) && timeoutMs >= 10_000 && timeoutMs <= 300_000, 'Invalid timeout')
  assert.ok(values.exe, '--exe is required; installed clients are never selected automatically')
  const exe = resolve(values.exe)
  assert.ok((await stat(exe)).isFile(), 'Packaged executable is missing')
  const output = join(root, '.tmp/real-vpn')
  await mkdir(output, { recursive: true })
  await run({ exe, output, cancelAfterMs, timeoutMs }, seed)
}
