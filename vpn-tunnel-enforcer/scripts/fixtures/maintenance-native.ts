// AT-00-001/004/005, AT-08-005: production cleanup, real isolated files and sandbox bridge.
import { app, BrowserWindow, ipcMain, shell } from 'electron'
import assert from 'node:assert/strict'
import * as files from 'node:fs/promises'
import { join, resolve, sep } from 'node:path'
import { pathToFileURL } from 'node:url'
import { installTrustedIpcBoundary, registerTrustedRenderer } from '../../src/main/ipcSecurity'
import { IpcFault, ipcError, type IpcErrorCategory } from '../../src/shared/ipc-result'

const work = process.env.VPNTE_SMOKE_DIR!
const base = resolve(work, 'maintenance-files')
const snapshots = join(base, 'snapshots'), runtime = join(base, 'tun-runtime'), forensics = join(base, 'traffic-forensics')
app.setPath('userData', join(work, 'maintenance-userData'))
app.setPath('sessionData', join(work, 'maintenance-sessionData'))
let view: BrowserWindow | undefined
let fault: unknown, partial = false, active = false, trusted = true
const bounded = (path: string) => { const resolved = resolve(path); assert.ok(resolved.startsWith(base + sep)); return resolved }
Object.assign(globalThis, {
  vpnteMaintenanceRuntime: (kind: string) => kind === 'traffic-forensics' ? forensics : runtime,
  vpnteMaintenanceSnapshots: () => snapshots,
  vpnteMaintenanceCapture: async () => ({ running: active, cleanupPending: active }),
  vpnteMaintenanceAcl: async (path: string) => { bounded(path); return { hardened: trusted } },
  vpnteMaintenanceExists: async (path: string) => { bounded(path); return files.stat(path).then(() => true, error => { if (error.code === 'ENOENT') return false; throw error }) },
  vpnteMaintenanceRm: async (path: string, options: object) => {
    bounded(path)
    if (fault) throw fault
    if (partial && path === snapshots) throw Object.assign(new Error('FAKE-SECRET at /private/snapshots'), { code: 'EACCES' })
    return files.rm(path, options)
  },
  vpnteMaintenanceTruncate: async (path: string, len: number) => {
    if (partial && path === join(runtime, 'xray.log')) throw Object.assign(new Error('FAKE-SECRET at /private/xray.log'), { code: 'EACCES' })
    return files.truncate(path, len)
  }
})
shell.openPath = async () => { if (fault) throw fault; return partial ? 'FAKE-SECRET at /private/shell' : '' }
const watchdog = setTimeout(() => app.exit(1), 30_000)
app.whenReady().then(async () => {
  for (const dir of [runtime, snapshots, forensics]) await files.mkdir(dir, { recursive: true })
  await files.writeFile(join(runtime, 'xray.log'), 'retained xray evidence')
  await files.writeFile(join(snapshots, 'evidence.txt'), 'retained snapshot evidence')
  installTrustedIpcBoundary()
  ipcMain.handle('i18n:set-locale', () => undefined)
  const { registerDiagnosticMaintenanceHandlers } = await import('../../src/main/diagnosticMaintenance')
  const { flushAppLog, getAppLogPath } = await import('../../src/main/appLogger')
  registerDiagnosticMaintenanceHandlers()
  const entry = pathToFileURL(join(work, 'renderer.html')).href
  view = new BrowserWindow({ show: false, webPreferences: { preload: process.env.VPNTE_SMOKE_PRELOAD!, sandbox: true, contextIsolation: true, nodeIntegration: false } })
  registerTrustedRenderer(view.webContents, entry); await view.loadURL(entry)
  const invoke = (expression: string) => view!.webContents.executeJavaScript(`window.electronAPI.${expression}.catch(e=>e)`)
  for (const locale of ['en', 'ru'] as const) {
    await invoke(`i18nSetLocale('${locale}')`)
    for (const category of ['permission', 'network', 'validation', 'conflict', 'cancelled', 'timeout', 'internal'] as IpcErrorCategory[]) {
      fault = Object.assign(new IpcFault(category), { message: 'FAKE-SECRET at /private/failure' })
      const report = await invoke('clearDiagnosticArtifacts()')
      assert.equal(report.success, false)
      assert.deepEqual(report.errors.map((item: any) => item.error), [ipcError(category), ipcError(category)])
      assert.ok(report.cleared.includes('app-log'))
      assert.doesNotMatch(JSON.stringify(report), /FAKE-SECRET|private|stack/)
      const error = await invoke('openSnapshotsFolder()')
      assert.equal(error.name, 'IpcRemoteError'); assert.equal(error.category, category)
      assert.equal(error.message, ipcError(category, locale).message)
      assert.match(error.correlationId, /^ipc_[0-9a-f]{32}$/)
    }
  }
  fault = undefined; active = true
  assert.equal((await invoke('clearDiagnosticArtifacts()')).category, 'conflict')
  assert.equal(await files.readFile(join(snapshots, 'evidence.txt'), 'utf8'), 'retained snapshot evidence')
  active = false; trusted = false
  assert.equal((await invoke('clearDiagnosticArtifacts()')).category, 'permission')
  await flushAppLog()
  assert.match(await files.readFile(getAppLogPath(), 'utf8'), /clear-diagnostic-artifacts failed/)
  trusted = true
  await files.writeFile(join(runtime, 'xray.log'), 'retained xray evidence')
  active = false; partial = true
  const report = await invoke('clearDiagnosticArtifacts()')
  assert.equal(report.success, false)
  assert.deepEqual(report.errors.map((item: any) => item.artifact), ['snapshots', 'xray-log'])
  assert.ok(report.absent.includes('app-previous-log'))
  assert.equal(report.cleared.includes('app-previous-log'), false)
  assert.equal(await files.readFile(join(runtime, 'xray.log'), 'utf8'), 'retained xray evidence')
  assert.equal(await files.readFile(join(snapshots, 'evidence.txt'), 'utf8'), 'retained snapshot evidence')
  await flushAppLog()
  const log = await files.readFile(getAppLogPath(), 'utf8')
  assert.match(log, /artifact cleanup failed/); assert.match(log, /log cleanup failed/)
  const failures = log.trim().split('\n').map(line => JSON.parse(line)).filter(event => /cleanup failed:/.test(event.message))
  assert.equal(failures.length, 2)
  assert.ok(failures.every(event => event.details.message && /\n\s+at /.test(event.details.stack)))
  assert.doesNotMatch(log, /[A-Z]:\\Users\\/i)
  assert.equal((await invoke('openSnapshotsFolder()')).category, 'internal')
  partial = false
  assert.equal((await invoke('clearDiagnosticArtifacts()')).success, true)
  assert.equal(await files.readFile(join(runtime, 'xray.log'), 'utf8'), '')
  assert.equal(await files.stat(snapshots).then(() => true, () => false), false)
  assert.equal((await invoke('openSnapshotsFolder()')).success, true)
  console.log('MAINTENANCE_NATIVE_PASS', JSON.stringify({ electron: process.versions.electron, categories: 7, locales: 2, actualIsolatedFiles: true, partialEvidence: true, retry: true }))
}).then(() => { clearTimeout(watchdog); app.exit(0) }).catch(error => {
  console.error('MAINTENANCE_NATIVE_FAIL', error)
  if (view && !view.isDestroyed()) view.destroy()
  clearTimeout(watchdog); app.exit(1)
})
