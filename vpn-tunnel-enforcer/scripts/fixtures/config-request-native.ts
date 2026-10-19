// AT-00-001/003/008: production config handlers/registry/stores and contextBridge.
// Dialog responses and a profile-write queue barrier are controlled; no VPN I/O.
import { app, BrowserWindow, dialog } from 'electron'
import assert from 'node:assert/strict'
import { existsSync } from 'node:fs'
import { writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { setTimeout as delay } from 'node:timers/promises'
import { installTrustedIpcBoundary, registerTrustedRenderer } from '../../src/main/ipcSecurity'
import { operations, registerOperationHandlers } from '../../src/main/operations'
import { withProfileStoreWriteLock } from '../../src/main/profileStoreQueue'

const work = process.env.VPNTE_SMOKE_DIR!
app.setPath('userData', join(work, 'config-userData'))
app.setPath('sessionData', join(work, 'config-sessionData'))
const windows: BrowserWindow[] = []
const entry = pathToFileURL(join(work, 'renderer.html')).href
const id = '11111111-1111-4111-8111-111111111111'
const other = '22222222-2222-4222-8222-222222222222'
const watchdog = setTimeout(() => app.exit(1), 30_000)
async function renderer() {
  const view = new BrowserWindow({ show: false, webPreferences: { preload: process.env.VPNTE_SMOKE_PRELOAD!,
    sandbox: true, contextIsolation: true, nodeIntegration: false } })
  windows.push(view)
  registerTrustedRenderer(view.webContents, entry)
  await view.loadURL(entry)
  return view.webContents
}
async function drain(resource: string) {
  for (let attempt = 0; operations.isBusy(resource) && attempt < 200; attempt++) await delay(5)
  assert.equal(operations.isBusy(resource), false)
}
app.whenReady().then(async () => {
  installTrustedIpcBoundary(); registerOperationHandlers()
  const { registerConfigManagerIpcHandlers, configManager } = await import('../../src/main/configManager')
  registerConfigManagerIpcHandlers()
  const owner = await renderer(), foreign = await renderer()
  const selected = join(work, 'config-selected.json')
  const snapshot = configManager.collectCurrentConfig()
  snapshot.notifications.sound = false
  await writeFile(selected, JSON.stringify(snapshot))
  for (const kind of ['import', 'export'] as const) {
    let release!: () => void
    if (kind === 'import') dialog.showOpenDialog = (() => new Promise(done => {
      release = () => done({ canceled: false, filePaths: [selected] })
    })) as typeof dialog.showOpenDialog
    else dialog.showSaveDialog = (() => new Promise(done => {
      release = () => done({ canceled: false, filePath: join(work, 'must-not-export.json') })
    })) as typeof dialog.showSaveDialog
    const result = await owner.executeJavaScript(`(async () => {
      const run = window.electronAPI.${kind === 'import' ? `configBrowseImport('${id}')` : `configExport('redacted','${id}')`}.catch(e=>e);
      const started = performance.now();
      const cancel = await window.electronAPI.configCancel('${id}');
      const outcome = await run;
      return {cancel,outcome,elapsed:performance.now()-started};
    })()`)
    assert.equal(result.cancel, true)
    assert.equal(result.outcome.category, 'cancelled')
    assert.ok(result.elapsed < 900)
    assert.notEqual(operations.list().at(-1)!.operationId, id)
    assert.equal(result.outcome.correlationId, operations.list().at(-1)!.correlationId)
    if (kind === 'export') assert.equal(operations.isBusy('config:export'), true)
    release(); await delay(0)
    if (kind === 'export') await drain('config:export')
    assert.equal(await owner.executeJavaScript(`window.electronAPI.configCancel('${id}')`), false)
  }
  assert.equal(existsSync(join(work, 'must-not-export.json')), false)
  dialog.showOpenDialog = (async () => ({ canceled: false, filePaths: [selected] })) as typeof dialog.showOpenDialog
  assert.equal(await owner.executeJavaScript(`window.electronAPI.configBrowseImport('${id}')`), selected)
  assert.equal(await foreign.executeJavaScript(`window.electronAPI.configCancel('${id}')`), false)
  assert.equal(await owner.executeJavaScript(`window.electronAPI.configCancel('${other}')`), false)
  const mismatch = await owner.executeJavaScript(`window.electronAPI.configImport(${JSON.stringify(selected)},'${other}').catch(e=>e)`)
  assert.equal(mismatch.category, 'permission')
  let releaseQueue!: () => void
  const queued = withProfileStoreWriteLock(() => new Promise<void>(done => { releaseQueue = done }))
  await owner.executeJavaScript(`window.configOutcome=window.electronAPI.configImportApply(${JSON.stringify(selected)},['notifications'],'replace','${id}').catch(e=>e); 'started'`)
  assert.equal(await owner.executeJavaScript(`window.electronAPI.configCancel('${id}')`), true)
  assert.equal((await owner.executeJavaScript('window.configOutcome')).category, 'cancelled')
  releaseQueue(); await queued; await drain('config:apply')
  assert.equal(configManager.collectCurrentConfig().notifications.sound, true)
  const revoked = await owner.executeJavaScript(`window.electronAPI.configImport(${JSON.stringify(selected)},'${id}').catch(e=>e)`)
  assert.equal(revoked.category, 'permission')
  await owner.executeJavaScript(`window.electronAPI.configBrowseImport('${other}')`)
  assert.equal((await owner.executeJavaScript(`window.electronAPI.configImport(${JSON.stringify(selected)},'${other}')`)).success, true)
  assert.equal((await owner.executeJavaScript(`window.electronAPI.configImportApply(${JSON.stringify(selected)},['notifications'],'replace','${other}')`)).success, true)
  assert.equal(configManager.collectCurrentConfig().notifications.sound, false)
  assert.equal(await owner.executeJavaScript(`window.electronAPI.configCancel('${other}')`), false)
  await operations.close()
  console.log('CONFIG_REQUEST_NATIVE_PASS', JSON.stringify({ electron: process.versions.electron,
    checks: ['actual preload request cancel before native picker resolves; main UUID and correlation',
      'foreign/stale request rejected; selection bound to workflow token', 'queued apply cancellation prevents late store writes'] }))
}).then(() => { clearTimeout(watchdog); app.exit(0) }).catch(error => {
  console.error('CONFIG_REQUEST_NATIVE_FAIL', error)
  for (const view of windows) if (!view.isDestroyed()) view.destroy()
  clearTimeout(watchdog); app.exit(1)
})
