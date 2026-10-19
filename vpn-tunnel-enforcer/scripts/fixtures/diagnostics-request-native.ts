// AT-00-001/003/004/005: actual handler, preload, registry, ZIP/ACL/file operations.
// Snapshot/diagnostic/forensic collection is controlled; no VPN/network mutation.
import { app, BrowserWindow, dialog } from 'electron'
import assert from 'node:assert/strict'
import { existsSync, rmSync } from 'node:fs'
import { readFile, writeFile, readdir } from 'node:fs/promises'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { setTimeout as delay } from 'node:timers/promises'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { installTrustedIpcBoundary, registerTrustedRenderer } from '../../src/main/ipcSecurity'
import { operations, registerOperationHandlers } from '../../src/main/operations'
import { privateExportDirectory } from '../../src/main/testFixtures/privateExportDirectory'
const work = process.env.VPNTE_SMOKE_DIR!
app.setPath('userData', join(work, 'diagnostics-userData'))
app.setPath('sessionData', join(work, 'diagnostics-sessionData'))
const entry = pathToFileURL(join(work, 'renderer.html')).href
const token = '11111111-1111-4111-8111-111111111111'
const windows: BrowserWindow[] = []
let privateDirectory: string | undefined
const watchdog = setTimeout(() => app.exit(1), 45_000)
async function renderer() {
  const view = new BrowserWindow({ show: false, webPreferences: { preload: process.env.VPNTE_SMOKE_PRELOAD!, sandbox: true, contextIsolation: true, nodeIntegration: false } })
  windows.push(view); registerTrustedRenderer(view.webContents, entry); await view.loadURL(entry)
  return view.webContents
}
app.whenReady().then(async () => {
  installTrustedIpcBoundary(); registerOperationHandlers()
  const { registerDiagnosticsExportHandler } = await import('../../src/main/diagnosticsExport')
  registerDiagnosticsExportHandler()
  const owner = await renderer(), foreign = await renderer()
  let target = join(work, 'diagnostics.zip')
  await writeFile(target, 'old archive')
  const events = ['destroyed', 'render-process-gone', 'did-navigate']
  const baseline = events.map(event => owner.listenerCount(event))
  for (const phase of ['snapshot', 'picker'] as const) {
    let release: (() => void) | undefined, pickerCalls = 0
    ;(globalThis as any).vpnteDiagnosticSnapshot = phase === 'snapshot'
      ? () => new Promise(done => { release = () => done(null) }) : async () => null
    dialog.showSaveDialog = (() => {
      pickerCalls++
      return new Promise(done => { release = () => done({ canceled: false, filePath: target }) })
    }) as typeof dialog.showSaveDialog
    await owner.executeJavaScript(`window.zipResult=window.electronAPI.exportDiagnostics('${token}').catch(e=>e); 'started'`)
    for (let attempt = 0; !release && attempt < 200; attempt++) await delay(5)
    assert.equal(typeof release, 'function')
    const operation = operations.list().at(-1)!
    assert.equal(operation.status, 'running'); assert.notEqual(operation.operationId, token)
    assert.equal(await foreign.executeJavaScript(`window.electronAPI.operationsCancelRequest('${token}')`), false)
    const result = await owner.executeJavaScript(`(async()=>{const start=performance.now();const cancelled=await window.electronAPI.operationsCancelRequest('${token}');return {cancelled,result:await window.zipResult,elapsed:performance.now()-start}})()`)
    assert.equal(result.cancelled, true); assert.equal(result.result.category, 'cancelled')
    assert.equal(result.result.correlationId, operation.correlationId); assert.ok(result.elapsed < 900)
    assert.equal(operations.isBusy('diagnostics:export'), true)
    release!(); await operations.close(); operations.resumeAdmission()
    assert.equal(await readFile(target, 'utf8'), 'old archive')
    if (phase === 'snapshot') assert.equal(pickerCalls, 0)
    assert.deepEqual(events.map(event => owner.listenerCount(event)), baseline)
  }
  ;(globalThis as any).vpnteDiagnosticSnapshot = async () => null
  // The workspace grants sandbox accounts DELETE_CHILD; the real export guard
  // correctly rejects it. Use the existing private native-export fixture.
  privateDirectory = privateExportDirectory('.vpnte-diag-native-')
  target = join(privateDirectory, 'diagnostics.zip')
  await writeFile(target, 'old archive')
  dialog.showSaveDialog = (async () => ({ canceled: false, filePath: target })) as typeof dialog.showSaveDialog
  const completed = await owner.executeJavaScript(`window.electronAPI.exportDiagnostics('${token}')`)
  assert.equal(completed.success, true); assert.equal(completed.path, target)
  assert.equal((await readFile(target)).subarray(0, 2).toString(), 'PK')
  const script = `$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.IO.Compression.FileSystem; $zip=[IO.Compression.ZipFile]::OpenRead([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${Buffer.from(target).toString('base64')}'))); try { $zip.Entries.FullName | ConvertTo-Json -Compress } finally {$zip.Dispose()}`
  const { stdout } = await promisify(execFile)('powershell.exe', ['-NoProfile', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], { windowsHide: true, timeout: 15_000 })
  const entries = JSON.parse(stdout.trim()) as string[]
  for (const name of ['settings.json', 'app-log.json', 'system-info.json', 'system-diagnostics.json', 'diagnostics-manifest.json', 'README.txt']) assert.ok(entries.includes(name))
  assert.deepEqual(await readdir(privateDirectory), ['diagnostics.zip'])
  assert.equal(await owner.executeJavaScript(`window.electronAPI.operationsCancelRequest('${token}')`), false)
  // Legacy zero-argument invocations still pass the real bridge and native picker.
  dialog.showSaveDialog = (async () => ({ canceled: true, filePath: '' })) as typeof dialog.showSaveDialog
  assert.deepEqual(await owner.executeJavaScript('window.electronAPI.exportDiagnostics()'), { success: false, cancelled: true })
  assert.equal(existsSync(target), true)
  await operations.close()
  console.log('DIAGNOSTICS_REQUEST_NATIVE_PASS', JSON.stringify({ electron: process.versions.electron,
    checks: ['owned snapshot/picker cancellation <900ms; foreign refusal and original correlation',
      'physical drain and listener cleanup; destination unchanged after cancellation',
      'actual Compress-Archive, binary stream, ACL-checked atomic replacement and ZIP entries', 'legacy bridge arity and user cancellation'] }))
}).then(() => { if (privateDirectory) rmSync(privateDirectory, { recursive: true, force: true }); clearTimeout(watchdog); app.exit(0) }).catch(error => {
  console.error('DIAGNOSTICS_REQUEST_NATIVE_FAIL', error)
  for (const view of windows) if (!view.isDestroyed()) view.destroy()
  if (privateDirectory) rmSync(privateDirectory, { recursive: true, force: true })
  clearTimeout(watchdog); app.exit(1)
})
