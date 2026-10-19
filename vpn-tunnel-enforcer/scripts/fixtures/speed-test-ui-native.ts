// AT-00-001/003/008: actual speed handlers, registry, preload and WebContents.
// Only VPN readiness and HTTP transport are controlled; no VPN or external I/O.
import { app, BrowserWindow } from 'electron'
import assert from 'node:assert/strict'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { setTimeout as delay } from 'node:timers/promises'
import { installTrustedIpcBoundary, registerTrustedRenderer } from '../../src/main/ipcSecurity'
import { operations, registerOperationHandlers } from '../../src/main/operations'

const work = process.env.VPNTE_SMOKE_DIR!
app.setPath('userData', join(work, 'speed-userData'))
app.setPath('sessionData', join(work, 'speed-sessionData'))
const windows: BrowserWindow[] = []
const file = pathToFileURL(join(work, 'renderer.html')).href
let release!: (value: unknown) => void
;(globalThis as any).vpnteSpeedBoundary = () => new Promise(resolve => { release = resolve })
async function renderer() {
  const window = new BrowserWindow({ show: false, webPreferences: { preload: process.env.VPNTE_SMOKE_PRELOAD!,
    sandbox: true, contextIsolation: true, nodeIntegration: false } })
  windows.push(window)
  registerTrustedRenderer(window.webContents, file)
  await window.loadURL(file)
  return window
}
async function drained() {
  release({ data: {} })
  for (let attempt = 0; operations.isBusy('speed-test') && attempt < 200; attempt++) await delay(5)
  assert.equal(operations.isBusy('speed-test'), false)
}
app.whenReady().then(async () => {
  installTrustedIpcBoundary()
  registerOperationHandlers()
  const { speedTest } = await import('../../src/main/speedTest')
  speedTest.registerHandlers()
  const window = await renderer(), foreign = await renderer()
  const request = '11111111-1111-4111-8111-111111111111'
  // Both invoke messages are issued without a progress event or operation list.
  const immediate = await window.webContents.executeJavaScript(`(async () => {
    window.framesSeen=[];
    window.electronAPI.onSpeedTestProgress(frame=>window.framesSeen.push(frame));
    const run=window.electronAPI.speedTestRun('${request}').catch(e=>e);
    const started=performance.now();
    const cancel=await window.electronAPI.speedTestCancel('${request}');
    let timer;
    try {const result=await Promise.race([run,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Cancel exceeded 900 ms')),900)})]);
      return {cancel,result,elapsed:performance.now()-started};}
    finally {clearTimeout(timer);}
  })()`)
  assert.equal(immediate.cancel, true)
  assert.equal(immediate.result.category, 'cancelled')
  assert.ok(immediate.elapsed < 900)
  const first = operations.list().at(-1)!
  assert.notEqual(first.operationId, request)
  assert.equal(first.correlationId, immediate.result.correlationId)
  assert.equal(operations.isBusy('speed-test'), true)
  await drained()
  assert.deepEqual(speedTest.getHistory(), [])
  const frames = await window.webContents.executeJavaScript('window.framesSeen')
  assert.ok(frames.length > 0)
  assert.ok(frames.every((frame: any) => frame.requestId === request && frame.operationId === first.operationId))

  const reloader = await renderer(), reloadRequest = '33333333-3333-4333-8333-333333333333'
  await reloader.webContents.executeJavaScript(`window.speedOutcome=window.electronAPI.speedTestRun('${reloadRequest}').catch(e=>e);'started'`)
  const reloadOperation = operations.list().at(-1)!
  assert.equal(reloadOperation.status, 'running')
  await new Promise<void>(resolve => { reloader.webContents.once('did-finish-load', () => resolve()); reloader.webContents.reload() })
  const reloadStatus = () => operations.list().find(item => item.operationId === reloadOperation.operationId)?.status
  for (let attempt = 0; reloadStatus() === 'running' && attempt < 200; attempt++) await delay(5)
  assert.equal(reloader.webContents.isDestroyed(), false)
  assert.equal(reloadStatus(), 'cancelled')
  assert.equal(operations.isBusy('speed-test'), true)
  assert.equal(await reloader.webContents.executeJavaScript(`window.electronAPI.speedTestCancel('${reloadRequest}')`), false)
  await drained()
  assert.deepEqual(speedTest.getHistory(), [])

  const secondRequest = '22222222-2222-4222-8222-222222222222'
  await window.webContents.executeJavaScript(`window.speedOutcome=window.electronAPI.speedTestRun('${secondRequest}').catch(e=>e);'started'`)
  assert.equal(await foreign.webContents.executeJavaScript(`window.electronAPI.speedTestCancel('${secondRequest}')`), false)
  assert.equal(await window.webContents.executeJavaScript(`window.electronAPI.speedTestCancel('${request}')`), false)
  assert.equal(operations.list().at(-1)!.status, 'running')
  window.destroy()
  for (let attempt = 0; operations.list().at(-1)!.status === 'running' && attempt < 200; attempt++) await delay(5)
  assert.equal(operations.list().at(-1)!.status, 'cancelled')
  await drained()
  assert.deepEqual(speedTest.getHistory(), [])
  await operations.close()
  console.log('SPEED_UI_NATIVE_PASS', JSON.stringify({ electron: process.versions.electron,
    checks: ['immediate request cancellation before progress receipt; native UUID/correlation and retained drain',
      'stale and foreign WebContents cancellation refused', 'renderer reload cancels without WebContents destruction or history commit',
      'destroyed requesting WebContents aborts without history commit'] }))
}).catch(error => { console.error('SPEED_UI_NATIVE_FAIL', error); process.exitCode = 1 }).finally(() => {
  for (const window of windows) if (!window.isDestroyed()) window.destroy()
  app.quit()
})
