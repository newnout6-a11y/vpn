// AT-00-001/003/008: production refresh/import/registry/preload/stores; held resolver.
import { app, BrowserWindow, dialog } from 'electron'
import { existsSync } from 'node:fs'
import assert from 'node:assert/strict'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { setTimeout as delay } from 'node:timers/promises'
import { installTrustedIpcBoundary, registerTrustedRenderer } from '../../src/main/ipcSecurity'
import { operations, registerOperationHandlers } from '../../src/main/operations'
import { IpcFault, ipcError, type IpcErrorCategory } from '../../src/shared/ipc-result'

const work = process.env.VPNTE_SMOKE_DIR!
app.setPath('userData', join(work, 'server-request-userData'))
app.setPath('sessionData', join(work, 'server-request-sessionData'))
const windows: BrowserWindow[] = []
const entry = pathToFileURL(join(work, 'renderer.html')).href
const id = '11111111-1111-4111-8111-111111111111'
let release!: () => void
const response = { profiles: [{ name: 'Native', protocol: 'vless', outbound: { type: 'vless', server: 'native.example.test', server_port: 443 } }], source: 'subscription', fetched: true }
;(globalThis as any).vpnteProfileBoundary = () => new Promise(done => { release = () => done(response) })
const watchdog = setTimeout(() => app.exit(1), 30_000)
async function renderer() {
  const view = new BrowserWindow({ show: false, webPreferences: { preload: process.env.VPNTE_SMOKE_PRELOAD!,
    sandbox: true, contextIsolation: true, nodeIntegration: false } })
  windows.push(view); registerTrustedRenderer(view.webContents, entry)
  await view.loadURL(entry)
  return view.webContents
}
app.whenReady().then(async () => {
  installTrustedIpcBoundary(); registerOperationHandlers()
  const { serverGroups, registerServerGroupsHandlers } = await import('../../src/main/serverGroups')
  const { serverPicker, registerServerPickerHandlers } = await import('../../src/main/serverPicker')
  registerServerGroupsHandlers(); registerServerPickerHandlers()
  const owner = await renderer(), foreign = await renderer()
  const group = serverGroups.createGroup({ name: 'Native', source: 'subscription', sourceUrl: 'https://sub.example.test/native', status: 'active', importedAt: 1 })
  const snapshot = () => JSON.stringify({ profiles: serverPicker.getProfiles(), groups: serverGroups.getGroups() })
  const baseline = ['destroyed', 'render-process-gone', 'did-navigate'].map(event => owner.listenerCount(event))
  for (const kind of ['refresh', 'import', 'target', 'repaste'] as const) {
    const resource = kind === 'refresh' || kind === 'repaste' ? `refresh:${group.id}` : undefined
    const invoke = kind === 'refresh' ? `groupsRefresh('${group.id}','${id}')`
      : kind === 'target' ? `serversAddToGroup('https://sub.example.test/new','${group.id}',{clientDevice:'android'},'${id}')`
      : `serversAdd('https://sub.example.test/${kind === 'repaste' ? 'native' : 'new'}',{clientDevice:'pc'},'${id}')`
    await owner.executeJavaScript(`window.requestResult=window.electronAPI.${invoke}.catch(e=>e); 'started'`)
    for (let attempt = 0; !release && attempt < 200; attempt++) await delay(5)
    assert.equal(typeof release, 'function')
    const before = snapshot(), operation = operations.list().at(-1)!
    assert.equal(operation.status, 'running')
    assert.notEqual(operation.operationId, id)
    assert.equal(await foreign.executeJavaScript(`window.electronAPI.operationsCancelRequest('${id}')`), false)
    const result = await owner.executeJavaScript(`(async()=>{const start=performance.now(); const cancelled=await window.electronAPI.operationsCancelRequest('${id}'); return {cancelled,result:await window.requestResult,elapsed:performance.now()-start}})()`)
    assert.equal(result.cancelled, true); assert.equal(result.result.category, 'cancelled')
    assert.equal(result.result.correlationId, operation.correlationId)
    assert.ok(result.elapsed < 900)
    if (resource) assert.equal(operations.isBusy(resource), true)
    assert.equal(await owner.executeJavaScript(`window.electronAPI.operationsCancelRequest('${id}')`), false)
    release(); release = undefined as any
    // Admission stays held until the actual resolver and persistence lane drain.
    await operations.close(); operations.resumeAdmission()
    assert.equal(snapshot(), before)
    assert.deepEqual(['destroyed', 'render-process-gone', 'did-navigate'].map(event => owner.listenerCount(event)), baseline)
  }
  // AT-00-004/005: the feature catch must preserve typed errors across the
  // actual sandbox/contextBridge, including its durable group error metadata.
  const savedProfiles = JSON.stringify(serverPicker.getProfiles())
  for (const category of ['network', 'permission', 'validation', 'conflict', 'internal', 'cancelled', 'timeout'] as IpcErrorCategory[]) {
    ;(globalThis as any).vpnteProfileBoundary = async () => { throw Object.assign(new IpcFault(category), {
      message: 'FAKE-SECRET at C:\\private\\subscription.json\n    at featureHandler (C:\\private\\main.js:1:2)'
    }) }
    const result = await owner.executeJavaScript(`window.electronAPI.groupsRefresh('${group.id}','${id}').catch(e=>e)`)
    assert.equal(result.name, 'IpcRemoteError')
    assert.equal(result.category, category); assert.equal(result.code, ipcError(category).code)
    assert.equal(result.message, ipcError(category).message)
    assert.doesNotMatch(JSON.stringify(result), /FAKE-SECRET|\bat |[A-Z]:[\\/]/)
    const operation = operations.list().at(-1)!
    assert.equal(operation.correlationId, result.correlationId)
    assert.equal(operation.status, 'error'); assert.equal(operation.category, category)
    assert.equal(JSON.stringify(serverPicker.getProfiles()), savedProfiles)
    const groups = await owner.executeJavaScript('window.electronAPI.groupsList()')
    assert.equal(groups.find((item: { id: string }) => item.id === group.id).lastFetchError, ipcError(category).message)
    assert.equal(await owner.executeJavaScript(`window.electronAPI.operationsCancelRequest('${id}')`), false)
    assert.deepEqual(['destroyed', 'render-process-gone', 'did-navigate'].map(event => owner.listenerCount(event)), baseline)
  }
  ;(globalThis as any).vpnteProfileBoundary = async () => response
  assert.equal((await owner.executeJavaScript(`window.electronAPI.groupsRefresh('${group.id}','${id}')`)).ok, true)
  assert.equal(serverGroups.getGroup(group.id)?.lastFetchError, null)
  ;(globalThis as any).vpnteProfileBoundary = async () => ({ ...response, profiles: [{
    ...response.profiles[0], outbound: { ...response.profiles[0].outbound, server: 'fresh-native.example.test' }
  }] })
  assert.ok((await owner.executeJavaScript(`window.electronAPI.serversAdd('https://sub.example.test/success',{clientDevice:'pc'},'${id}')`)).length > 0)
  assert.equal(await owner.executeJavaScript(`window.electronAPI.operationsCancelRequest('${id}')`), false)
  // No real clipboard mutation or file picker: cancel before the controlled
  // consent resolves. The handlers, preload, registry and DPAPI stores are real.
  let saveCalls = 0
  dialog.showSaveDialog = (async () => { saveCalls++; return { canceled: false, filePath: join(work, 'must-not-export.txt') } }) as typeof dialog.showSaveDialog
  const profileId = serverPicker.getProfiles()[0].id
  for (const method of ['serversExportKey', 'serversCopyKey', 'serversExportKeyToFile', 'serversExportAllKeysToFile', 'serversExportAllProxiesToFile']) {
    let consent!: () => void
    dialog.showMessageBox = (() => new Promise(done => { consent = () => done({ response: 1, checkboxChecked: false }) })) as typeof dialog.showMessageBox
    const args = method.includes('All') ? `'${id}'` : `${JSON.stringify(profileId)},'${id}'`
    await owner.executeJavaScript(`window.keyResult=window.electronAPI.${method}(${args}).catch(e=>e); 'started'`)
    for (let attempt = 0; !consent && attempt < 200; attempt++) await delay(5)
    assert.equal(typeof consent, 'function')
    const operation = operations.list().at(-1)!
    assert.notEqual(operation.operationId, id)
    assert.equal(await foreign.executeJavaScript(`window.electronAPI.operationsCancelRequest('${id}')`), false)
    const result = await owner.executeJavaScript(`(async()=>{const start=performance.now();const cancelled=await window.electronAPI.operationsCancelRequest('${id}');return {cancelled,result:await window.keyResult,elapsed:performance.now()-start}})()`)
    assert.equal(result.cancelled, true); assert.equal(result.result.category, 'cancelled')
    assert.equal(result.result.correlationId, operation.correlationId); assert.ok(result.elapsed < 900)
    assert.equal(operations.isBusy('keys:' + (method === 'serversExportKey' ? 'renderer' : method === 'serversCopyKey' ? 'clipboard' : 'file')), true)
    assert.equal(await owner.executeJavaScript(`window.electronAPI.operationsCancelRequest('${id}')`), false)
    consent(); await operations.close(); operations.resumeAdmission()
    assert.equal(saveCalls, 0); assert.equal(existsSync(join(work, 'must-not-export.txt')), false)
    assert.deepEqual(['destroyed', 'render-process-gone', 'did-navigate'].map(event => owner.listenerCount(event)), baseline)
  }
  dialog.showMessageBox = (async () => ({ response: 1, checkboxChecked: false })) as typeof dialog.showMessageBox
  assert.equal((await owner.executeJavaScript(`window.electronAPI.serversExportKey(${JSON.stringify(profileId)},'${id}')`)).ok, true)
  assert.equal(await owner.executeJavaScript(`window.electronAPI.operationsCancelRequest('${id}')`), false)
  await operations.close()
  console.log('SERVER_REQUEST_NATIVE_PASS', JSON.stringify({ electron: process.versions.electron,
    checks: ['actual refresh/import/target/repaste handlers and preload; owned cancellation <900ms with original correlation',
      'foreign/stale token refusal; retained physical drain, no late store writes and listener cleanup', 'fresh import succeeds after cancellation',
      'seven caught refresh fault categories cross real contextBridge with matching history/correlation and safe persisted metadata; fresh retry succeeds',
      'five key export entrypoints cancel before secret consent; no save picker/file; fresh secret export succeeds'] }))
}).then(() => { clearTimeout(watchdog); app.exit(0) }).catch(error => {
  console.error('SERVER_REQUEST_NATIVE_FAIL', error)
  for (const view of windows) if (!view.isDestroyed()) view.destroy()
  clearTimeout(watchdog); app.exit(1)
})
