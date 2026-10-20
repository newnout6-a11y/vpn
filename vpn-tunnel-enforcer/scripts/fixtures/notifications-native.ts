// AT-00-001/004/005: real notification source/handlers/preload and DPAPI store.
// Only reg.exe execution and the external Settings launch are controlled.
import { app, BrowserWindow, ipcMain, shell } from 'electron'
import assert from 'node:assert/strict'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { installTrustedIpcBoundary, registerTrustedRenderer } from '../../src/main/ipcSecurity'
import { ipcError, IpcFault, type IpcErrorCategory } from '../../src/shared/ipc-result'

const work = process.env.VPNTE_SMOKE_DIR!
app.setPath('userData', join(work, 'notification-userData'))
app.setPath('sessionData', join(work, 'notification-sessionData'))
app.setName('notification-legacy-fixture')
const entry = pathToFileURL(join(work, 'renderer.html')).href
let view: BrowserWindow | undefined
let fault: unknown
let mode: 'fault' | 'partial' | 'enabled' | 'missing' = 'fault'
const commands: string[][] = []
;(globalThis as any).vpnteNotificationReg = async (file: string, args: string[]) => {
  assert.equal(file, 'reg.exe')
  commands.push(args)
  if (mode === 'fault') throw fault
  if (mode === 'missing') throw Object.assign(new Error('missing'), { code: 1, stderr: Buffer.from('ERROR: The system was unable to find the specified registry key or value.') })
  if (mode === 'partial' && args[1].includes('notification-legacy-fixture')) throw Object.assign(new Error('FAKE-SECRET at /private/registry'), { code: 'EACCES' })
  return { stdout: Buffer.from(args[0] === 'query' ? `Enabled REG_DWORD ${mode === 'enabled' ? '0x1' : '0x0'}` : ''), stderr: Buffer.alloc(0) }
}
const watchdog = setTimeout(() => app.exit(1), 30_000)
app.whenReady().then(async () => {
  installTrustedIpcBoundary()
  ipcMain.handle('i18n:set-locale', () => undefined)
  const { registerNotificationPrefsIpcHandlers } = await import('../../src/main/notificationPrefs')
  const { invalidateOsNotificationStateCache } = await import('../../src/main/notifications')
  registerNotificationPrefsIpcHandlers()
  view = new BrowserWindow({ show: false, webPreferences: { preload: process.env.VPNTE_SMOKE_PRELOAD!, sandbox: true, contextIsolation: true, nodeIntegration: false } })
  registerTrustedRenderer(view.webContents, entry)
  await view.loadURL(entry)
  const invoke = (expression: string) => view!.webContents.executeJavaScript(`window.electronAPI.${expression}.catch(e=>e)`)
  const before = await invoke('notificationsGetPrefs()')
  for (const locale of ['en', 'ru'] as const) {
    await invoke(`i18nSetLocale('${locale}')`)
    for (const category of ['permission', 'network', 'validation', 'conflict', 'cancelled', 'timeout', 'internal'] as IpcErrorCategory[]) {
      fault = category === 'permission' ? Object.assign(new Error('FAKE-SECRET'), { code: 1, stderr: Buffer.from('ERROR: Access is denied.') })
        : category === 'timeout' ? Object.assign(new Error('FAKE-SECRET'), { killed: true, signal: 'SIGTERM' })
          : Object.assign(new IpcFault(category), { message: 'FAKE-SECRET at /private/registry' })
      mode = 'fault'; invalidateOsNotificationStateCache()
      const result = await invoke('checkOsNotificationState()')
      assert.equal(result.name, 'IpcRemoteError')
      assert.equal(result.category, category)
      assert.equal(result.code, ipcError(category).code)
      assert.equal(result.message, ipcError(category, locale).message)
      assert.match(result.correlationId, /^ipc_[0-9a-f]{32}$/)
      assert.doesNotMatch(JSON.stringify(result), /FAKE-SECRET|private|stack/)
      const report = await invoke('notificationsResetOsBlock()')
      assert.deepEqual(report.cleared, [])
      assert.equal(report.errors.length, 2)
      for (const item of report.errors) assert.deepEqual(item.error, ipcError(category))
      assert.doesNotMatch(JSON.stringify(report), /FAKE-SECRET|private|stack/)
    }
  }
  mode = 'partial'
  const report = await invoke('notificationsResetOsBlock()')
  assert.deepEqual(report, { cleared: ['com.vpntunnelenforcer.app'], errors: [{ appUserModelId: 'notification-legacy-fixture', error: ipcError('permission') }] })
  assert.ok(commands.some(args => args[0] === 'delete' && args.includes('/v') && args.includes('Enabled')))
  assert.equal(commands.some(args => args.includes('/va')), false)
  mode = 'enabled'; invalidateOsNotificationStateCache()
  assert.equal((await invoke('checkOsNotificationState()')).osNotificationsEnabled, true)
  mode = 'missing'; invalidateOsNotificationStateCache()
  assert.deepEqual(await invoke('checkOsNotificationState()'), { osNotificationsEnabled: true, appUserModelId: null })
  assert.deepEqual(await invoke('notificationsGetPrefs()'), before)
  shell.openExternal = async () => { throw Object.assign(new Error('FAKE-SECRET'), { code: 'EACCES' }) }
  assert.equal((await invoke('notificationsOpenWindowsSettings()')).category, 'permission')
  console.log('NOTIFICATIONS_NATIVE_PASS', JSON.stringify({ electron: process.versions.electron, categories: 7, locales: 2, partialReset: true, safeRetry: true }))
}).then(() => { clearTimeout(watchdog); app.exit(0) }).catch(error => {
  console.error('NOTIFICATIONS_NATIVE_FAIL', error)
  if (view && !view.isDestroyed()) view.destroy()
  clearTimeout(watchdog); app.exit(1)
})
