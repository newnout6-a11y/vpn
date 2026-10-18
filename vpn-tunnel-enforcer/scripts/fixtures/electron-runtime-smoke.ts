import { app, BrowserWindow, ipcMain, safeStorage } from 'electron'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { readFileSync, writeFileSync } from 'node:fs'
import { once } from 'node:events'
import { installTrustedIpcBoundary, registerTrustedRenderer } from '../../src/main/ipcSecurity'
import { encryptSecret, decryptSecret } from '../../src/main/secretStorage'
import { IPC_ERRORS, IpcFault, ipcError, isIpcRemoteErrorData, type IpcErrorCategory, type IpcErrorLocale } from '../../src/shared/ipc-result'
import type { ServerProfile } from '../../src/shared/ipc-types'

const work = process.env.VPNTE_SMOKE_DIR!
app.setPath('userData', join(work, 'userData'))
app.setPath('sessionData', join(work, 'sessionData'))
const windows: BrowserWindow[] = []
const checks: string[] = []
const server = createServer((_req, res) => {
  res.setHeader('Content-Type', 'text/html')
  res.setHeader('Content-Security-Policy', "default-src 'none'")
  res.end('<!doctype html><title>Development origin</title>')
})

function window(): BrowserWindow {
  const w = new BrowserWindow({ show: false, webPreferences: {
    preload: process.env.VPNTE_SMOKE_PRELOAD!,
    sandbox: true, contextIsolation: true, nodeIntegration: false
  } })
  windows.push(w)
  w.webContents.on('preload-error', (_event, _path, error) => { throw error })
  return w
}
async function bridge(w: BrowserWindow): Promise<void> {
  const preferences = w.webContents.getLastWebPreferences()
  assert.equal(preferences.sandbox, true)
  assert.equal(preferences.contextIsolation, true)
  assert.equal(preferences.nodeIntegration, false)
  assert.deepEqual(await w.webContents.executeJavaScript(`(async () => ({
    require: typeof require, process: typeof process,
    status: await window.electronAPI.getTunStatus()
  }))()`), { require: 'undefined', process: 'undefined', status: { running: false, smoke: true } })
}

app.whenReady().then(async () => {
  assert.equal(process.versions.electron, process.env.VPNTE_SMOKE_VERSION)
  checks.push('pinned Electron runtime')
  assert.equal(safeStorage.isEncryptionAvailable(), true)
  const marker = 'FAKE-ELECTRON-MIGRATION-SECRET'
  const secret = encryptSecret(marker)
  assert.ok(!secret.ciphertext.startsWith('test:'))
  const persisted = JSON.stringify(secret)
  assert.ok(!persisted.includes(marker))
  const secretFile = join(work, 'encrypted.json')
  writeFileSync(secretFile, persisted)
  assert.equal(decryptSecret(JSON.parse(readFileSync(secretFile, 'utf8'))), marker)
  checks.push('native safeStorage encrypted persistence and decryption')

  installTrustedIpcBoundary()
  ipcMain.handle('get-tun-status', () => ({ running: false, smoke: true }))
  const profile: ServerProfile = {
    id: 'json-profile', name: 'JSON profile', protocol: 'vless', server: 'vpn.example.test', port: 443, status: 'unknown',
    outbound: { type: 'vless', server: 'vpn.example.test', server_port: 443,
      tls: { enabled: true, utls: { fingerprint: 'chrome' }, alpn: ['h2'] },
      protocol_extension: { values: [null, true, 0, 'fixture', { nested: ['value'] }] } }
  }
  let activeProfile: ServerProfile | null = profile
  ipcMain.handle('servers:list', () => [profile])
  ipcMain.handle('servers:get-active', () => ({ profile: activeProfile, activeId: activeProfile?.id ?? null }))
  let settingsCalls = 0
  ipcMain.handle('save-settings', () => { settingsCalls++; return { ok: true } })
  ipcMain.handle('i18n:get-locale', () => 'en')
  ipcMain.handle('i18n:set-locale', () => undefined)
  let scheduleCalls = 0
  ipcMain.handle('scheduler:update', () => { scheduleCalls++ })
  let faultCategory: IpcErrorCategory = 'internal'
  ipcMain.handle('get-settings', () => { throw Object.assign(new IpcFault(faultCategory), { message: 'raw-secret at C:\\private\\file' }) })
  const file = pathToFileURL(join(work, 'renderer.html')).href
  const trusted = window()
  registerTrustedRenderer(trusted.webContents, file)
  await trusted.loadURL(file)
  await bridge(trusted)
  checks.push('production preload/contextBridge and sandbox')
  const reloaded = once(trusted.webContents, 'did-finish-load')
  trusted.reload()
  await reloaded
  await bridge(trusted)
  checks.push('contextBridge survives reload')
  const locale: IpcErrorLocale = await trusted.webContents.executeJavaScript(`navigator.language.startsWith('ru') ? 'ru' : 'en'`)
  const badPayload = await trusted.webContents.executeJavaScript(`
    window.electronAPI.saveSettings({ checkInterval: NaN }).then(() => ({ message: 'accepted' }), e => ({ message: e.message, stack: e.stack, code: e.code, category: e.category, correlationId: e.correlationId }))
  `)
  assert.equal(badPayload.message, ipcError('validation', locale).message)
  assert.equal(badPayload.code, 'IPC_VALIDATION_ERROR')
  assert.equal(badPayload.category, 'validation')
  assert.equal(badPayload.correlationId, undefined) // Rejected locally before main allocates a correlation.
  assert.doesNotMatch(badPayload.stack ?? '', /\bat |[A-Z]:[\\/]|file:\/\//i)
  assert.equal(settingsCalls, 0)
  checks.push('invalid settings rejected locally before handler')
  await trusted.webContents.executeJavaScript(`window.electronAPI.i18nGetLocale()`)
  for (const selected of ['en', 'ru'] as const) {
    const message = await trusted.webContents.executeJavaScript(`window.electronAPI.i18nSetLocale('${selected}').then(() => window.electronAPI.saveSettings({ checkInterval: NaN })).catch(e => e.message)`)
    assert.equal(message, ipcError('validation', selected).message)
  }
  assert.equal(settingsCalls, 0)
  checks.push('canonical IPC errors follow persisted/selected English and Russian locale')
  const failureIds = new Set<string>()
  for (const selected of ['en', 'ru'] as const) {
    await trusted.webContents.executeJavaScript(`window.electronAPI.i18nSetLocale('${selected}')`)
    for (const category of Object.keys(IPC_ERRORS) as IpcErrorCategory[]) {
      faultCategory = category
      const failure = await trusted.webContents.executeJavaScript(`window.electronAPI.getSettings().catch(e => ({ data: e, isError: e instanceof Error }))`)
      assert.equal(failure.isError, false)
      assert.ok(isIpcRemoteErrorData(failure.data))
      assert.deepEqual(failure.data, { name: 'IpcRemoteError', ...ipcError(category, selected), correlationId: failure.data.correlationId })
      assert.ok(failure.data.correlationId)
      assert.ok(!failureIds.has(failure.data.correlationId))
      failureIds.add(failure.data.correlationId)
      assert.doesNotMatch(JSON.stringify(failure.data), /raw-secret|\bat |[A-Z]:[\\/]|file:\/\//i)
    }
  }
  const localFailure = await trusted.webContents.executeJavaScript(`window.electronAPI.saveSettings('not-an-object').catch(e => e)`)
  assert.ok(isIpcRemoteErrorData(localFailure))
  assert.equal(localFailure.category, 'validation'); assert.equal(localFailure.correlationId, undefined)
  checks.push('all seven typed error categories/codes/correlation IDs survive contextBridge in en/ru; local validators are typed too')
  const nestedFailure = await trusted.webContents.executeJavaScript(`window.electronAPI.schedulerUpdate('id', { days: [7] }).catch(e => e)`)
  assert.ok(isIpcRemoteErrorData(nestedFailure))
  assert.equal(nestedFailure.category, 'validation'); assert.equal(nestedFailure.correlationId, undefined)
  assert.equal(scheduleCalls, 0)
  await trusted.webContents.executeJavaScript(`window.electronAPI.schedulerUpdate('id', { enabled: false })`)
  assert.equal(scheduleCalls, 1)
  checks.push('nested request schemas reject invalid fields before effects and preserve valid partial updates')
  const flagFailure = await trusted.webContents.executeJavaScript(`window.electronAPI.saveSettings({ autoStart: 'false' }).catch(e => e)`)
  assert.ok(isIpcRemoteErrorData(flagFailure))
  assert.equal(flagFailure.category, 'validation'); assert.equal(settingsCalls, 0)
  await trusted.webContents.executeJavaScript(`window.electronAPI.saveSettings({ autoStart: false })`)
  assert.equal(settingsCalls, 1)
  checks.push('typed settings reject a string flag before effects and accept a boolean partial update')
  assert.deepEqual(await trusted.webContents.executeJavaScript(`window.electronAPI.serversList()`), [profile])
  assert.deepEqual(await trusted.webContents.executeJavaScript(`window.electronAPI.serversGetActive()`), { profile, activeId: profile.id })
  activeProfile = null
  assert.deepEqual(await trusted.webContents.executeJavaScript(`window.electronAPI.serversGetActive()`), { profile: null, activeId: null })
  checks.push('profile result JSON and nullable active profile survive production contextBridge unchanged (AT-00-001)')

  const foreign = window()
  await foreign.loadURL(file)
  const foreignResult = await foreign.webContents.executeJavaScript(`
    window.electronAPI.getTunStatus().then(() => 'accepted', e => e.message)
  `)
  assert.equal(foreignResult, ipcError('permission', locale).message)
  checks.push('unregistered WebContents rejected')
  await trusted.loadFile(join(work, 'other.html'))
  const navigatedResult = await trusted.webContents.executeJavaScript(`
    window.electronAPI.getTunStatus().then(() => 'accepted', e => e.message)
  `)
  assert.equal(navigatedResult, ipcError('permission', locale).message)
  checks.push('navigated file origin rejected')

  server.listen(0, '127.0.0.1')
  await once(server, 'listening')
  const address = server.address()
  assert.ok(address && typeof address === 'object')
  const devUrl = `http://127.0.0.1:${address.port}/`
  const dev = window()
  registerTrustedRenderer(dev.webContents, devUrl, true)
  await dev.loadURL(devUrl)
  await bridge(dev)
  checks.push('development loopback preload and sandbox parity')
  console.log('ELECTRON_SMOKE_PASS', JSON.stringify({ electron: process.versions.electron, node: process.versions.node, checks }))
  return 0
}).catch(error => {
  console.error(error)
  return 1
}).then(code => {
  for (const w of windows) if (!w.isDestroyed()) w.destroy()
  server.close()
  app.exit(code)
})
