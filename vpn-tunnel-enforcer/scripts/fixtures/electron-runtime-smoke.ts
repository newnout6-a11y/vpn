import { app, BrowserWindow, ipcMain, safeStorage } from 'electron'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { readFileSync, writeFileSync } from 'node:fs'
import { once } from 'node:events'
import { installTrustedIpcBoundary, registerTrustedRenderer } from '../../src/main/ipcSecurity'
import { encryptSecret, decryptSecret } from '../../src/main/secretStorage'

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
  let settingsCalls = 0
  ipcMain.handle('save-settings', () => { settingsCalls++; return { ok: true } })
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
  const badPayload = await trusted.webContents.executeJavaScript(`
    window.electronAPI.saveSettings({ value: NaN }).then(() => 'accepted', e => e.message)
  `)
  assert.match(badPayload, /Invalid IPC payload/)
  assert.equal(settingsCalls, 0)
  checks.push('invalid IPC rejected before handler')

  const foreign = window()
  await foreign.loadURL(file)
  const foreignResult = await foreign.webContents.executeJavaScript(`
    window.electronAPI.getTunStatus().then(() => 'accepted', e => e.message)
  `)
  assert.match(foreignResult, /unregistered renderer/)
  checks.push('unregistered WebContents rejected')
  await trusted.loadFile(join(work, 'other.html'))
  const navigatedResult = await trusted.webContents.executeJavaScript(`
    window.electronAPI.getTunStatus().then(() => 'accepted', e => e.message)
  `)
  assert.match(navigatedResult, /untrusted renderer origin/)
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
