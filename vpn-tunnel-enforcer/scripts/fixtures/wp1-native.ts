// Local Windows/native subsets of AT-01-002/003/006/007/008/009.
// No VPN, firewall, DNS, login-item or installer mutations are performed.
import { app, BrowserWindow, ipcMain, dialog, clipboard } from 'electron'
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { once } from 'node:events'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { mkdirSync, writeFileSync, readFileSync, readdirSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { installTrustedIpcBoundary, registerTrustedRenderer } from '../../src/main/ipcSecurity'
import { copySecretToClipboard } from '../../src/main/secretClipboard'
import { verifyDirectoryHardened } from '../../src/main/runtimeDirSecurity'
import { logEvent, getFullLogs } from '../../src/main/appLogger'

const work = process.env.VPNTE_WP1_WORK!
app.setPath('userData', join(work, 'userData')); app.setPath('sessionData', join(work, 'sessionData'))
const checks: string[] = [], skipped: string[] = [], windows: BrowserWindow[] = []
const marker = 'FAKE-WP1-NATIVE-SECRET'
let initialClipboard: Electron.ClipboardItem[] | undefined
let clipboardUsed = false
const systemRoot = process.env.SystemRoot
if (!systemRoot) throw new Error('Windows SystemRoot unavailable')
const ps = (script: string) => execFileSync('powershell.exe', ['-NoProfile', '-Sta', '-Command', '-'], {
  input: script, encoding: 'utf8', windowsHide: true, timeout: 60_000,
  // Independent reader uses Windows PowerShell modules, not inherited PS7 modules.
  env: { ...process.env, PSModulePath: join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'Modules') }
})
function window(extra: Electron.WebPreferences = {}) {
  const w = new BrowserWindow({ show: false, webPreferences: { preload: process.env.VPNTE_WP1_PRELOAD!,
    sandbox: true, contextIsolation: true, nodeIntegration: false, ...extra } })
  windows.push(w); return w
}
function scan(directory: string): number {
  let matches = 0
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name)
    matches += entry.isDirectory() ? scan(path) : Number(readFileSync(path).includes(Buffer.from(marker)))
  }
  return matches
}
app.whenReady().then(async () => {
  installTrustedIpcBoundary()
  let effects = 0
  ipcMain.handle('save-settings', () => { effects++; return { ok: true } })
  ipcMain.handle('get-tun-status', () => ({ running: false }))
  const file = pathToFileURL(join(work, 'renderer.html')).href
  const w = window(); registerTrustedRenderer(w.webContents, file); await w.loadURL(file)
  const violations = await w.webContents.executeJavaScript(`(async () => {
    const reports = []; window.addEventListener('securitypolicyviolation', e => reports.push(e.violatedDirective));
    const inline = document.createElement('script'); inline.textContent = 'window.INLINE_RAN=true'; document.body.append(inline);
    const remote = document.createElement('script'); remote.src = 'https://evil.invalid/attack.js'; document.body.append(remote);
    const evalScript = document.createElement('script'); evalScript.src = './eval.js'; document.body.append(evalScript);
    const style = document.createElement('link'); style.rel = 'stylesheet'; style.href = 'https://evil.invalid/style.css'; document.head.append(style);
    const image = document.createElement('img'); image.src = 'https://evil.invalid/leak'; document.body.append(image);
    await new Promise(resolve => setTimeout(resolve, 500));
    return { reports, inline: !!window.INLINE_RAN, evaluated: !!window.EVAL_RAN };
  })()`)
  assert.equal(violations.inline, false); assert.equal(violations.evaluated, false)
  for (const directive of ['script-src-elem', 'script-src', 'style-src-elem', 'img-src']) assert.ok(violations.reports.includes(directive), directive)
  checks.push('AT-01-006 actual production meta CSP blocks inline/eval/remote script/style/image; inline style is the documented exception')
  const bad = await w.webContents.executeJavaScript(`window.electronAPI.saveSettings({ bad: NaN }).then(() => 'accepted', e => e.message)`)
  assert.match(bad, /Invalid IPC payload/); assert.equal(effects, 0)
  const foreign = window(); await foreign.loadURL(file)
  assert.match(await foreign.webContents.executeJavaScript(`window.electronAPI.saveSettings({}).then(() => 'accepted', e => e.message)`), /unregistered/)
  checks.push('AT-01-003 native unknown WebContents has zero handler effects')

  // Deliberately expose ipcRenderer in subframes only in this adversarial
  // fixture, so the production guard is exercised with a real senderFrame.
  const subframeResult = new Promise<string>(resolve => ipcMain.once('wp1:subframe-result', (_event, result) => resolve(result)))
  const hostile = window({ preload: join(work, 'hostile-preload.cjs'), nodeIntegrationInSubFrames: true })
  const hostileFile = pathToFileURL(join(work, 'hostile.html')).href
    registerTrustedRenderer(hostile.webContents, hostileFile); await hostile.loadURL(hostileFile)
  await hostile.webContents.executeJavaScript(`const frame=document.createElement('iframe');frame.src='./child.html';document.body.append(frame)`)
  const result = await Promise.race([subframeResult, new Promise<string>(resolve => setTimeout(() => resolve('timeout'), 5000))])
  assert.match(result, /subframes/); assert.equal(effects, 0)
  checks.push('AT-01-003 real hostile subframe rejected before effects')

  for (const win of [w, foreign]) {
    const prefs = win.webContents.getLastWebPreferences()
    assert.equal(prefs.sandbox, true); assert.equal(prefs.contextIsolation, true); assert.equal(prefs.nodeIntegration, false)
  }
  checks.push('AT-01-007 native production preferences; dev parity covered by test:electron')
  const weak = join(work, 'weak-runtime'); mkdirSync(weak)
  const acl = await verifyDirectoryHardened(weak)
  const nativeOwner = ps(`(Get-Acl -LiteralPath '${weak.replace(/'/g, "''")}').GetOwner([System.Security.Principal.SecurityIdentifier]).Value`).trim()
  assert.match(nativeOwner, /^S-\d+(?:-\d+)+$/)
  assert.equal(acl.hardened, false)
  // Namespace refusal intentionally happens before reading a leaf behind an
  // unsafe parent. The independent oracle must prove the user-controlled chain,
  // not accept any unrelated reader/import failure as a successful security test.
  assert.ok(acl.refusalCode === 'namespace-untrusted' || acl.offenders?.some(offender => offender.includes(nativeOwner)), 'an unrelated inspection/import failure is not an ACL refusal oracle')
  assert.ok(!['S-1-5-18', 'S-1-5-32-544'].includes(nativeOwner))
  checks.push('AT-01-009 user-owned isolated namespace refused; independent native owner readback; no elevated launch/ProgramData bootstrap in this subset')

  const { serverPickerStore } = await import('../../src/main/sharedStores')
  serverPickerStore.set('profiles', [{ id: 'p1', name: 'Fixture', protocol: 'vless', server: 'vpn.test', port: 443,
    status: 'unknown', ping: null, outbound: { type: 'vless', uuid: marker }, sourceUri: `vless://${marker}@vpn.test:443` }])
  const runtime = join(app.getPath('userData'), 'tun-runtime'); mkdirSync(runtime, { recursive: true })
  writeFileSync(join(runtime, 'core.json'), JSON.stringify({ uuid: marker, password: marker, private_key: marker }))
  logEvent('info', 'wp1-canary', `password=${marker}`, { password: marker, uuid: marker })
  const { exportDiagnosticsZip } = await import('../../src/main/diagnosticsExport')
  const zip = join(work, 'diagnostics.zip')
  dialog.showSaveDialog = (async () => ({ canceled: false, filePath: zip })) as typeof dialog.showSaveDialog
  assert.equal((await exportDiagnosticsZip()).success, true)
  ps(`Expand-Archive -LiteralPath '${zip.replace(/'/g, "''")}' -DestinationPath '${join(work, 'expanded').replace(/'/g, "''")}'`)
  assert.equal(scan(join(work, 'expanded')), 0)
  await getFullLogs()
  assert.equal(scan(join(app.getPath('userData'), 'logs')), 0)
  const canary = join(work, 'positive-control'); mkdirSync(canary); writeFileSync(join(canary, 'canary.txt'), marker)
  assert.equal(scan(canary), 1)
  checks.push('AT-01-002 L2 Windows ZIP pipeline + log dual-canary scan, positive control detected; system diagnostics/manifest readers are fixtures, full VPN cycle remains NOT-CHECKED')

  if (process.env.VPNTE_WP1_CLIPBOARD === '1') {
    initialClipboard = await Promise.all((await clipboard.read()).map(async item => {
      const data = new Map(await Promise.all(item.types.map(async type => [type, await item.getType(type)] as const)))
      return { types: [...item.types], getType: async (type: string) => data.get(type)! }
    }))
    await copySecretToClipboard(marker); clipboardUsed = true
    assert.equal(await clipboard.readText(), marker)
    await new Promise(resolve => setTimeout(resolve, 61_000))
    // Forms uses the Win32 clipboard API; an independent native reader.
    const clipboardText = ps('Add-Type -AssemblyName System.Windows.Forms\n[System.Windows.Forms.Clipboard]::GetText()\n').trim()
    assert.equal(clipboardText, '')
    checks.push('AT-01-008 real 60s clipboard cleanup, independently read through Win32')
  } else {
    skipped.push('AT-01-008 native clipboard: NOT-CHECKED (requires explicit --clipboard; user clipboard untouched)')
  }
  skipped.push('Full installed/OS-matrix/VM/VPN secret scan and elevated ACL abuse: NOT-CHECKED')
  console.log('WP1_NATIVE_PASS', JSON.stringify({ electron: process.versions.electron, scope: 'local subsets only', checks, skipped }))
  return 0
}).catch(error => { console.error(error); return 1 }).then(async code => {
  // Preserve user clipboard changes made while the test was running.
  if (clipboardUsed && initialClipboard) {
    const text = await clipboard.readText()
    const current = await clipboard.read()
    if (current.length === 0 || (text === marker && current.every(item => item.types.every(type => type === 'text/plain')))) {
      if (initialClipboard.length) await clipboard.write(initialClipboard)
      else clipboard.clear()
    }
  }
  for (const w of windows) if (!w.isDestroyed()) w.destroy()
  app.exit(code)
})
