// AT-11-002 / AT-11-009, F-183: production shutdown handlers and harmless PS fixtures.
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { execFile as execFileCb } from 'node:child_process'
import { promisify } from 'node:util'
import ts from 'typescript'
import { describe, expect, it, vi } from 'vitest'
import { shutdown as shutdownEn } from '../renderer/i18n/locales/en.json'
import { shutdown as shutdownRu } from '../renderer/i18n/locales/ru.json'

const root = join(__dirname, '../..')
const source = readFileSync(join(root, 'src/main/index.ts'), 'utf8')
const installer = readFileSync(join(root, 'build/installer.nsh'), 'utf8')
const helperPath = join(root, 'build/shutdown-for-update.ps1')
const helper = readFileSync(helperPath, 'utf8')

function handler(event: string, installerRequested = false) {
  const ast = ts.createSourceFile('index.ts', source, ts.ScriptTarget.Latest, true)
  let callback = ''
  function visit(node: ts.Node) {
    if (ts.isCallExpression(node) && node.expression.getText(ast) === 'app.on' && node.arguments[0]?.getText(ast) === `'${event}'`) {
      callback = node.arguments[1].getText(ast)
    }
    ts.forEachChild(node, visit)
  }
  visit(ast)
  if (!callback) throw new Error(`Missing app handler: ${event}`)
  const dependencies = {
    app: { exit: vi.fn(), quit: vi.fn(), whenReady: vi.fn(async () => {}) },
    performShutdownCleanup: vi.fn(async () => {}), handleSecureStartupBeforeQuit: vi.fn(() => false),
    restoreAndFocusMainWindow: vi.fn(), logEvent: vi.fn(),
    dialog: { showMessageBox: vi.fn(async () => ({})) }, i18nBackend: { getLocale: () => 'ru' }, shutdownEn, shutdownRu
  }
  const text = `let isQuitting=false, shutdownInProgress=false, secureStartupRefused=false, installerShutdownRequested=${installerRequested};
return { run: ${callback}, state: () => ({isQuitting,shutdownInProgress,installerShutdownRequested}), busy: () => {shutdownInProgress=true} };`
  const js = ts.transpileModule(text, { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText
  const control = new Function(...Object.keys(dependencies), js)(...Object.values(dependencies))
  return { ...control, ...dependencies }
}

describe('installer shutdown contract', () => {
  it('overrides builder fallback and gates init/check/uninstall without force-kill', () => {
    for (const name of ['customInit', 'customCheckAppRunning', 'customUnInit']) {
      expect(installer).toMatch(new RegExp(`!macro ${name}\\s+!insertmacro requestSafeShutdown`))
    }
    expect(installer).not.toMatch(/taskkill|killRunningApp|Sleep 800/)
    expect(installer).toContain('SetErrorLevel 1')
    const gate = installer.slice(installer.indexOf('!macro requestSafeShutdown'), installer.indexOf('!macro customCheckAppRunning'))
    expect(gate).toContain('-EncodedCommand ${VPNTE_SHUTDOWN_COMMAND}')
    expect(gate).not.toContain('$PLUGINSDIR')
    expect(gate).not.toContain('-File')
    expect(installer).toContain('Quit')
    expect(helper.replace(/^\s*#.*$/gm, '')).not.toMatch(/Stop-Process|taskkill|Invoke-Expression/)
    expect(helper).toContain('$process.ExitCode -ne 73')
    expect(source).toContain('app.exit(installerShutdownRequested ? 73 : 0)')
    expect(source).toContain("app.isPackaged && process.argv.includes('--shutdown-for-update')")
  })
  it('routes a secondary shutdown request to quit, not window-close/tray', async () => {
    const h = handler('second-instance')
    h.run({}, ['client.exe', '--shutdown-for-update'])
    await Promise.resolve()
    expect(h.app.quit).toHaveBeenCalledOnce()
    expect(h.state().installerShutdownRequested).toBe(true)
    expect(h.restoreAndFocusMainWindow).not.toHaveBeenCalled()
  })
  it('keeps ordinary second-instance launches focused without requesting shutdown', () => {
    const h = handler('second-instance')
    h.run({}, ['client.exe'])
    expect(h.restoreAndFocusMainWindow).toHaveBeenCalledOnce()
    expect(h.app.quit).not.toHaveBeenCalled()
  })
  it.each([false, true])('acknowledges only after cleanup resolves, installer=%s', async requested => {
    const h = handler('before-quit', requested)
    let release!: () => void
    const gate = new Promise<void>(resolve => { release = resolve })
    h.performShutdownCleanup.mockImplementationOnce(async () => { h.busy(); await gate })
    const event = { preventDefault: vi.fn() }
    const quitting = h.run(event)
    try {
      expect(event.preventDefault).toHaveBeenCalledOnce()
      expect(h.app.exit).not.toHaveBeenCalled()
      await h.run({ preventDefault: vi.fn() })
      expect(h.performShutdownCleanup).toHaveBeenCalledOnce()
    } finally { release(); await quitting }
    expect(h.app.exit).toHaveBeenCalledExactlyOnceWith(requested ? 73 : 0)
  })
  it('keeps the client alive after failure and allows a subsequent exit retry', async () => {
    const h = handler('before-quit', true)
    h.performShutdownCleanup.mockImplementationOnce(async () => { h.busy(); throw new Error('stop failed') })
    await h.run({ preventDefault: vi.fn() })
    expect(h.app.exit).not.toHaveBeenCalled()
    expect(h.dialog.showMessageBox).toHaveBeenCalledWith(expect.objectContaining({ message: shutdownRu.unconfirmed }))
    expect(h.state()).toEqual({ isQuitting: false, shutdownInProgress: false, installerShutdownRequested: false })
    await h.run({ preventDefault: vi.fn() })
    expect(h.app.exit).toHaveBeenCalledExactlyOnceWith(0)
  })
})

const execFile = promisify(execFileCb)
describe.skipIf(process.platform !== 'win32')('native shutdown gate (no real client/network effects)', () => {
  it.each([0, 73])('reads exit=%s from a real bound handle to a harmless PowerShell child', async code => {
    const child = Buffer.from(`Start-Sleep -Milliseconds 800; exit ${code}`, 'utf16le').toString('base64')
    const script = `
. '${helperPath.replace(/'/g, "''")}' -InstallDir 'C:\\fixture\\vpn'
$exe=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\\v1.0\\powershell.exe'
$child=Start-Process -FilePath $exe -ArgumentList '-NoProfile -NonInteractive -EncodedCommand ${child}' -PassThru
$bound=Open-VpnteAppProcess $child.Id
try {
  if(-not $bound.WaitForExit(10000)){throw 'harmless fixture timed out'}
  'BOUND_EXIT:'+$bound.ExitCode
} finally { $bound.Dispose(); $child.Dispose() }
`
    const { stdout } = await execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], {
      timeout: 15000, windowsHide: true, encoding: 'utf8'
    })
    expect(stdout).toContain(`BOUND_EXIT:${code}`)
  }, 20000)
  it.each(['success', 'absent', 'timeout', 'exit-zero', 'crash', 'foreign', 'query-error', 'remaining'] as const)('handles %s without forced termination', async scenario => {
    const script = `
. '${helperPath.replace(/'/g, "''")}' -InstallDir 'C:\\fixture\\vpn'
$global:scenario='${scenario}'; $global:queries=0; $global:launched=$false; $global:disposed=$false
function Get-VpnteProcesses {
  $global:queries++
  if ($global:scenario -eq 'query-error') { throw 'fixture query failed' }
  if ($global:scenario -eq 'absent') { return }
  if ($global:queries -gt 1) {
    if ($global:scenario -eq 'remaining') { return [pscustomobject]@{Name='vpnte-xray.exe'} }
    return
  }
  $path=if($global:scenario -eq 'foreign') {'C:\\foreign\\VPN Tunnel Enforcer.exe'} else {'C:\\fixture\\vpn\\VPN Tunnel Enforcer.exe'}
  [pscustomobject]@{Name='VPN Tunnel Enforcer.exe';ExecutablePath=$path;CommandLine='client';ProcessId=42}
}
function Open-VpnteAppProcess([int]$Id) {
  if($Id -ne 42){throw 'unexpected fixture PID'}
  $code=switch($global:scenario){'exit-zero'{0};'crash'{1};default{73}}
  $p=[pscustomobject]@{ExitCode=$code;MainModule=[pscustomobject]@{FileName='C:\\fixture\\vpn\\VPN Tunnel Enforcer.exe'}}
  $p | Add-Member ScriptMethod WaitForExit {param($ms) if($ms -ne 1000){throw 'unexpected timeout'}; return $global:scenario -ne 'timeout'}
  $p | Add-Member ScriptMethod Dispose {$global:disposed=$true}
  return $p
}
function Start-Process {param($FilePath,$ArgumentList,$ErrorAction)
  if($FilePath -ne 'C:\\fixture\\vpn\\VPN Tunnel Enforcer.exe' -or $ArgumentList -ne '--shutdown-for-update'){throw 'unexpected fixture launch'}
  $global:launched=$true
}
# Advance only the residual-process deadline, never touch a real process.
function Start-Sleep {param($Milliseconds) if($global:scenario -eq 'remaining'){throw 'fixture background process remains'}}
try { Invoke-VpnteShutdown 'C:\\fixture\\vpn' 1; 'RESULT:success' }
catch { 'RESULT:refused' }
'LAUNCHED:'+$global:launched
'DISPOSED:'+$global:disposed
`
    const { stdout } = await execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], {
      timeout: 10000, windowsHide: true, encoding: 'utf8'
    })
    expect(stdout).toContain(['success', 'absent'].includes(scenario) ? 'RESULT:success' : 'RESULT:refused')
    expect(stdout).toContain(['absent', 'foreign', 'query-error'].includes(scenario) ? 'LAUNCHED:False' : 'LAUNCHED:True')
    expect(stdout).toContain(['absent', 'foreign', 'query-error'].includes(scenario) ? 'DISPOSED:False' : 'DISPOSED:True')
  }, 15000)
})
