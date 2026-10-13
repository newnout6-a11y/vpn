// AT-01-009, F-002/F-104: the runtime ACL bootstrap runs through the elevated helper under its own command policy.
import { describe, expect, it, vi } from 'vitest'

vi.mock('./admin', () => ({ isProcessElevated: vi.fn().mockResolvedValue(true) }))
vi.mock('./appLogger', () => ({ logEvent: vi.fn() }))
vi.mock('./recoveryPsWorker', () => ({ executeRecoveryOperation: vi.fn() }))

import { validateScriptPolicy } from './elevatedPsHelper'
import { buildHelperBootstrapScript } from './runtimeDirSecurity'
import { SECURITY_MODULE_IMPORT_LINE } from './runtimeAclInspection'

const BS = String.fromCharCode(92)
const win = (...parts: string[]) => parts.join(BS)
const DIR = win('C:', 'ProgramData', 'VPNTE', 'runtime', '0123456789abcdef0123456789abcdef', 'tun-runtime')
const real = buildHelperBootstrapScript(DIR)

describe('runtime-acl helper policy', () => {
  it('accepts the real bootstrap script for each application component', () => {
    for (const part of ['tun-runtime', 'external-proxy-runtime', 'traffic-forensics']) {
      expect(() => validateScriptPolicy(buildHelperBootstrapScript(win('C:', 'ProgramData', 'VPNTE', 'runtime', '0123456789abcdef0123456789abcdef', part)), 'runtime-acl')).not.toThrow()
    }
  })

  it.each([
    ['a directory outside the VPNTE runtime tree', win('C:', 'Windows', 'System32', 'drivers')],
    ['the runtime root itself', win('C:', 'ProgramData', 'VPNTE', 'runtime')],
    ['an unknown component', win('C:', 'ProgramData', 'VPNTE', 'runtime', '0123456789abcdef0123456789abcdef', 'evil')],
    ['an instance id of the wrong shape', win('C:', 'ProgramData', 'VPNTE', 'runtime', 'ZZZ', 'tun-runtime')],
    ['a traversal out of the component', win('C:', 'ProgramData', 'VPNTE', 'runtime', '0123456789abcdef0123456789abcdef', 'tun-runtime', '..', 'x')]
  ])('rejects %s', (_name, dir) => {
    expect(() => validateScriptPolicy(buildHelperBootstrapScript(dir), 'runtime-acl')).toThrow(/runtime boundary/)
  })

  it.each([
    'Set-NetFirewallProfile -Profile Domain -Enabled False',
    'New-NetFirewallRule -DisplayName x -Action Allow',
    'netsh advfirewall set allprofiles state off',
    'reg add HKLM' + BS + 'Software' + BS + 'x /v y /d z',
    'Set-DnsClientServerAddress -InterfaceIndex 1 -ServerAddresses 1.1.1.1',
    'Disable-NetAdapterBinding -Name x -ComponentID ms_tcpip6',
    'icacls C:' + BS + 'ProgramData /grant Everyone:F',
    'Set-Acl -Path C:' + BS + 'x -AclObject $acl',
    'Out-File -FilePath C:' + BS + 'x.txt',
    'Get-ChildItem C:' + BS + ' -Recurse',
    'Invoke-Expression $payload',
    'Start-Process calc.exe',
    'Remove-Item -Path C:' + BS + 'x',
    'Add-Type -TypeDefinition $code'
  ])('rejects the real script with an extra command: %s', (extra) => {
    expect(() => validateScriptPolicy(real + '\n' + extra, 'runtime-acl')).toThrow(/rejected by runtime-acl policy/)
  })

  it('rejects a script that is not the bootstrap even with a legitimate directory line', () => {
    const body = `$dir = '${DIR}'\nWrite-Output 'HARDENED'`
    expect(() => validateScriptPolicy(body, 'runtime-acl')).toThrow(/missing module pin/)
    expect(() => validateScriptPolicy(SECURITY_MODULE_IMPORT_LINE + '\n' + body, 'runtime-acl')).toThrow(/no allowed command token/)
  })

  it('exempts only the exact module pin: a changed pin or a second mention of the word is still blocked', () => {
    expect(() => validateScriptPolicy(real.replace(SECURITY_MODULE_IMPORT_LINE, SECURITY_MODULE_IMPORT_LINE.replace('Stop', 'Continue')), 'runtime-acl')).toThrow(/missing module pin/)
    expect(() => validateScriptPolicy(real + '\n# powershell.exe -c calc', 'runtime-acl')).toThrow(/blocked token/)
  })

  it('does not widen the other policies: the bootstrap is not a firewall script', () => {
    expect(() => validateScriptPolicy(real, 'firewall-killswitch')).toThrow(/rejected by firewall-killswitch policy/)
  })
})

describe.runIf(process.platform === 'win32')('helper-style execution of the bootstrap (real PowerShell, no mutation)', () => {
  /** Mirrors the helper's runner: child scope, output captured through the success stream. */
  async function runLikeHelper(script: string): Promise<string> {
    const { execFileSync } = await vi.importActual<typeof import('node:child_process')>('node:child_process')
    const data = Buffer.from(script).toString('base64')
    const runner = `$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${data}'));` +
      '$sb=[ScriptBlock]::Create($s);$o=& $sb *>&1 | Out-String;Write-Output $o;' +
      "if (Get-Variable -Name runtimeOperation -Scope Script -ErrorAction SilentlyContinue) { Write-Output 'LEAKED' } else { Write-Output 'CLEAN' }"
    return execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(runner, 'utf16le').toString('base64')], {
      encoding: 'utf8', timeout: 30000, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe']
    })
  }

  it('reports a refused boundary as a receipt line in the captured output and leaves no state behind', async () => {
    // Inside ProgramData but outside the allowed components: the script refuses before it creates anything.
    const dir = win('C:', 'ProgramData', 'VPNTE', 'runtime', 'not-an-instance')
    const out = await runLikeHelper(buildHelperBootstrapScript(dir))
    expect(out).toMatch(/VPNTE_RUNTIME_FAILURE:.*RuntimeOutsideBoundary/)
    expect(out).not.toContain('HARDENED')
    expect(out.trim().endsWith('CLEAN')).toBe(true)
  })
})
