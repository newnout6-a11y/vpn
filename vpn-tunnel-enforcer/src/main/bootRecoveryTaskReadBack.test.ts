// AT-03-002 / AT-11-001/007 registration subset; F-043/F-150/F-203.
// Execute the production SID resolver and read-back gate in native PowerShell.
// New-ScheduledTask constructs CIM objects only; no task is registered or run.
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const powerShell = process.platform === 'win32' ? 'powershell.exe' : null
const source = readFileSync(join(process.cwd(), 'resources/vpnte-recover.ps1'), 'utf8')
const resolverSource = source.slice(source.indexOf('function Resolve-RecoveryPrincipalSid'), source.indexOf('# Registration is used'))
const readBackStart = source.indexOf("    $task = Get-ScheduledTask -TaskName 'BootRecoveryTask'")
const gate = source.slice(source.indexOf('\n', readBackStart) + 1, source.indexOf('    Unregister-ScheduledTask', readBackStart))

describe.skipIf(!powerShell)('native task principal normalization and recovery read-back', () => {
  it('accepts localized SYSTEM by SID while rejecting every altered task field', () => {
    const script = `
$ErrorActionPreference='Stop'
$source=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${Buffer.from(resolverSource).toString('base64')}'))
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Recovery source syntax error'}
$resolver=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Resolve-RecoveryPrincipalSid'},$true)
if(-not $resolver){throw 'Recovery principal resolver missing'}
. ([scriptblock]::Create($resolver.Extent.Text))
$readBack=[scriptblock]::Create([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${Buffer.from(gate).toString('base64')}')))
$arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand FAKE'
$action=New-ScheduledTaskAction -Execute "$env:WINDIR\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -Argument $arguments
$trigger=New-ScheduledTaskTrigger -AtStartup
$principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
$task=New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal
$nativeAccepted=$false
& $readBack
$nativeAccepted=$true
$nativeName=$task.Principal.UserId
$resolved=Resolve-RecoveryPrincipalSid $nativeName
function Fixture {
    [pscustomobject]@{
        Principal=[pscustomobject]@{UserId='S-1-5-18';RunLevel='Highest'}
        Actions=@([pscustomobject]@{Execute=$action.Execute;Arguments=$arguments})
        Triggers=@([pscustomobject]@{CimClass=[pscustomobject]@{CimClassName='MSFT_TaskBootTrigger'}})
    }
}
$accepted=@()
foreach($name in @('SYSTEM','S-1-5-18',$nativeName,'NT AUTHORITY\\SYSTEM')) {
    $task=Fixture
    $task.Principal.UserId=$name
    & $readBack
    $accepted += $name
}
$rejected=@()
foreach($case in @('non-system','unresolvable','run-level','execute','arguments','extra-action','no-action','wrong-trigger','extra-trigger','no-trigger')) {
    $task=Fixture
    switch($case) {
        'non-system' {$task.Principal.UserId='S-1-5-32-544'}
        'unresolvable' {$task.Principal.UserId='VPNTE-NO-SUCH-ACCOUNT-9F897D1B'}
        'run-level' {$task.Principal.RunLevel='Limited'}
        'execute' {$task.Actions[0].Execute='wrong.exe'}
        'arguments' {$task.Actions[0].Arguments='-Command FAKE'}
        'extra-action' {$task.Actions += $task.Actions[0]}
        'no-action' {$task.Actions=@()}
        'wrong-trigger' {$task.Triggers[0].CimClass.CimClassName='MSFT_TaskLogonTrigger'}
        'extra-trigger' {$task.Triggers += $task.Triggers[0]}
        'no-trigger' {$task.Triggers=@()}
    }
    try { & $readBack; throw "Accepted altered task: $case" }
    catch { if($_.Exception.Message -notmatch '^Recovery task read-back mismatch'){throw}; $rejected += $case }
}
@{nativeAccepted=$nativeAccepted;nativeName=$nativeName;resolved=$resolved;accepted=@($accepted);rejected=@($rejected)} | ConvertTo-Json -Compress
`
    const encoded = Buffer.from(script, 'utf16le').toString('base64')
    const result = JSON.parse(execFileSync(powerShell!, ['-NoProfile', '-NonInteractive', '-OutputFormat', 'Text', '-EncodedCommand', encoded], {
      encoding: 'utf8', windowsHide: true, timeout: 20_000, stdio: ['pipe', 'pipe', 'pipe']
    }).trim())
    expect(result.nativeAccepted).toBe(true)
    expect(result.resolved).toBe('S-1-5-18')
    expect(result.accepted).toContain(result.nativeName)
    expect(result.accepted).toContain('S-1-5-18')
    expect(result.rejected).toEqual(['non-system', 'unresolvable', 'run-level', 'execute', 'arguments', 'extra-action', 'no-action', 'wrong-trigger', 'extra-trigger', 'no-trigger'])
  }, 25_000)
})
