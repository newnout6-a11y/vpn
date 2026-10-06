// AT-11-005 / AT-11-009, F-167: owned task removal with fake native cmdlets.
import { join } from 'path'
import { execFile } from 'child_process'
import { promisify } from 'util'
import { describe, expect, it } from 'vitest'

const root = join(__dirname, '../..')
const run = promisify(execFile)

describe.skipIf(process.platform !== 'win32')('harmless native task-removal fixtures', () => {
  it.each(['owned', 'absent', 'foreign-path', 'foreign-arguments', 'foreign-principal', 'extra-action', 'query-denied', 'delete-failed', 'still-present'])('%s', async scenario => {
    // Extract production functions using PowerShell's parser. Cmdlets are mocked;
    // neither Task Scheduler nor network/system settings are changed.
    const script = `
$source=[IO.File]::ReadAllText('${join(root, 'resources/vpnte-recover.ps1').replace(/'/g, "''")}')
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Recovery script does not parse'}
$names=@('Resolve-RecoveryPrincipalSid','Get-BootRecoveryTaskOrNull','Remove-BootRecoveryTask')
$functions=$ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $names -contains $node.Name},$true)
foreach($fn in $functions){. ([ScriptBlock]::Create($fn.Extent.Text))}
$global:scenario='${scenario}';$global:queries=0;$global:removed=$false
$global:fixtureScript="C:\\Program Files\\O'Brien VPN\\vpnte-recover.ps1"
$encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("& '"+$global:fixtureScript.Replace("'","''")+"'"))
$global:fixtureArgs='-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand '+$encoded
function Get-ScheduledTask {
  param($TaskName,$TaskPath,$ErrorAction)
  if($TaskName -ne 'BootRecoveryTask' -or $TaskPath -ne '\\VPNTE\\'){throw 'Unexpected task query'}
  $global:queries++
  if($global:scenario -eq 'query-denied'){throw 'Access denied'}
  if($global:scenario -eq 'absent' -or ($global:removed -and $global:scenario -ne 'still-present')){
    $e=New-Object Management.Automation.ErrorRecord ([Exception]'Absent'),'Absent',([Management.Automation.ErrorCategory]::ObjectNotFound),$null
    throw $e
  }
  $exe="$env:WINDIR\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
  $args=$global:fixtureArgs;$sid='S-1-5-18'
  if($global:scenario -eq 'foreign-path'){$exe='C:\\foreign.exe'}
  if($global:scenario -eq 'foreign-arguments'){$args='foreign'}
  if($global:scenario -eq 'foreign-principal'){$sid='S-1-5-32-544'}
  $actions=@([pscustomobject]@{Execute=$exe;Arguments=$args})
  if($global:scenario -eq 'extra-action'){$actions+= $actions[0]}
  [pscustomobject]@{Actions=$actions;Principal=[pscustomobject]@{UserId=$sid}}
}
function Unregister-ScheduledTask {
  param($TaskName,$TaskPath,$Confirm,$ErrorAction)
  if($TaskName -ne 'BootRecoveryTask' -or $TaskPath -ne '\\VPNTE\\'){throw 'Unexpected deletion'}
  if($global:scenario -eq 'delete-failed'){throw 'Deletion denied'}
  $global:removed=$true
}
try {Remove-BootRecoveryTask $global:fixtureScript; 'RESULT:success'}
catch {'RESULT:refused';'REASON:'+$_.Exception.Message}
'REMOVED:'+$global:removed
`
    const { stdout } = await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')], { timeout: 15000, windowsHide: true })
    expect(stdout).toContain(['owned', 'absent'].includes(scenario) ? 'RESULT:success' : 'RESULT:refused')
    expect(stdout).toContain(['owned', 'still-present'].includes(scenario) ? 'REMOVED:True' : 'REMOVED:False')
  }, 20000)
})
