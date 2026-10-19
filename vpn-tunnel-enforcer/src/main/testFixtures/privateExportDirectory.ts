import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'

/** Native export fixtures need a trusted namespace. Workspace/OS Temp can grant
 * other sandbox accounts DELETE_CHILD. Change only this newly created fixture. */
export function privateExportDirectory(prefix: string): string {
  const directory = mkdtempSync(join(process.platform === 'win32' ? homedir() : tmpdir(), prefix))
  if (process.platform === 'win32') try {
    const data = Buffer.from(directory, 'utf8').toString('base64')
    const script = `$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
$path=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${data}'))
$acl=New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true,$false)
$user=[Security.Principal.WindowsIdentity]::GetCurrent().User
$acl.SetOwner($user)
foreach($sid in @($user.Value,'S-1-5-18')) {
  $id=New-Object Security.Principal.SecurityIdentifier($sid)
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
}
[IO.Directory]::SetAccessControl($path,$acl)`
    execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand',
      Buffer.from(script, 'utf16le').toString('base64')], { windowsHide: true, timeout: 15_000 })
  } catch (error) {
    rmSync(directory, { recursive: true, force: true })
    throw error
  }
  return directory
}
