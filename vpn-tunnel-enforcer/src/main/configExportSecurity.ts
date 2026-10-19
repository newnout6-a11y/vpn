import { execFile } from 'child_process'
import { lstat, chmod } from 'fs/promises'
import { lstatSync, type BigIntStats } from 'fs'
import { join } from 'path'
import { promisify } from 'util'
import { IpcFault } from '../shared/ipc-result'

const quote = (value: string) => "'" + value.replaceAll("'", "''") + "'"
function missing(error: unknown): boolean { return (error as NodeJS.ErrnoException)?.code === 'ENOENT' }
function sameFile(a: BigIntStats | undefined, b: BigIntStats | undefined): boolean {
  return !a || !b ? a === b : (['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'] as const).every(key => a[key] === b[key])
}

/** Protect an empty staging file before plaintext. Preserve existing owner/group/DACL,
 * and refuse a destination changed since that snapshot instead of replacing its policy. */
export async function prepareConfigExport(temporary: string, destination: string): Promise<() => void> {
  const before = await lstat(destination, { bigint: true }).catch(error => { if (!missing(error)) throw error; return undefined })
  if (before && !before.isFile()) throw new IpcFault('validation')
  if (process.platform === 'win32') {
    // .NET ACL APIs avoid PowerShell module-path/autoload drift; no elevation or FFI in main.
    const script = `$ErrorActionPreference='Stop';
$temporary=${quote(temporary)}
$sections=[Security.AccessControl.AccessControlSections]'Access,Owner,Group'
${before ? `$acl=[IO.File]::GetAccessControl(${quote(destination)},$sections)` : `$acl=New-Object Security.AccessControl.FileSecurity
$acl.SetAccessRuleProtection($true,$false)
$user=[Security.Principal.WindowsIdentity]::GetCurrent().User
$acl.SetOwner($user)
$acl.SetGroup($user)
foreach($sid in @($user.Value,'S-1-5-18')) {
  $id=New-Object Security.Principal.SecurityIdentifier($sid)
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id,'FullControl','Allow')))
}`}
$expected=$acl.GetSecurityDescriptorSddlForm($sections)
$copy=New-Object Security.AccessControl.FileSecurity
$copy.SetSecurityDescriptorSddlForm($expected,$sections)
[IO.File]::SetAccessControl($temporary,$copy)
$actual=[IO.File]::GetAccessControl($temporary,$sections).GetSecurityDescriptorSddlForm($sections)
function Normalize-Acl($sddl) {
  $descriptor=New-Object Security.AccessControl.RawSecurityDescriptor($sddl)
  $auto=[Security.AccessControl.ControlFlags]'DiscretionaryAclAutoInherited,DiscretionaryAclAutoInheritRequired'
  $descriptor.SetFlags($descriptor.ControlFlags -band (-bnot $auto))
  $descriptor.GetSddlForm($sections)
}
if((Normalize-Acl $actual) -cne (Normalize-Acl $expected)) {throw 'ConfigExportAclMismatch'}
'CONFIG_EXPORT_ACL_VERIFIED'`
    const executable = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
    try {
      const { stdout } = await promisify(execFile)(executable, ['-NoProfile', '-NonInteractive', '-EncodedCommand',
        Buffer.from(script, 'utf16le').toString('base64')], { windowsHide: true, timeout: 15_000, maxBuffer: 16_384 })
      if (stdout.trim() !== 'CONFIG_EXPORT_ACL_VERIFIED') throw new IpcFault('permission')
    } catch { throw new IpcFault('permission') }
  } else if (before) {
    if (process.getuid?.() !== Number(before.uid)) throw new IpcFault('permission')
    await chmod(temporary, Number(before.mode & 0o777n))
  }
  const verify = () => {
    let current: BigIntStats | undefined
    try { current = lstatSync(destination, { bigint: true }) } catch (error) { if (!missing(error)) throw error }
    if (!sameFile(before, current)) throw new IpcFault('conflict')
  }
  verify()
  return verify
}
