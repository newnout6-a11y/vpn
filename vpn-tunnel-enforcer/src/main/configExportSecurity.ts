import { execFile } from 'child_process'
import { lstat, chmod, chown } from 'fs/promises'
import { lstatSync, type BigIntStats } from 'fs'
import { join } from 'path'
import { promisify } from 'util'
import { IpcFault } from '../shared/ipc-result'

// Paths are opaque data, never PowerShell string literals (including smart quotes).
const pathData = (value: string) => "[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('" + Buffer.from(value, 'utf8').toString('base64') + "'))"
function missing(error: unknown): boolean { return (error as NodeJS.ErrnoException)?.code === 'ENOENT' }
function sameFile(a: BigIntStats | undefined, b: BigIntStats | undefined): boolean {
  return !a || !b ? a === b : (['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'] as const).every(key => a[key] === b[key])
}

const privateAclScript = `$acl=New-Object Security.AccessControl.FileSecurity
$acl.SetAccessRuleProtection($true,$false)
$user=[Security.Principal.WindowsIdentity]::GetCurrent().User
$acl.SetOwner($user)
$acl.SetGroup($user)
foreach($sid in @($user.Value,'S-1-5-18')) {
  $id=New-Object Security.Principal.SecurityIdentifier($sid)
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id,'FullControl','Allow')))
}`

async function runSecurityScript(script: string): Promise<string> {
  const executable = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
  try {
    const { stdout } = await promisify(execFile)(executable, ['-NoProfile', '-NonInteractive', '-EncodedCommand',
      Buffer.from("$ErrorActionPreference='Stop';\n" + script, 'utf16le').toString('base64')], { windowsHide: true, timeout: 15_000, maxBuffer: 16_384 })
    return stdout.trim()
  } catch { throw new IpcFault('permission') }
}

/** Windows access checks happen when a reader opens a handle. Install the DACL
 * in CreateNew itself: changing permissions on an existing empty file is too late. */
export async function createPrivateConfigExport(temporary: string): Promise<{ dev: bigint; ino: bigint }> {
  const output = await runSecurityScript(`Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class VpnteExportIdentity {
 [StructLayout(LayoutKind.Sequential)] public struct Info {
  public uint Attributes;
  public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
  public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
 }
 [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GetFileInformationByHandle(SafeFileHandle handle, out Info info);
}
'@
${privateAclScript}
$stream=[IO.FileStream]::new(${pathData(temporary)},[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::None,$acl)
try {
  $info=New-Object VpnteExportIdentity+Info
  if(-not [VpnteExportIdentity]::GetFileInformationByHandle($stream.SafeFileHandle,[ref]$info)) {throw 'ConfigExportIdentityFailed'}
  @{dev=$info.Volume.ToString();ino=([uint64]$info.IndexHigh*4294967296+[uint64]$info.IndexLow).ToString()}|ConvertTo-Json -Compress
} finally {$stream.Dispose()}`)
  try {
    const identity = JSON.parse(output)
    if (typeof identity?.dev !== 'string' || typeof identity.ino !== 'string'
      || !/^\d+$/.test(identity.dev) || !/^[1-9]\d*$/.test(identity.ino)) throw new Error()
    return { dev: BigInt(identity.dev), ino: BigInt(identity.ino) }
  } catch { throw new IpcFault('permission') }
}

/** Protect staging before plaintext. Secret exports always use private access;
 * redacted replacements preserve the chosen file's owner/group/DACL. */
export async function prepareConfigExport(temporary: string, destination: string, mode: 'redacted' | 'secrets'): Promise<() => void> {
  if (mode !== 'redacted' && mode !== 'secrets') throw new IpcFault('validation')
  const before = await lstat(destination, { bigint: true }).catch(error => { if (!missing(error)) throw error; return undefined })
  if (before && !before.isFile()) throw new IpcFault('validation')
  if (process.platform === 'win32') {
    // .NET ACL APIs avoid PowerShell module-path/autoload drift; no elevation or FFI in main.
    const script = `$ErrorActionPreference='Stop';
$temporary=${pathData(temporary)}
$sections=[Security.AccessControl.AccessControlSections]'Access,Owner,Group'
${before && mode !== 'secrets' ? `$acl=[IO.File]::GetAccessControl(${pathData(destination)},$sections)` : privateAclScript}
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
    if (await runSecurityScript(script) !== 'CONFIG_EXPORT_ACL_VERIFIED') throw new IpcFault('permission')
  } else if (mode === 'secrets') {
    if (before && process.getuid?.() !== Number(before.uid)) throw new IpcFault('permission')
    await chmod(temporary, 0o600)
    const protectedFile = await lstat(temporary, { bigint: true })
    if (protectedFile.uid !== BigInt(process.getuid!()) || (protectedFile.mode & 0o777n) !== 0o600n) throw new IpcFault('permission')
  } else if (before) {
    if (process.getuid?.() !== Number(before.uid)) throw new IpcFault('permission')
    // chown may clear mode bits: preserve owner/group first, then permissions.
    await chown(temporary, Number(before.uid), Number(before.gid))
    await chmod(temporary, Number(before.mode & 0o777n))
    const copied = await lstat(temporary, { bigint: true })
    if (copied.uid !== before.uid || copied.gid !== before.gid || (copied.mode & 0o777n) !== (before.mode & 0o777n)) throw new IpcFault('permission')
  }
  const verify = () => {
    let current: BigIntStats | undefined
    try { current = lstatSync(destination, { bigint: true }) } catch (error) { if (!missing(error)) throw error }
    if (!sameFile(before, current)) throw new IpcFault('conflict')
  }
  verify()
  return verify
}
