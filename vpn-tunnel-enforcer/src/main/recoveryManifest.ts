import { open, rename, unlink, lstat } from 'fs/promises'
import { join } from 'path'
import { randomUUID } from 'crypto'
import { execFile as execFileCb } from 'child_process'
import { promisify } from 'util'
import { execElevated } from './admin'

const execFile = promisify(execFileCb)
const MAX_MANIFEST_BYTES = 1024 * 1024
export function getRecoveryManifestDir(): string {
  return join(process.env.ProgramData || 'C:\\ProgramData', 'VPNTE', 'manifests')
}
export function recoveryManifestPath(name: string): string {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,160}$/.test(name)) throw new Error('Invalid recovery artifact name')
  return join(getRecoveryManifestDir(), name)
}
function quote(value: string): string { return `'${value.replace(/'/g, "''")}'` }
const TRUST_CHECK = `
function Assert-TrustedArtifact($path, $directory) {
  $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse recovery artifact rejected' }
  if ([bool]$item.PSIsContainer -ne [bool]$directory) { throw 'Wrong recovery artifact type' }
  $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
  $allowed = @('S-1-5-18','S-1-5-32-544')
  if ($allowed -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { throw 'Untrusted recovery owner' }
  if (-not $acl.AreAccessRulesProtected) { throw 'Recovery ACL must be protected' }
  foreach ($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -eq 'Allow' -and $allowed -notcontains $rule.IdentityReference.Value) { throw 'Untrusted recovery ACE' }
  }
}
`
async function runRead(script: string): Promise<string> {
  const encoded = Buffer.from("[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ErrorActionPreference='Stop';" + script, 'utf16le').toString('base64')
  const { stdout } = await execFile('powershell.exe', ['-NoProfile','-NonInteractive','-EncodedCommand',encoded], {
    windowsHide: true, timeout: 15000, encoding: 'utf8', maxBuffer: MAX_MANIFEST_BYTES * 2
  })
  return String(stdout).replace(/^\uFEFF/, '').trim()
}
export async function ensureRecoveryManifestDir(): Promise<void> {
  if (process.platform !== 'win32') throw new Error('Trusted recovery storage requires Windows')
  const programData = process.env.ProgramData || 'C:\\ProgramData'
  const root = join(programData, 'VPNTE')
  // Never recursively reset ACLs or bless pre-existing user-controlled contents.
  // DirectoryInfo.Create(DirectorySecurity) creates new directories with their
  // restrictive DACL in the same operation (Windows PowerShell / .NET Framework).
  const script = `$ErrorActionPreference='Stop';${TRUST_CHECK}
$parent = Get-Item -LiteralPath ${quote(programData)} -Force -ErrorAction Stop
if (-not $parent.PSIsContainer -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Untrusted ProgramData path' }
foreach ($dir in @(${quote(root)},${quote(getRecoveryManifestDir())})) {
  if (-not (Test-Path -LiteralPath $dir)) {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
      $id = New-Object Security.Principal.SecurityIdentifier($sid)
      $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))
    }
    $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    $info = New-Object IO.DirectoryInfo($dir)
    $info.Create($acl)
  }
  Assert-TrustedArtifact $dir $true
}
Write-Output 'RECOVERY_STORAGE_VERIFIED'`
  const { stdout } = await execElevated(`powershell.exe -NoProfile -NonInteractive -EncodedCommand ${Buffer.from(script, 'utf16le').toString('base64')}`, { timeout: 15000 })
  if (!String(stdout).split(/\r?\n/).includes('RECOVERY_STORAGE_VERIFIED')) throw new Error('Recovery storage verification failed')
}
/** Reads and checks directory AND file ACLs before any manifest content is used. */
export async function readRecoveryManifest<T>(name: string, validate: (value: unknown) => T): Promise<T | null> {
  const target = recoveryManifestPath(name)
  // ENOENT is distinct from corrupt/unsupported/untrusted data. Never read AppData.
  try { await lstat(target) } catch (error: any) { if (error?.code === 'ENOENT') return null; throw error }
  const root = join(process.env.ProgramData || 'C:\\ProgramData', 'VPNTE')
  const raw = await runRead(`${TRUST_CHECK}
Assert-TrustedArtifact ${quote(root)} $true
Assert-TrustedArtifact ${quote(getRecoveryManifestDir())} $true
Assert-TrustedArtifact ${quote(target)} $false
if ((Get-Item -LiteralPath ${quote(target)}).Length -gt ${MAX_MANIFEST_BYTES}) { throw 'Recovery manifest exceeds limit' }
Get-Content -LiteralPath ${quote(target)} -Raw -Encoding UTF8`)
  return validate(JSON.parse(raw))
}
/** Unique temp + fsync + admin-owned protected file ACL + rename commit point. */
export async function writeRecoveryArtifact(name: string, content: string): Promise<void> {
  const target = recoveryManifestPath(name)
  if (Buffer.byteLength(content, 'utf8') > MAX_MANIFEST_BYTES) throw new Error('Recovery artifact exceeds limit')
  await ensureRecoveryManifestDir()
  const temporary = recoveryManifestPath(`tmp-${randomUUID()}`)
  try {
    const handle = await open(temporary, 'wx', 0o600)
    try { await handle.writeFile(content, 'utf8'); await handle.sync() } finally { await handle.close() }
    const script = `$ErrorActionPreference='Stop';${TRUST_CHECK}
$acl = New-Object Security.AccessControl.FileSecurity
$acl.SetAccessRuleProtection($true,$false)
foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
  $id = New-Object Security.Principal.SecurityIdentifier($sid)
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id,'FullControl','Allow')))
}
$acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
Set-Acl -LiteralPath ${quote(temporary)} -AclObject $acl
Assert-TrustedArtifact ${quote(temporary)} $false`
    await execElevated(`powershell.exe -NoProfile -NonInteractive -EncodedCommand ${Buffer.from(script, 'utf16le').toString('base64')}`, { timeout: 15000 })
    await rename(temporary, target)
  } finally { await unlink(temporary).catch((error: any) => { if (error?.code !== 'ENOENT') throw error }) }
}
export async function writeRecoveryManifest<T>(name: string, value: T, validate: (value: unknown) => T): Promise<void> {
  await writeRecoveryArtifact(name, JSON.stringify(validate(value), null, 2))
}
export async function removeRecoveryManifest(name: string): Promise<void> {
  try { await unlink(recoveryManifestPath(name)) } catch (error: any) { if (error?.code !== 'ENOENT') throw error }
}

export function validateRecoveryPolicy(value: unknown): { schemaVersion: 1; owner: 'VPNTE'; strictMode: boolean } {
  const v = value as any
  if (!v || v.schemaVersion !== 1 || v.owner !== 'VPNTE' || typeof v.strictMode !== 'boolean') throw new Error('Invalid recovery policy')
  return { schemaVersion: 1, owner: 'VPNTE', strictMode: v.strictMode }
}
export async function persistRecoveryPolicy(strictMode: boolean): Promise<void> {
  await writeRecoveryManifest('recovery-policy.json', { schemaVersion: 1, owner: 'VPNTE', strictMode }, validateRecoveryPolicy)
}
export async function strictRecoveryRequired(): Promise<boolean> {
  try { return (await readRecoveryManifest('recovery-policy.json', validateRecoveryPolicy))?.strictMode === true }
  catch { return true } // An unreadable strict policy must never permit fail-open recovery.
}
export async function recordOwnedTunAdapter(alias: string): Promise<void> {
  if (process.platform !== 'win32') return
  const raw = await runRead(`$adapter = Get-NetAdapter -Name ${quote(alias)} -ErrorAction Stop
if ($adapter.InterfaceDescription -notmatch 'Wintun') { throw 'VPNTE TUN driver identity mismatch' }
$ip = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.IPAddress -eq '192.168.250.253' -and $_.PrefixLength -eq 30 }
if (-not $ip) { throw 'VPNTE TUN address identity mismatch' }
[pscustomobject]@{schemaVersion=1;owner='VPNTE';alias=[string]$adapter.Name;interfaceGuid=[string]$adapter.InterfaceGuid} | ConvertTo-Json -Compress`)
  const value = JSON.parse(raw)
  const validate = (v: any) => {
    if (!v || v.schemaVersion !== 1 || v.owner !== 'VPNTE' || v.alias !== alias ||
      !/^\{?[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\}?$/i.test(v.interfaceGuid)) throw new Error('Invalid TUN ownership snapshot')
    return v
  }
  await writeRecoveryManifest('tun-owner.json', value, validate)
}
