import { mkdir, open, rename, unlink, lstat } from 'fs/promises'
import { join } from 'path'
import { randomUUID } from 'crypto'
import { execFile as execFileCb } from 'child_process'
import { promisify } from 'util'
import { execElevated } from './admin'
import { ensureElevatedRuntimeDirHardened, verifyDirectoryHardened } from './runtimeDirSecurity'

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
async function rejectReparse(path: string): Promise<void> {
  const item = await lstat(path)
  if (item.isSymbolicLink() || !item.isDirectory()) throw new Error('Recovery directory is not a real directory')
}
export async function ensureRecoveryManifestDir(): Promise<void> {
  if (process.platform !== 'win32') throw new Error('Trusted recovery storage requires Windows')
  const root = join(process.env.ProgramData || 'C:\\ProgramData', 'VPNTE')
  for (const dir of [root, getRecoveryManifestDir()]) {
    await mkdir(dir, { recursive: true })
    await rejectReparse(dir)
    const result = await ensureElevatedRuntimeDirHardened(dir, 'recovery-manifest')
    const verified = await verifyDirectoryHardened(dir)
    if (!result.hardened || !verified.hardened || result.skipped || verified.skipped) throw new Error('Recovery storage ACL is not trusted')
  }
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
  await ensureRecoveryManifestDir()
  const target = recoveryManifestPath(name)
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
