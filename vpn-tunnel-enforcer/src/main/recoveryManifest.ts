import { open, rename, unlink } from 'fs/promises'
import { join } from 'path'
import { createHash, randomUUID } from 'crypto'
import { execFile as execFileCb } from 'child_process'
import { promisify } from 'util'
import { execElevated } from './admin'
import { executeRecoveryOperation, RecoveryWorkerError } from './recoveryPsWorker'
import { type RecoveryRequest, RECOVERY_QUARANTINE_SCRIPT } from './recoveryPsProtocol'

const execFile = promisify(execFileCb)
const MAX_MANIFEST_BYTES = 1024 * 1024
export class RecoveryManifestReadError extends Error {
  constructor(public reason: 'invalid-content' | 'unsupported-version', message: string, public contentHash?: string) { super(message) }
}
// Only pre-dispatch unavailability may fall back. Rejection/timeout/unknown
// completion must not replay recovery mutations in a second process.
async function tryRecoveryWorker(request: RecoveryRequest): Promise<string | undefined> {
  try { return await executeRecoveryOperation(request) }
  catch (error) {
    if (error instanceof RecoveryWorkerError && error.code === 'unavailable') return undefined
    throw error
  }
}
async function workerTrustedRead(request: RecoveryRequest): Promise<string | undefined> {
  const raw = await tryRecoveryWorker(request)
  if (raw !== 'RECOVERY_STORAGE_MISSING') return raw
  await ensureRecoveryManifestDir()
  const initialized = await tryRecoveryWorker(request)
  if (initialized === undefined || initialized === 'RECOVERY_STORAGE_MISSING') throw new Error('Recovery storage disappeared after bootstrap')
  return initialized
}
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
async function runRead(script: string, elevated = false): Promise<string> {
  const encoded = Buffer.from("[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ErrorActionPreference='Stop';" + script, 'utf16le').toString('base64')
  if (elevated) {
    const { stdout } = await execElevated(`powershell.exe -NoProfile -NonInteractive -EncodedCommand ${encoded}`, { timeout: 15000 })
    return String(stdout).replace(/^\uFEFF/, '').trim()
  }
  const { stdout } = await execFile('powershell.exe', ['-NoProfile','-NonInteractive','-EncodedCommand',encoded], {
    windowsHide: true, timeout: 15000, encoding: 'utf8', maxBuffer: MAX_MANIFEST_BYTES * 2
  })
  return String(stdout).replace(/^\uFEFF/, '').trim()
}
function programDataTrustCheck(): string {
  const programData = process.env.ProgramData || 'C:\\ProgramData'
  return `
$knownProgramData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
if (-not [string]::Equals([IO.Path]::GetFullPath(${quote(programData)}).TrimEnd([char]92),[IO.Path]::GetFullPath($knownProgramData).TrimEnd([char]92),[StringComparison]::OrdinalIgnoreCase)) { throw 'ProgramData environment does not match the Windows known folder' }
$parent = Get-Item -LiteralPath $knownProgramData -Force -ErrorAction Stop
if (-not $parent.PSIsContainer -or ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Untrusted ProgramData path' }
`
}
/** Every read rechecks the known folder, directory ACLs and the artifact.
 * Bootstrap is needed only when a checked directory is actually absent.
 * Never retry a rejected ACL/reparse/permission check as "missing" storage.
 */
async function runTrustedRead(script: string, elevated = false): Promise<string> {
  if (process.platform !== 'win32') throw new Error('Trusted recovery storage requires Windows')
  const root = join(process.env.ProgramData || 'C:\\ProgramData', 'VPNTE')
  const checked = `${TRUST_CHECK}${programDataTrustCheck()}
foreach ($dir in @(${quote(root)},${quote(getRecoveryManifestDir())})) {
  if (-not (Test-Path -LiteralPath $dir -ErrorAction Stop)) { Write-Output 'RECOVERY_STORAGE_MISSING'; return }
  Assert-TrustedArtifact $dir $true
}
${script}`
  const raw = await runRead(checked, elevated)
  if (raw !== 'RECOVERY_STORAGE_MISSING') return raw
  await ensureRecoveryManifestDir()
  const initialized = await runRead(checked, elevated)
  if (initialized === 'RECOVERY_STORAGE_MISSING') throw new Error('Recovery storage disappeared after bootstrap')
  return initialized
}
export async function ensureRecoveryManifestDir(): Promise<void> {
  if (process.platform !== 'win32') throw new Error('Trusted recovery storage requires Windows')
  const workerResult = await tryRecoveryWorker({ op: 'ensure' })
  if (workerResult !== undefined) {
    if (workerResult !== 'RECOVERY_STORAGE_VERIFIED') throw new Error('Recovery storage verification failed')
    return
  }
  const programData = process.env.ProgramData || 'C:\\ProgramData'
  const root = join(programData, 'VPNTE')
  // Never recursively reset ACLs or bless pre-existing user-controlled contents.
  // DirectoryInfo.Create(DirectorySecurity) creates new directories with their
  // restrictive DACL in the same operation (Windows PowerShell / .NET Framework).
  const script = `$ErrorActionPreference='Stop';${TRUST_CHECK}${programDataTrustCheck()}
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
  // Even absence is trusted only after checking the containing directories.
  // An attacker-controlled directory must not trigger an Allow fallback.
  const raw = await workerTrustedRead({ op: 'read', name }) ?? await runTrustedRead(`
if (-not (Test-Path -LiteralPath ${quote(target)})) { Write-Output 'RECOVERY_ARTIFACT_ABSENT'; return }
Assert-TrustedArtifact ${quote(target)} $false
if ((Get-Item -LiteralPath ${quote(target)}).Length -gt ${MAX_MANIFEST_BYTES}) { throw 'Recovery manifest exceeds limit' }
Get-Content -LiteralPath ${quote(target)} -Raw -Encoding UTF8`)
  if (raw === 'RECOVERY_ARTIFACT_ABSENT') return null
  const normalized = raw.replace(/^\uFEFF/, '').trim()
  const contentHash = createHash('sha256').update(normalized, 'utf8').digest('hex')
  let value: any
  try { value = JSON.parse(normalized) }
  catch { throw new RecoveryManifestReadError('invalid-content', `Invalid recovery JSON: ${name}`, contentHash) }
  if (typeof value?.schemaVersion === 'number' && value.schemaVersion !== 1) {
    throw new RecoveryManifestReadError('unsupported-version', `Unsupported recovery manifest version: ${name}`)
  }
  try { return validate(value) }
  catch (error) {
    if (error instanceof RecoveryManifestReadError) throw error
    throw new RecoveryManifestReadError('invalid-content', String(error), contentHash)
  }
}
export async function quarantineRecoveryManifest(name: string, contentHash?: string): Promise<void> {
  if (!contentHash || !/^[a-f0-9]{64}$/.test(contentHash)) throw new Error('Recovery quarantine needs the rejected content fingerprint')
  const target = recoveryManifestPath(name)
  const proof = await workerTrustedRead({ op: 'quarantine', name, contentHash }) ?? await runTrustedRead(`
$path=${quote(target)}
$expectedHash=${quote(contentHash)}
${RECOVERY_QUARANTINE_SCRIPT}`, true)
  if (proof !== 'RECOVERY_ARTIFACT_QUARANTINED') throw new Error('Recovery quarantine not confirmed')
}
/** Unique temp + fsync + admin-owned protected file ACL + rename commit point. */
export async function writeRecoveryArtifact(name: string, content: string | Buffer): Promise<void> {
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
    const workerResult = await tryRecoveryWorker({ op: 'protect', name: temporary.split(/[\\/]/).at(-1)! })
    if (workerResult === undefined) {
      await execElevated(`powershell.exe -NoProfile -NonInteractive -EncodedCommand ${Buffer.from(script, 'utf16le').toString('base64')}`, { timeout: 15000 })
    } else if (workerResult !== 'RECOVERY_TEMP_VERIFIED') throw new Error('Recovery temporary verification failed')
    await rename(temporary, target)
  } finally { await unlink(temporary).catch((error: any) => { if (error?.code !== 'ENOENT') throw error }) }
}
export async function writeRecoveryManifest<T>(name: string, value: T, validate: (value: unknown) => T): Promise<void> {
  await writeRecoveryArtifact(name, JSON.stringify(validate(value), null, 2))
}
export async function readRecoveryArtifact(name: string): Promise<Buffer> {
  const target = recoveryManifestPath(name)
  const raw = await workerTrustedRead({ op: 'binary', name }) ?? await runTrustedRead(`
Assert-TrustedArtifact ${quote(target)} $false
if ((Get-Item -LiteralPath ${quote(target)}).Length -gt ${MAX_MANIFEST_BYTES}) { throw 'Recovery artifact exceeds limit' }
[Convert]::ToBase64String([IO.File]::ReadAllBytes(${quote(target)}))`)
  return Buffer.from(raw, 'base64')
}
export async function removeRecoveryManifest(name: string): Promise<void> {
  // Do not follow a replaced parent or delete an artifact from an untrusted tree.
  const target = recoveryManifestPath(name)
  const workerResult = await workerTrustedRead({ op: 'remove', name })
  if (workerResult !== undefined) {
    if (!['RECOVERY_ARTIFACT_ABSENT', 'RECOVERY_ARTIFACT_REMOVED'].includes(workerResult)) throw new Error('Recovery removal not confirmed')
    return
  }
  await runTrustedRead(`
if (Test-Path -LiteralPath ${quote(target)}) {
  Assert-TrustedArtifact ${quote(target)} $false
  Remove-Item -LiteralPath ${quote(target)} -Force -ErrorAction Stop
}`)
}

export interface BootRecoveryReport {
  schemaVersion: 1
  owner: 'VPNTE'
  completedAt: number
  status: 'restored' | 'strict-retained' | 'warnings'
  messages: Array<{ time: number; message: string }>
}
export function validateBootRecoveryReport(value: unknown): BootRecoveryReport {
  const v = value as BootRecoveryReport
  if (!v || v.schemaVersion !== 1 || v.owner !== 'VPNTE' || !Number.isSafeInteger(v.completedAt) || v.completedAt <= 0 ||
      !['restored','strict-retained','warnings'].includes(v.status) || !Array.isArray(v.messages) || v.messages.length > 500 ||
      v.messages.some(m => !m || !Number.isSafeInteger(m.time) || typeof m.message !== 'string' || m.message.length > 4096)) throw new Error('Invalid Boot Recovery report')
  return v
}
export function readBootRecoveryReport(): Promise<BootRecoveryReport | null> {
  return readRecoveryManifest('recovery-result.json', validateBootRecoveryReport)
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
  const raw = await tryRecoveryWorker({ op: 'inspect-tun', alias }) ?? await runRead(`$adapter = Get-NetAdapter -Name ${quote(alias)} -ErrorAction Stop
if ([string]$adapter.Status -ne 'Up') { throw 'VPNTE TUN adapter is not Up' }
if ($adapter.DriverDescription -notmatch '^Wintun\\b' -or $adapter.PnPDeviceID -notlike 'SWD\\Wintun\\*') { throw 'VPNTE TUN driver identity mismatch' }
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
