/** AT-01-009, F-002/F-104: privileged runtime storage is trusted only when
 * its namespace cannot be replaced by an unelevated user. A protected child
 * DACL alone is insufficient: DELETE_CHILD on a parent overrides child DELETE.
 * Never repair/bless a pre-existing user-writable directory or its contents. */
import { stat } from 'fs/promises'
import { execFile as execFileCb } from 'child_process'
import { promisify } from 'util'
import { win32 } from 'path'
import { execElevated, isProcessElevated } from './admin'
import { logEvent } from './appLogger'

const execFile = promisify(execFileCb)
const SID_SYSTEM = 'S-1-5-18'
const SID_ADMINISTRATORS = 'S-1-5-32-544'
const SID_TRUSTED_INSTALLER = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
const ALLOWED_SIDS = new Set([SID_SYSTEM, SID_ADMINISTRATORS])
const ANCESTOR_SIDS = new Set([...ALLOWED_SIDS, SID_TRUSTED_INSTALLER])
// Data/EA/attributes, delete-child/delete, WRITE_DAC and WRITE_OWNER.
const ARTIFACT_WRITE_MASK = 0x500D0156
// Creating siblings or writing directory attributes is not a grant to rename
// an existing protected child. DELETE_CHILD/DELETE/WRITE_DAC/WRITE_OWNER and
// GENERIC_ALL are. InheritOnly ACEs do not apply to the ancestor itself.
const NAMESPACE_WRITE_MASK = 0x100D0040

export interface DirectoryHardeningResult {
  hardened: boolean
  skipped?: boolean
  refusalCode?: 'namespace-untrusted' | 'inspection-failed'
  message: string
  offenders?: string[]
  owner?: string | null
  diagnostic?: RuntimeFailureDiagnostic
}

interface RuntimeFailureDiagnostic {
  operation: string
  path: string
  reason: string
  errorType: string
  hresult?: number
  principal?: string
  rights?: number
}
const FAILURE_PREFIX = 'VPNTE_RUNTIME_FAILURE:'
const POLICY_FAILURE = /^(RuntimeNamespaceUntrusted(?:Owner|Type|Reparse|Access)|RuntimeAclNotProtected|RuntimeAclMissingRules|RuntimeProgramDataMismatch|RuntimeOutsideBoundary)$/

// Only consume our bounded metadata receipt, never log stderr/argv/exception text.
function failureDiagnostic(error: unknown): RuntimeFailureDiagnostic {
  const failure = error as { stdout?: unknown; code?: unknown; killed?: unknown }
  const line = typeof failure?.stdout === 'string' ? failure.stdout.split(/\r?\n/).find(s => s.startsWith(FAILURE_PREFIX)) : undefined
  try {
    const v = line && line.length <= 4096 ? JSON.parse(line.slice(FAILURE_PREFIX.length)) : null
    if (v && /^(import-acl-module|known-folder|runtime-boundary|read-item|read-acl|validate-acl|list-children|create-directory)$/.test(v.operation) &&
        typeof v.path === 'string' && v.path.length <= 1024 && (v.path === '' || win32.isAbsolute(v.path)) &&
        (v.reason === 'PowerShellError' || POLICY_FAILURE.test(v.reason)) &&
        typeof v.errorType === 'string' && /^[A-Za-z][A-Za-z0-9.]{0,160}$/.test(v.errorType) && Number.isInteger(v.hresult)) {
      return { operation: v.operation, path: v.path, reason: v.reason, errorType: v.errorType, hresult: v.hresult,
        ...(typeof v.principal === 'string' && /^S-\d+(?:-\d+)+$/.test(v.principal) ? { principal: v.principal } : {}),
        ...(Number.isSafeInteger(v.rights) && v.rights >= 0 && v.rights <= 0xFFFFFFFF ? { rights: v.rights } : {}) }
    }
  } catch { /* A missing/malformed diagnostic never authorizes the runtime. */ }
  return { operation: 'powershell', path: '', reason: failure?.killed === true ? 'ProcessTerminated' : 'DiagnosticUnavailable',
    errorType: typeof failure?.code === 'number' ? `ExitCode.${failure.code}` : 'ProcessError' }
}

function psSingleQuote(value: string): string { return `'${value.replace(/'/g, "''")}'` }
function encodedPowerShell(script: string): string {
  const prelude = `
$ErrorActionPreference='Stop'
$script:runtimeOperation='import-acl-module'; $script:runtimePath=''; $script:runtimePrincipal=$null; $script:runtimeRights=$null
trap {
  $reason='PowerShellError'
  if ($_.Exception.Message -match '${POLICY_FAILURE.source}') { $reason=$_.Exception.Message }
  $cause=$_.Exception
  while ($cause.InnerException) { $cause=$cause.InnerException }
  $diagnostic=[ordered]@{operation=$script:runtimeOperation;path=$script:runtimePath;reason=$reason;
    errorType=$cause.GetType().FullName;hresult=$cause.HResult;principal=$script:runtimePrincipal;rights=$script:runtimeRights}
  [Console]::Out.WriteLine('${FAILURE_PREFIX}' + ($diagnostic | ConvertTo-Json -Compress))
  break
}
` +
    "Import-Module -Name (Join-Path $PSHOME 'Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop;" +
    '$OutputEncoding=[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();$ProgressPreference="SilentlyContinue";'
  return Buffer.from(prelude + script, 'utf16le').toString('base64')
}
async function runPowerShell(script: string, elevated: boolean, timeout: number): Promise<string> {
  const encoded = encodedPowerShell(script)
  if (elevated) {
    const { stdout } = await execElevated(`powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ${encoded}`, { timeout, maxBuffer: 4 * 1024 * 1024 })
    return checkedPowerShellOutput(stdout)
  }
  const { stdout } = await execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], {
    windowsHide: true, timeout, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024
  })
  return checkedPowerShellOutput(stdout)
}
function checkedPowerShellOutput(value: unknown): string {
  const stdout = String(value ?? '').replace(/^\uFEFF/, '').trim()
  if (stdout.split(/\r?\n/).some(line => line.startsWith(FAILURE_PREFIX))) {
    throw Object.assign(new Error('Runtime PowerShell refused'), { stdout })
  }
  return stdout
}

const RUNTIME_TREE_HELPERS = `
$artifactSids = @('${SID_SYSTEM}', '${SID_ADMINISTRATORS}')
$ancestorSids = @('${SID_SYSTEM}', '${SID_ADMINISTRATORS}', '${SID_TRUSTED_INSTALLER}')
function Get-RuntimeItem($path) {
  $script:runtimeOperation='read-item'; $script:runtimePath=$path; $script:runtimePrincipal=$null; $script:runtimeRights=$null
  $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'RuntimeNamespaceUntrustedReparse' }
  return $item
}
function Get-RuntimeAcl($path) {
  $item = Get-RuntimeItem $path
  $script:runtimeOperation='read-acl'
  $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
  $rules = @()
  foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    $rules += [ordered]@{
      sid = $rule.IdentityReference.Value
      rights = ([long][int]$rule.FileSystemRights -band 4294967295)
      type = $rule.AccessControlType.ToString()
      inheritOnly = (($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0)
    }
  }
  return [ordered]@{
    path = $item.FullName
    directory = [bool]$item.PSIsContainer
    reparse = $false
    owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    protected = $acl.AreAccessRulesProtected
    rules = $rules
  }
}
function Assert-RuntimeAcl($snapshot, $ancestor) {
  $script:runtimeOperation='validate-acl'; $script:runtimePath=$snapshot.path; $script:runtimePrincipal=$snapshot.owner; $script:runtimeRights=$null
  $allowed = $artifactSids; $mask = ${ARTIFACT_WRITE_MASK}
  if ($ancestor) { $allowed = $ancestorSids; $mask = ${NAMESPACE_WRITE_MASK} }
  if ($allowed -notcontains $snapshot.owner) { throw 'RuntimeNamespaceUntrustedOwner' }
  if ($ancestor -and -not $snapshot.directory) { throw 'RuntimeNamespaceUntrustedType' }
  if (-not $ancestor -and -not $snapshot.protected) { throw 'RuntimeAclNotProtected' }
  if ($snapshot.rules.Count -eq 0) { throw 'RuntimeAclMissingRules' }
  foreach ($rule in $snapshot.rules) {
    if ((-not $ancestor -or -not $rule.inheritOnly) -and $rule.type -eq 'Allow' -and $allowed -notcontains $rule.sid -and
        ($rule.rights -band $mask) -ne 0) {
      $script:runtimePrincipal=$rule.sid; $script:runtimeRights=$rule.rights
      throw 'RuntimeNamespaceUntrustedAccess'
    }
  }
}
function Get-RuntimeAncestors($path) {
  $components = New-Object 'System.Collections.Generic.Stack[string]'
  $candidate = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($path))
  while ($candidate) {
    $components.Push($candidate)
    $candidate = [IO.Path]::GetDirectoryName($candidate)
  }
  while ($components.Count -gt 0) {
    $snapshot = Get-RuntimeAcl ($components.Pop())
    Write-Output $snapshot
    # Refuse before walking into the next component, not after reading its ACL.
    Assert-RuntimeAcl $snapshot $true
  }
}
function Get-RuntimeChildren($root) {
  $pending = New-Object 'System.Collections.Generic.Stack[string]'
  $pending.Push($root)
  while ($pending.Count -gt 0) {
    $parent = Get-RuntimeItem ($pending.Pop())
    if (-not $parent.PSIsContainer) { throw 'RuntimeNamespaceUntrustedType' }
    $script:runtimeOperation='list-children'
    foreach ($entry in @(Get-ChildItem -LiteralPath $parent.FullName -Force -ErrorAction Stop)) {
      $item = Get-RuntimeItem $entry.FullName
      Write-Output (Get-RuntimeAcl $item.FullName)
      if ($item.PSIsContainer) { $pending.Push($item.FullName) }
    }
  }
}
`

function knownFolderCheck(): string {
  const programData = process.env.ProgramData || 'C:\\ProgramData'
  return `$script:runtimeOperation='known-folder'; $script:runtimePath=${psSingleQuote(programData)}
$knownProgramData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
if (-not [string]::Equals([IO.Path]::GetFullPath(${psSingleQuote(programData)}).TrimEnd([char]92),
    [IO.Path]::GetFullPath($knownProgramData).TrimEnd([char]92), [StringComparison]::OrdinalIgnoreCase)) {
  throw 'RuntimeProgramDataMismatch'
}`
}

function buildInspectScript(dir: string): string {
  return `$ErrorActionPreference = 'Stop'
$dir = ${psSingleQuote(dir)}
${RUNTIME_TREE_HELPERS}
${knownFolderCheck()}
# The parent chain is walked root-first and must be authorized before children.
$ancestors = @(Get-RuntimeAncestors $dir)
$root = Get-RuntimeAcl $dir
if (-not $root.directory) { throw 'RuntimeNamespaceUntrustedType' }
$root['ancestors'] = $ancestors
$root['ancestorsInspected'] = $true
$root['children'] = @(Get-RuntimeChildren $dir)
$root['childrenInspected'] = $true
$root | ConvertTo-Json -Depth 7 -Compress`
}

/** Only create missing application components with a restrictive ACL atomically.
 * Existing roots (including VPNTE shared with recovery) must already be trusted.
 * System directories and user profiles are never modified. */
function buildBootstrapScript(dir: string): string {
  return `$ErrorActionPreference = 'Stop'
$dir = ${psSingleQuote(dir)}
${RUNTIME_TREE_HELPERS}
${knownFolderCheck()}
$base = Join-Path $knownProgramData 'VPNTE'
$runtimeBase = Join-Path $base 'runtime'
$script:runtimeOperation='runtime-boundary'; $script:runtimePath=$dir
$relative = [IO.Path]::GetFullPath($dir).Substring($runtimeBase.Length)
if (-not $dir.StartsWith($runtimeBase + [char]92, [StringComparison]::OrdinalIgnoreCase) -or
    $relative -notmatch '^\\\\[a-f0-9]{32}\\\\(tun-runtime|external-proxy-runtime|traffic-forensics)$') {
  throw 'RuntimeOutsideBoundary'
}
$null = @(Get-RuntimeAncestors (Join-Path $knownProgramData 'boundary'))
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in $artifactSids) {
  $id = New-Object Security.Principal.SecurityIdentifier($sid)
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
$acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('${SID_ADMINISTRATORS}')))
$instance = [IO.Path]::GetDirectoryName($dir)
foreach ($component in @($base, $runtimeBase, $instance, $dir)) {
  # The containing namespace was already proven safe. Never reset an existing
  # DACL/owner, recursively create, or accept contents from untrusted storage.
  $script:runtimeOperation='create-directory'; $script:runtimePath=$component; $script:runtimePrincipal=$null; $script:runtimeRights=$null
  if (-not (Test-Path -LiteralPath $component -ErrorAction Stop)) {
    $info = New-Object IO.DirectoryInfo($component)
    $info.Create($acl)
  }
  $snapshot = Get-RuntimeAcl $component
  if (-not $snapshot.directory) { throw 'RuntimeNamespaceUntrustedType' }
  Assert-RuntimeAcl $snapshot $false
}
Write-Output 'HARDENED'`
}

interface AclSnapshot {
  path: string
  owner: string
  protected: boolean
  directory: boolean
  reparse: boolean
  rules: Array<{ sid: string; rights: number; type: 'Allow' | 'Deny'; inheritOnly: boolean }>
}
interface RuntimeTreeSnapshot extends AclSnapshot { children: AclSnapshot[]; ancestors: AclSnapshot[] }
function parseAcl(value: unknown): AclSnapshot | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  const v = value as AclSnapshot
  if (typeof v.path !== 'string' || !win32.isAbsolute(v.path) || typeof v.owner !== 'string' || !/^S-\d+(?:-\d+)+$/.test(v.owner) ||
      typeof v.protected !== 'boolean' || typeof v.directory !== 'boolean' || typeof v.reparse !== 'boolean' ||
      !Array.isArray(v.rules) || !v.rules.length) return null
  for (const r of v.rules) {
    if (!r || typeof r.sid !== 'string' || !/^S-\d+(?:-\d+)+$/.test(r.sid) ||
        !Number.isSafeInteger(r.rights) || r.rights < 0 || r.rights > 0xFFFFFFFF ||
        (r.type !== 'Allow' && r.type !== 'Deny') || typeof r.inheritOnly !== 'boolean') return null
  }
  return v
}
function parseAclSnapshot(stdout: string): RuntimeTreeSnapshot | null {
  try {
    const v = JSON.parse(stdout)
    const root = parseAcl(v)
    if (!root || v.childrenInspected !== true || v.ancestorsInspected !== true ||
        !Array.isArray(v.children) || !Array.isArray(v.ancestors)) return null
    const children = v.children.map(parseAcl), ancestors = v.ancestors.map(parseAcl)
    if (children.includes(null) || ancestors.includes(null)) return null
    return { ...root, children, ancestors }
  } catch { return null }
}
function findOffenders(snapshot: AclSnapshot, ancestor = false): string[] {
  const allowed = ancestor ? ANCESTOR_SIDS : ALLOWED_SIDS
  const mask = ancestor ? NAMESPACE_WRITE_MASK : ARTIFACT_WRITE_MASK
  const offenders: string[] = []
  if (!allowed.has(snapshot.owner)) offenders.push(`${snapshot.path}: ${snapshot.owner} (owner: implicit WRITE_DAC)`)
  for (const rule of snapshot.rules) {
    if ((!ancestor || !rule.inheritOnly) && rule.type === 'Allow' && !allowed.has(rule.sid) && (rule.rights & mask) !== 0) {
      offenders.push(`${snapshot.path}: ${rule.sid} (rights: ${rule.rights})`)
    }
  }
  return offenders
}
function normalize(path: string): string { return win32.resolve(path).toLowerCase() }
export async function verifyDirectoryHardened(dir: string): Promise<DirectoryHardeningResult> {
  if (process.platform !== 'win32') return { hardened: true, skipped: true, message: 'ACL hardening не применяется (не Windows)' }
  try {
    const snapshot = parseAclSnapshot(await runPowerShell(buildInspectScript(dir), false, 15000))
    if (!snapshot || normalize(snapshot.path) !== normalize(dir) || !snapshot.directory || snapshot.reparse) {
      return { hardened: false, message: 'не удалось подтвердить полный ACL/namespace снимок runtime' }
    }
    const expected: string[] = []
    for (let p = win32.dirname(normalize(dir)); ; p = win32.dirname(p)) {
      expected.unshift(p)
      if (p === win32.dirname(p)) break
    }
    if (snapshot.ancestors.length !== expected.length || snapshot.ancestors.some((s, i) =>
      normalize(s.path) !== expected[i] || !s.directory || s.reparse)) {
      return { hardened: false, message: 'неполная или некорректная родительская цепочка runtime', owner: snapshot.owner }
    }
    const paths = new Set([normalize(dir)]), directories = new Set(paths)
    for (const child of snapshot.children) {
      const p = normalize(child.path), relative = win32.relative(normalize(dir), p)
      if (!relative || relative === '..' || relative.startsWith('..\\') || win32.isAbsolute(relative) || paths.has(p) || child.reparse) {
        return { hardened: false, message: 'некорректный путь/reparse в runtime-дереве', owner: snapshot.owner }
      }
      paths.add(p)
      if (child.directory) directories.add(p)
    }
    if (snapshot.children.some(s => !directories.has(normalize(win32.dirname(s.path))))) {
      return { hardened: false, message: 'неполный снимок каталогов runtime-дерева', owner: snapshot.owner }
    }
    const offenders = [...findOffenders(snapshot), ...snapshot.ancestors.flatMap(s => findOffenders(s, true)),
      ...snapshot.children.flatMap(s => findOffenders(s))]
    if (offenders.length) return { hardened: false, message: 'runtime или его namespace доступны непривилегированным пользователям', offenders, owner: snapshot.owner }
    if (!snapshot.protected) return { hardened: false, message: 'ACL runtime наследуется от внешнего родителя', owner: snapshot.owner }
    return { hardened: true, message: 'runtime-дерево и родительская цепочка защищены от записи и подмены', owner: snapshot.owner }
  } catch (error: unknown) {
    const failure = error as { stderr?: unknown; message?: unknown }
    const text = `${String(failure?.stderr ?? '')} ${String(failure?.message ?? '')}`
    const diagnostic = failureDiagnostic(error)
    const namespaceRefusal = /RuntimeNamespaceUntrusted(?:Owner|Type|Reparse|Access)/.test(`${diagnostic.reason} ${text}`)
    return {
      hardened: false,
      refusalCode: namespaceRefusal ? 'namespace-untrusted' : 'inspection-failed',
      message: namespaceRefusal ? 'небезопасная родительская цепочка runtime: запуск запрещён' : 'не удалось проверить ACL/владельца/reparse родительской цепочки runtime',
      diagnostic
    }
  }
}

const hardenedDirs = new Map<string, Promise<DirectoryHardeningResult>>()
async function hardenOnce(dir: string, label: string): Promise<DirectoryHardeningResult> {
  const before = await verifyDirectoryHardened(dir)
  if (before.hardened) return before
  if (!await isProcessElevated()) {
    logEvent('error', 'runtime-acl', `${label}: runtime elevation required`, { dir, before })
    return { hardened: false, message: 'нет прав администратора для создания доверенного runtime' }
  }
  try {
    const stdout = await runPowerShell(buildBootstrapScript(dir), true, 60000)
    if (!stdout.split(/\r?\n/).includes('HARDENED')) throw new Error('Missing runtime bootstrap confirmation')
  } catch (error: unknown) {
    const diagnostic = failureDiagnostic(error)
    logEvent('error', 'runtime-acl', `${label}: runtime bootstrap refused`, { dir, diagnostic, before })
    return { hardened: false, diagnostic, message: 'RuntimeSecurityAclError: создание доверенного runtime отклонено; существующие небезопасные каталоги не исправляются автоматически. Причина и путь — в журнале runtime-acl' }
  }
  const after = await verifyDirectoryHardened(dir)
  if (!after.hardened) logEvent('error', 'runtime-acl', `${label}: runtime readback refused`, { dir, result: after })
  return after
}
export async function ensureElevatedRuntimeDirHardened(dir: string, label: string): Promise<DirectoryHardeningResult> {
  const key = normalize(dir)
  const cached = hardenedDirs.get(key)
  if (cached) return cached
  const attempt = hardenOnce(dir, label)
  hardenedDirs.set(key, attempt)
  try { return await attempt }
  finally { if (hardenedDirs.get(key) === attempt) hardenedDirs.delete(key) }
}
export function resetRuntimeDirHardeningCache(): void { hardenedDirs.clear() }
export async function directoryExists(path: string): Promise<boolean> {
  try { return (await stat(path)).isDirectory() } catch { return false }
}
