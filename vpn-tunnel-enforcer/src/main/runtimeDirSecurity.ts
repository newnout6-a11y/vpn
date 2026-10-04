/**
 * ACL hardening for directories we execute code from while elevated.
 *
 * THE PROBLEM THIS SOLVES. `electron-builder.yml` sets
 * `requestedExecutionLevel: requireAdministrator`, so this app always runs with
 * administrator rights. It also stages `vpnte-sing-box.exe`, `wintun.dll` and
 * `libcronet.dll` into `%APPDATA%\VPN Tunnel Enforcer\tun-runtime` and launches
 * them from there — and `%APPDATA%` grants the interactive user Full Control by
 * default. Any unprivileged process running as that same user could therefore
 * replace the exe, or drop its own `wintun.dll` next to it, and get its code
 * executed with administrator rights on the next connect. Same class for the
 * traffic-forensics directory, where we write a `.ps1` and immediately run it
 * elevated (a write→exec TOCTOU window). This is CWE-379 / CWE-732 — precisely
 * what UAC is supposed to prevent.
 *
 * THE FIX. Replace the directory's DACL with a protected one containing only
 * SYSTEM and Administrators, and make Administrators the owner. Two details
 * matter:
 *
 *   1. Protection (`SetAccessRuleProtection($true, $false)`) is what drops the
 *      inherited user grants. Adding admin-only rules on top of an inherited
 *      DACL changes nothing.
 *   2. The owner MUST be changed. An object's owner implicitly holds
 *      READ_CONTROL and WRITE_DAC, so leaving the interactive user as owner
 *      would let them simply rewrite the DACL and grant themselves back write
 *      access. Failing to set the owner is a failed hardening, not a cosmetic
 *      issue.
 *
 * An elevated token of an administrator user has the Administrators group
 * enabled and passes this DACL; the *unelevated* token of the very same user
 * carries that group as deny-only and does not. That asymmetry is the whole
 * point — it is how `%ProgramFiles%` protects itself.
 *
 * This helper returns a verified result rather than deciding policy. Callers
 * that stage or execute privileged code MUST fail closed when `hardened` is
 * false: availability never justifies executing a user-replaceable binary as
 * administrator.
 */

import { stat } from 'fs/promises'
import { execFile as execFileCb } from 'child_process'
import { promisify } from 'util'
import { win32 } from 'path'
import { execElevated, isProcessElevated } from './admin'
import { logEvent } from './appLogger'

const execFile = promisify(execFileCb)

/** Well-known SIDs, used instead of names so localized Windows installs work. */
const SID_SYSTEM = 'S-1-5-18'
const SID_ADMINISTRATORS = 'S-1-5-32-544'

/**
 * Identities allowed to appear in a hardened DACL. Anything else holding a
 * write-ish right means the directory is still attackable.
 */
const ALLOWED_SIDS = new Set([SID_SYSTEM, SID_ADMINISTRATORS])

/**
 * Rights that let a caller plant or alter a binary. Read/Execute/Synchronize
 * are harmless — we do not care who can *read* the runtime directory, only who
 * can write to it or re-permission it.
 */
const DANGEROUS_RIGHTS = [
  'FullControl',
  'Modify',
  'Write',
  'WriteData',
  'CreateFiles',
  'CreateDirectories',
  'AppendData',
  'WriteAttributes',
  'WriteExtendedAttributes',
  'Delete',
  'DeleteSubdirectoriesAndFiles',
  'ChangePermissions',
  'TakeOwnership'
]

const KNOWN_RIGHTS = new Set([...DANGEROUS_RIGHTS,
  'ReadData', 'ListDirectory', 'ReadExtendedAttributes', 'Traverse', 'ExecuteFile',
  'ReadAttributes', 'ReadPermissions', 'Synchronize', 'Read', 'ReadAndExecute'])

export interface DirectoryHardeningResult {
  /** True only when the directory and all existing descendants are trusted. */
  hardened: boolean
  /** True when hardening was skipped because it does not apply (non-Windows). */
  skipped?: boolean
  /** Human-readable reason, always set when `hardened` is false. */
  message: string
  /** Identities that still hold a write-ish right, if any. */
  offenders?: string[]
  /** Current owner SID, when we managed to read it. */
  owner?: string | null
}

function psSingleQuote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`
}

function encodedPowerShell(script: string): string {
  // A host PSModulePath can put PS7 modules before Windows PowerShell 5.1's.
  // Pin ACL cmdlets to this process's builtin manifest, never module discovery.
  const prelude =
    "Import-Module -Name (Join-Path $PSHOME 'Modules\\Microsoft.PowerShell.Security\\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop;" +
    '$OutputEncoding=[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();' +
    '$ProgressPreference="SilentlyContinue";'
  return Buffer.from(prelude + script, 'utf16le').toString('base64')
}

async function runPowerShell(script: string, elevated: boolean, timeout: number): Promise<string> {
  const encoded = encodedPowerShell(script)
  if (elevated) {
    const { stdout } = await execElevated(
      `powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand ${encoded}`,
      { timeout, maxBuffer: 1024 * 1024 * 4 }
    )
    return String(stdout ?? '')
  }
  const { stdout } = await execFile(
    'powershell.exe',
    ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded],
    { windowsHide: true, timeout, encoding: 'utf8', maxBuffer: 1024 * 1024 * 4 }
  )
  return String(stdout ?? '')
}

// AT-01-009: manual, parent-before-child traversal. Neither enumeration nor
// icacls may recursively follow an untrusted junction. Recheck paths before use.
const RUNTIME_TREE_HELPERS = `
function Get-RuntimeItem($path) {
  $components = New-Object 'System.Collections.Generic.Stack[string]'
  $candidate = [IO.Path]::GetFullPath($path)
  while ($candidate) {
    $components.Push($candidate)
    $candidate = [IO.Path]::GetDirectoryName($candidate.TrimEnd([char]92))
  }
  while ($components.Count -gt 0) {
    $item = Get-Item -LiteralPath ($components.Pop()) -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Runtime path is a reparse point' }
    if ($components.Count -gt 0 -and -not $item.PSIsContainer) { throw 'Runtime ancestor is not a directory' }
  }
  return $item
}
function Get-RuntimeChildren($root) {
  $pending = New-Object 'System.Collections.Generic.Stack[string]'
  $pending.Push($root)
  while ($pending.Count -gt 0) {
    $parent = Get-RuntimeItem ($pending.Pop())
    if (-not $parent.PSIsContainer) { throw 'Runtime directory changed type' }
    foreach ($entry in @(Get-ChildItem -LiteralPath $parent.FullName -Force -ErrorAction Stop)) {
      $item = Get-RuntimeItem $entry.FullName
      Write-Output $item
      if ($item.PSIsContainer) { $pending.Push($item.FullName) }
    }
  }
}
`

/** Protect the root, then repair checked children individually. Resetting the
 * root would undo its protected DACL; resetting children alone leaves their
 * old owner with implicit WRITE_DAC, so both owner and ACL must be repaired. */
function buildHardenScript(dir: string): string {
  return `
$ErrorActionPreference = 'Stop'
$dir = ${psSingleQuote(dir)}
${RUNTIME_TREE_HELPERS}
$system = New-Object System.Security.Principal.SecurityIdentifier('${SID_SYSTEM}')
$admins = New-Object System.Security.Principal.SecurityIdentifier('${SID_ADMINISTRATORS}')
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in @($system, $admins)) {
  $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
$acl.SetOwner($admins)
$parent = Get-RuntimeItem ([IO.Path]::GetDirectoryName($dir))
if (-not $parent.PSIsContainer) { throw 'Runtime parent is not a directory' }
try { $null = Get-Item -LiteralPath $dir -Force -ErrorAction Stop }
catch [System.Management.Automation.ItemNotFoundException] {
  $info = New-Object System.IO.DirectoryInfo($dir)
  $info.Create($acl)
}
$root = Get-RuntimeItem $dir
if (-not $root.PSIsContainer) { throw 'Runtime root is not a directory' }
# Reject the entire existing reparse tree before modifying any existing ACL.
$children = @(Get-RuntimeChildren $dir)
$null = Get-RuntimeItem $dir
Set-Acl -LiteralPath $dir -AclObject $acl
foreach ($child in $children) {
  $path = $child.FullName
  $null = Get-RuntimeItem $path
  & icacls $path /setowner '*${SID_ADMINISTRATORS}' /L /Q | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Runtime child owner reset failed' }
  $null = Get-RuntimeItem $path
  & icacls $path /reset /L /Q | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'Runtime child ACL reset failed' }
  $null = Get-RuntimeItem $path
  $childAcl = Get-Acl -LiteralPath $path -ErrorAction Stop
  if ($childAcl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne '${SID_ADMINISTRATORS}') {
    throw 'Runtime child owner readback failed'
  }
  foreach ($rule in $childAcl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -notin @('${SID_SYSTEM}', '${SID_ADMINISTRATORS}') -and
        ([int]$rule.FileSystemRights -band 0x500D0156) -ne 0) { throw 'Runtime child ACL readback failed' }
  }
}
Write-Output 'HARDENED'
`
}

/** One read-only PowerShell call inspects the complete existing tree. A partial
 * traversal, inaccessible child or unknown owner must never produce success. */
function buildInspectScript(dir: string): string {
  return `
$ErrorActionPreference = 'Stop'
$dir = ${psSingleQuote(dir)}
${RUNTIME_TREE_HELPERS}
function Get-RuntimeAcl($path) {
  $item = Get-RuntimeItem $path
  $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
  $after = Get-RuntimeItem $path
  if ([bool]$item.PSIsContainer -ne [bool]$after.PSIsContainer) { throw 'Runtime artifact changed type' }
  $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  $rules = @()
  foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
    $rules += [ordered]@{
      sid = $rule.IdentityReference.Value
      rights = $rule.FileSystemRights.ToString()
      type = $rule.AccessControlType.ToString()
    }
  }
  return [ordered]@{
    path = $item.FullName
    directory = [bool]$item.PSIsContainer
    reparse = $false
    owner = $owner
    protected = $acl.AreAccessRulesProtected
    rules = $rules
  }
}
$root = Get-RuntimeAcl $dir
if (-not $root.directory) { throw 'Runtime root is not a directory' }
$children = @(foreach ($child in @(Get-RuntimeChildren $dir)) { Get-RuntimeAcl $child.FullName })
$root['children'] = $children
$root['childrenInspected'] = $true
$root | ConvertTo-Json -Depth 6 -Compress
`
}

interface AclSnapshot {
  owner: string
  protected: boolean
  directory: boolean
  reparse: boolean
  rules: Array<{ sid: string; rights: string; type: 'Allow' | 'Deny' }>
}
interface RuntimeTreeSnapshot extends AclSnapshot {
  children: Array<AclSnapshot & { path: string }>
}

function parseAcl(value: unknown): AclSnapshot | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  const parsed = value as Record<string, unknown>
  if (typeof parsed.owner !== 'string' || !/^S-\d+(?:-\d+)+$/.test(parsed.owner) ||
      typeof parsed.protected !== 'boolean' || typeof parsed.directory !== 'boolean' || typeof parsed.reparse !== 'boolean') return null
  // Preserve compatibility with single-rule PS snapshots, but never discard a
  // malformed rule or interpret missing/null/empty rules as a safe DACL.
  const rawRules = Array.isArray(parsed.rules) ? parsed.rules : [parsed.rules]
  if (!rawRules.length) return null
  const rules: AclSnapshot['rules'] = []
  for (const raw of rawRules) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null
    const rule = raw as Record<string, unknown>
    if (typeof rule.sid !== 'string' || !/^S-\d+(?:-\d+)+$/.test(rule.sid) ||
        typeof rule.rights !== 'string' || !rule.rights.split(',').every(right => KNOWN_RIGHTS.has(right.trim())) ||
        (rule.type !== 'Allow' && rule.type !== 'Deny')) return null
    rules.push({ sid: rule.sid, rights: rule.rights, type: rule.type })
  }
  return { owner: parsed.owner, protected: parsed.protected, directory: parsed.directory, reparse: parsed.reparse, rules }
}

function parseAclSnapshot(stdout: string): RuntimeTreeSnapshot | null {
  try {
    const parsed = JSON.parse(stdout)
    const root = parseAcl(parsed)
    if (!root || parsed.childrenInspected !== true || !Array.isArray(parsed.children)) return null
    const children: RuntimeTreeSnapshot['children'] = []
    for (const raw of parsed.children) {
      const child = parseAcl(raw)
      if (!child || typeof raw.path !== 'string' || !win32.isAbsolute(raw.path)) return null
      children.push({ ...child, path: raw.path })
    }
    return { ...root, children }
  } catch { return null }
}

function findOffenders(snapshot: AclSnapshot): string[] {
  const offenders = new Set<string>()
  for (const rule of snapshot.rules) {
    if (rule.type !== 'Allow') continue
    if (ALLOWED_SIDS.has(rule.sid)) continue
    const grantsWrite = DANGEROUS_RIGHTS.some(right => rule.rights.includes(right))
    if (grantsWrite) offenders.add(`${rule.sid} (${rule.rights})`)
  }
  // An owner outside the allow-list can rewrite the DACL regardless of the
  // rules above, so it counts as an offender in its own right.
  if (snapshot.owner && !ALLOWED_SIDS.has(snapshot.owner)) {
    offenders.add(`${snapshot.owner} (owner: implicit WRITE_DAC)`)
  }
  return [...offenders]
}

/**
 * Inspect the root and every descendant without changing anything. Child ACLs
 * may inherit from the verified tree, but every owner and write grant is checked.
 * Only the root must be protected against inheritance from outside that tree.
 */
export async function verifyDirectoryHardened(dir: string): Promise<DirectoryHardeningResult> {
  if (process.platform !== 'win32') {
    return { hardened: true, skipped: true, message: 'ACL hardening не применяется (не Windows)' }
  }
  try {
    const stdout = await runPowerShell(buildInspectScript(dir), false, 15000)
    const snapshot = parseAclSnapshot(stdout)
    if (!snapshot || !snapshot.directory || snapshot.reparse || snapshot.children.some(child => child.reparse)) {
      return { hardened: false, message: 'не удалось подтвердить ACL и отсутствие reparse во всём runtime-дереве' }
    }
    const normalize = (path: string) => win32.resolve(path).toLowerCase()
    const root = normalize(dir)
    const paths = new Set([root])
    const directories = new Set([root])
    for (const child of snapshot.children) {
      const path = normalize(child.path)
      const relative = win32.relative(root, path)
      if (!relative || relative === '..' || relative.startsWith('..\\') || win32.isAbsolute(relative) || paths.has(path)) {
        return { hardened: false, message: 'некорректный путь в снимке runtime-дерева' }
      }
      paths.add(path)
      if (child.directory) directories.add(path)
    }
    if (snapshot.children.some(child => !directories.has(normalize(win32.dirname(child.path))))) {
      return { hardened: false, message: 'неполный снимок каталогов runtime-дерева' }
    }
    const offenders = [...findOffenders(snapshot), ...snapshot.children.flatMap(child =>
      findOffenders(child).map(offender => `${child.path}: ${offender}`))]
    if (offenders.length > 0) {
      return {
        hardened: false,
        message: `runtime-дерево доступно на запись не только администраторам: ${offenders.join('; ')}`,
        offenders,
        owner: snapshot.owner
      }
    }
    if (!snapshot.protected) {
      // No offender today, but an inherited DACL means the parent can hand out
      // write access at any time without us noticing.
      return {
        hardened: false,
        message: 'ACL каталога наследуется от родителя и может измениться',
        owner: snapshot.owner
      }
    }
    return { hardened: true, message: 'каталог и его содержимое доступны на запись только администраторам', owner: snapshot.owner }
  } catch (err: any) {
    return { hardened: false, message: `проверка ACL не удалась: ${err?.message || String(err)}` }
  }
}

/**
 * Share an in-flight inspection only. A previous successful inspection cannot
 * authorize a later launch: ACLs and owners can change between connections.
 */
const hardenedDirs = new Map<string, Promise<DirectoryHardeningResult>>()

async function hardenOnce(dir: string, label: string): Promise<DirectoryHardeningResult> {
  if (process.platform !== 'win32') {
    return { hardened: true, skipped: true, message: 'ACL hardening не применяется (не Windows)' }
  }

  // A fresh proof of the entire existing tree can avoid all elevated writes.
  const before = await verifyDirectoryHardened(dir)
  if (before.hardened) {
    logEvent('debug', 'runtime-acl', `${label}: ACL already hardened`, { dir })
    return before
  }

  const elevated = await isProcessElevated()
  if (!elevated) {
    // Without elevation we can neither set an admin-only DACL nor change the
    // owner. Say so plainly rather than pretending we tried.
    logEvent('warn', 'runtime-acl', `${label}: cannot harden ACL without elevation`, {
      dir,
      reason: before.message
    })
    return {
      hardened: false,
      message: `нет прав администратора для ужесточения ACL (${before.message})`,
      offenders: before.offenders,
      owner: before.owner
    }
  }

  try {
    const stdout = await runPowerShell(buildHardenScript(dir), true, 60000)
    if (!stdout.includes('HARDENED')) {
      logEvent('warn', 'runtime-acl', `${label}: hardening script produced no confirmation`, {
        dir,
        stdout: stdout.slice(0, 400)
      })
    }
  } catch (err: any) {
    const message = err?.message || String(err)
    logEvent('error', 'runtime-acl', `${label}: ACL hardening failed`, { dir, error: message })
    return { hardened: false, message: `не удалось ужесточить ACL: ${message}` }
  }

  // Never trust the write: reread the entire tree, including child owners.
  // An exit code or a clean root alone cannot authorize privileged execution.
  const after = await verifyDirectoryHardened(dir)
  if (after.hardened) {
    logEvent('info', 'runtime-acl', `${label}: ACL hardened to admin-only`, { dir, owner: after.owner ?? null })
  } else {
    logEvent('error', 'runtime-acl', `${label}: ACL still not admin-only after hardening`, {
      dir,
      reason: after.message,
      offenders: after.offenders ?? []
    })
  }
  return after
}

/**
 * Make `dir` writable only by SYSTEM and Administrators, creating it if needed.
 * Idempotent, with fresh read-back on every connect.
 *
 * Call this BEFORE staging anything executable into the directory — otherwise
 * there is a window where an attacker's file is already in place.
 */
export async function ensureElevatedRuntimeDirHardened(
  dir: string,
  label: string
): Promise<DirectoryHardeningResult> {
  const key = dir.toLowerCase()
  const cached = hardenedDirs.get(key)
  if (cached) return cached
  const attempt = hardenOnce(dir, label)
  hardenedDirs.set(key, attempt)
  try { return await attempt }
  finally { if (hardenedDirs.get(key) === attempt) hardenedDirs.delete(key) }
}

/** Test seam: drop the memo so a suite can exercise the retry path. */
export function resetRuntimeDirHardeningCache(): void {
  hardenedDirs.clear()
}

/**
 * True when `path` exists and is a directory. Used by callers that want to skip
 * hardening for a path that was never created.
 */
export async function directoryExists(path: string): Promise<boolean> {
  try {
    return (await stat(path)).isDirectory()
  } catch {
    return false
  }
}
