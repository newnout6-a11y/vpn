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
 * Everything here is best-effort by design: a directory we cannot lock down is
 * a serious warning, but refusing to bring up the tunnel over it would leave
 * the user with no VPN at all, which is worse. Callers log the warning and
 * continue; `verifyDirectoryHardened` lets diagnostics report the real state.
 */

import { stat } from 'fs/promises'
import { execFile as execFileCb } from 'child_process'
import { promisify } from 'util'
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

export interface DirectoryHardeningResult {
  /** True only when the directory is confirmed admin-only afterwards. */
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
  const prelude =
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

/**
 * Build the exact DACL we want and stamp it onto the directory, then let every
 * existing child inherit it (`icacls /reset /T` replaces child ACLs with the
 * ones inherited from the now-protected parent).
 *
 * `-LiteralPath` throughout: runtime paths contain spaces and may contain
 * brackets, which PowerShell would otherwise treat as wildcards.
 */
function buildHardenScript(dir: string): string {
  const quoted = psSingleQuote(dir)
  return `
$ErrorActionPreference = 'Stop'
$dir = ${quoted}
if (-not (Test-Path -LiteralPath $dir -PathType Container)) {
  New-Item -ItemType Directory -Path $dir -Force | Out-Null
}
$system = New-Object System.Security.Principal.SecurityIdentifier('${SID_SYSTEM}')
$admins = New-Object System.Security.Principal.SecurityIdentifier('${SID_ADMINISTRATORS}')
$acl = New-Object System.Security.AccessControl.DirectorySecurity
# $true = protect from inheritance, $false = do NOT copy the inherited rules in.
$acl.SetAccessRuleProtection($true, $false)
foreach ($sid in @($system, $admins)) {
  $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
    $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
}
# The owner implicitly holds WRITE_DAC. Leaving the interactive user as owner
# would let them undo everything above, so this is load-bearing.
$acl.SetOwner($admins)
Set-Acl -LiteralPath $dir -AclObject $acl
# Existing children keep their own explicit ACEs unless we reset them.
& icacls $dir /reset /T /C /Q | Out-Null
Write-Output 'HARDENED'
`
}

/**
 * Read the DACL back and report anyone outside the allow-list who can write.
 * Reading an ACL needs no elevation, so diagnostics can call this freely.
 */
function buildInspectScript(dir: string): string {
  return `
$ErrorActionPreference = 'Stop'
$dir = ${psSingleQuote(dir)}
$acl = Get-Acl -LiteralPath $dir
$owner = try { $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value } catch { $null }
$rules = @()
foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
  $rules += [ordered]@{
    sid = $rule.IdentityReference.Value
    rights = $rule.FileSystemRights.ToString()
    type = $rule.AccessControlType.ToString()
  }
}
[ordered]@{
  owner = $owner
  protected = $acl.AreAccessRulesProtected
  rules = $rules
} | ConvertTo-Json -Depth 4 -Compress
`
}

interface AclSnapshot {
  owner: string | null
  protected: boolean
  rules: Array<{ sid: string; rights: string; type: string }>
}

function parseAclSnapshot(stdout: string): AclSnapshot | null {
  const text = stdout.trim()
  if (!text) return null
  try {
    const parsed = JSON.parse(text)
    // ConvertTo-Json emits a bare object for one rule and an array for many.
    const rawRules = parsed?.rules
    const rules = Array.isArray(rawRules) ? rawRules : rawRules ? [rawRules] : []
    return {
      owner: typeof parsed?.owner === 'string' ? parsed.owner : null,
      protected: parsed?.protected === true,
      rules: rules
        .filter((r: any) => r && typeof r.sid === 'string')
        .map((r: any) => ({
          sid: String(r.sid),
          rights: String(r.rights ?? ''),
          type: String(r.type ?? '')
        }))
    }
  } catch {
    return null
  }
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
 * Inspect a directory's DACL without changing anything. Returns `hardened:
 * true` only when the DACL is protected, admin-owned, and grants no write-ish
 * right to anyone outside SYSTEM/Administrators.
 */
export async function verifyDirectoryHardened(dir: string): Promise<DirectoryHardeningResult> {
  if (process.platform !== 'win32') {
    return { hardened: true, skipped: true, message: 'ACL hardening не применяется (не Windows)' }
  }
  try {
    const stdout = await runPowerShell(buildInspectScript(dir), false, 15000)
    const snapshot = parseAclSnapshot(stdout)
    if (!snapshot) {
      return { hardened: false, message: 'не удалось прочитать ACL каталога' }
    }
    const offenders = findOffenders(snapshot)
    if (offenders.length > 0) {
      return {
        hardened: false,
        message: `каталог доступен на запись не только администраторам: ${offenders.join('; ')}`,
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
    return { hardened: true, message: 'каталог доступен на запись только администраторам', owner: snapshot.owner }
  } catch (err: any) {
    return { hardened: false, message: `проверка ACL не удалась: ${err?.message || String(err)}` }
  }
}

/**
 * Per-directory memo. Hardening costs an elevated PowerShell round-trip
 * (~300-800ms) and the result cannot change under us while we hold the only
 * write access, so once per process is enough. A FAILED attempt is not cached:
 * the next connect retries, which matters when the first failure was transient
 * (a file locked by a still-exiting sing-box, for instance).
 */
const hardenedDirs = new Map<string, Promise<DirectoryHardeningResult>>()

async function hardenOnce(dir: string, label: string): Promise<DirectoryHardeningResult> {
  if (process.platform !== 'win32') {
    return { hardened: true, skipped: true, message: 'ACL hardening не применяется (не Windows)' }
  }

  // Already correct (e.g. hardened by a previous run) — nothing to do. This is
  // the common case on every connect after the first.
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

  // Never trust the write — read the DACL back. A script that "succeeded" but
  // left the user with Modify is the failure mode that matters here.
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
 * Idempotent, memoized per process, and safe to call on every connect.
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
  if (cached) {
    const result = await cached
    if (result.hardened || result.skipped) return result
    // Previous attempt failed — fall through and retry.
  }
  const attempt = hardenOnce(dir, label)
  hardenedDirs.set(key, attempt)
  const result = await attempt
  if (!result.hardened && !result.skipped) hardenedDirs.delete(key)
  return result
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
