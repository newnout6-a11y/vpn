import { app } from 'electron'
import { mkdir, readFile, writeFile, unlink, stat, rename } from 'fs/promises'
import { join } from 'path'
import { execFile as execFileCb } from 'child_process'
import { isIP } from 'net'
import { promisify } from 'util'
import { execElevated } from './admin'
import { execElevatedPs, isElevatedPsHelperRunning } from './elevatedPsHelper'
import { logEvent } from './appLogger'
import { TUN_ADAPTER_ALIAS, TUN_IPV4_NETWORK_CIDR } from './tunAdapter'

const execFile = promisify(execFileCb)

// Rule-name prefix for every firewall rule we add. We rely on this prefix to
// find and remove our rules during rollback, even if our manifest is missing
// (e.g. user wiped %APPDATA% manually after a crash).
const RULE_PREFIX = 'VPNTE-killswitch'
const EXTERNAL_PROXY_RUNTIME_EXE_NAME = 'vpnte-external-proxy.exe'

// Exported for combinedPreStartProbe in connectionPlanner.ts so it can build
// the firewall rule query without spawning a separate PowerShell process.
export const KILL_SWITCH_RULE_PREFIX = RULE_PREFIX

// Outbound traffic that must keep flowing while the kill-switch is engaged so
// the box stays usable but can never reach the public internet by accident.
// Localhost — sing-box ↔ Happ proxy on 127.0.0.1 lives here.
// RFC1918 + link-local + multicast + IPv6 ULA — printers, NAS, mDNS, router admin UI.
const LAN_BYPASS_CIDRS = [
  '127.0.0.0/8',
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '169.254.0.0/16',
  '224.0.0.0/4',
  '::1/128',
  'fc00::/7',
  'fe80::/10',
  'ff00::/8'
]

export interface FirewallKillSwitchResult {
  success: boolean
  message: string
  details?: string
  // True iff the call was a no-op because there was nothing to do (kill-switch
  // already inactive). The renderer uses this to suppress the noisy
  // "Kill-switch снят вручную" warn log that fired every stop because main
  // had already auto-disabled before the user-driven IPC arrived.
  skipped?: boolean
}

interface SavedProfile {
  name: string
  defaultOutbound: string
}

interface FirewallManifest {
  createdAt: number
  ruleNames: string[]
  singboxExePath: string | null
  savedProfiles: SavedProfile[]
}

function backupDir() {
  return join(app.getPath('userData'), 'firewall-killswitch')
}

function manifestPath() {
  return join(backupDir(), 'manifest.json')
}

async function readManifest(): Promise<FirewallManifest | null> {
  try {
    const raw = await readFile(manifestPath(), 'utf-8')
    return JSON.parse(raw) as FirewallManifest
  } catch (err: any) {
    if (err?.code === 'ENOENT') {
      // File doesn't exist — normal state, no manifest = no active kill-switch
      return null
    }
    // File exists but is corrupt (partial write during crash). Log it —
    // this is important because a corrupt manifest means the kill-switch
    // may actually be active but we can't read its state. The caller
    // falls through to probeFirewallForOurRules() as a safety net.
    logEvent('warn', 'firewall-killswitch', 'manifest file is corrupt — treating as no manifest', {
      error: err?.message || String(err)
    })
    return null
  }
}

// Exported for combinedPreStartProbe: a file-read-only check that determines
// whether the firewall rule probe should be included in the combined PS script.
export async function killSwitchManifestExists(): Promise<boolean> {
  return (await readManifest()) !== null
}

async function writeManifest(m: FirewallManifest): Promise<void> {
  await mkdir(backupDir(), { recursive: true })
  const tmp = manifestPath() + '.tmp'
  await writeFile(tmp, JSON.stringify(m, null, 2), 'utf-8')
  await rename(tmp, manifestPath())
}

async function clearManifest(): Promise<void> {
  try {
    await unlink(manifestPath())
  } catch {
    // already gone
  }
}

function withPowerShellPrelude(script: string) {
  const prelude =
    '$OutputEncoding=[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new();' +
    '[Console]::InputEncoding=[System.Text.UTF8Encoding]::new();' +
    '$ProgressPreference="SilentlyContinue";' +
    '$ErrorActionPreference="Stop";'
  return prelude + script
}

function cmdDoubleQuote(value: string): string {
  return `"${value.replace(/"/g, '\\"')}"`
}

async function ps(script: string, elevated = false, timeout = 30000) {
  // Keep elevated scripts under userData instead of %TEMP% and do not remove them
  // immediately: sudo-prompt can return before the elevated PowerShell has opened
  // the -File path, which made PowerShell report "argument for -File does not exist".
  const scriptDir = join(backupDir(), 'ps')
  await mkdir(scriptDir, { recursive: true })
  const scriptPath = join(
    scriptDir,
    `script-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}.ps1`
  )
  await writeFile(scriptPath, '\ufeff' + withPowerShellPrelude(script), 'utf8')

  try {
    if (elevated) {
      // Use persistent PS helper if available — avoids 300-800ms
      // powershell.exe startup overhead per call.
      if (isElevatedPsHelperRunning()) {
        try {
          const result = await execElevatedPs(script, timeout, 'firewall-killswitch')
          return { stdout: result.stdout, stderr: result.stderr }
        } catch (err: any) {
          // PS helper failed — fall back to execElevated
        }
      }
      const command = `powershell -NoProfile -ExecutionPolicy Bypass -File ${cmdDoubleQuote(scriptPath)}`
      return execElevated(command, { timeout, maxBuffer: 1024 * 1024 * 4 })
    }
    const result = await execFile(
      'powershell',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', scriptPath],
      {
        windowsHide: true,
        timeout,
        maxBuffer: 1024 * 1024 * 4,
        encoding: 'utf8'
      }
    ) as { stdout: string; stderr: string }
    return {
      stdout: String(result.stdout ?? ''),
      stderr: String(result.stderr ?? '')
    }
  } finally {
    if (!elevated) {
      await unlink(scriptPath).catch(() => undefined)
    } else {
      // Elevated scripts can't be unlinked synchronously (sudo-prompt may not
      // have opened the -File yet on return), so we leave THIS run's file and
      // instead sweep older ones. Without this, every enable/disable/probe
      // leaves a .ps1 behind forever — a slow disk leak that also keeps adapter
      // aliases on disk. Delete elevated scripts older than 60s; the in-flight
      // one is always newer than that.
      void sweepStaleElevatedScripts(scriptDir, scriptPath).catch(() => undefined)
    }
  }
}

// Remove leftover elevated .ps1 files older than 60 seconds. The currently
// running script (`keepPath`) and anything fresh enough to still be in use by
// a concurrent elevated call are preserved.
async function sweepStaleElevatedScripts(scriptDir: string, keepPath: string): Promise<void> {
  const { readdir } = await import('fs/promises')
  let entries: string[]
  try {
    entries = await readdir(scriptDir)
  } catch {
    return
  }
  const now = Date.now()
  await Promise.all(
    entries
      .filter((name) => name.endsWith('.ps1'))
      .map(async (name) => {
        const full = join(scriptDir, name)
        if (full === keepPath) return
        try {
          const st = await stat(full)
          if (now - st.mtimeMs > 60_000) {
            await unlink(full).catch(() => undefined)
          }
        } catch {
          // stat failed (file already gone / locked) — skip.
        }
      })
  )
}

function psSingleQuote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`
}

function externalProxyProgramPath(): string {
  return join(app.getPath('userData'), 'external-proxy-runtime', EXTERNAL_PROXY_RUNTIME_EXE_NAME)
}

function stableRuleSuffix(value: string): string {
  return String(value || 'program').replace(/[^a-z0-9_-]/gi, '-').slice(0, 48) || 'program'
}

/**
 * Validate a user-supplied IP/CIDR exception before it is interpolated into a
 * New-NetFirewallRule -RemoteAddress argument. We accept:
 *   - IPv4 (optionally /0-32):     203.0.113.4   203.0.113.0/24
 *   - IPv6 (optionally /0-128):    2001:db8::1   2001:db8::/32
 * Anything else (hostnames, ranges, garbage, injection attempts) is rejected.
 * This is a allow-list gate — the addresses come from the granular kill-switch
 * exception UI which is user-editable.
 */
export function isValidIpOrCidr(value: string): boolean {
  const v = String(value || '').trim()
  if (!v) return false
  const [addr, prefix, ...rest] = v.split('/')
  if (rest.length > 0) return false

  const ipVersion = isIP(addr)
  if (ipVersion === 4) {
    if (addr === '0.0.0.0') return false
    if (prefix !== undefined) {
      const p = Number(prefix)
      if (!Number.isInteger(p) || p < 1 || p > 32) return false
    }
    return true
  }

  if (ipVersion === 6) {
    if (addr === '::') return false
    if (prefix !== undefined) {
      const p = Number(prefix)
      if (!Number.isInteger(p) || p < 1 || p > 128) return false
    }
    return true
  }

  return false
}

export async function isKillSwitchActive(): Promise<boolean> {
  return (await readManifest()) !== null || await probeFirewallForOurRules()
}

export async function ensureKillSwitchProgramAllowed(
  programPath: string,
  ruleSuffix = 'program',
  description = 'VPN Tunnel Enforcer kill-switch: allow managed helper outbound.'
): Promise<FirewallKillSwitchResult> {
  if (process.platform !== 'win32') {
    return { success: true, skipped: true, message: 'Firewall kill-switch недоступен (не Windows)' }
  }
  const trimmed = String(programPath || '').trim()
  if (!trimmed) {
    return { success: false, message: 'Kill-switch allow rule: program path is empty' }
  }
  if (!(await isKillSwitchActive())) {
    return { success: true, skipped: true, message: 'Kill-switch inactive' }
  }

  const ruleName = `${RULE_PREFIX}-allow-${stableRuleSuffix(ruleSuffix)}`
  const script = `
$ruleName = ${psSingleQuote(ruleName)}
$program = ${psSingleQuote(trimmed)}
Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue |
  Remove-NetFirewallRule -ErrorAction SilentlyContinue
New-NetFirewallRule \`
  -DisplayName $ruleName \`
  -Description ${psSingleQuote(description)} \`
  -Direction Outbound -Action Allow \`
  -Program $program \`
  -Profile Any -Enabled True | Out-Null
Write-Output "RULE:$ruleName"
`

  try {
    await ps(script, true, 30000)
    logEvent('info', 'firewall-killswitch', 'program allow rule ensured', { ruleName, programPath: trimmed })
    return { success: true, message: `Kill-switch allow rule ensured: ${ruleName}` }
  } catch (err: any) {
    logEvent('warn', 'firewall-killswitch', 'failed to ensure program allow rule', {
      ruleName,
      programPath: trimmed,
      error: err?.message || String(err)
    })
    return {
      success: false,
      message: `Не удалось разрешить ${trimmed} в kill-switch`,
      details: err?.stderr || err?.message || String(err)
    }
  }
}

/**
 * Install Windows Firewall kill-switch using the DefaultOutboundAction strategy.
 *
 * Previous approach (Block by InterfaceAlias) failed because Windows Firewall
 * Block rules always win over Allow rules at the same specificity — the block
 * on the physical adapter also blocked sing-box.exe itself.
 *
 * New approach:
 *  1. Save the current DefaultOutboundAction for each profile (Domain/Private/Public).
 *  2. Add Allow rules for: sing-box.exe, proxy owner processes, VPNTE-TUN,
 *     LAN CIDRs, TUN subnet.
 *  3. Set DefaultOutboundAction=Block for all profiles.
 *
 * With DefaultOutboundAction=Block, ONLY explicitly allowed programs/destinations
 * can send outbound traffic. Program-based Allow rules correctly override the
 * default Block (unlike explicit Block rules which always win).
 *
 * Safety: Allow rules are created BEFORE setting the default to Block, so if
 * the script fails partway, only harmless extra Allow rules remain.
 */
export async function enableKillSwitch(opts: {
  singboxExePath: string
  proxyOwnerProgramPaths?: string[]
  extraAllowedRemoteCidrs?: string[]
}): Promise<FirewallKillSwitchResult> {
  if (process.platform !== 'win32') {
    return { success: true, message: 'Firewall kill-switch недоступен (не Windows)' }
  }

  const singboxAllow = `${RULE_PREFIX}-allow-singbox`
  const tunInterfaceAllow = `${RULE_PREFIX}-allow-tun-interface`
  const lanAllow = `${RULE_PREFIX}-allow-lan`
  const tunAllow = `${RULE_PREFIX}-allow-tun`
  const dhcpAllow = `${RULE_PREFIX}-allow-dhcp`
  const extraIpAllow = `${RULE_PREFIX}-allow-extra-ip`

  // Windows Firewall can be picky about mixed IPv4/IPv6 CIDR arrays here. IPv6 is
  // disabled by adapter lockdown anyway, so keep the firewall LAN bypass IPv4-only.
  const lanRemoteAddresses = LAN_BYPASS_CIDRS
    .filter((c) => !c.includes(':'))
    .map((c) => `'${c}'`)
    .join(',')

  // Build proxy process allow rules dynamically
  const proxyPaths = [...new Set([...(opts.proxyOwnerProgramPaths ?? []), externalProxyProgramPath()])]
  const proxyAllowParts: string[] = []
  for (let i = 0; i < proxyPaths.length; i++) {
    const ruleName = `${RULE_PREFIX}-allow-proxy-${i}`
    proxyAllowParts.push(`
try {
  New-NetFirewallRule \`
    -DisplayName ${psSingleQuote(ruleName)} \`
    -Description 'VPN Tunnel Enforcer kill-switch: allow upstream proxy process outbound.' \`
    -Direction Outbound -Action Allow \`
    -Program ${psSingleQuote(proxyPaths[i])} \`
    -Profile Any -Enabled True | Out-Null
  $rules += ${psSingleQuote(ruleName)}
} catch { Write-Output "WARN allow-proxy-${i}: $_" }`)
  }

  // User-defined IP/CIDR exceptions (from the granular kill-switch UI). These
  // were previously collected but never applied — the address stayed blocked.
  // We validate each entry as an IPv4/IPv6 address or CIDR before letting it
  // anywhere near New-NetFirewallRule (defence against injection through the
  // exception list). Anything that doesn't look like an address is dropped.
  const extraCidrs = (opts.extraAllowedRemoteCidrs ?? []).filter(isValidIpOrCidr)
  let extraIpAllowPart = ''
  if (extraCidrs.length > 0) {
    const addressList = extraCidrs.map((c) => `'${c}'`).join(',')
    extraIpAllowPart = `
try {
  New-NetFirewallRule \`
    -DisplayName ${psSingleQuote(extraIpAllow)} \`
    -Description 'VPN Tunnel Enforcer kill-switch: allow user-defined IP/CIDR exceptions.' \`
    -Direction Outbound -Action Allow \`
    -RemoteAddress ${addressList} \`
    -Profile Any -Enabled True | Out-Null
  $rules += ${psSingleQuote(extraIpAllow)}
} catch { Write-Output "WARN allow-extra-ip: $_" }`
  }

  // One atomic elevated PowerShell script: save defaults → add allows → set block.
  const script = `
# --- Step 1: Save current DefaultOutboundAction ---
$profileNames = @('Domain','Private','Public')
$saved = @()
foreach ($pn in $profileNames) {
  $prof = Get-NetFirewallProfile -Profile $pn
  $saved += @{ name = $pn; defaultOutbound = $prof.DefaultOutboundAction.ToString() }
}
$savedJson = ($saved | ConvertTo-Json -Compress)

# --- Step 2: Clean stale rules ---
Get-NetFirewallRule -DisplayName '${RULE_PREFIX}*' -ErrorAction SilentlyContinue |
  Remove-NetFirewallRule -ErrorAction SilentlyContinue

$rules = @()

# --- Step 3: Add Allow rules (BEFORE setting Block default) ---

# 3a. Allow the TUN runtime (sing-box.exe) outbound.
try {
  New-NetFirewallRule \`
    -DisplayName ${psSingleQuote(singboxAllow)} \`
    -Description 'VPN Tunnel Enforcer kill-switch: allow VPNTE sing-box outbound.' \`
    -Direction Outbound -Action Allow \`
    -Program ${psSingleQuote(opts.singboxExePath)} \`
    -Profile Any -Enabled True | Out-Null
  $rules += ${psSingleQuote(singboxAllow)}
} catch { Write-Output "WARN allow-singbox: $_" }

# 3b. Allow proxy owner processes (Happ xray.exe, etc.)
${proxyAllowParts.join('\n')}

# 3c. Allow all captured app traffic on VPNTE-TUN. Without this, the global
# DefaultOutboundAction=Block blocks the browser before Windows can route the
# packet into the TUN, which looks like "internet is blocked" even though
# sing-box itself is allowed.
# The -InterfaceAlias rule requires the TUN adapter to exist. We poll for it
# here (up to ~15s) so the entire kill-switch script can be kicked off in
# parallel with the JS-side waitForTunInterface, saving ~2-3s of sequential
# waiting. If the adapter never appears, we skip this rule rather than
# blocking the whole script.
$tunAliasFound = $false
for ($i = 0; $i -lt 150; $i++) {
  $a = Get-NetAdapter -Name '${TUN_ADAPTER_ALIAS}' -ErrorAction SilentlyContinue
  if ($a -and $a.Status -eq 'Up') { $tunAliasFound = $true; break }
  Start-Sleep -Milliseconds 100
}
if ($tunAliasFound) {
  try {
    New-NetFirewallRule \`
      -DisplayName ${psSingleQuote(tunInterfaceAllow)} \`
      -Description 'VPN Tunnel Enforcer kill-switch: allow captured app traffic through ${TUN_ADAPTER_ALIAS}.' \`
      -Direction Outbound -Action Allow \`
      -InterfaceAlias '${TUN_ADAPTER_ALIAS}' \`
      -Profile Any -Enabled True | Out-Null
    $rules += ${psSingleQuote(tunInterfaceAllow)}
  } catch { Write-Output "WARN allow-tun-interface: $_" }
} else {
  Write-Output "WARN allow-tun-interface: adapter not found after 15s"
}

# 3d. Allow IPv4 LAN ranges outbound (printers, NAS, router, mDNS).
try {
  New-NetFirewallRule \`
    -DisplayName ${psSingleQuote(lanAllow)} \`
    -Description 'VPN Tunnel Enforcer kill-switch: allow private-LAN destinations.' \`
    -Direction Outbound -Action Allow \`
    -RemoteAddress ${lanRemoteAddresses} \`
    -Profile Any -Enabled True | Out-Null
  $rules += ${psSingleQuote(lanAllow)}
} catch { Write-Output "WARN allow-lan: $_" }

# 3e. Allow TUN subnet (${TUN_IPV4_NETWORK_CIDR}) so sing-box TUN traffic works.
try {
  New-NetFirewallRule \`
    -DisplayName ${psSingleQuote(tunAllow)} \`
    -Description 'VPN Tunnel Enforcer kill-switch: allow TUN subnet.' \`
    -Direction Outbound -Action Allow \`
    -RemoteAddress '${TUN_IPV4_NETWORK_CIDR}' \`
    -Profile Any -Enabled True | Out-Null
  $rules += ${psSingleQuote(tunAllow)}
} catch { Write-Output "WARN allow-tun: $_" }

# 3f. Allow DHCP (UDP 67/68) so Wi-Fi lease renewal works.
try {
  New-NetFirewallRule \`
    -DisplayName ${psSingleQuote(dhcpAllow)} \`
    -Description 'VPN Tunnel Enforcer kill-switch: allow DHCP.' \`
    -Direction Outbound -Action Allow \`
    -Protocol UDP -RemotePort 67,68 \`
    -Profile Any -Enabled True | Out-Null
  $rules += ${psSingleQuote(dhcpAllow)}
} catch { Write-Output "WARN allow-dhcp: $_" }

# 3g. Allow user-defined IP/CIDR exceptions (granular kill-switch UI).
${extraIpAllowPart}

# --- Step 4: Set DefaultOutboundAction=Block ---
# Only set Block if the required allow-list core exists. A single optional
# Allow rule is not enough: with DefaultOutboundAction=Block, missing sing-box
# or TUN-interface allows can wedge all app traffic until recovery runs.
$requiredRules = @(
  ${psSingleQuote(singboxAllow)},
  ${psSingleQuote(tunInterfaceAllow)},
  ${psSingleQuote(lanAllow)},
  ${psSingleQuote(tunAllow)},
  ${psSingleQuote(dhcpAllow)}
)
$missingRequired = @($requiredRules | Where-Object { $rules -notcontains $_ })
if ($missingRequired.Count -gt 0) {
  Write-Output ("FATAL: missing required allow rules before Block: " + ($missingRequired -join ','))
  Get-NetFirewallRule -DisplayName '${RULE_PREFIX}*' -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue
  throw ("Missing required allow rules before DefaultOutboundAction=Block: " + ($missingRequired -join ','))
}
try {
  Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block
} catch {
  Write-Output "FATAL set-block: $_"
  # Rollback: remove rules we just added
  Get-NetFirewallRule -DisplayName '${RULE_PREFIX}*' -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue
  throw
}

# Output: JSON with rules + saved profiles
$rulesCsv = ($rules -join ',')
Write-Output "RULES:$rulesCsv"
Write-Output "SAVED:$savedJson"
`

  let installedRules: string[] = []
  let savedProfiles: SavedProfile[] = []
  try {
    const { stdout } = await ps(script, true, 60000)
    const output = String(stdout || '')
    const lines = output.split('\n').map((l) => l.trim())

    const rulesLine = lines.find((l) => l.startsWith('RULES:'))
    if (rulesLine) {
      installedRules = rulesLine
        .slice(6)
        .split(',')
        .map((n) => n.trim())
        .filter((n) => n.startsWith(RULE_PREFIX))
    }

    const savedLine = lines.find((l) => l.startsWith('SAVED:'))
    if (savedLine) {
      try {
        const parsed = JSON.parse(savedLine.slice(5))
        savedProfiles = Array.isArray(parsed)
          ? parsed.map((p: any) => ({ name: String(p.name), defaultOutbound: String(p.defaultOutbound) }))
          : []
      } catch {
        savedProfiles = [
          { name: 'Domain', defaultOutbound: 'Allow' },
          { name: 'Private', defaultOutbound: 'Allow' },
          { name: 'Public', defaultOutbound: 'Allow' }
        ]
      }
    }
  } catch (err: any) {
    logEvent('error', 'firewall-killswitch', 'failed to install kill-switch', err)
    return {
      success: false,
      message: 'Не удалось установить kill-switch (DefaultOutboundAction)',
      details: err?.stderr || err?.message || String(err)
    }
  }

  if (installedRules.length === 0) {
    return {
      success: false,
      message: 'Kill-switch: ни одно Allow-правило не создалось'
    }
  }

  await writeManifest({
    createdAt: Date.now(),
    ruleNames: installedRules,
    singboxExePath: opts.singboxExePath,
    savedProfiles
  })

  logEvent('info', 'firewall-killswitch', 'kill-switch engaged (DefaultOutboundAction=Block)', {
    ruleNames: installedRules,
    savedProfiles
  })
  return {
    success: true,
    message: `Firewall kill-switch активирован (правил: ${installedRules.length}, DefaultOutbound=Block)`
  }
}

/**
 * Restore DefaultOutboundAction to saved values and remove all our rules.
 * Order: restore defaults FIRST (so traffic flows), then remove allow rules.
 */
async function restoreAndCleanup(): Promise<void> {
  const manifest = await readManifest()

  // Build restore script. Even if manifest is missing, try to set defaults
  // back to Allow and remove any stale rules.
  const profiles = manifest?.savedProfiles ?? [
    { name: 'Domain', defaultOutbound: 'Allow' },
    { name: 'Private', defaultOutbound: 'Allow' },
    { name: 'Public', defaultOutbound: 'Allow' }
  ]

  const restoreLines = profiles.map(
    (p) => `Set-NetFirewallProfile -Profile '${p.name}' -DefaultOutboundAction ${p.defaultOutbound} -ErrorAction SilentlyContinue`
  )

  await ps(
    restoreLines.join('\n') + '\n' +
    `Get-NetFirewallRule -DisplayName '${RULE_PREFIX}*' -ErrorAction SilentlyContinue | ` +
      `Remove-NetFirewallRule -ErrorAction SilentlyContinue`,
    true,
    30000
  )
}

export async function disableKillSwitch(reason: string): Promise<FirewallKillSwitchResult> {
  if (process.platform !== 'win32') {
    return { success: true, message: 'Firewall kill-switch недоступен (не Windows)' }
  }

  try {
    await restoreAndCleanup()
  } catch (err: any) {
    logEvent('warn', 'firewall-killswitch', 'failed to fully restore kill-switch', err)
    return {
      success: false,
      message: 'Часть правил kill-switch не снялась — проверьте Windows Firewall вручную',
      details: err?.stderr || err?.message || String(err)
    }
  }

  await clearManifest()
  logEvent('info', 'firewall-killswitch', `kill-switch disengaged: ${reason}`)
  return { success: true, message: 'Firewall kill-switch снят' }
}

/**
 * Idempotent disable. Safe to call multiple times. No-op if kill-switch is not
 * currently active.
 */
export async function disableKillSwitchIfActive(
  reason: string
): Promise<FirewallKillSwitchResult> {
  if (process.platform !== 'win32') {
    return { success: true, skipped: true, message: 'Firewall kill-switch недоступен (не Windows)' }
  }
  if (!(await isKillSwitchActive())) {
    // This path is hit on every stop-tun: tunController.stop() calls us
    // BEFORE the renderer's own disable-IPC arrives. Logging at `warn` made
    // the user think something went wrong every time. It didn't — the
    // kill-switch is just already gone.
    logEvent('debug', 'firewall-killswitch', 'kill-switch already inactive — skip', { reason })
    return { success: true, skipped: true, message: 'Kill-switch already inactive' }
  }
  logEvent('info', 'firewall-killswitch', `auto-disable kill-switch: ${reason}`)
  return disableKillSwitch(reason)
}

async function probeForStuckBlockDefault(): Promise<boolean> {
  if (process.platform !== 'win32') return false
  try {
    const { stdout } = await ps(
      `(Get-NetFirewallProfile -Profile Domain,Private,Public -ErrorAction SilentlyContinue | Where-Object { $_.DefaultOutboundAction -eq 'Block' } | Measure-Object).Count`,
      false,
      15000
    )
    const count = parseInt(String(stdout || '0').trim(), 10)
    return Number.isFinite(count) && count > 0
  } catch {
    return false
  }
}

async function probeFirewallForOurRules(): Promise<boolean> {
  if (process.platform !== 'win32') return false
  try {
    const { stdout } = await ps(
      `(Get-NetFirewallRule -DisplayName '${RULE_PREFIX}*' -ErrorAction SilentlyContinue | Measure-Object).Count`,
      false,
      15000
    )
    const count = parseInt(String(stdout || '0').trim(), 10)
    return Number.isFinite(count) && count > 0
  } catch {
    return false
  }
}

/**
 * Crash recovery: if a previous session left kill-switch rules behind but
 * sing-box is no longer running, the user is locked out of the internet for
 * no good reason. Restore defaults and snip the rules on next startup.
 *
 * We check BOTH our manifest AND a direct probe of Windows Firewall, because
 * the app could have crashed between rule installation and manifest write,
 * leaving rules in place with no manifest to recover from.
 */
export async function recoverStaleKillSwitch(isSingboxRunning: () => Promise<boolean>): Promise<void> {
  if (process.platform !== 'win32') return
  const manifest = await readManifest()
  const manifestSaysActive = manifest !== null
  const firewallSaysActive = manifestSaysActive || await probeFirewallForOurRules()
  const stuckBlockDefault = !manifestSaysActive && !firewallSaysActive && await probeForStuckBlockDefault()
  if (!manifestSaysActive && !firewallSaysActive && !stuckBlockDefault) return
  if (await isSingboxRunning()) {
    logEvent(
      'info',
      'firewall-killswitch',
      'kill-switch rules found and sing-box is still running — keeping kill-switch',
      { manifestSaysActive, firewallSaysActive, stuckBlockDefault }
    )
    return
  }
  logEvent(
    'warn',
    'firewall-killswitch',
    'stale kill-switch detected on startup (sing-box not running) — clearing',
    { manifestSaysActive, firewallSaysActive, stuckBlockDefault }
  )
  await disableKillSwitch('crash recovery on startup').catch((err) =>
    logEvent('warn', 'firewall-killswitch', 'crash-recovery disable failed', err)
  )
  if (stuckBlockDefault) {
    logEvent('warn', 'firewall-killswitch', 'restoring DefaultOutboundAction to Allow — was stuck on Block with no rules')
    try {
      await ps(
        `Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Allow -ErrorAction SilentlyContinue`,
        true,
        15000
      )
    } catch (err) {
      logEvent('error', 'firewall-killswitch', 'failed to restore DefaultOutboundAction after stuck Block', err)
    }
  }
}

export interface FirewallRepairHealth {
  platform: 'win32' | 'other'
  protectedTunnelActive?: boolean
  manifestPresent: boolean
  ourRuleCount: number
  stuckBlockDefault: boolean
  services: Array<{ name: string; status: string }>
  profiles: Array<{ name: string; enabled: string; defaultInbound: string; defaultOutbound: string }>
  summary: 'ok' | 'warn' | 'fail'
  message: string
  recommendedActions: string[]
}

export async function getFirewallRepairHealth(
  options: { protectedTunnelActive?: boolean } = {}
): Promise<FirewallRepairHealth> {
  if (process.platform !== 'win32') {
    return {
      platform: 'other',
      protectedTunnelActive: options.protectedTunnelActive === true,
      manifestPresent: false,
      ourRuleCount: 0,
      stuckBlockDefault: false,
      services: [],
      profiles: [],
      summary: 'ok',
      message: 'Windows Firewall checks are not available on this platform',
      recommendedActions: []
    }
  }

  const protectedTunnelActive = options.protectedTunnelActive === true
  const manifestPresent = await killSwitchManifestExists()
  const stuckBlockDefault = await probeForStuckBlockDefault()
  let ourRuleCount = 0
  let services: FirewallRepairHealth['services'] = []
  let profiles: FirewallRepairHealth['profiles'] = []

  try {
    const { stdout } = await ps(`
$rules = (Get-NetFirewallRule -DisplayName '${RULE_PREFIX}*' -ErrorAction SilentlyContinue | Measure-Object).Count
$services = @(Get-Service -Name BFE,MpsSvc -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{ name = [string]$_.Name; status = [string]$_.Status }
})
$profiles = @(Get-NetFirewallProfile -Profile Domain,Private,Public -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{
    name = [string]$_.Name
    enabled = [string]$_.Enabled
    defaultInbound = [string]$_.DefaultInboundAction
    defaultOutbound = [string]$_.DefaultOutboundAction
  }
})
[pscustomobject]@{
  rules = [int]$rules
  services = $services
  profiles = $profiles
} | ConvertTo-Json -Compress -Depth 4
`, false, 15000)
    const parsed = JSON.parse(String(stdout || '{}').trim() || '{}')
    ourRuleCount = Number(parsed.rules) || 0
    services = Array.isArray(parsed.services)
      ? parsed.services.map((service: any) => ({
          name: String(service.name || ''),
          status: String(service.status || 'Unknown')
        })).filter((service: any) => service.name)
      : []
    profiles = Array.isArray(parsed.profiles)
      ? parsed.profiles.map((profile: any) => ({
          name: String(profile.name || ''),
          enabled: String(profile.enabled || 'Unknown'),
          defaultInbound: String(profile.defaultInbound || 'Unknown'),
          defaultOutbound: String(profile.defaultOutbound || 'Unknown')
        })).filter((profile: any) => profile.name)
      : []
  } catch (err) {
    logEvent('warn', 'firewall-killswitch', 'firewall health probe failed', err)
  }

  const serviceDown = services.some((service) => service.status.toLowerCase() !== 'running')
  const expectedActiveFirewall = protectedTunnelActive && !serviceDown && (ourRuleCount > 0 || manifestPresent || stuckBlockDefault)
  const recommendedActions: string[] = []
  if (!expectedActiveFirewall && (ourRuleCount > 0 || manifestPresent)) {
    recommendedActions.push('Remove VPNTE firewall rules and restore saved outbound policy')
  }
  if (!expectedActiveFirewall && stuckBlockDefault) {
    recommendedActions.push('Restore firewall DefaultOutboundAction from VPNTE backup or Windows safe default')
  }
  if (serviceDown) {
    recommendedActions.push('Check Windows services BFE and MpsSvc')
  }

  const summary: FirewallRepairHealth['summary'] = serviceDown
    ? 'fail'
    : expectedActiveFirewall
      ? 'ok'
      : (ourRuleCount > 0 || manifestPresent || stuckBlockDefault)
      ? 'warn'
      : 'ok'

  return {
    platform: 'win32',
    protectedTunnelActive,
    manifestPresent,
    ourRuleCount,
    stuckBlockDefault,
    services,
    profiles,
    summary,
    message: summary === 'ok'
      ? expectedActiveFirewall
        ? 'VPNTE firewall is protecting the active tunnel'
        : 'VPNTE firewall state looks clean'
      : summary === 'fail'
        ? 'Windows Firewall services need attention'
        : 'VPNTE firewall cleanup is recommended',
    recommendedActions
  }
}

export async function repairVpnteFirewallRules(): Promise<FirewallKillSwitchResult & { health: FirewallRepairHealth }> {
  if (process.platform !== 'win32') {
    return {
      success: true,
      skipped: true,
      message: 'Windows Firewall repair is not available on this platform',
      health: await getFirewallRepairHealth()
    }
  }

  const before = await getFirewallRepairHealth()
  if (!before.manifestPresent && before.ourRuleCount === 0 && !before.stuckBlockDefault) {
    return {
      success: true,
      skipped: true,
      message: 'VPNTE firewall rules are already clean',
      health: before
    }
  }

  const result = await disableKillSwitch('manual targeted maintenance repair')
  const after = await getFirewallRepairHealth()
  return {
    ...result,
    message: result.success
      ? `VPNTE firewall cleanup completed. Rules left: ${after.ourRuleCount}`
      : result.message,
    health: after
  }
}

/**
 * Nuclear option: reset Windows Firewall back to factory defaults.
 *
 * This is the last-resort recovery for users whose firewall is jammed by
 * accumulated rules / a stuck DefaultOutboundAction=Block / our own kill-switch
 * that won't come off cleanly. `netsh advfirewall reset` wipes ALL rules
 * (including third-party ones), then we re-apply the safe Windows default of
 * "block inbound, allow outbound" so the user has working internet again.
 *
 * Returns success=true even if the second `set allprofiles` step fails — the
 * reset itself usually unblocks things. Returns success=false only if the
 * reset itself errors out (typically a privilege failure).
 */
function firewallBackupPath(): string {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-')
  return join(backupDir(), `windows-firewall-before-reset-${stamp}.wfw`)
}

export async function nuclearFirewallReset(): Promise<{ success: boolean; message: string; backupPath?: string }> {
  if (process.platform !== 'win32') {
    return { success: false, message: 'Only supported on Windows' }
  }
  const backupPath = firewallBackupPath()
  try {
    await mkdir(backupDir(), { recursive: true })
    await execElevated(`netsh advfirewall export "${backupPath}"`, { timeout: 15000 })
    await execElevated('netsh advfirewall reset', { timeout: 10000 })
    await execElevated('netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound', { timeout: 10000 })
    // After a full reset our manifest no longer reflects reality — clear it.
    await clearManifest()
    logEvent('info', 'firewall-killswitch', 'nuclear firewall reset completed', { backupPath })
    return {
      success: true,
      message: `Windows Firewall сброшен. Backup правил сохранён: ${backupPath}`,
      backupPath
    }
  } catch (err: any) {
    logEvent('error', 'firewall-killswitch', 'nuclear firewall reset failed', err)
    return { success: false, message: err.message || String(err) }
  }
}
