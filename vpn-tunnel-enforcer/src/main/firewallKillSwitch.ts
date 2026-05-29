import { app } from 'electron'
import { mkdir, readFile, writeFile, unlink, stat } from 'fs/promises'
import { join } from 'path'
import { execFile as execFileCb } from 'child_process'
import { promisify } from 'util'
import { execElevated } from './admin'
import { logEvent } from './appLogger'
import { TUN_ADAPTER_ALIAS, TUN_IPV4_NETWORK_CIDR } from './tunAdapter'

const execFile = promisify(execFileCb)

// Rule-name prefix for every firewall rule we add. We rely on this prefix to
// find and remove our rules during rollback, even if our manifest is missing
// (e.g. user wiped %APPDATA% manually after a crash).
const RULE_PREFIX = 'VPNTE-killswitch'

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
  } catch {
    return null
  }
}

async function writeManifest(m: FirewallManifest): Promise<void> {
  await mkdir(backupDir(), { recursive: true })
  await writeFile(manifestPath(), JSON.stringify(m, null, 2), 'utf-8')
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

export async function isKillSwitchActive(): Promise<boolean> {
  return (await readManifest()) !== null || await probeFirewallForOurRules()
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
}): Promise<FirewallKillSwitchResult> {
  if (process.platform !== 'win32') {
    return { success: true, message: 'Firewall kill-switch недоступен (не Windows)' }
  }

  const singboxAllow = `${RULE_PREFIX}-allow-singbox`
  const tunInterfaceAllow = `${RULE_PREFIX}-allow-tun-interface`
  const lanAllow = `${RULE_PREFIX}-allow-lan`
  const tunAllow = `${RULE_PREFIX}-allow-tun`
  const dhcpAllow = `${RULE_PREFIX}-allow-dhcp`

  // Windows Firewall can be picky about mixed IPv4/IPv6 CIDR arrays here. IPv6 is
  // disabled by adapter lockdown anyway, so keep the firewall LAN bypass IPv4-only.
  const lanRemoteAddresses = LAN_BYPASS_CIDRS
    .filter((c) => !c.includes(':'))
    .map((c) => `'${c}'`)
    .join(',')

  // Build proxy process allow rules dynamically
  const proxyPaths = opts.proxyOwnerProgramPaths ?? []
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
} catch { Write-Host "WARN allow-proxy-${i}: $_" }`)
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
} catch { Write-Host "WARN allow-singbox: $_" }

# 3b. Allow proxy owner processes (Happ xray.exe, etc.)
${proxyAllowParts.join('\n')}

# 3c. Allow all captured app traffic on VPNTE-TUN. Without this, the global
# DefaultOutboundAction=Block blocks the browser before Windows can route the
# packet into the TUN, which looks like "internet is blocked" even though
# sing-box itself is allowed.
try {
  New-NetFirewallRule \`
    -DisplayName ${psSingleQuote(tunInterfaceAllow)} \`
    -Description 'VPN Tunnel Enforcer kill-switch: allow captured app traffic through ${TUN_ADAPTER_ALIAS}.' \`
    -Direction Outbound -Action Allow \`
    -InterfaceAlias '${TUN_ADAPTER_ALIAS}' \`
    -Profile Any -Enabled True | Out-Null
  $rules += ${psSingleQuote(tunInterfaceAllow)}
} catch { Write-Host "WARN allow-tun-interface: $_" }

# 3d. Allow IPv4 LAN ranges outbound (printers, NAS, router, mDNS).
try {
  New-NetFirewallRule \`
    -DisplayName ${psSingleQuote(lanAllow)} \`
    -Description 'VPN Tunnel Enforcer kill-switch: allow private-LAN destinations.' \`
    -Direction Outbound -Action Allow \`
    -RemoteAddress ${lanRemoteAddresses} \`
    -Profile Any -Enabled True | Out-Null
  $rules += ${psSingleQuote(lanAllow)}
} catch { Write-Host "WARN allow-lan: $_" }

# 3e. Allow TUN subnet (${TUN_IPV4_NETWORK_CIDR}) so sing-box TUN traffic works.
try {
  New-NetFirewallRule \`
    -DisplayName ${psSingleQuote(tunAllow)} \`
    -Description 'VPN Tunnel Enforcer kill-switch: allow TUN subnet.' \`
    -Direction Outbound -Action Allow \`
    -RemoteAddress '${TUN_IPV4_NETWORK_CIDR}' \`
    -Profile Any -Enabled True | Out-Null
  $rules += ${psSingleQuote(tunAllow)}
} catch { Write-Host "WARN allow-tun: $_" }

# 3f. Allow DHCP (UDP 67/68) so Wi-Fi lease renewal works.
try {
  New-NetFirewallRule \`
    -DisplayName ${psSingleQuote(dhcpAllow)} \`
    -Description 'VPN Tunnel Enforcer kill-switch: allow DHCP.' \`
    -Direction Outbound -Action Allow \`
    -Protocol UDP -RemotePort 67,68 \`
    -Profile Any -Enabled True | Out-Null
  $rules += ${psSingleQuote(dhcpAllow)}
} catch { Write-Host "WARN allow-dhcp: $_" }

# --- Step 4: Set DefaultOutboundAction=Block ---
try {
  Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block
} catch {
  Write-Host "FATAL set-block: $_"
  # Rollback: remove rules we just added
  Get-NetFirewallRule -DisplayName '${RULE_PREFIX}*' -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue
  throw
}

# Output: JSON with rules + saved profiles
$rulesCsv = ($rules -join ',')
Write-Host "RULES:$rulesCsv"
Write-Host "SAVED:$savedJson"
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
    // Still clear manifest so the app doesn't get stuck thinking kill-switch is
    // active. The rules will still be removed by the next successful disable.
    await clearManifest()
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
  const manifestSaysActive = await isKillSwitchActive()
  const firewallSaysActive = manifestSaysActive ? true : await probeFirewallForOurRules()
  if (!manifestSaysActive && !firewallSaysActive) return
  if (await isSingboxRunning()) {
    logEvent(
      'info',
      'firewall-killswitch',
      'kill-switch rules found and sing-box is still running — keeping kill-switch',
      { manifestSaysActive, firewallSaysActive }
    )
    return
  }
  logEvent(
    'warn',
    'firewall-killswitch',
    'stale kill-switch detected on startup (sing-box not running) — clearing',
    { manifestSaysActive, firewallSaysActive }
  )
  await disableKillSwitch('crash recovery on startup').catch((err) =>
    logEvent('warn', 'firewall-killswitch', 'crash-recovery disable failed', err)
  )
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
export async function nuclearFirewallReset(): Promise<{ success: boolean; message: string }> {
  if (process.platform !== 'win32') {
    return { success: false, message: 'Only supported on Windows' }
  }
  try {
    const { exec } = await import('child_process')
    const { promisify } = await import('util')
    const execAsync = promisify(exec)
    await execAsync('netsh advfirewall reset', { windowsHide: true, timeout: 10000 })
    await execAsync('netsh advfirewall set allprofiles firewallpolicy blockinbound,allowoutbound', { windowsHide: true, timeout: 10000 })
    // After a full reset our manifest no longer reflects reality — clear it.
    await clearManifest()
    logEvent('info', 'firewall-killswitch', 'nuclear firewall reset completed')
    return { success: true, message: 'Firewall сброшен к настройкам по умолчанию' }
  } catch (err: any) {
    logEvent('error', 'firewall-killswitch', 'nuclear firewall reset failed', err)
    return { success: false, message: err.message || String(err) }
  }
}
