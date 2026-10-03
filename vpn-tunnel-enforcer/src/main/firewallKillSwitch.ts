import { app, BrowserWindow, dialog } from 'electron'
import { mkdir, readFile, writeFile, unlink, stat, rename, access, realpath } from 'fs/promises'
import { join, isAbsolute, win32 } from 'path'
import { constants as fsConstants } from 'fs'
import { execFile as execFileCb } from 'child_process'
import { isIP } from 'net'
import { promisify } from 'util'
import { execElevated } from './admin'
import { execElevatedPs, isElevatedPsHelperRunning } from './elevatedPsHelper'
import { logEvent } from './appLogger'
import { randomUUID, createHash } from 'crypto'
import { getRecoveryManifestDir, recoveryManifestPath, readRecoveryManifest, writeRecoveryManifest, writeRecoveryArtifact, removeRecoveryManifest, strictRecoveryRequired } from './recoveryManifest'
import { TUN_ADAPTER_ALIAS, TUN_IPV4_NETWORK_CIDR, getTunAdapterAlias } from './tunAdapter'
import { withFirewallRulesApi } from './firewallRulesApi'

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

// Loopback bypass CIDRs: covers BOTH IPv4 and IPv6 loopback addresses.
export const LOOPBACK_BYPASS_CIDRS = ['127.0.0.0/8', '::1/128']

export interface FirewallKillSwitchResult {
  success: boolean
  message: string
  details?: string
  // True iff the call was a no-op because there was nothing to do (kill-switch
  // already inactive). The renderer uses this to suppress the noisy
  // "Kill-switch снят вручную" warn log that fired every stop because main
  // had already auto-disabled before the user-driven IPC arrived.
  skipped?: boolean
  state?: 'unknown'
}

export interface SavedProfile {
  name: 'Domain' | 'Private' | 'Public'
  defaultOutbound: 'Allow' | 'Block' | 'NotConfigured'
}
export interface FirewallManifest {
  schemaVersion: 1
  owner: 'VPNTE'
  operationId: string
  phase: 'prepared' | 'active'
  strictMode: boolean
  createdAt: number
  ruleNames: string[]
  singboxExePath: string | null
  savedProfiles: SavedProfile[]
  exceptionPolicy?: FirewallExceptionPolicy
  pendingExceptionPolicy?: FirewallExceptionPolicy
}
export function validateSavedProfiles(value: unknown): SavedProfile[] {
  if (!Array.isArray(value) || value.length !== 3) throw new Error('Invalid firewall snapshot: all profiles required')
  const names = new Set<string>()
  return value.map(item => {
    if (!item || typeof item !== 'object' || !['Domain','Private','Public'].includes(item.name) ||
        !['Allow','Block','NotConfigured'].includes(item.defaultOutbound) || names.has(item.name)) {
      throw new Error('Invalid firewall profile or policy')
    }
    names.add(item.name)
    return { name: item.name, defaultOutbound: item.defaultOutbound }
  })
}
export function validateFirewallManifest(value: unknown): FirewallManifest {
  const v = value as Partial<FirewallManifest> | null
  if (!v || typeof v !== 'object' || v.schemaVersion !== 1 || v.owner !== 'VPNTE' ||
      typeof v.operationId !== 'string' || !/^[a-f0-9-]{36}$/i.test(v.operationId) ||
      !['prepared','active'].includes(v.phase || '') || typeof v.strictMode !== 'boolean' ||
      !Number.isSafeInteger(v.createdAt) || (v.createdAt ?? 0) <= 0 ||
      !Array.isArray(v.ruleNames) || v.ruleNames.length > 500 ||
      v.ruleNames.some(name => typeof name !== 'string' || !/^VPNTE-killswitch-[a-zA-Z0-9_-]{1,100}$/.test(name)) ||
      !(v.singboxExePath === null || (typeof v.singboxExePath === 'string' && /^[a-z]:\\/i.test(v.singboxExePath) && !/[\x00-\x1f]/.test(v.singboxExePath)))) {
    throw new Error('Invalid or unsupported firewall manifest')
  }
  return { schemaVersion: 1, owner: 'VPNTE', operationId: v.operationId, phase: v.phase!,
    strictMode: v.strictMode, createdAt: v.createdAt!, ruleNames: [...new Set(v.ruleNames)],
    singboxExePath: v.singboxExePath!, savedProfiles: validateSavedProfiles(v.savedProfiles),
    ...(v.exceptionPolicy ? { exceptionPolicy: validateFirewallExceptionPolicy(v.exceptionPolicy) } : {}),
    ...(v.pendingExceptionPolicy ? { pendingExceptionPolicy: validateFirewallExceptionPolicy(v.pendingExceptionPolicy) } : {}) }
}
export function getKillSwitchManifestPath(): string { return recoveryManifestPath('firewall.json') }
function backupDir(): string { return getRecoveryManifestDir() }
let manifestReadFailure: string | null = null
async function readManifest(): Promise<FirewallManifest | null> {
  manifestReadFailure = null
  try { return await readRecoveryManifest('firewall.json', validateFirewallManifest) }
  catch (error) {
    manifestReadFailure = error instanceof Error ? error.message : String(error)
    logEvent('error', 'firewall-killswitch', 'CRITICAL_SECURITY_EVENT: recovery manifest rejected', { error: manifestReadFailure })
    return null
  }
}
// Exported for combinedPreStartProbe: a file-read-only check that determines
// whether the firewall rule probe should be included in the combined PS script.
export async function killSwitchManifestExists(): Promise<boolean> {
  return (await readManifest()) !== null
}

async function writeManifest(m: Omit<FirewallManifest, 'schemaVersion' | 'owner' | 'operationId' | 'phase' | 'strictMode'> & Partial<FirewallManifest>): Promise<void> {
  await writeRecoveryManifest('firewall.json', { schemaVersion: 1, owner: 'VPNTE', operationId: randomUUID(),
    phase: 'active', strictMode: false, ...m }, validateFirewallManifest)
}
async function clearManifest(): Promise<void> { await removeRecoveryManifest('firewall.json') }

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

const NATIVE_FIREWALL_PHASES = new Set([
  'initial-stale-cleanup', 'initial-create-allows', 'initial-set-block', 'initial-exceptions',
  'restore-profiles', 'restore-remove-rules'
])
function logNativeFirewallTimings(stdout: string): void {
  // Diagnostic markers carry no security proof and never affect the result.
  // Accept only fixed names and bounded integer milliseconds, once per phase.
  const timings = new Map<string, number>()
  const duplicates = new Set<string>()
  for (const line of stdout.split(/\r?\n/)) {
    const match = /^VPNTE_FW_TIMING:([a-z-]+):([0-9]{1,5})$/.exec(line.trim())
    if (!match || !NATIVE_FIREWALL_PHASES.has(match[1])) continue
    const durationMs = Number(match[2])
    if (durationMs > 60000) continue
    if (timings.has(match[1])) duplicates.add(match[1])
    timings.set(match[1], durationMs)
  }
  for (const [phase, durationMs] of timings) {
    if (!duplicates.has(phase)) logEvent('debug', 'firewall-killswitch', 'native phase timing', { phase, durationMs })
  }
}

async function ps(script: string, elevated = false, timeout = 30000) {
  const ruleBackend = /\b(?:Get-VpnteFirewallRuleNames|New-VpnteFirewallRule|Remove-VpnteFirewallRules)\b/.test(script) ? 'com' : 'netsecurity'
  script = withFirewallRulesApi(script)
  // The persistent helper executes source from its pipe. A protected .ps1 is
  // needed only by the fallback; writing it first adds two cold PS launches.
  if (isElevatedPsHelperRunning()) {
    const started = performance.now()
    let result: Awaited<ReturnType<typeof execElevatedPs>> | undefined
    try {
      result = await execElevatedPs(script, timeout, 'firewall-killswitch')
    } catch (err: any) {
      // Only a known rejection before execution permits a fallback. A timeout
      // or lost reply may follow effects; replaying would duplicate mutation.
      if (!['elevated-helper-script-rejected', 'elevated-helper-script-too-large', 'elevated-helper-unavailable'].includes(err?.code)) throw err
      logEvent('debug', 'firewall-killswitch', 'helper fallback', {
        code: err?.code ?? 'unclassified', durationMs: Math.round(performance.now() - started)
      })
    }
    if (result) {
      logEvent('debug', 'firewall-killswitch', 'command timing', {
        transport: 'helper', ruleBackend, durationMs: Math.round(performance.now() - started)
      })
      if (result.exitCode) throw new Error(result.stderr || `Firewall command failed (exit ${result.exitCode})`)
      logNativeFirewallTimings(result.stdout)
      return { stdout: result.stdout, stderr: result.stderr }
    }
  }
  // Keep elevated scripts under userData instead of %TEMP% and do not remove them
  // immediately: sudo-prompt can return before the elevated PowerShell has opened
  // the -File path, which made PowerShell report "argument for -File does not exist".
  const scriptDir = backupDir()
  const scriptPath = join(
    scriptDir,
    `script-${process.pid}-${Date.now()}-${Math.random().toString(36).slice(2)}.ps1`
  )
  const persistStarted = performance.now()
  await writeRecoveryArtifact(scriptPath.slice(scriptDir.length + 1), '\ufeff' + withPowerShellPrelude(script))
  const persistMs = Math.round(performance.now() - persistStarted)
  const executionStarted = performance.now()

  try {
    if (elevated) {
      const command = `powershell -NoProfile -ExecutionPolicy Bypass -File ${cmdDoubleQuote(scriptPath)}`
      const result = await execElevated(command, { timeout, maxBuffer: 1024 * 1024 * 4 })
      logNativeFirewallTimings(String(result.stdout ?? ''))
      return result
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
    logNativeFirewallTimings(String(result.stdout ?? ''))
    return {
      stdout: String(result.stdout ?? ''),
      stderr: String(result.stderr ?? '')
    }
  } finally {
    logEvent('debug', 'firewall-killswitch', 'command timing', {
      transport: elevated ? 'elevated-file' : 'file', ruleBackend, persistMs,
      durationMs: Math.round(performance.now() - executionStarted)
    })
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
 * New-VpnteFirewallRule -RemoteAddress argument. We accept:
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
Remove-VpnteFirewallRules -DisplayName $ruleName -ErrorAction Stop
New-VpnteFirewallRule \`
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
let firewallQueue: Promise<unknown> = Promise.resolve()
async function timedFirewallPhase<T>(phase: string, operation: () => Promise<T>): Promise<T> {
  const started = performance.now()
  let outcome = 'rejected'
  try {
    const result = await operation()
    outcome = 'fulfilled'
    return result
  } finally {
    logEvent('debug', 'firewall-killswitch', 'phase timing', {
      phase, outcome, durationMs: Math.round(performance.now() - started)
    })
  }
}
function serializeFirewall<T>(operation: () => Promise<T>): Promise<T> {
  const result = firewallQueue.then(operation, operation)
  firewallQueue = result.then(() => undefined, () => undefined)
  return result
}
export interface KillSwitchOptions {
  singboxExePath: string
  proxyOwnerProgramPaths?: string[]
  appExceptionPaths?: string[]
  extraAllowedRemoteCidrs?: string[]
  tunAdapterAlias?: string
  // Internal startup barrier: true only after the controller verifies and
  // journals this adapter's GUID, Wintun identity and owned address.
  tunAdapterReady?: Promise<boolean>
  strictMode?: boolean
}
export async function enableKillSwitch(opts: KillSwitchOptions): Promise<FirewallKillSwitchResult> {
  // Attach the rejection handler before entering the serialized queue.
  const ready = opts.tunAdapterReady?.then(value => value === true, () => false)
  return serializeFirewall(() => enableKillSwitchUnlocked({ ...opts, tunAdapterReady: ready }))
}
export interface FirewallExceptionPolicy { apps: string[]; cidrs: string[] }
function validateFirewallExceptionPolicy(value: unknown): FirewallExceptionPolicy {
  const v = value as FirewallExceptionPolicy
  if (!v || !Array.isArray(v.apps) || !Array.isArray(v.cidrs) || v.apps.length + v.cidrs.length > 256 ||
      v.apps.some(p => typeof p !== 'string' || !/^[a-z]:\\/i.test(p) || !/\.exe$/i.test(p) || /[\x00-\x1f]/.test(p)) ||
      v.cidrs.some(c => typeof c !== 'string' || !isValidIpOrCidr(c))) throw new Error('Invalid firewall exception policy')
  return { apps: [...new Set(v.apps)], cidrs: [...new Set(v.cidrs)] }
}
export async function canonicalizeExceptionAppPath(raw: string): Promise<string> {
  if (!raw || raw.length > 2048 || /[\x00-\x1f]/.test(raw) || !/\.exe$/i.test(raw)) throw new Error('exception.value must be an executable path')
  if (process.platform === 'win32') {
    if (!/^[a-z]:\\/i.test(raw) || !win32.isAbsolute(raw) || raw.slice(2).includes(':') || raw.split(/[\\/]/).includes('..')) throw new Error('exception.value must be a local absolute Windows path')
  } else if (!isAbsolute(raw)) throw new Error('exception.value must be an absolute path')
  await access(raw, fsConstants.R_OK)
  const canonical = await realpath(raw)
  if (!(await stat(canonical)).isFile() || !/\.exe$/i.test(canonical) || (process.platform === 'win32' && !/^[a-z]:\\/i.test(canonical))) throw new Error('exception.value must be a local readable .exe file')
  return canonical
}
function exceptionRuleNames(policy: FirewallExceptionPolicy): string[] {
  return [...policy.apps.map(p => 'app:' + p.toLowerCase()), ...policy.cidrs.map(c => 'ip:' + c)].map(value =>
    `${RULE_PREFIX}-user-${createHash('sha256').update(value).digest('hex').slice(0,24)}`)
}
function exceptionPolicyScript(policy: FirewallExceptionPolicy): string {
  const names = exceptionRuleNames(policy)
  const rules = [...policy.apps.map((value, i) => ({ name: names[i], program: value, remote: null })),
    ...policy.cidrs.map((value, i) => ({ name: names[policy.apps.length + i], program: null, remote: value }))]
  const encoded = Buffer.from(JSON.stringify(rules)).toString('base64')
  const bulkApplicationReadback = policy.apps.length >= 8
  const createRule = `
  $ruleParams=@{DisplayName=$r.name;Direction='Outbound';Action='Allow';Profile='Any';Enabled='True'}
  if($r.program){$ruleParams.Program=$r.program}else{$ruleParams.RemoteAddress=$r.remote}
  New-VpnteFirewallRule @ruleParams -ErrorAction Stop | Out-Null`
  return `
$ErrorActionPreference='Stop'
$profiles=@(Get-NetFirewallProfile -Profile Domain,Private,Public -ErrorAction Stop)
if ($profiles.Count -ne 3 -or @($profiles | Where-Object { [string]$_.DefaultOutboundAction -ne 'Block' }).Count) { throw 'Live update requires verified Block policies' }
# Only user exceptions are replaced. Core, TUN, Xray and Happ rules stay intact.
# Removal-first may temporarily narrow an exception, but never opens new traffic
# before the requested policy has been validated. Never set DefaultOutboundAction.
# One native lookup for the same two disjoint stale groups. The final set
# read-back below is a new query after removal/creation, never this result.
Remove-VpnteFirewallRules -DisplayName @('${RULE_PREFIX}-user-*','${RULE_PREFIX}-allow-extra-ip') -ErrorAction Stop
$requested=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encoded}')) | ConvertFrom-Json
# Association queries cost one CIM round trip per application. For larger sets,
# read the same default PersistentStore once; never reuse this operation's index.
$applicationIndex=$null
${bulkApplicationReadback ? `foreach ($r in $requested) {${createRule}
}
  $applicationIndex=@{}
  foreach($filter in @(Get-NetFirewallApplicationFilter -All -ErrorAction Stop)){
    $key=[string]$filter.InstanceID
    if($applicationIndex.ContainsKey($key)){$applicationIndex[$key]=@($applicationIndex[$key])+@($filter)}
    else{$applicationIndex[$key]=@($filter)}
  }` : ''}
foreach ($r in $requested) {
${bulkApplicationReadback ? '' : createRule}
  $actual=@(Get-NetFirewallRule -DisplayName $r.name -ErrorAction Stop)
  if($actual.Count -ne 1 -or [string]$actual[0].Enabled -ne 'True' -or [string]$actual[0].Action -ne 'Allow' -or [string]$actual[0].Direction -ne 'Outbound'){throw 'Exception rule read-back mismatch'}
  if($r.program){
    if($null -ne $applicationIndex){
      $key=[string]$actual[0].Name
      if(-not $key -or -not $applicationIndex.ContainsKey($key)){throw 'Program filter read-back mismatch'}
      $filters=@($applicationIndex[$key])
    }else{$filters=@($actual[0] | Get-NetFirewallApplicationFilter -ErrorAction Stop)}
    if($filters.Count -ne 1 -or [string]$filters[0].Program -ine [string]$r.program){throw 'Program filter read-back mismatch'}
  }else{
    $filter=$actual[0] | Get-NetFirewallAddressFilter -ErrorAction Stop
    if(@($filter.RemoteAddress).Count -ne 1 -or [string]@($filter.RemoteAddress)[0] -ne [string]$r.remote){throw 'Remote filter read-back mismatch'}
  }
}
$actualNames=@(Get-VpnteFirewallRuleNames -DisplayName '${RULE_PREFIX}-user-*' -ErrorAction Stop)
if($actualNames.Count -ne $requested.Count -or @($actualNames | Where-Object { $_ -notin @($requested.name) }).Count){throw 'Exception set read-back mismatch'}
Write-Output 'EXCEPTIONS_VERIFIED'
`
}
export function updateKillSwitchExceptions(apps: string[], cidrs: string[], strictMode?: boolean): Promise<FirewallKillSwitchResult> {
  return serializeFirewall(() => updateExceptionsUnlocked(apps, cidrs, strictMode))
}
async function updateExceptionsUnlocked(apps: string[], cidrs: string[], strictMode?: boolean): Promise<FirewallKillSwitchResult> {
  const previous = await timedFirewallPhase('live-read-manifest', readManifest)
  if (!previous || manifestReadFailure || previous.phase !== 'active') return { success: false, state: 'unknown', message: 'Live exceptions require a trusted active firewall transaction' }
  const policy = validateFirewallExceptionPolicy({ apps: await Promise.all(apps.map(canonicalizeExceptionAppPath)), cidrs })
  const old = previous.exceptionPolicy ?? { apps: [], cidrs: [] }
  // Original baseline and core rule names are never replaced by a live update.
  await timedFirewallPhase('live-prepare-journal', () => writeManifest({ ...previous, pendingExceptionPolicy: policy }))
  try {
    const { stdout } = await timedFirewallPhase('live-apply-policy', () => ps(exceptionPolicyScript(policy), true, 30000))
    if (!String(stdout).split(/\r?\n/).includes('EXCEPTIONS_VERIFIED')) throw new Error('Exception verification marker missing')
    const { pendingExceptionPolicy: _pending, ...committed } = previous
    await timedFirewallPhase('live-commit-journal', () => writeManifest({ ...committed, strictMode: strictMode ?? previous.strictMode, exceptionPolicy: policy,
      ruleNames: [...previous.ruleNames.filter(n => !n.startsWith(`${RULE_PREFIX}-user-`) && n !== `${RULE_PREFIX}-allow-extra-ip`), ...exceptionRuleNames(policy)] }))
    return { success: true, message: 'User exceptions verified; core/upstream protection preserved' }
  } catch (error) {
    try {
      const { stdout } = await ps(exceptionPolicyScript(old), true, 30000)
      if (!String(stdout).split(/\r?\n/).includes('EXCEPTIONS_VERIFIED')) throw new Error('Exception compensation not verified')
      await writeManifest(previous)
    } catch (compensationError) {
      logEvent('error', 'firewall-killswitch', 'exception update and compensation failed', {
        update: String((error as any)?.stderr || error).replace(/-EncodedCommand\s+\S+/gi, '-EncodedCommand <omitted>').slice(-2000),
        compensation: String((compensationError as any)?.stderr || compensationError).replace(/-EncodedCommand\s+\S+/gi, '-EncodedCommand <omitted>').slice(-2000)
      })
      reportRecoveryWarning('Live-обновление исключений не подтверждено. Core-защита сохранена, но набор исключений требует повторной проверки.')
      return { success: false, state: 'unknown', message: 'Live exception update and compensation failed; recovery journal retained' }
    }
    return { success: false, message: 'Exception update failed; previous exception policy restored', details: String(error) }
  }
}

async function snapshotFirewallProfiles(): Promise<SavedProfile[]> {
  const { stdout } = await ps(`$snapshot = @(Get-NetFirewallProfile -Profile Domain,Private,Public -ErrorAction Stop | ForEach-Object {
  [pscustomobject]@{name=[string]$_.Name;defaultOutbound=[string]$_.DefaultOutboundAction}
})
Write-Output ('SNAPSHOT:' + ($snapshot | ConvertTo-Json -Compress))`, true)
  const line = String(stdout).split(/\r?\n/).find(line => line.startsWith('SNAPSHOT:'))
  if (!line) throw new Error('Firewall policy snapshot was not confirmed')
  return validateSavedProfiles(JSON.parse(line.slice('SNAPSHOT:'.length)))
}
function reportRecoveryWarning(message: string): void {
  logEvent('error', 'firewall-killswitch', 'CRITICAL_SECURITY_EVENT: protection is unknown', { message })
  for (const win of BrowserWindow.getAllWindows()) {
    if (!win.isDestroyed()) win.webContents.send('network-recovery-warning', { state: 'unknown', message })
  }
  void dialog.showMessageBox({ type: 'warning', title: 'VPNTE: защита не подтверждена', message }).catch(() => undefined)
}
async function enableKillSwitchUnlocked(opts: KillSwitchOptions): Promise<FirewallKillSwitchResult> {
  if (process.platform !== 'win32') {
    return { success: true, message: 'Firewall kill-switch недоступен (не Windows)' }
  }

  if ((opts.extraAllowedRemoteCidrs ?? []).some(c => !isValidIpOrCidr(c))) return { success: false, message: 'Invalid exception IP/CIDR' }
  if (opts.appExceptionPaths) opts = { ...opts, appExceptionPaths: await Promise.all(opts.appExceptionPaths.map(canonicalizeExceptionAppPath)) }
  const initialExceptions = opts.appExceptionPaths !== undefined || opts.extraAllowedRemoteCidrs !== undefined
    ? validateFirewallExceptionPolicy({ apps: opts.appExceptionPaths ?? [], cidrs: opts.extraAllowedRemoteCidrs ?? [] })
    : null
  const previous = await timedFirewallPhase('initial-read-manifest', readManifest)
  if (manifestReadFailure) return { success: false, state: 'unknown', message: 'Recovery manifest is untrusted or invalid; refusing to replace its baseline' }
  if (previous?.phase === 'active') {
    if (opts.appExceptionPaths !== undefined || opts.extraAllowedRemoteCidrs !== undefined || opts.strictMode !== undefined) {
      return updateExceptionsUnlocked(opts.appExceptionPaths ?? previous.exceptionPolicy?.apps ?? [], opts.extraAllowedRemoteCidrs ?? previous.exceptionPolicy?.cidrs ?? [], opts.strictMode)
    }
    return { success: true, skipped: true, message: 'Active firewall preserved; use differential exceptions update' }
  }
  const savedProfiles = previous?.savedProfiles ?? await timedFirewallPhase('snapshot-profiles', snapshotFirewallProfiles)
  const prepared: FirewallManifest = {
    schemaVersion: 1, owner: 'VPNTE', operationId: previous?.operationId ?? randomUUID(),
    phase: 'prepared', strictMode: opts.strictMode ?? previous?.strictMode ?? false,
    createdAt: previous?.createdAt ?? Date.now(), savedProfiles,
    ruleNames: previous?.ruleNames ?? [], singboxExePath: opts.singboxExePath,
    ...(initialExceptions ? { pendingExceptionPolicy: initialExceptions } : {})
  }
  // This durable snapshot MUST precede any New/Remove/Set-NetFirewall operation.
  try { await timedFirewallPhase('initial-prepare-journal', () => writeManifest(prepared)) } catch (error) {
    return { success: false, message: 'Firewall unchanged: recovery snapshot could not be committed', details: String(error) }
  }

  const tunAlias = opts.tunAdapterAlias || getTunAdapterAlias()
  const singboxAllow = `${RULE_PREFIX}-allow-singbox`
  const appAllow = `${RULE_PREFIX}-allow-app`
  const tunInterfaceAllow = `${RULE_PREFIX}-allow-tun-interface`
  const loopbackOutAllow = `${RULE_PREFIX}-allow-loopback-out`
  const loopbackInAllow = `${RULE_PREFIX}-allow-loopback-in`
  const lanAllow = `${RULE_PREFIX}-allow-lan`
  const tunAllow = `${RULE_PREFIX}-allow-tun`
  const dhcpAllow = `${RULE_PREFIX}-allow-dhcp`
  const ntpAllow = `${RULE_PREFIX}-allow-ntp`

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
  New-VpnteFirewallRule \`
    -DisplayName ${psSingleQuote(ruleName)} \`
    -Description 'VPN Tunnel Enforcer kill-switch: allow upstream proxy process outbound.' \`
    -Direction Outbound -Action Allow \`
    -Program ${psSingleQuote(proxyPaths[i])} \`
    -Profile Any -Enabled True | Out-Null
  $rules += ${psSingleQuote(ruleName)}
} catch { Write-Output "WARN allow-proxy-${i}: $_" }`)
  }

  // Startup callers share their verified adapter barrier. Other callers keep
  // the bounded native wait; helper policies remain separate and unchanged.
  const adapterWaitScript = opts.tunAdapterReady ? '$tunAliasFound = $true' : `
$tunAliasFound = $false
for ($i = 0; $i -lt 150; $i++) {
  $a = Get-NetAdapter -Name ${psSingleQuote(tunAlias)} -ErrorAction SilentlyContinue
  if ($a -and $a.Status -eq 'Up') { $tunAliasFound = $true; break }
  Start-Sleep -Milliseconds 100
}`

  // One atomic elevated PowerShell script: save defaults → add allows → set block.
  const script = `
# Snapshot is already durable in the protected manifest before this transaction.
$savedJson = ${psSingleQuote(JSON.stringify(savedProfiles))}

# --- Step 2: Clean stale rules ---
$nativePhaseWatch = [Diagnostics.Stopwatch]::StartNew()
Remove-VpnteFirewallRules -DisplayName '${RULE_PREFIX}*' -ErrorAction Stop
Write-Output ('VPNTE_FW_TIMING:initial-stale-cleanup:' + $nativePhaseWatch.ElapsedMilliseconds)
$nativePhaseWatch.Restart()

$rules = @()

# --- Step 3: Add Allow rules (BEFORE setting Block default) ---

# 3a. Allow the TUN runtime (sing-box.exe) outbound.
try {
  New-VpnteFirewallRule \`
    -DisplayName ${psSingleQuote(singboxAllow)} \`
    -Description 'VPN Tunnel Enforcer kill-switch: allow VPNTE sing-box outbound.' \`
    -Direction Outbound -Action Allow \`
    -Program ${psSingleQuote(opts.singboxExePath)} \`
    -Profile Any -Enabled True | Out-Null
  $rules += ${psSingleQuote(singboxAllow)}
} catch { Write-Output "WARN allow-singbox: $_" }

# 3a-bis. Allow the Electron application binary (process.execPath) outbound.
try {
  New-VpnteFirewallRule \`
    -DisplayName ${psSingleQuote(appAllow)} \`
    -Description 'VPN Tunnel Enforcer kill-switch: allow Electron app outbound.' \`
    -Direction Outbound -Action Allow \`
    -Program ${psSingleQuote(process.execPath)} \`
    -Profile Any -Enabled True | Out-Null
  $rules += ${psSingleQuote(appAllow)}
} catch { Write-Output "WARN allow-app: $_" }

# 3b. Allow proxy owner processes (Happ xray.exe, etc.)
${proxyAllowParts.join('\n')}

# 3c. Allow all captured app traffic on VPNTE-TUN. Without this, the global
# DefaultOutboundAction=Block blocks the browser before Windows can route the
# packet into the TUN, which looks like "internet is blocked" even though
# sing-box itself is allowed.
# The controller's barrier verifies ownership before native effects. Legacy
# callers without that barrier still wait for adapter Up here.
${adapterWaitScript}
if ($tunAliasFound) {
  try {
    New-VpnteFirewallRule \`
      -DisplayName ${psSingleQuote(tunInterfaceAllow)} \`
      -Description 'VPN Tunnel Enforcer kill-switch: allow captured app traffic through ${tunAlias}.' \`
      -Direction Outbound -Action Allow \`
      -InterfaceAlias ${psSingleQuote(tunAlias)} \`
      -Profile Any -Enabled True | Out-Null
    $rules += ${psSingleQuote(tunInterfaceAllow)}
  } catch { Write-Output "WARN allow-tun-interface: $_" }
} else {
  Write-Output "WARN allow-tun-interface: adapter not found after 15s"
}

# 3c-bis. Dedicated Outbound Allow rules for loopback (IPv4 127.0.0.0/8 and IPv6 ::1/128).
# Windows Firewall rejects mixing IPv4 and IPv6 CIDRs in a single rule, so we create separate rules.
try {
  New-VpnteFirewallRule \`
    -DisplayName ${psSingleQuote(loopbackOutAllow)} \`
    -Description 'VPN Tunnel Enforcer kill-switch: allow loopback outbound (IPv4).' \`
    -Direction Outbound -Action Allow \`
    -RemoteAddress '127.0.0.0/8' \`
    -Profile Any -Enabled True | Out-Null
  try {
    New-VpnteFirewallRule \`
      -DisplayName ${psSingleQuote(loopbackOutAllow)} \`
      -Description 'VPN Tunnel Enforcer kill-switch: allow loopback outbound (IPv6).' \`
      -Direction Outbound -Action Allow \`
      -RemoteAddress '::1/128' \`
      -Profile Any -Enabled True | Out-Null
  } catch { Write-Output "WARN allow-loopback-out-v6: $_" }
  $rules += ${psSingleQuote(loopbackOutAllow)}
} catch { Write-Output "WARN allow-loopback-out: $_" }

# 3c-ter. Dedicated Inbound Allow rules for loopback (IPv4 127.0.0.0/8 and IPv6 ::1/128).
# Allows background listening workers (kimi-webbridge.exe on 127.0.0.1:10086 and Daimon standalone
# runtime on dynamic WebSocket ports) to receive local IPC connections on any port.
try {
  New-VpnteFirewallRule \`
    -DisplayName ${psSingleQuote(loopbackInAllow)} \`
    -Description 'VPN Tunnel Enforcer kill-switch: allow loopback inbound for local IPC workers (IPv4).' \`
    -Direction Inbound -Action Allow \`
    -LocalAddress '127.0.0.0/8' \`
    -Profile Any -Enabled True | Out-Null
  try {
    New-VpnteFirewallRule \`
      -DisplayName ${psSingleQuote(loopbackInAllow)} \`
      -Description 'VPN Tunnel Enforcer kill-switch: allow loopback inbound for local IPC workers (IPv6).' \`
      -Direction Inbound -Action Allow \`
      -LocalAddress '::1/128' \`
      -Profile Any -Enabled True | Out-Null
  } catch { Write-Output "WARN allow-loopback-in-v6: $_" }
  $rules += ${psSingleQuote(loopbackInAllow)}
} catch { Write-Output "WARN allow-loopback-in: $_" }

# 3d. Allow IPv4 LAN ranges outbound (printers, NAS, router, mDNS).
try {
  New-VpnteFirewallRule \`
    -DisplayName ${psSingleQuote(lanAllow)} \`
    -Description 'VPN Tunnel Enforcer kill-switch: allow private-LAN destinations.' \`
    -Direction Outbound -Action Allow \`
    -RemoteAddress ${lanRemoteAddresses} \`
    -Profile Any -Enabled True | Out-Null
  $rules += ${psSingleQuote(lanAllow)}
} catch { Write-Output "WARN allow-lan: $_" }

# 3e. Allow TUN subnet (${TUN_IPV4_NETWORK_CIDR}) so sing-box TUN traffic works.
try {
  New-VpnteFirewallRule \`
    -DisplayName ${psSingleQuote(tunAllow)} \`
    -Description 'VPN Tunnel Enforcer kill-switch: allow TUN subnet.' \`
    -Direction Outbound -Action Allow \`
    -RemoteAddress '${TUN_IPV4_NETWORK_CIDR}' \`
    -Profile Any -Enabled True | Out-Null
  $rules += ${psSingleQuote(tunAllow)}
} catch { Write-Output "WARN allow-tun: $_" }

# 3f. Allow DHCP (UDP 67/68) so Wi-Fi lease renewal works.
try {
  New-VpnteFirewallRule \`
    -DisplayName ${psSingleQuote(dhcpAllow)} \`
    -Description 'VPN Tunnel Enforcer kill-switch: allow DHCP.' \`
    -Direction Outbound -Action Allow \`
    -Protocol UDP -RemotePort 67,68 \`
    -Profile Any -Enabled True | Out-Null
  $rules += ${psSingleQuote(dhcpAllow)}
} catch { Write-Output "WARN allow-dhcp: $_" }

# 3g. Allow NTP (UDP 123) so Windows Time service keeps clocks synced for Reality/TLS.
try {
  New-VpnteFirewallRule \`
    -DisplayName ${psSingleQuote(ntpAllow)} \`
    -Description 'VPN Tunnel Enforcer kill-switch: allow NTP clock sync.' \`
    -Direction Outbound -Action Allow \`
    -Protocol UDP -RemotePort 123 \`
    -Profile Any -Enabled True | Out-Null
  $rules += ${psSingleQuote(ntpAllow)}
} catch { Write-Output "WARN allow-ntp: $_" }

# User exceptions are installed once, with full read-back below.

# --- Step 4: Set DefaultOutboundAction=Block ---
# Only set Block if the required allow-list core exists. A single optional
# Allow rule is not enough: with DefaultOutboundAction=Block, missing sing-box
# or TUN-interface allows can wedge all app traffic until recovery runs.
$requiredRules = @(
  ${psSingleQuote(singboxAllow)},
  ${psSingleQuote(appAllow)},
  ${psSingleQuote(tunInterfaceAllow)},
  ${psSingleQuote(loopbackOutAllow)},
  ${psSingleQuote(loopbackInAllow)},
  ${psSingleQuote(lanAllow)},
  ${psSingleQuote(tunAllow)},
  ${psSingleQuote(dhcpAllow)},
  ${psSingleQuote(ntpAllow)}
)
$missingRequired = @($requiredRules | Where-Object { $rules -notcontains $_ })
if ($missingRequired.Count -gt 0) {
  Write-Output ("FATAL: missing required allow rules before Block: " + ($missingRequired -join ','))
  Remove-VpnteFirewallRules -DisplayName '${RULE_PREFIX}*' -ErrorAction Stop
  throw ("Missing required allow rules before DefaultOutboundAction=Block: " + ($missingRequired -join ','))
}
Write-Output ('VPNTE_FW_TIMING:initial-create-allows:' + $nativePhaseWatch.ElapsedMilliseconds)
$nativePhaseWatch.Restart()
try {
  Set-NetFirewallProfile -Profile Domain,Private,Public -DefaultOutboundAction Block
} catch {
  Write-Output "FATAL set-block: $_"
  # Rollback: remove rules we just added
  Remove-VpnteFirewallRules -DisplayName '${RULE_PREFIX}*' -ErrorAction Stop
  throw
}
Write-Output ('VPNTE_FW_TIMING:initial-set-block:' + $nativePhaseWatch.ElapsedMilliseconds)
$nativePhaseWatch.Restart()

# Output: JSON with rules + saved profiles
# Initial exceptions share the prepared recovery journal and the native
# transaction. Their full read-back still runs, including the empty policy.
${initialExceptions ? exceptionPolicyScript(initialExceptions) : ''}
Write-Output ('VPNTE_FW_TIMING:initial-exceptions:' + $nativePhaseWatch.ElapsedMilliseconds)
$rulesCsv = ($rules -join ',')
Write-Output "RULES:$rulesCsv"
Write-Output "SAVED:$savedJson"
`

  let installedRules: string[] = []
  try {
    if (opts.tunAdapterReady && !await timedFirewallPhase('verified-adapter-wait', () => opts.tunAdapterReady!)) {
      throw new Error('Owned TUN adapter was not confirmed; initial firewall apply cancelled')
    }
    const { stdout } = await timedFirewallPhase('initial-apply-policy', () => ps(script, true, 60000))
    const output = String(stdout || '')
    const lines = output.split('\n').map((l) => l.trim())

    if (initialExceptions && !lines.includes('EXCEPTIONS_VERIFIED')) {
      throw new Error('Initial exception verification marker missing')
    }

    const rulesLine = lines.find((l) => l.startsWith('RULES:'))
    if (rulesLine) {
      installedRules = rulesLine
        .slice(6)
        .split(',')
        .map((n) => n.trim())
        .filter((n) => n.startsWith(RULE_PREFIX))
    }

  } catch (err: any) {
    try { await restoreAndCleanup(prepared); await clearManifest() }
    catch (rollbackError) { logEvent('error', 'firewall-killswitch', 'failed transaction recovery retained', { rollbackError: String(rollbackError) }) }
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

  try {
    const { pendingExceptionPolicy: _pending, ...committed } = prepared
    if (initialExceptions) installedRules = [
      ...installedRules.filter(n => n !== `${RULE_PREFIX}-allow-extra-ip`), ...exceptionRuleNames(initialExceptions)
    ]
    await timedFirewallPhase('initial-commit-journal', () => writeManifest({ ...committed, phase: 'active', ruleNames: installedRules,
      ...(initialExceptions ? { exceptionPolicy: initialExceptions } : {}) }))
  } catch (error: any) {
    // The firewall transaction is not committed until its recovery manifest
    // is durable. Compensate immediately instead of leaving Block active with
    // no authoritative baseline.
    try { await restoreAndCleanup(prepared); await clearManifest() }
    catch (rollbackError) {
      logEvent('error', 'firewall-killswitch', 'manifest commit and verified rollback failed; snapshot retained', { rollbackError: String(rollbackError) })
    }
    return {
      success: false,
      message: 'Kill-switch отменён: не удалось надёжно записать recovery manifest',
      details: error?.message || String(error)
    }
  }

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
async function restoreAndCleanup(snapshot?: FirewallManifest): Promise<void> {
  const manifest = snapshot ?? await readManifest()
  if (!manifest && !(await probeFirewallForOurRules())) {
    if (manifestReadFailure) throw new Error('Invalid recovery manifest; no proven VPNTE rules, no system changes allowed')
    return // Never change a foreign Block policy without proof of ownership.
  }
  const profiles = validateSavedProfiles(manifest?.savedProfiles ?? [
    { name: 'Domain', defaultOutbound: 'Allow' }, { name: 'Private', defaultOutbound: 'Allow' }, { name: 'Public', defaultOutbound: 'Allow' }
  ])
  if (!manifest) reportRecoveryWarning('Манифест сетевой защиты утерян или повреждён. Выполняется сброс Allow. Защита не подтверждена; трафик может идти напрямую.')
  const restores = profiles.map(p => `
try {
  Set-NetFirewallProfile -Profile ${psSingleQuote(p.name)} -DefaultOutboundAction ${p.defaultOutbound} -ErrorAction Stop
  if ([string](Get-NetFirewallProfile -Profile ${psSingleQuote(p.name)} -ErrorAction Stop).DefaultOutboundAction -ne ${psSingleQuote(p.defaultOutbound)}) { throw 'Policy read-back mismatch' }
} catch { $errors += ${psSingleQuote(p.name)} + ': ' + [string]$_ }
`).join('\n')
  const { stdout } = await ps(`$errors = @()
$nativePhaseWatch = [Diagnostics.Stopwatch]::StartNew()
${restores}
Write-Output ('VPNTE_FW_TIMING:restore-profiles:' + $nativePhaseWatch.ElapsedMilliseconds)
$nativePhaseWatch.Restart()
try {
  Remove-VpnteFirewallRules -DisplayName '${RULE_PREFIX}*' -ErrorAction Stop
  if ((Get-VpnteFirewallRuleNames -DisplayName '${RULE_PREFIX}*' -ErrorAction Stop | Measure-Object).Count -ne 0) { throw 'VPNTE rules remain' }
} catch { $errors += 'rules: ' + [string]$_ }
Write-Output ('VPNTE_FW_TIMING:restore-remove-rules:' + $nativePhaseWatch.ElapsedMilliseconds)
if ($errors.Count -gt 0) { throw ($errors -join ' | ') }
Write-Output 'RESTORED'`, true, 30000)
  if (!String(stdout).split(/\r?\n/).includes('RESTORED')) throw new Error('Firewall rollback read-back was not confirmed')
}
export async function disableKillSwitch(reason: string): Promise<FirewallKillSwitchResult> {
  return serializeFirewall(() => disableKillSwitchUnlocked(reason))
}
async function disableKillSwitchUnlocked(reason: string): Promise<FirewallKillSwitchResult> {
  if (process.platform !== 'win32') {
    return { success: true, message: 'Firewall kill-switch недоступен (не Windows)' }
  }

  try {
    await timedFirewallPhase('restore-policy', () => restoreAndCleanup())
    await timedFirewallPhase('clear-journal', clearManifest)
  } catch (err: any) {
    logEvent('warn', 'firewall-killswitch', 'failed to fully restore kill-switch', err)
    return {
      success: false,
      message: 'Часть правил kill-switch не снялась — проверьте Windows Firewall вручную',
      details: err?.stderr || err?.message || String(err)
    }
  }

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
      `(Get-VpnteFirewallRuleNames -DisplayName '${RULE_PREFIX}*' -ErrorAction Stop | Measure-Object).Count`,
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
  if (manifest?.strictMode || await strictRecoveryRequired()) {
    logEvent('info', 'firewall-killswitch', 'strict recovery keeps firewall blocked until explicit user action')
    return
  }
  const manifestSaysActive = manifest !== null
  const firewallSaysActive = manifestSaysActive || await probeFirewallForOurRules()
  const stuckBlockDefault = false // A foreign Block policy is not evidence of VPNTE ownership.
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
$rules = (Get-VpnteFirewallRuleNames -DisplayName '${RULE_PREFIX}*' -ErrorAction Stop | Measure-Object).Count
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
