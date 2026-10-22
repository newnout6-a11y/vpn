import type { SystemNetworkResult } from '../shared/network'
export type { SystemNetworkResult } from '../shared/network'
import { execFile as execFileCb } from 'child_process'
import { promisify } from 'util'
import { randomUUID } from 'crypto'
import { execElevated } from './admin'
import { logEvent } from './appLogger'
import { timePs } from './psTiming'
import { ipcError, IpcFault, type IpcErrorCategory } from '../shared/ipc-result'
import { classifyRecoveryError } from './recoveryErrors'
import { notifyWinInetSettingsChangedNative, WinInetCallError } from './native/winInet'
import { readRecoveryManifest, writeRecoveryManifest, removeRecoveryManifest, recoveryManifestPath } from './recoveryManifest'

const execFile = promisify(execFileCb)
const BASELINE_NAME = 'latest-tun-network-baseline.json'
const PROXY_ENV_KEYS = ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy']
const TARGETS = {
  internet: { key: 'Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings', names: ['ProxyEnable', 'ProxyServer', 'AutoConfigURL', 'AutoDetect'] },
  environment: { key: 'Environment', names: ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY'] },
  winhttp: { key: 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections', names: ['WinHttpSettings'] }
} as const
interface RegistrySnapshot {
  target: keyof typeof TARGETS
  name: string
  exists: boolean
  kind: 'String' | 'ExpandString' | 'DWord' | 'QWord' | 'Binary' | 'MultiString' | null
  data: string | number | string[] | number[] | null
}
export interface NetworkBackupManifest {
  schemaVersion: 1
  owner: 'VPNTE'
  createdAt: number
  userSid: string
  values: RegistrySnapshot[]
}

// No paths, registry keys, executable commands or import files come from disk.
// The whitelist defines every value VPNTE may modify or restore.
// Only recovery supplies rejected, after the storage layer verifies ACL/owner.
export function validateNetworkBackupManifest(value: unknown, rejected?: string[]): NetworkBackupManifest {
  const v = value as NetworkBackupManifest
  if (!v || v.schemaVersion !== 1 || v.owner !== 'VPNTE' || !Number.isSafeInteger(v.createdAt) || v.createdAt <= 0 ||
      typeof v.userSid !== 'string' || !/^S-1-5-21-\d+-\d+-\d+-\d+$/.test(v.userSid) || !Array.isArray(v.values) ||
      (rejected ? v.values.length > 9 : v.values.length !== 9)) {
    throw new Error('Invalid network baseline schema or identity')
  }
  const seen = new Set<string>()
  const values = v.values.flatMap((s, index) => {
    try {
    if (!s || !Object.hasOwn(TARGETS, s.target) || typeof s.name !== 'string' ||
        !(TARGETS[s.target].names as readonly string[]).includes(s.name) || typeof s.exists !== 'boolean') throw new Error('Invalid baseline registry target')
    const id = `${s.target}/${s.name}`
    // Reject every conflicting entry, including the first; disk order is not authority.
    if (v.values.filter(other => other?.target === s.target && other?.name === s.name).length !== 1) throw new Error('Duplicate baseline registry target')
    seen.add(id)
    let valid = !s.exists && s.kind === null && s.data === null
    if (s.exists) {
      switch (s.kind) {
        case 'String': case 'ExpandString': valid = typeof s.data === 'string' && s.data.length <= 65536; break
        case 'DWord': valid = Number.isInteger(s.data) && Number(s.data) >= -2147483648 && Number(s.data) <= 2147483647; break
        // QWords are serialized as decimal text to avoid loss of precision in JS.
        case 'QWord': valid = typeof s.data === 'string' && /^-?\d{1,19}$/.test(s.data) && BigInt(s.data) >= -(1n << 63n) && BigInt(s.data) < (1n << 63n); break
        case 'Binary': valid = Array.isArray(s.data) && s.data.length <= 65536 && s.data.every(x => Number.isInteger(x) && Number(x) >= 0 && Number(x) <= 255); break
        case 'MultiString': valid = Array.isArray(s.data) && s.data.length <= 1024 && s.data.every(x => typeof x === 'string' && x.length <= 65536); break
      }
    }
    if (!valid) throw new Error('Invalid baseline registry value or type')
    return [{ target: s.target, name: s.name, exists: s.exists, kind: s.kind, data: s.data }]
    } catch (error) {
      if (!rejected) throw error
      rejected.push(`baseline entry ${index}: invalid or conflicting snapshot; skipped`)
      return []
    }
  })
  if (rejected) for (const [target, spec] of Object.entries(TARGETS)) {
    for (const name of spec.names) if (!seen.has(`${target}/${name}`)) rejected.push(`${target}/${name}: missing snapshot; skipped`)
  }
  return { schemaVersion: 1, owner: 'VPNTE', createdAt: v.createdAt, userSid: v.userSid, values }
}

let baselineOpQueue: Promise<unknown> = Promise.resolve()
function withBaselineOpLock<T>(operation: () => Promise<T>): Promise<T> {
  const result = baselineOpQueue.then(operation, operation)
  baselineOpQueue = result.then(() => undefined, () => undefined)
  return result
}
export function getTunNetworkBaselineManifestPath(): string { return recoveryManifestPath(BASELINE_NAME) }
function readManifest(rejected?: string[]) { return readRecoveryManifest(BASELINE_NAME, value => validateNetworkBackupManifest(value, rejected)) }
export async function isBaselineApplied(recovery = false): Promise<boolean> { return (await readManifest(recovery ? [] : undefined)) !== null }
function psJson(value: unknown): string { return `[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${Buffer.from(JSON.stringify(value)).toString('base64')}')) | ConvertFrom-Json` }
function ps(script: string, elevated = false, timeout = 30000, operationId?: string) {
  return timePs('cold-ps', elevated ? 'system-network-elevated' : 'system-network', () => psUntimed(script, elevated, timeout, operationId))
}
async function psUntimed(script: string, elevated: boolean, timeout: number, operationId?: string) {
  const prelude = '$OutputEncoding=[Console]::OutputEncoding=[Text.UTF8Encoding]::new();$ErrorActionPreference="Stop";'
  const command = `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ${Buffer.from(prelude + script, 'utf16le').toString('base64')}`
  try {
    if (elevated) return await execElevated(command, { timeout, maxBuffer: 4 * 1024 * 1024 })
    return await execFile('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand',
      Buffer.from(prelude + script, 'utf16le').toString('base64')
    ], { windowsHide: true, timeout, maxBuffer: 4 * 1024 * 1024, encoding: 'utf8' })
  } catch (error) {
    // Log the actual failure before the length limit, without the snapshot.
    const failure = error as { stderr?: string; code?: string | number; message?: string }
    const diagnostic = String(failure.stderr || failure.message || error)
      .replace(/-EncodedCommand\s+[A-Za-z0-9+/=]+/g, '-EncodedCommand [omitted]').trim()
    logEvent('error', 'system-network', 'PowerShell failed', { diagnostic: diagnostic.slice(0, 2000), code: failure.code, operationId })
    throw new IpcFault(classifyRecoveryError(error))
  }
}
// Shared snapshot/restore code uses .NET APIs: no locale-dependent reg parsing.
const REGISTRY_HELPERS = `
$targets = ${psJson(TARGETS)}
function Get-BaseKey($target) {
  if ($target -eq 'winhttp') { return [Microsoft.Win32.Registry]::LocalMachine }
  return [Microsoft.Win32.Registry]::CurrentUser
}
function Get-Snapshot($target, $name) {
  $key = (Get-BaseKey $target).OpenSubKey($targets.$target.key)
  try {
    $exists = $key -and @($key.GetValueNames()) -contains $name
    $kind = $null; $data = $null
    if ($exists) {
      $kind = [string]$key.GetValueKind($name)
      $data = $key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
      if ($kind -eq 'QWord') { $data = [string]$data }
      if ($kind -eq 'Binary' -or $kind -eq 'MultiString') { $data = @($data) }
    }
    return [pscustomobject]@{target=$target;name=$name;exists=[bool]$exists;kind=$kind;data=$data}
  } finally { if ($key) { $key.Close() } }
}
function Restore-Snapshot($s) {
  $key = (Get-BaseKey $s.target).CreateSubKey($targets.($s.target).key)
  try {
    if ($s.exists) {
      $data = $s.data
      switch ($s.kind) {
        'DWord' { $data = [int]$s.data }
        'QWord' { $data = [long]$s.data }
        'Binary' { $data = [byte[]]@($s.data) }
        'MultiString' { $data = [string[]]@($s.data) }
      }
      $key.SetValue($s.name,$data,[Enum]::Parse([Microsoft.Win32.RegistryValueKind],[string]$s.kind))
    } else { $key.DeleteValue($s.name,$false) }
  } finally { $key.Close() }
  $actual = Get-Snapshot $s.target $s.name
  if ($actual.exists -ne $s.exists -or $actual.kind -cne $s.kind -or
      ($actual.data | ConvertTo-Json -Compress -Depth 5) -cne ($s.data | ConvertTo-Json -Compress -Depth 5)) { throw 'Registry read-back mismatch' }
}
`
async function createBackup(): Promise<NetworkBackupManifest> {
  const { stdout } = await ps(`${REGISTRY_HELPERS}
$values = @()
foreach ($target in @('internet','environment','winhttp')) {
  foreach ($name in $targets.$target.names) { $values += Get-Snapshot $target $name }
}
[pscustomobject]@{schemaVersion=1;owner='VPNTE';createdAt=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();userSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;values=$values} | ConvertTo-Json -Depth 8 -Compress`)
  const manifest = validateNetworkBackupManifest(JSON.parse(String(stdout).replace(/^\uFEFF/, '').trim()))
  await writeRecoveryManifest(BASELINE_NAME, manifest, validateNetworkBackupManifest)
  return manifest
}
const WININET_NOTIFY_FUNCTION = `
function Send-WinInetSettingsChanged {
$sig='[DllImport("wininet.dll", SetLastError=true)] public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);'
$type=Add-Type -MemberDefinition $sig -Name WinInet -Namespace Native -PassThru
if (-not $type::InternetSetOption([IntPtr]::Zero,39,[IntPtr]::Zero,0)) { throw 'WinINet settings notification failed' }
if (-not $type::InternetSetOption([IntPtr]::Zero,37,[IntPtr]::Zero,0)) { throw 'WinINet refresh failed' }
}
`
async function notifyWinInetSettingsChanged(operationId?: string, deadline = Infinity) {
  const requireTime = () => { if (performance.now() >= deadline) throw new IpcFault('timeout') }
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    requireTime()
    const pending = notifyWinInetSettingsChangedNative()
    if (Number.isFinite(deadline)) {
      await Promise.race([pending, new Promise<void>((_resolve, reject) => {
        timer = setTimeout(() => reject(new IpcFault('timeout')), Math.max(0, Math.floor(deadline - performance.now())))
      })])
    } else await pending
    requireTime()
    return
  } catch (error) {
    // A real WinINet failure is authoritative. Only an unusable native binding falls back (fail closed).
    if (error instanceof WinInetCallError) throw error
    requireTime()
    logEvent('warn', 'system-network', 'native WinINet notification unavailable; falling back to PowerShell', { error: String(error), operationId })
  } finally { clearTimeout(timer) }
  const timeout = Math.min(10000, Math.floor(deadline - performance.now()))
  if (timeout <= 0) throw new IpcFault('timeout')
  await ps(`${WININET_NOTIFY_FUNCTION}\nSend-WinInetSettingsChanged`, false, timeout, operationId)
  requireTime()
}

export function applyTunNetworkBaseline(): Promise<SystemNetworkResult> { return withBaselineOpLock(applyUnlocked) }
async function applyUnlocked(): Promise<SystemNetworkResult> {
  if (process.platform !== 'win32') return { success: false, error: ipcError('conflict'), message: 'Сетевой baseline доступен только на Windows' }
  let prepared = false
  try {
    if (await readManifest()) return { success: true, skipped: true, message: 'Baseline уже применён; исходный снимок сохранён' }
    await createBackup() // Mandatory durable commit before any registry or WinHTTP changes.
    prepared = true
    await execElevated('netsh winhttp reset proxy', { timeout: 10000 })
    const { stdout } = await ps(`${REGISTRY_HELPERS}
foreach ($name in $targets.internet.names) {
  $s = [pscustomobject]@{target='internet';name=$name;exists=$false;kind=$null;data=$null}
  if ($name -in @('ProxyEnable','AutoDetect')) { $s.exists=$true; $s.kind='DWord'; $s.data=0 }
  Restore-Snapshot $s
}
foreach ($name in $targets.environment.names) { Restore-Snapshot ([pscustomobject]@{target='environment';name=$name;exists=$false;kind=$null;data=$null}) }
Write-Output 'BASELINE_APPLIED'`)
    if (!String(stdout).includes('BASELINE_APPLIED')) throw new Error('Baseline application verification missing')
    await notifyWinInetSettingsChanged()
    for (const key of PROXY_ENV_KEYS) delete process.env[key]
    return { success: true, message: 'Сеть нормализована для TUN', warnings: [] }
  } catch (error) {
    const failure = ipcError(classifyRecoveryError(error))
    const warnings = [failure.message]
    let restoredSteps: string[] | undefined
    if (prepared) {
      const rollback = await rollbackUnlocked()
      restoredSteps = rollback.restoredSteps
      if (!rollback.success) warnings.push(...(rollback.warnings || [rollback.message]))
    }
    logEvent('error', 'system-network', 'baseline application failed', { error: String(error), warnings })
    return { success: false, error: failure, message: 'Baseline не применён; проверьте отчёт восстановления', ...(restoredSteps ? { restoredSteps } : {}), warnings, details: warnings.join(' | ') }
  }
}
export function rollbackTunNetworkBaseline(): Promise<SystemNetworkResult> { return withBaselineOpLock(() => rollbackUnlocked()) }
async function rollbackUnlocked(reason = 'manual', operationId: string = `baseline_${randomUUID().replaceAll('-', '')}`): Promise<SystemNetworkResult> {
  if (process.platform !== 'win32') return { success: false, error: ipcError('conflict'), message: 'Rollback доступен только на Windows' }
  logEvent('info', 'system-network', 'baseline rollback started', { operationId, reason })
  let restoredSteps: string[] | undefined
  try {
    const warnings: string[] = []
    const manifest = await readManifest(warnings)
    if (!manifest) {
      logEvent('info', 'system-network', 'baseline rollback completed', { operationId, success: true, skipped: true })
      return { success: true, operationId, skipped: true, message: 'Активный VPNTE network baseline не найден' }
    }
    for (const error of warnings) logEvent('error', 'system-network', 'baseline rollback step rejected', { operationId, error, success: false })
    if (!manifest.values.length) {
      logEvent('error', 'system-network', 'baseline rollback completed', { operationId, success: false, warnings })
      return { success: false, error: ipcError('validation'), operationId, message: 'Нет валидных шагов baseline; снимок сохранён', warnings, restoredSteps: [] }
    }
    const hasRejectedRecords = warnings.length > 0
    const recoveryDeadline = performance.now() + 30000
    const { stdout } = await ps(`${REGISTRY_HELPERS}
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne '${manifest.userSid}') { throw 'Baseline user identity mismatch' }
# ConvertFrom-Json emits the decoded array as one pipeline object in Windows
# PowerShell 5.1. An extra @() would nest it and collapse nine steps into one.
$values = ${psJson(manifest.values)}
function Get-RecoveryErrorCategory($failure) {
  if ($failure.CategoryInfo.Category -in @('PermissionDenied','SecurityError')) { return 'permission' }
  for ($exception = $failure.Exception; $null -ne $exception; $exception = $exception.InnerException) {
    if ($exception -is [UnauthorizedAccessException] -or $exception -is [System.Security.SecurityException] -or $exception.HResult -eq -2147024891) { return 'permission' }
  }
  return 'internal'
}
$results = @()
$watch = [Diagnostics.Stopwatch]::StartNew()
foreach ($s in $values) {
  try { Restore-Snapshot $s; $results += [pscustomobject]@{name=($s.target+'/'+$s.name);success=$true;error=$null} }
  catch { $results += [pscustomobject]@{name=($s.target+'/'+$s.name);success=$false;error=[string]$_;category=(Get-RecoveryErrorCategory $_)} }
}
$registryMs = $watch.ElapsedMilliseconds
$watch.Stop()
[pscustomobject]@{steps=@($results);timings=@{registryMs=$registryMs}} | ConvertTo-Json -Depth 6 -Compress`, true, 30000, operationId)
    const report = JSON.parse(String(stdout).trim()) as {
      steps: Array<{ name: string; success: boolean; error: string | null; category?: IpcErrorCategory }>
      timings: { registryMs: number }
    }
    const validOutcome = (s: { success: boolean; error: string | null; category?: IpcErrorCategory }) => s && typeof s.success === 'boolean' && (s.success ? s.error === null : typeof s.error === 'string' && (s.category === 'permission' || s.category === 'internal'))
    const steps = report?.steps
    if (!Array.isArray(steps) || steps.length !== manifest.values.length || steps.some((s, i) => !validOutcome(s) || s.name !== `${manifest.values[i].target}/${manifest.values[i].name}`) ||
        !report.timings || !Number.isSafeInteger(report.timings.registryMs) || report.timings.registryMs < 0) throw new Error('Invalid baseline recovery report')
    logEvent('debug', 'system-network', 'baseline native phase timing', { operationId, phase: 'registryMs', durationMs: report.timings.registryMs })
    restoredSteps = steps.filter(step => step.success).map(step => step.name)
    // Keep the operation lock and durable journal until notification also settles.
    // A real WinINet false is authoritative; only unavailable bindings use the existing fallback.
    let notification: { success: boolean; error: string | null; category?: IpcErrorCategory } = { success: true, error: null }
    const notifyStarted = performance.now()
    try { await notifyWinInetSettingsChanged(operationId, recoveryDeadline) }
    catch (error) { notification = { success: false, error: String(error), category: classifyRecoveryError(error) } }
    logEvent('debug', 'system-network', 'baseline native phase timing', { operationId, phase: 'notifyMs', durationMs: Math.round(performance.now() - notifyStarted) })
    for (const step of steps) {
      logEvent(step.success ? 'info' : 'error', 'system-network', 'baseline rollback step', { ...step, operationId })
      if (!step.success) warnings.push(`${step.name}: ${ipcError(step.category!).message}`)
    }
    logEvent(notification.success ? 'info' : 'error', 'system-network', 'baseline rollback notification', { ...notification, operationId })
    if (!notification.success) warnings.push(`WinINet: ${ipcError(notification.category!).message}`)
    if (warnings.length) {
      logEvent('error', 'system-network', 'baseline rollback completed', { operationId, success: false, warnings })
      const category = steps.some(s => !s.success && s.category === 'permission') || notification.category === 'permission' ? 'permission'
        : hasRejectedRecords ? 'validation' : notification.category ?? 'internal'
      const message = `Baseline восстановлен частично: ${restoredSteps.length} из 9 записей; снимок сохранён.${notification.success ? '' : ' Уведомление Windows не подтверждено.'}`
      return { success: false, error: ipcError(category), operationId, message, restoredSteps, warnings, details: warnings.join(' | ') }
    }
    await removeRecoveryManifest(BASELINE_NAME)
    logEvent('info', 'system-network', 'baseline rollback completed', { operationId, success: true })
    return { success: true, operationId, message: 'Сетевые настройки восстановлены и проверены', restoredSteps, details: `Backup created at: ${new Date(manifest.createdAt).toISOString()}` }
  } catch (error) {
    logEvent('error', 'system-network', 'CRITICAL_SECURITY_EVENT: baseline recovery unknown', { operationId, error: String(error) })
    const failure = ipcError(classifyRecoveryError(error))
    return { success: false, error: failure, operationId,
      message: `Baseline recovery не подтверждён; снимок сохранён.${restoredSteps ? ` Подтверждено восстановление записей: ${restoredSteps.length}.` : ''}`,
      ...(restoredSteps ? { restoredSteps } : {}), warnings: [failure.message] }
  }
}
export function rollbackTunNetworkBaselineIfApplied(reason: string, operationId?: string): Promise<SystemNetworkResult> {
  if (process.platform !== 'win32') return Promise.resolve({ success: true, skipped: true, message: 'Rollback недоступен (не Windows)' })
  return withBaselineOpLock(() => rollbackUnlocked(reason, operationId))
}

/** For recovery callers using catch: trusted absence is a no-op; partial recovery rejects. */
export async function rollbackTunNetworkBaselineOrThrow(reason: string): Promise<SystemNetworkResult> {
  const result = await rollbackTunNetworkBaselineIfApplied(reason)
  if (!result.success) {
    const details = result.details || result.warnings?.join(' | ')
    const fault = new IpcFault(result.error?.category ?? 'internal')
    fault.message = `${result.message}${details ? `: ${details}` : ''}. Повторите восстановление сети и проверьте диагностику.`
    throw fault
  }
  return result
}
