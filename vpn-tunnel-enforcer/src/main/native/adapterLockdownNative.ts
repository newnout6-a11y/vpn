// AT-03-006/007/010/011/012: mutations have a separate owner from the native read host.
// A dispatched batch is never replayed and cancellation cannot release its owner
// before child.close. The existing durable manifest remains the recovery authority.
import { spawn } from 'child_process'
import { existsSync } from 'fs'
import { join } from 'path'
import { release } from 'os'
import { isIP } from 'net'
import { app } from 'electron'
import { isProcessElevated } from '../admin'
import { getPrivilegedRuntimeDir } from '../runtimePaths'
import { ensureElevatedRuntimeDirHardened, verifyDirectoryHardened } from '../runtimeDirSecurity'
import { stageVerifiedRuntimeArtifact } from '../runtimeArtifact'
import { logEvent } from '../appLogger'

export interface LockdownAdapter {
  interfaceGuid?: string
  isCellularOrTethering?: boolean
  ipv6Enabled: boolean
  forcedIpv6Off: boolean
  forcedDnsTo: string[] | null
  ipv4DnsSource?: 'dhcp' | 'static' | 'unknown'
  ipv4DnsServers: string[]
}
export interface AdapterCommand { guid: string; ipv6: 'off' | 'on' | 'skip' | 'noop'; dns: 'set' | 'restore' | 'reset' | 'skip' | 'noop'; servers: string[] }
const GUID = /^(?:[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$/i
const BINARY = 'vpnte-adapter-lockdown.exe'

export function encodeAdapterCommands(commands: AdapterCommand[]): string {
  if (!commands.length || commands.length > 256) throw new Error('Invalid adapter command count')
  const seen = new Set<string>()
  const lines = commands.map((c, index) => {
    const guid = c.guid.replace(/^\{(.*)\}$/, '$1').toLowerCase()
    if (!GUID.test(guid) || /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(guid) || seen.has(guid) || !['off','on','skip','noop'].includes(c.ipv6) ||
        !['set','restore','reset','skip','noop'].includes(c.dns) || !Array.isArray(c.servers) || c.servers.length > 16 || new Set(c.servers).size !== c.servers.length ||
        c.servers.some(s => typeof s !== 'string' || isIP(s) !== 4) ||
        (['set','restore'].includes(c.dns) ? !c.servers.length : !!c.servers.length)) throw new Error('Invalid adapter command')
    seen.add(guid)
    return `${index}|{${guid}}|${c.ipv6}|${c.dns}|${c.servers.join(',') || '-'}`
  })
  return `VPNTE_LOCKDOWN_V1\n${lines.join('\n')}\n`
}

function cancelled(signal?: AbortSignal): void {
  if (signal?.aborted) throw Object.assign(new Error('Adapter apply cancelled before dispatch'), { code: 'physical-lockdown-cancelled-before-dispatch' })
}

export function checkAdapterReceipt(output: string, commands: AdapterCommand[]): string {
  const lines = output.trim().split(/\r?\n/)
  if (lines.length > commands.length * 5 + 32 || lines.some(line =>
    !/^A\d+_(?:ipv6|dns)(?::(?:off|on|skip|noop|already-off|changed|set|reset|restore)|_err: native code=\d+)$/.test(line) &&
    !/^NATIVE_TIMING phase=[a-z-]+ durationMs=\d+(?:\.\d+)?$/.test(line))) throw new Error('Invalid native adapter receipt')
  for (let i = 0; i < commands.length; i++) for (const field of ['ipv6', 'dns']) {
    const records = lines.filter(line => line.startsWith(`A${i}_${field}:`) || line.startsWith(`A${i}_${field}_err:`))
    // IPv6 changed/already-off is supplementary; exactly one outcome is mandatory.
    const outcomes = records.filter(line => !/:changed$|:already-off$/.test(line))
    if (outcomes.length !== 1) throw new Error('Incomplete native adapter receipt')
    const expected = field === 'ipv6' ? commands[i].ipv6 : commands[i].dns
    if (!outcomes[0].includes('_err:') && outcomes[0] !== `A${i}_${field}:${expected}`) throw new Error('Mismatched native adapter receipt')
    if (records.length > outcomes.length && (field !== 'ipv6' || expected !== 'off')) throw new Error('Unexpected supplementary adapter receipt')
  }
  if (lines.some(line => /^A\d+_/.test(line) && Number(line.slice(1).split('_')[0]) >= commands.length)) throw new Error('Foreign native adapter receipt')
  return output
}

async function executable(): Promise<string | null> {
  if (process.platform !== 'win32' || process.arch !== 'x64' || process.env.VPNTE_DISABLE_NATIVE_LOCKDOWN === '1' ||
      Number(release().split('.')[2]) < 19041) return null
  const source = app.isPackaged ? join(process.resourcesPath, BINARY) : join(process.cwd(), 'resources', BINARY)
  if (!existsSync(source) || !await isProcessElevated()) return null
  const dir = getPrivilegedRuntimeDir('tun-runtime')
  if (!(await ensureElevatedRuntimeDirHardened(dir, 'adapter-lockdown-native')).hardened) throw new Error('Native adapter runtime untrusted')
  const destination = join(dir, BINARY)
  await stageVerifiedRuntimeArtifact(source, destination)
  if (!(await verifyDirectoryHardened(dir)).hardened) throw new Error('Native adapter runtime ACL not verified')
  return destination
}

export async function runAdapterCommands(commands: AdapterCommand[], signal?: AbortSignal, mode: '--batch' | '--restore' = '--batch'): Promise<string | null> {
  cancelled(signal)
  if (!commands.length) return null
  const input = encodeAdapterCommands(commands)
  if (commands.every(c => ['skip', 'noop'].includes(c.ipv6) && ['skip', 'noop'].includes(c.dns))) {
    return commands.map((c, i) => `A${i}_ipv6:${c.ipv6}\nA${i}_dns:${c.dns}\n`).join('')
  }
  const path = await executable()
  cancelled(signal)
  if (path === null) return null // Only an explicit, pre-dispatch capability fallback.
  const started = performance.now()
  const output = await new Promise<string>((resolve, reject) => {
    const child = spawn(path, [mode], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] })
    let stdout = '', invalid = false, failed = false
    const warning = setTimeout(() => logEvent('warn', 'phys-lockdown', 'native adapter batch still pending; recovery owner retained'), 30000)
    child.stdout.on('data', (chunk: Buffer) => { if (stdout.length + chunk.length > 262144) invalid = true; else stdout += chunk.toString('utf8') })
    child.stderr.on('data', () => { failed = true }) // Never expose native paths/topology/error text.
    child.on('error', () => { failed = true })
    child.stdin.on('error', () => { failed = true })
    child.on('close', code => {
      clearTimeout(warning)
      // Exit 1 with a complete error receipt is a known partial outcome. Preserve
      // successful independent recovery fields; a crash/malformed receipt is unknown.
      if (invalid || failed || (code !== 0 && code !== 1)) reject(new Error('Native adapter batch did not complete; recovery journal retained'))
      else if (code === 1 && !/_err: native code=\d+/.test(stdout)) reject(new Error('Native adapter batch failed without receipt'))
      else { try { resolve(checkAdapterReceipt(stdout, commands)) } catch (err) { reject(err) } }
    })
    // No AbortSignal/timeout kills a mutating child. Once admitted, wait for
    // its complete receipt/exit; lifecycle cancellation compensates afterwards.
    child.stdin.end(input)
  }).catch(() => {
    logEvent('warn', 'phys-lockdown', 'native adapter batch outcome unverified; recovery journal retained')
    return commands.map((_, i) => `A${i}_ipv6_err: native code=1\nA${i}_dns_err: native code=1`).join('\n') + '\n'
  })
  logEvent('debug', 'phys-lockdown', 'native adapter batch timing', { durationMs: Math.round(performance.now() - started), adapters: commands.length })
  return output
}

export function applyNativeAdapterLockdown(adapters: LockdownAdapter[], dns: string, forceDns: boolean, signal?: AbortSignal): Promise<string | null> {
  return runAdapterCommands(adapters.map(a => ({ guid: a.interfaceGuid || '', ipv6: a.isCellularOrTethering ? 'skip' : 'off',
    dns: forceDns ? 'set' : 'skip', servers: forceDns ? [dns] : [] })), signal)
}

export function restoreNativeAdapterLockdown(adapters: LockdownAdapter[], resetDnsToDhcp: boolean): Promise<string | null> {
  return runAdapterCommands(adapters.map(a => {
    const restoreDns = !!a.forcedDnsTo?.length
    const reset = resetDnsToDhcp || a.ipv4DnsSource !== 'static'
    return { guid: a.interfaceGuid || '', ipv6: a.forcedIpv6Off && a.ipv6Enabled ? 'on' : 'noop',
      dns: !restoreDns ? 'noop' : reset ? 'reset' : 'restore', servers: restoreDns && !reset ? a.ipv4DnsServers : [] }
  }), undefined, '--restore')
}
