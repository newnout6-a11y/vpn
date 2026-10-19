/**
 * Build a ZIP bundle the user can hand to support: app log, sing-box log,
 * settings, baseline manifest, kill-switch manifest, system info.
 *
 * Uses PowerShell's built-in `Compress-Archive` so we don't need a new npm
 * dependency for a one-off feature. The whole app is Windows-only at runtime
 * anyway, so this is fine.
 *
 * Output: `%USERPROFILE%/Desktop/vpn-tunnel-enforcer-diagnostics-<ts>.zip`
 *  (or whichever directory the user picks via the save dialog).
 */
import { execFile as execFileCb } from 'child_process'
import { dialog, app, ipcMain, type WebContents } from 'electron'
import { createReadStream } from 'node:fs'
import { finished } from 'node:stream/promises'
import { operations } from './operations'
import type { OperationLease } from './operationRegistry'
import { runRequesterOperation } from './requesterOperation'
import { captureSnapshot } from './systemSnapshot'
import { writeConfigExport } from './configOperationIo'
import { ioFailureDetails } from './ioFailureDiagnostics'
import { IpcFault } from '../shared/ipc-result'
import { mkdtemp, writeFile, copyFile, readdir, rm, readFile, mkdir, stat } from 'fs/promises'
import { existsSync } from 'fs'
import { tmpdir, hostname, release, type as osType, arch as osArch, totalmem, freemem, cpus } from 'os'
import { join } from 'path'
import { promisify } from 'util'
import { logEvent, getFullLogs } from './appLogger'
import { settingsStore } from './settings'
import { runSystemDiagnostics } from './systemDiagnostics'
import { stageTrafficForensicsArtifacts } from './trafficForensics'
import { getTunRuntimeDir } from './tunController'
import { redactSensitiveConfig, redactSensitiveText, redactSettingsForDiagnostics } from './vpnProfiles'
import { validateNetworkBackupManifest } from './systemNetwork'
import { validateFirewallManifest } from './firewallKillSwitch'
import { validateLockdownManifest } from './physicalAdapterLockdown'
import { readRecoveryManifest, validateBootRecoveryReport } from './recoveryManifest'

const execFile = promisify(execFileCb)
const DIAGNOSTICS_SNAPSHOT_RECENT_MS = 2 * 60 * 60 * 1000
const DIAGNOSTICS_SNAPSHOT_MAX_FILES = 40

function encodedPowerShell(script: string): string {
  return Buffer.from(script, 'utf-16le').toString('base64')
}

function psQuote(value: string): string {
  return `'${value.replace(/'/g, "''")}'`
}

interface ExportResult {
  success: boolean
  path?: string
  error?: string
  cancelled?: boolean
  warning?: 'cleanup-failed'
}

async function snapshotSystemInfo(): Promise<string> {
  const info = {
    timestamp: new Date().toISOString(),
    hostname: hostname(),
    osType: osType(),
    osRelease: release(),
    arch: osArch(),
    totalMemMB: Math.round(totalmem() / 1024 / 1024),
    freeMemMB: Math.round(freemem() / 1024 / 1024),
    cpuCount: cpus().length,
    cpuModel: cpus()[0]?.model ?? 'unknown',
    appVersion: app.getVersion(),
    electronVersion: process.versions.electron,
    nodeVersion: process.versions.node
  }
  return JSON.stringify(info, null, 2)
}

async function copyIfExists(src: string, dst: string): Promise<boolean> {
  try {
    if (!existsSync(src)) return false
    await copyFile(src, dst)
    return true
  } catch (err) {
    logEvent('warn', 'diag-export', 'failed to copy file', { src, err: (err as Error)?.message })
    return false
  }
}

const REDACTABLE_DIAGNOSTIC_FILE_RE = /\.(?:json|jsonl|ndjson|log|txt|csv|md|manifest)$/i

export async function redactStagedDiagnostics(root: string, assertActive: () => void = () => {}): Promise<void> {
  assertActive()
  const entries = await readdir(root, { withFileTypes: true })
  assertActive()
  for (const entry of entries) {
    const path = join(root, entry.name)
    if (entry.isDirectory()) {
      await redactStagedDiagnostics(path, assertActive)
      continue
    }
    if (!entry.isFile() || !REDACTABLE_DIAGNOSTIC_FILE_RE.test(entry.name)) continue

    const raw = await readFile(path, 'utf8')
    assertActive()
    if (/\.json$/i.test(entry.name)) {
      try {
        const parsed = JSON.parse(raw)
        await writeFile(path, JSON.stringify(redactSensitiveConfig(parsed), null, 2), 'utf8')
        assertActive()
        continue
      } catch {
        assertActive()
        // Malformed JSON is still text and must pass through the final scrub.
      }
    }
    await writeFile(path, redactSensitiveText(raw), 'utf8')
    assertActive()
  }
}

/** Diagnostics use the same trusted, schema-checked artifacts as recovery.
 * AppData copies are not authoritative and must never masquerade as baseline.
 * Redact before writing to the staging directory, not only before compression.
 */
export async function stageRecoveryManifests(root: string, assertActive: () => void = () => {}): Promise<void> {
  assertActive()
  const artifacts = [
    ['latest-tun-network-baseline.json', 'baseline-manifest.json', validateNetworkBackupManifest],
    ['firewall.json', 'killswitch-manifest.json', validateFirewallManifest],
    ['latest-physical-adapter-lockdown.json', 'adapter-lockdown-manifest.json', validateLockdownManifest],
    ['recovery-result.json', 'boot-recovery-result.json', validateBootRecoveryReport]
  ] as const
  const statuses: Array<{ artifact: string; status: string }> = []
  for (const [name, output, validate] of artifacts) {
    let value: unknown
    try {
      value = await readRecoveryManifest<unknown>(name, validate)
      assertActive()
    } catch {
      assertActive()
      statuses.push({ artifact: name, status: 'unavailable-or-untrusted' })
      logEvent('warn', 'diag-export', 'trusted recovery artifact unavailable', { artifact: name })
      continue
    }
    if (value === null) { statuses.push({ artifact: name, status: 'absent' }); continue }
    await writeFile(join(root, output), JSON.stringify(redactSensitiveConfig(value), null, 2), 'utf8')
    assertActive()
    statuses.push({ artifact: name, status: 'trusted-and-redacted' })
  }
  await writeFile(join(root, 'recovery-artifacts-status.json'), JSON.stringify(statuses, null, 2), 'utf8')
}

function snapshotTimeFromName(name: string): number | null {
  const match = name.match(/^snapshot-(\d{4}-\d{2}-\d{2}T\d{2})-(\d{2})-(\d{2})-(\d{3}Z)-/)
  if (!match) return null
  const parsed = Date.parse(`${match[1]}:${match[2]}:${match[3]}.${match[4]}`)
  return Number.isFinite(parsed) ? parsed : null
}

export async function exportDiagnosticsZip(sender: WebContents, requestId?: unknown): Promise<ExportResult> {
  try {
    return await runRequesterOperation(sender, requestId, (signal, admitted) => operations.run('export', async lease => {
      admitted(lease)
      // The snapshot belongs to this operation, including the shared collection queue.
      try { await lease.wait(captureSnapshot('manual', { signal: lease.signal, assertActive: () => lease.assertActive() })) }
      catch { lease.assertActive() }
      return buildDiagnosticsZip(lease)
    }, { signal, resource: 'diagnostics:export' }))
  } catch (error) {
    const details = ioFailureDetails(error)
    if (!(error instanceof IpcFault)) logEvent('error', 'diag-export', 'failed to build diagnostics zip', details)
    throw new IpcFault(details.reason)
  }
}

export function registerDiagnosticsExportHandler(): void {
  ipcMain.handle('export-diagnostics', (event, requestId?: unknown) => exportDiagnosticsZip(event.sender, requestId))
}

async function buildDiagnosticsZip(lease: OperationLease): Promise<ExportResult> {
  // Await raw settlement before cleanup; the registry separately bounds callers.
  const boundary = async <T>(task: Promise<T>): Promise<T> => {
    const value = await lease.retain(task)
    lease.assertActive()
    return value
  }
  // Ask the user where to drop the zip.
  const defaultName = `vpn-tunnel-enforcer-diagnostics-${new Date().toISOString().replace(/[:.]/g, '-')}.zip`
  const choice = await lease.waitForUser(dialog.showSaveDialog({
    title: 'Сохранить диагностику',
    defaultPath: join(app.getPath('desktop'), defaultName),
    filters: [{ name: 'ZIP archive', extensions: ['zip'] }]
  }))
  if (choice.canceled || !choice.filePath) {
    return { success: false, cancelled: true }
  }
  const targetZip = choice.filePath

  // Stage the bundle in a temp dir so we can ship it as one Compress-Archive.
  let stage: string | null = null
  let work: string | null = null
  const result: ExportResult = { success: true, path: targetZip }
  try {
    work = await mkdtemp(join(tmpdir(), 'vpnte-diag-'))
    lease.assertActive()
    stage = join(work, 'bundle')
    await boundary(mkdir(stage))

    // 1. Settings. Direct-VPN subscriptions/keys are secrets, redact them.
    await boundary(writeFile(join(stage, 'settings.json'), JSON.stringify(redactSettingsForDiagnostics(settingsStore.get()), null, 2), 'utf-8'))

    // 2. App logs (the in-memory + on-disk app log).
    const logs = await boundary(getFullLogs())
    await boundary(writeFile(join(stage, 'app-log.json'), JSON.stringify(logs, null, 2), 'utf-8'))

    // 3. System info snapshot.
    await boundary(writeFile(join(stage, 'system-info.json'), await boundary(snapshotSystemInfo()), 'utf-8'))

    // 4. Live diagnostics (route table, ipconfig, netsh dumps).
    try {
      const diagnostics = await boundary(runSystemDiagnostics(() => lease.assertActive()))
      await boundary(writeFile(join(stage, 'system-diagnostics.json'), JSON.stringify(diagnostics, null, 2), 'utf-8'))
    } catch (err) {
      lease.assertActive()
      logEvent('warn', 'diag-export', 'system diagnostics failed', { err: (err as Error)?.message })
    }

    // 5. sing-box runtime files (config, log, manifest if any).
    const runtime = getTunRuntimeDir()
    if (existsSync(runtime)) {
      try {
        const entries = await boundary(readdir(runtime))
        for (const name of entries) {
          // Skip the binaries themselves - they're huge and the user already
          // has them. Only ship configs/logs/manifests.
          if (/\.(json|log|txt|manifest)$/i.test(name)) {
            const src = join(runtime, name)
            const dst = join(stage, `runtime-${name}`)
            if (/\.json$/i.test(name)) {
              try {
                const parsed = JSON.parse(await boundary(readFile(src, 'utf-8')))
                await boundary(writeFile(dst, JSON.stringify(redactSensitiveConfig(parsed), null, 2), 'utf-8'))
              } catch {
                lease.assertActive()
                await boundary(writeFile(dst, '<redacted: runtime json>\n', 'utf-8'))
              }
            } else {
              try {
                await boundary(writeFile(dst, redactSensitiveText(await boundary(readFile(src, 'utf-8'))), 'utf-8'))
              } catch {
                lease.assertActive()
                await boundary(writeFile(dst, '<redacted: runtime log>\n', 'utf-8'))
              }
            }
          }
        }
      } catch (err) {
        lease.assertActive()
        logEvent('warn', 'diag-export', 'reading runtime dir failed', { err: (err as Error)?.message })
      }
    }

    // 6. Baseline manifest (so support can see what we changed in the registry).
    const userData = app.getPath('userData')
    await boundary(stageRecoveryManifests(stage, () => lease.assertActive()))

    // 6b. Snapshots dir - every captured network/system snapshot from app
    // start, every TUN start/stop, periodic 60s captures, and any
    // leak-detected event. This is the bulk of the support-relevant data.
    const snapshotsDir = join(userData, 'snapshots')
    if (existsSync(snapshotsDir)) {
      try {
        const stagedSnaps = join(stage, 'snapshots')
        await boundary(mkdir(stagedSnaps, { recursive: true }))
        const now = Date.now()
        const candidates = await boundary(Promise.all((await boundary(readdir(snapshotsDir)))
          .filter(name => /\.json$/i.test(name))
          .map(async (name) => {
            const src = join(snapshotsDir, name)
            const mtime = await boundary(stat(src).then(s => s.mtimeMs).catch(() => 0))
            return { name, src, time: snapshotTimeFromName(name) ?? mtime }
          })))
        const latestAppStart = candidates
          .filter(item => /-app-start\.json$/i.test(item.name))
          .sort((a, b) => b.time - a.time)[0]?.time ?? 0
        const recent = candidates
          .sort((a, b) => b.time - a.time)
          .filter(item =>
            item.time > 0 &&
            now - item.time <= DIAGNOSTICS_SNAPSHOT_RECENT_MS &&
            (!latestAppStart || item.time >= latestAppStart)
          )
          .slice(0, DIAGNOSTICS_SNAPSHOT_MAX_FILES)
        const selected = recent.length > 0
          ? recent
          : candidates.sort((a, b) => b.time - a.time).slice(0, Math.min(12, DIAGNOSTICS_SNAPSHOT_MAX_FILES))
        for (const { name, src } of selected.sort((a, b) => a.time - b.time)) {
          const dst = join(stagedSnaps, name)
          const raw = await boundary(readFile(src, 'utf-8'))
          try {
            const parsed = JSON.parse(raw)
            await boundary(writeFile(dst, JSON.stringify(redactSensitiveConfig(parsed), null, 2), 'utf-8'))
          } catch {
            lease.assertActive()
            await boundary(writeFile(dst, redactSensitiveText(raw), 'utf-8'))
          }
        }
      } catch (err) {
        lease.assertActive()
        logEvent('warn', 'diag-export', 'failed to copy snapshots', { err: (err as Error)?.message })
      }
    }

    let forensicsStaged = false
    try {
      forensicsStaged = await boundary(stageTrafficForensicsArtifacts(stage, () => lease.assertActive()))
    } catch (err) {
      lease.assertActive()
      logEvent('warn', 'diag-export', 'failed to stage traffic forensics artifacts', { err: (err as Error)?.message })
    }

    try {
      const refreshedLogs = await boundary(getFullLogs())
      await boundary(writeFile(join(stage, 'app-log.json'), JSON.stringify(redactSensitiveConfig(refreshedLogs), null, 2), 'utf-8'))
    } catch (err) {
      lease.assertActive()
      logEvent('warn', 'diag-export', 'failed to refresh app log after traffic forensics staging', { err: (err as Error)?.message })
    }

    // 7. README so the user/support knows what's inside.
    //
    // There used to be two READMEs here: this one, and a second that overwrote
    // it a few lines later. The first was written with Russian text that had
    // been through a UTF-8/Windows-1251 round-trip and was committed in that
    // mangled state, so the overwrite was the only reason users saw readable
    // text at all. One README, correctly encoded.
    const readme = `Диагностика VPN Tunnel Enforcer
Создано: ${new Date().toISOString()}

Содержимое:
  diagnostics-manifest.json         - версия приложения, runtime и политика редактирования секретов
  settings.json                     - текущие настройки приложения, секреты скрыты
  app-log.json                      - последние записи app/sing-box логов
  system-info.json                  - версия Windows, память, CPU, Electron/Node
  system-diagnostics.json           - маршруты, proxy, DNS, firewall и итог проверок
  runtime-*.json/log                - конфиг и логи sing-box, секреты скрыты
  baseline-manifest.json            - изменения WinHTTP/WinINet/env proxy
  killswitch-manifest.json          - правила Windows Firewall, созданные VPNTE
  adapter-lockdown-manifest.json    - изменения физических адаптеров (IPv6/DNS)
  snapshots/                        - снимки состояния сети и системы
  traffic-forensics/                - packet/WFP/DNS/TCP артефакты для глубокого разбора
  traffic-forensics/REDACTION.txt   - как именно псевдонимизированы эти артефакты

Про traffic-forensics:
  Адреса и домены заменены на устойчивые токены (<ip-public-1>, <domain-2>.ru
  и т.п.), одинаковые во всех файлах архива. Связки DNS → соединение → reset →
  drop разбираются как раньше, сами адреса в архив не попадают. Подробности —
  в traffic-forensics/REDACTION.txt.

  Raw-захваты пакетов (*.etl, *.pcapng, pktmon-trace.txt) в архив НЕ включены:
  они содержат payload целиком. Путь к ним локально есть в логе приложения —
  если поддержка попросит именно их, их нужно приложить осознанно.

Что в архиве всё равно остаётся:
  Имя компьютера, версия ОС, состав адаптеров, названия интерфейсов и структура
  маршрутов — этого требует разбор сетевых проблем.

Архив подготовлен для поддержки или повторного локального разбора.
`
    await boundary(writeFile(join(stage, 'README.txt'), readme, 'utf-8'))

    const topLevelFiles = await boundary(readdir(stage).catch(() => []))
    const diagnosticsManifest = {
      schemaVersion: 2,
      createdAt: new Date().toISOString(),
      appVersion: app.getVersion(),
      electronVersion: process.versions.electron,
      nodeVersion: process.versions.node,
      platform: process.platform,
      arch: process.arch,
      // Describe what is ACTUALLY done, per artifact class. The previous version
      // listed three lines about settings/runtime/logs and said nothing about
      // traffic-forensics, which at the time was copied verbatim — so a reader
      // reasonably concluded the whole bundle was scrubbed when the most
      // sensitive part of it was not.
      redaction: {
        settings: 'subscriptions, profile links and known secrets are redacted',
        runtimeJson: 'runtime JSON is parsed and sensitive values are redacted',
        logs: 'text logs are redacted with the same sensitive-pattern scrubber',
        snapshots: 'snapshot JSON goes through the same sensitive-value redaction as runtime JSON',
        trafficForensics: forensicsStaged
          ? 'IPs, IPv6, MACs and hostnames are replaced with stable per-export pseudonyms; ' +
            'address class (public/private) and public suffix are preserved so leak and ' +
            'split-routing analysis still work. See traffic-forensics/REDACTION.txt'
          : 'not included in this bundle',
        rawPacketCaptures: 'excluded entirely (*.etl, *.pcapng, pktmon-trace.txt) — payloads cannot be redacted',
        notRedacted: 'hostname, OS build, adapter names/aliases and route structure are kept — ' +
          'network diagnosis is not possible without them'
      },
      topLevelFiles: topLevelFiles.sort()
    }
    await boundary(writeFile(join(stage, 'diagnostics-manifest.json'), JSON.stringify(diagnosticsManifest, null, 2), 'utf-8'))

    // Last line of defence: copied manifests, third-party diagnostics and
    // future staged text files all pass through one final scrub immediately
    // before compression. This prevents a newly added artifact from silently
    // bypassing the per-source redaction above.
    await boundary(redactStagedDiagnostics(stage, () => lease.assertActive()))

    const compressScript = `
$ErrorActionPreference='Stop'
$stage=${psQuote(stage)}
$target=${psQuote(join(work, 'diagnostics.zip'))}
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $target -Force
`
    await boundary(execFile(
      'powershell.exe',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encodedPowerShell(compressScript)],
      { windowsHide: true, timeout: 120_000 }
    ))

    // Stream the archive into the existing identity-checked atomic export path.
    async function* bytes() {
      const stream = createReadStream(join(work!, 'diagnostics.zip'))
      try { for await (const chunk of stream) yield chunk as Buffer }
      finally { stream.destroy(); await finished(stream).catch(() => {}) }
    }
    return await writeConfigExport(targetZip, bytes(), lease, result, 'redacted')
  } finally {
    if (work) try { await rm(work, { recursive: true, force: true }) }
    catch (error) {
      result.warning = 'cleanup-failed'
      logEvent('warn', 'diag-export', 'diagnostics cleanup failed', ioFailureDetails(error))
    }
  }
}
