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
import { dialog, app } from 'electron'
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
import { getTunNetworkBaselineManifestPath } from './systemNetwork'

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

function snapshotTimeFromName(name: string): number | null {
  const match = name.match(/^snapshot-(\d{4}-\d{2}-\d{2}T\d{2})-(\d{2})-(\d{2})-(\d{3}Z)-/)
  if (!match) return null
  const parsed = Date.parse(`${match[1]}:${match[2]}:${match[3]}.${match[4]}`)
  return Number.isFinite(parsed) ? parsed : null
}

export async function exportDiagnosticsZip(): Promise<ExportResult> {
  // Ask the user where to drop the zip.
  const defaultName = `vpn-tunnel-enforcer-diagnostics-${new Date().toISOString().replace(/[:.]/g, '-')}.zip`
  const choice = await dialog.showSaveDialog({
    title: 'Сохранить диагностику',
    defaultPath: join(app.getPath('desktop'), defaultName),
    filters: [{ name: 'ZIP archive', extensions: ['zip'] }]
  })
  if (choice.canceled || !choice.filePath) {
    return { success: false, cancelled: true }
  }
  const targetZip = choice.filePath

  // Stage the bundle in a temp dir so we can ship it as one Compress-Archive.
  let stage: string | null = null
  try {
    stage = await mkdtemp(join(tmpdir(), 'vpnte-diag-'))

    // 1. Settings. Direct-VPN subscriptions/keys are secrets, redact them.
    await writeFile(join(stage, 'settings.json'), JSON.stringify(redactSettingsForDiagnostics(settingsStore.get()), null, 2), 'utf-8')

    // 2. App logs (the in-memory + on-disk app log).
    const logs = await getFullLogs()
    await writeFile(join(stage, 'app-log.json'), JSON.stringify(logs, null, 2), 'utf-8')

    // 3. System info snapshot.
    await writeFile(join(stage, 'system-info.json'), await snapshotSystemInfo(), 'utf-8')

    // 4. Live diagnostics (route table, ipconfig, netsh dumps).
    try {
      const diagnostics = await runSystemDiagnostics()
      await writeFile(join(stage, 'system-diagnostics.json'), JSON.stringify(diagnostics, null, 2), 'utf-8')
    } catch (err) {
      logEvent('warn', 'diag-export', 'system diagnostics failed', { err: (err as Error)?.message })
    }

    // 5. sing-box runtime files (config, log, manifest if any).
    const runtime = getTunRuntimeDir()
    if (existsSync(runtime)) {
      try {
        const entries = await readdir(runtime)
        for (const name of entries) {
          // Skip the binaries themselves - they're huge and the user already
          // has them. Only ship configs/logs/manifests.
          if (/\.(json|log|txt|manifest)$/i.test(name)) {
            const src = join(runtime, name)
            const dst = join(stage, `runtime-${name}`)
            if (/\.json$/i.test(name)) {
              try {
                const parsed = JSON.parse(await readFile(src, 'utf-8'))
                await writeFile(dst, JSON.stringify(redactSensitiveConfig(parsed), null, 2), 'utf-8')
              } catch {
                await writeFile(dst, '<redacted: runtime json>\n', 'utf-8')
              }
            } else {
              try {
                await writeFile(dst, redactSensitiveText(await readFile(src, 'utf-8')), 'utf-8')
              } catch {
                await writeFile(dst, '<redacted: runtime log>\n', 'utf-8')
              }
            }
          }
        }
      } catch (err) {
        logEvent('warn', 'diag-export', 'reading runtime dir failed', { err: (err as Error)?.message })
      }
    }

    // 6. Baseline manifest (so support can see what we changed in the registry).
    const userData = app.getPath('userData')
    await copyIfExists(getTunNetworkBaselineManifestPath(), join(stage, 'baseline-manifest.json'))
    await copyIfExists(join(userData, 'firewall-killswitch', 'manifest.json'), join(stage, 'killswitch-manifest.json'))
    await copyIfExists(join(userData, 'latest-physical-adapter-lockdown.json'), join(stage, 'adapter-lockdown-manifest.json'))

    // 6b. Snapshots dir - every captured network/system snapshot from app
    // start, every TUN start/stop, periodic 60s captures, and any
    // leak-detected event. This is the bulk of the support-relevant data.
    const snapshotsDir = join(userData, 'snapshots')
    if (existsSync(snapshotsDir)) {
      try {
        const stagedSnaps = join(stage, 'snapshots')
        await mkdir(stagedSnaps, { recursive: true })
        const now = Date.now()
        const candidates = await Promise.all((await readdir(snapshotsDir))
          .filter(name => /\.json$/i.test(name))
          .map(async (name) => {
            const src = join(snapshotsDir, name)
            const mtime = await stat(src).then(s => s.mtimeMs).catch(() => 0)
            return { name, src, time: snapshotTimeFromName(name) ?? mtime }
          }))
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
          const raw = await readFile(src, 'utf-8')
          try {
            const parsed = JSON.parse(raw)
            await writeFile(dst, JSON.stringify(redactSensitiveConfig(parsed), null, 2), 'utf-8')
          } catch {
            await writeFile(dst, redactSensitiveText(raw), 'utf-8')
          }
        }
      } catch (err) {
        logEvent('warn', 'diag-export', 'failed to copy snapshots', { err: (err as Error)?.message })
      }
    }

    let forensicsStaged = false
    try {
      forensicsStaged = await stageTrafficForensicsArtifacts(stage)
    } catch (err) {
      logEvent('warn', 'diag-export', 'failed to stage traffic forensics artifacts', { err: (err as Error)?.message })
    }

    try {
      const refreshedLogs = await getFullLogs()
      await writeFile(join(stage, 'app-log.json'), JSON.stringify(redactSensitiveConfig(refreshedLogs), null, 2), 'utf-8')
    } catch (err) {
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
    await writeFile(join(stage, 'README.txt'), readme, 'utf-8')

    const topLevelFiles = await readdir(stage).catch(() => [])
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
    await writeFile(join(stage, 'diagnostics-manifest.json'), JSON.stringify(diagnosticsManifest, null, 2), 'utf-8')

    const compressScript = `
$ErrorActionPreference='Stop'
$stage=${psQuote(stage)}
$target=${psQuote(targetZip)}
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $target -Force
`
    await execFile(
      'powershell.exe',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encodedPowerShell(compressScript)],
      { windowsHide: true }
    )

    logEvent('info', 'diag-export', 'diagnostics zip written', { path: targetZip })
    return { success: true, path: targetZip }
  } catch (err: any) {
    logEvent('error', 'diag-export', 'failed to build diagnostics zip', err)
    return { success: false, error: err?.message || String(err) }
  } finally {
    if (stage) {
      rm(stage, { recursive: true, force: true }).catch(() => undefined)
    }
  }
}
