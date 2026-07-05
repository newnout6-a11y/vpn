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
    title: 'РЎРѕС…СЂР°РЅРёС‚СЊ РґРёР°РіРЅРѕСЃС‚РёРєСѓ',
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
        const recent = candidates
          .sort((a, b) => b.time - a.time)
          .filter(item => item.time > 0 && now - item.time <= DIAGNOSTICS_SNAPSHOT_RECENT_MS)
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

    try {
      await stageTrafficForensicsArtifacts(stage)
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
    const readme = `Р”РёР°РіРЅРѕСЃС‚РёРєР° VPN Tunnel Enforcer
РЎРѕР·РґР°РЅРѕ: ${new Date().toISOString()}

РЎРѕРґРµСЂР¶РёРјРѕРµ:
  settings.json                     - С‚РµРєСѓС‰РёРµ РЅР°СЃС‚СЂРѕР№РєРё РїСЂРёР»РѕР¶РµРЅРёСЏ
  app-log.json                      - РїРѕСЃР»РµРґРЅРёРµ Р·Р°РїРёСЃРё Р»РѕРіР° РїСЂРёР»РѕР¶РµРЅРёСЏ
  system-info.json                  - РІРµСЂСЃРёСЏ Windows, РїР°РјСЏС‚СЊ, CPU
  system-diagnostics.json           - СЃРЅРёРјРѕРє РјР°СЂС€СЂСѓС‚РѕРІ, ipconfig, netsh Рё РёС‚РѕРіРѕРІР°СЏ СЃРІРѕРґРєР° РїСЂРѕРІРµСЂРѕРє
  runtime-*.json/log                - РєРѕРЅС„РёРі Рё Р»РѕРіРё sing-box
  baseline-manifest.json            - РєР°РєРёРµ proxy-РЅР°СЃС‚СЂРѕР№РєРё Windows Р±С‹Р»Рё РёР·РјРµРЅРµРЅС‹
  killswitch-manifest.json          - РєР°РєРёРµ РїСЂР°РІРёР»Р° Windows Firewall Р±С‹Р»Рё РїСЂРёРјРµРЅРµРЅС‹
  adapter-lockdown-manifest.json    - РєР°РєРёРµ РёР·РјРµРЅРµРЅРёСЏ РІРЅРѕСЃРёР»РёСЃСЊ РІ С„РёР·РёС‡РµСЃРєРёРµ Р°РґР°РїС‚РµСЂС‹ (IPv6/DNS)
  snapshots/                        - СЃРЅРёРјРєРё СЃРѕСЃС‚РѕСЏРЅРёСЏ СЃРµС‚Рё Рё СЃРёСЃС‚РµРјС‹ РЅР° РєР»СЋС‡РµРІС‹С… СЌС‚Р°РїР°С… СЂР°Р±РѕС‚С‹ РїСЂРёР»РѕР¶РµРЅРёСЏ
  traffic-forensics/                - РіР»СѓР±РѕРєР°СЏ packet-level С‚СЂР°СЃСЃР°: ETL/PCAP/TXT, СЃС‡С‘С‚С‡РёРєРё pktmon,
                                      РїСЂРёС‡РёРЅС‹ drop/reset, WFP netevents/state, manifest РїРѕ СЃРµСЃСЃРёСЏРј
                                      Рё РЅРѕСЂРјР°Р»РёР·РѕРІР°РЅРЅР°СЏ СЃРІРѕРґРєР° summary.json/timeline.ndjson
  traffic-forensics/*/summary.json  - evidence-linked РІС‹РІРѕРґС‹: TUN path, WFP/firewall block,
                                      DNS/TCP/drop СЃРёРіРЅР°Р»С‹ Рё СѓСЂРѕРІРµРЅСЊ РґРѕСЃС‚Р°С‚РѕС‡РЅРѕСЃС‚Рё РґРѕРєР°Р·Р°С‚РµР»СЊСЃС‚РІ
  traffic-forensics/*/*.ndjson      - timeline, dns, drops, tcp-health, packet-metrics, flows, app-events РґР»СЏ РєРѕСЂСЂРµР»СЏС†РёРё
  traffic-forensics/*/events.ndjson - optional ETW sidecar input: TCPIP/DNS/WFP/Winsock/WebIO normalized events

traffic-forensics РѕСЃРѕР±РµРЅРЅРѕ РїРѕР»РµР·РµРЅ РґР»СЏ СЂР°Р·Р±РѕСЂР°:
  - ERR_CONNECTION_CLOSED / reset / timeout РІРЅРµ РїСЂРёР»РѕР¶РµРЅРёСЏ
  - РґРѕР»РіРёС… Р·Р°РіСЂСѓР·РѕРє Рё Р·Р°РІРёСЃР°СЋС‰РёС… СЃР°Р№С‚РѕРІ
  - РІРЅРµС€РЅРµР№ С„РёР»СЊС‚СЂР°С†РёРё, РѕР±СЂС‹РІРѕРІ РїРѕ РїСѓС‚Рё Рё СЃРїРѕСЂРЅС‹С… РїСЂРѕР±Р»РµРј Windows-СЃРµС‚Рё

Р’Р°Р¶РЅРѕ: raw ETL/PCAP/TXT РјРѕРіСѓС‚ СЃРѕРґРµСЂР¶Р°С‚СЊ С‡СѓРІСЃС‚РІРёС‚РµР»СЊРЅС‹Р№ СЃРµС‚РµРІРѕР№ С‚СЂР°С„РёРє.

РђСЂС…РёРІ РїРѕРґРіРѕС‚РѕРІР»РµРЅ РґР»СЏ РѕС‚РїСЂР°РІРєРё РІ РїРѕРґРґРµСЂР¶РєСѓ РёР»Рё РґР»СЏ РїРѕРІС‚РѕСЂРЅРѕРіРѕ СЂР°Р·Р±РѕСЂР° РїРѕР·Р¶Рµ.
`
    await writeFile(join(stage, 'README.txt'), readme, 'utf-8')

    const cleanReadme = `Диагностика VPN Tunnel Enforcer
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

Важно: raw ETL/PCAP/TXT могут содержать чувствительный сетевой трафик.
Архив подготовлен для поддержки или повторного локального разбора.
`
    const topLevelFiles = await readdir(stage).catch(() => [])
    const diagnosticsManifest = {
      schemaVersion: 1,
      createdAt: new Date().toISOString(),
      appVersion: app.getVersion(),
      electronVersion: process.versions.electron,
      nodeVersion: process.versions.node,
      platform: process.platform,
      arch: process.arch,
      redaction: {
        settings: 'subscriptions, profile links and known secrets are redacted',
        runtimeJson: 'runtime JSON is parsed and sensitive values are redacted',
        logs: 'text logs are redacted with the same sensitive-pattern scrubber'
      },
      topLevelFiles: topLevelFiles.sort()
    }
    await writeFile(join(stage, 'diagnostics-manifest.json'), JSON.stringify(diagnosticsManifest, null, 2), 'utf-8')
    await writeFile(join(stage, 'README.txt'), cleanReadme, 'utf-8')

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
