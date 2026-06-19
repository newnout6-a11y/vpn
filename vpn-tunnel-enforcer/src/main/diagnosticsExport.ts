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
import { exec as execCb } from 'child_process'
import { dialog, app } from 'electron'
import { mkdtemp, writeFile, copyFile, readdir, rm, readFile } from 'fs/promises'
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

const exec = promisify(execCb)

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
    // NOTE: these manifests live in subdirectories, not the userData root.
    // network baseline -> network-backups/, kill-switch -> firewall-killswitch/.
    // The old root-level paths never matched, so the ZIP shipped without them.
    const userData = app.getPath('userData')
    await copyIfExists(join(userData, 'network-backups', 'latest-tun-network-baseline.json'), join(stage, 'baseline-manifest.json'))
    await copyIfExists(join(userData, 'firewall-killswitch', 'manifest.json'), join(stage, 'killswitch-manifest.json'))
    await copyIfExists(join(userData, 'latest-physical-adapter-lockdown.json'), join(stage, 'adapter-lockdown-manifest.json'))

    // 6b. Snapshots dir - every captured network/system snapshot from app
    // start, every TUN start/stop, periodic 60s captures, and any
    // leak-detected event. This is the bulk of the support-relevant data.
    const snapshotsDir = join(userData, 'snapshots')
    if (existsSync(snapshotsDir)) {
      try {
        const stagedSnaps = join(stage, 'snapshots')
        await import('fs/promises').then((fp) => fp.mkdir(stagedSnaps, { recursive: true }))
        const entries = await readdir(snapshotsDir)
        for (const name of entries) {
          if (/\.json$/i.test(name)) {
            const src = join(snapshotsDir, name)
            const dst = join(stagedSnaps, name)
            const raw = await readFile(src, 'utf-8')
            try {
              const parsed = JSON.parse(raw)
              await writeFile(dst, JSON.stringify(redactSensitiveConfig(parsed), null, 2), 'utf-8')
            } catch {
              await writeFile(dst, redactSensitiveText(raw), 'utf-8')
            }
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

    // 8. Compress-Archive expects forward slashes to be quoted on PS5; use \"
    // and -Force to overwrite if the user picks an existing file.
    const psCmd = `powershell -NoProfile -ExecutionPolicy Bypass -Command "Compress-Archive -Path '${stage.replace(/'/g, "''")}\\*' -DestinationPath '${targetZip.replace(/'/g, "''")}' -Force"`
    await exec(psCmd, { windowsHide: true })

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
