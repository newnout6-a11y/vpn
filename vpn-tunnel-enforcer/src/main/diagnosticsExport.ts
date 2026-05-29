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
          // Skip the binaries themselves — they're huge and the user already
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
    // NOTE: these manifests live in SUBDIRECTORIES, not the userData root.
    // network baseline → network-backups/, kill-switch → firewall-killswitch/.
    // The old root-level paths never matched, so the ZIP shipped without them.
    const userData = app.getPath('userData')
    await copyIfExists(join(userData, 'network-backups', 'latest-tun-network-baseline.json'), join(stage, 'baseline-manifest.json'))
    await copyIfExists(join(userData, 'firewall-killswitch', 'manifest.json'), join(stage, 'killswitch-manifest.json'))
    await copyIfExists(join(userData, 'latest-physical-adapter-lockdown.json'), join(stage, 'adapter-lockdown-manifest.json'))

    // 6b. Snapshots dir — every captured network/system snapshot from app
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

    // 7. README so the user/support knows what's inside.
    const readme = `Диагностика VPN Tunnel Enforcer
Создано: ${new Date().toISOString()}

Содержимое:
  settings.json              — текущие настройки приложения
  app-log.json               — последние записи лога приложения
  system-info.json           — версия Windows, ОЗУ, ЦП
  system-diagnostics.json    — снимок маршрутов, ipconfig, netsh interface
  runtime-*.json/log         — конфиг и логи sing-box
  baseline-manifest.json     — что было изменено в proxy-настройках Windows (если применялось)
  killswitch-manifest.json   — установленные правила Windows Firewall (если применялись)
  adapter-lockdown-manifest.json — что было изменено на физических адаптерах (IPv6/DNS), если применялось
  snapshots/                 — снимки сетевого состояния (адаптеры/маршруты/DNS/firewall) на каждом важном
                               событии (старт app, пред-/пост-старт TUN, краш sing-box, утечка, периодика 60с)

Файл предназначен для отправки в поддержку.
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
