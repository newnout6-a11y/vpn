import { ipcMain, shell, type IpcMainInvokeEvent } from 'electron'
import { mkdir, rm } from 'fs/promises'
import type { DiagnosticArtifact, DiagnosticClearReport } from '../shared/diagnostics'
import { classifyIpcError, ipcError, IpcFault } from '../shared/ipc-result'
import { clearAppLog, logEvent } from './appLogger'
import { stopTrafficForensicsSession } from './trafficForensics'
import { getSnapshotsDir } from './systemSnapshot'
import { getPrivilegedRuntimeDir } from './runtimePaths'
import { directoryExists, verifyDirectoryHardened } from './runtimeDirSecurity'
import { getTunRuntimeDir } from './tunController'

function handleLogged<T>(channel: string, listener: (event: IpcMainInvokeEvent) => Promise<T>) {
  ipcMain.handle(channel, async event => {
    const started = Date.now()
    logEvent('debug', 'ipc', `${channel} started`)
    try {
      const result = await listener(event)
      logEvent('debug', 'ipc', `${channel} finished`, { ms: Date.now() - started })
      return result
    }
    catch (error) { logEvent('error', 'ipc', `${channel} failed`, error); throw error }
  })
}

export function registerDiagnosticMaintenanceHandlers() {
  handleLogged('clear-app-log', () => clearAppLog())

  handleLogged('clear-diagnostic-artifacts', async (): Promise<DiagnosticClearReport> => {
    const capture = await stopTrafficForensicsSession('manual diagnostics artifact clear')
    if (capture.running || capture.cleanupPending) throw new IpcFault('conflict')
    const forensicRoot = getPrivilegedRuntimeDir('traffic-forensics')
    const targets: Array<{ artifact: DiagnosticArtifact; path: string }> = [{ artifact: 'snapshots', path: getSnapshotsDir() }]
    if (await directoryExists(forensicRoot)) {
      const acl = await verifyDirectoryHardened(forensicRoot)
      if (!acl.hardened) throw new IpcFault('permission')
      targets.push({ artifact: 'traffic-forensics', path: forensicRoot })
    }
    const report: DiagnosticClearReport = { success: true, cleared: [], absent: targets.length === 1 ? ['traffic-forensics'] : [], errors: [] }
    const results = await Promise.allSettled(targets.map(async target => {
      try { await rm(target.path, { recursive: true }); return 'cleared' as const }
      catch (error) {
        if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') return 'absent' as const
        throw error
      }
    }))
    results.forEach((result, index) => {
      const artifact = targets[index].artifact
      if (result.status === 'fulfilled') report[result.value].push(artifact)
      else {
        report.errors.push({ artifact, error: ipcError(classifyIpcError(result.reason)) })
      }
    })
    try {
      const logs = await clearAppLog()
      report.cleared.push(...logs.cleared)
      report.absent.push(...logs.absent)
      report.errors.push(...logs.errors)
    } catch (error) {
      report.errors.push({ artifact: 'logs', error: ipcError(classifyIpcError(error)) })
      logEvent('error', 'diagnostics', 'log cleanup failed', error)
    }
    // Record failures after clearing app.log so cleanup cannot erase its own evidence.
    results.forEach((result, index) => {
      if (result.status === 'rejected') logEvent('error', 'diagnostics', `artifact cleanup failed: ${targets[index].artifact}`, result.reason)
    })
    report.success = report.errors.length === 0
    logEvent(report.success ? 'info' : 'warn', 'diagnostics', 'diagnostic cleanup finished', report)
    return report
  })

  handleLogged('open-tun-log-folder', async () => {
    const folder = getTunRuntimeDir()
    const error = await shell.openPath(folder)
    if (error) throw new Error(error)
    return folder
  })

  handleLogged('open-snapshots-folder', async () => {
    const dir = getSnapshotsDir()
    await mkdir(dir, { recursive: true })
    const error = await shell.openPath(dir)
    if (error) throw new Error(error)
    return { success: true as const, path: dir }
  })
}
