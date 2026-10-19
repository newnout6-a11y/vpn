import type { AppSettings } from '../shared/settings'
export type { AppSettings } from '../shared/settings'
import { app, dialog } from 'electron'
import Store from './versionedStore'
import { join } from 'path'
import { execElevated } from './admin'
import { domainEnrichmentService } from './domainEnrichment'
import { readBootRecoveryReport } from './recoveryManifest'
import { logEvent } from './appLogger'
import { assertMigrationReadBack, migrateSecretStore } from './storeMigrations'
import {
  decryptJsonSecret,
  decryptSecret,
  encryptJsonSecret,
  encryptSecret,
  isSecretEncryptionAvailable,
  isSecretRef,
  type SecretRef
} from './secretStorage'

const defaults: AppSettings = {
  connectionMode: 'localProxy',
  routingMode: 'hard',
  proxyOverride: '',
  proxyType: 'socks5',
  bootstrapRouteMode: 'auto',
  directVpnInput: '',
  directVpnSelectedIndex: 0,
  directVpnCachedInput: '',
  directVpnCachedSource: '',
  directVpnCachedAt: null,
  directVpnCachedProfiles: [],
  checkInterval: 30000,
  disableGeoLookup: false,
  autoStart: false,
  autoPilotEnabled: true,
  minimizeToTray: true,
  locationPrivacyEnabled: false,
  domainEnrichmentEnabled: false,
  // Off by default — wiping HKCU\Internet Settings + WinHTTP + env proxies is destructive
  // and not actually required for TUN to capture traffic at the routing layer. Users who
  // need to fix UWP/Store traffic capture can opt in via Settings → "Auto baseline".
  autoNetworkBaseline: false,
  // Off by default: Windows Firewall block rules can also block the VPN core
  // process on public Wi-Fi, which looks exactly like "DNS/internet died".
  firewallKillSwitch: false,
  advancedMode: false,
  firstRunComplete: false,
  autoRestartOnCrash: true,
  desktopNotifications: true,
  publicWifiCompatibility: true,
  strictAdapterLockdown: true,
  deepTrafficInspectionEnabled: false,
  deepTrafficInspectionMaxSizeMb: 512,
  deepTrafficInspectionRetainSessions: 3,
  stealthMode: false,
  adaptiveBypassEnabled: true,
  adaptiveBypassServerFallback: true,
  smartRuSplit: false,
  smartRuMapsDirect: false,
  smartRuRuleSetMode: 'bundled',
  smartRuRuleSetAutoUpdate: true,
  smartRuRuleSetUseProxy: true,
  smartRuRuleSetUpdateIntervalHours: 24,
  proxyEngine: 'auto'
}

type PersistedAppSettings = Omit<
  AppSettings,
  'proxyOverride' | 'directVpnInput' | 'directVpnCachedInput' | 'directVpnCachedSource' | 'directVpnCachedProfiles'
> & {
  proxyOverride: string | SecretRef
  directVpnInput: string | SecretRef
  directVpnCachedInput: string | SecretRef
  directVpnCachedSource: string | SecretRef
  directVpnCachedProfiles: AppSettings['directVpnCachedProfiles'] | SecretRef
}

const store = new Store<{ settings: PersistedAppSettings | AppSettings; schemaVersion: number; migration?: unknown }>({
  // Supply read defaults below: Conf constructor defaults would rewrite an
  // unversioned legacy file before its migration backup can be made.
  name: 'settings'
})

function hasPlaintextSettingsSecrets(value: PersistedAppSettings | AppSettings | undefined): boolean {
  if (!value) return false
  return Boolean(
    (typeof value.proxyOverride === 'string' && /@/.test(value.proxyOverride)) ||
    (typeof value.directVpnInput === 'string' && value.directVpnInput) ||
    (typeof value.directVpnCachedInput === 'string' && value.directVpnCachedInput) ||
    (typeof value.directVpnCachedSource === 'string' && value.directVpnCachedSource) ||
    (Array.isArray(value.directVpnCachedProfiles) && value.directVpnCachedProfiles.length > 0)
  )
}

function decodePersistedSettings(value: PersistedAppSettings | AppSettings): AppSettings {
  return {
    ...value,
    proxyOverride: isSecretRef(value.proxyOverride) ? decryptSecret(value.proxyOverride) : value.proxyOverride,
    directVpnInput: isSecretRef(value.directVpnInput) ? decryptSecret(value.directVpnInput) : value.directVpnInput,
    directVpnCachedInput: isSecretRef(value.directVpnCachedInput) ? decryptSecret(value.directVpnCachedInput) : value.directVpnCachedInput,
    directVpnCachedSource: isSecretRef(value.directVpnCachedSource) ? decryptSecret(value.directVpnCachedSource) : value.directVpnCachedSource,
    directVpnCachedProfiles: isSecretRef(value.directVpnCachedProfiles)
      ? decryptJsonSecret<AppSettings['directVpnCachedProfiles']>(value.directVpnCachedProfiles)
      : value.directVpnCachedProfiles
  }
}

function encodeSettings(value: AppSettings): PersistedAppSettings {
  return {
    ...value,
    proxyOverride: /@/.test(value.proxyOverride) ? encryptSecret(value.proxyOverride) : value.proxyOverride,
    directVpnInput: value.directVpnInput ? encryptSecret(value.directVpnInput) : value.directVpnInput,
    directVpnCachedInput: value.directVpnCachedInput ? encryptSecret(value.directVpnCachedInput) : value.directVpnCachedInput,
    directVpnCachedSource: value.directVpnCachedSource ? encryptSecret(value.directVpnCachedSource) : value.directVpnCachedSource,
    directVpnCachedProfiles: value.directVpnCachedProfiles?.length > 0
      ? encryptJsonSecret(value.directVpnCachedProfiles)
      : value.directVpnCachedProfiles
  }
}

function readSettingsWithMigration(): AppSettings {
  migrateSecretStore('settings', {
    path: store.path,
    read: () => ({ ...store.store }),
    write: value => { store.store = value },
    hasPlaintext: value => hasPlaintextSettingsSecrets(value.settings),
    prepare(value) {
      const decoded = decodePersistedSettings(value.settings)
      if (!hasPlaintextSettingsSecrets(value.settings)) return value
      const encoded = encodeSettings(decoded)
      assertMigrationReadBack(decoded, decodePersistedSettings(encoded))
      return { ...value, settings: encoded }
    }
  })
  return decodePersistedSettings(store.get('settings', defaults))
}

function persistSettings(value: AppSettings): void {
  const containsSecrets = Boolean(
    /@/.test(value.proxyOverride) ||
    value.directVpnInput ||
    value.directVpnCachedInput ||
    value.directVpnCachedSource ||
    value.directVpnCachedProfiles.length
  )
  if (containsSecrets && !isSecretEncryptionAvailable()) {
    throw new Error('Secure storage is unavailable; settings containing VPN secrets were not written')
  }
  store.set('settings', encodeSettings(value))
  store.set('schemaVersion', 2)
}

function normalizeSettings(input: Partial<AppSettings> | undefined): AppSettings {
  const merged = { ...defaults, ...(input ?? {}) }
  const cachedProfiles = Array.isArray(merged.directVpnCachedProfiles)
    ? merged.directVpnCachedProfiles
        .filter((profile: any) => profile && typeof profile === 'object' && profile.outbound && typeof profile.outbound === 'object')
        .map((profile: any) => ({
          name: typeof profile.name === 'string' && profile.name.trim() ? profile.name.trim() : 'VPN',
          protocol: typeof profile.protocol === 'string' && profile.protocol.trim() ? profile.protocol.trim() : String(profile.outbound?.type || 'sing-box'),
          outbound: profile.outbound
        }))
    : []
  return {
    connectionMode: merged.connectionMode === 'directVpn' ? 'directVpn' : 'localProxy',
    routingMode: merged.routingMode === 'soft' ? 'soft' : 'hard',
    proxyOverride: typeof merged.proxyOverride === 'string' ? merged.proxyOverride.trim() : '',
    proxyType: merged.proxyType === 'http' ? 'http' : 'socks5',
    bootstrapRouteMode: merged.bootstrapRouteMode === 'direct' || merged.bootstrapRouteMode === 'localProxy'
      ? merged.bootstrapRouteMode
      : 'auto',
    directVpnInput: typeof merged.directVpnInput === 'string' ? merged.directVpnInput.trim() : '',
    directVpnSelectedIndex: Math.max(0, Math.floor(Number(merged.directVpnSelectedIndex) || 0)),
    directVpnCachedInput: typeof merged.directVpnCachedInput === 'string' ? merged.directVpnCachedInput.trim() : '',
    directVpnCachedSource: typeof merged.directVpnCachedSource === 'string' ? merged.directVpnCachedSource.trim() : '',
    directVpnCachedAt: Number.isFinite(Number(merged.directVpnCachedAt)) ? Number(merged.directVpnCachedAt) : null,
    directVpnCachedProfiles: cachedProfiles,
    checkInterval: Math.min(300000, Math.max(5000, Number(merged.checkInterval) || defaults.checkInterval)),
    autoStart: Boolean(merged.autoStart),
    autoPilotEnabled: merged.autoPilotEnabled !== false,
    minimizeToTray: Boolean(merged.minimizeToTray),
    locationPrivacyEnabled: Boolean(merged.locationPrivacyEnabled),
    domainEnrichmentEnabled: Boolean(merged.domainEnrichmentEnabled),
    autoNetworkBaseline: Boolean(merged.autoNetworkBaseline),
    // Security-sensitive and invasive: absent/malformed input never opts the
    // user into a system-wide firewall block.
    firewallKillSwitch: merged.firewallKillSwitch === true,
    advancedMode: Boolean(merged.advancedMode),
    firstRunComplete: Boolean(merged.firstRunComplete),
    autoRestartOnCrash: merged.autoRestartOnCrash !== false,
    desktopNotifications: merged.desktopNotifications !== false,
    publicWifiCompatibility: merged.publicWifiCompatibility !== false,
    strictAdapterLockdown: merged.strictAdapterLockdown !== false,
    // `=== true`, not `!== false`, unlike the flags above. Those all default to
    // true, so "anything but an explicit false means on" matches their default.
    // This one defaults to false (see defaults above) and turning it on starts
    // writing packet captures to disk, so an absent or malformed value must
    // resolve to OFF. `!== false` only held because `merged` pre-fills from
    // defaults; an explicit undefined arriving via saveSettings would have
    // silently enabled forensics.
    deepTrafficInspectionEnabled: merged.deepTrafficInspectionEnabled === true,
    deepTrafficInspectionMaxSizeMb: Math.min(
      2048,
      Math.max(128, Math.floor(Number(merged.deepTrafficInspectionMaxSizeMb) || defaults.deepTrafficInspectionMaxSizeMb))
    ),
    deepTrafficInspectionRetainSessions: Math.min(
      10,
      Math.max(1, Math.floor(Number(merged.deepTrafficInspectionRetainSessions) || defaults.deepTrafficInspectionRetainSessions))
    ),
    // stealthMode is OFF by default — its mitigations (smaller MTU, TLS
    // fragmentation) cost a few % bandwidth and extra round-trips, only
    // worth paying on networks that actively shape VPN traffic. Without
    // this line the field was silently dropped on every save/load, so
    // the existing UI toggle had no effect.
    stealthMode: Boolean(merged.stealthMode),
    adaptiveBypassEnabled: merged.adaptiveBypassEnabled !== false,
    adaptiveBypassServerFallback: merged.adaptiveBypassServerFallback !== false,
    disableGeoLookup: Boolean(merged.disableGeoLookup),
    smartRuSplit: Boolean(merged.smartRuSplit),
    smartRuMapsDirect: Boolean(merged.smartRuMapsDirect),
    smartRuRuleSetMode: merged.smartRuRuleSetMode === 'managed' ? 'managed' : 'bundled',
    smartRuRuleSetAutoUpdate: merged.smartRuRuleSetAutoUpdate !== false,
    smartRuRuleSetUseProxy: merged.smartRuRuleSetUseProxy !== false,
    smartRuRuleSetUpdateIntervalHours: Math.min(
      720,
      Math.max(1, Math.floor(Number(merged.smartRuRuleSetUpdateIntervalHours) || defaults.smartRuRuleSetUpdateIntervalHours))
    ),
    proxyEngine: merged.proxyEngine === 'sing-box' || merged.proxyEngine === 'xray'
      ? merged.proxyEngine
      : 'auto'
  }
}

let bootRecoveryTaskEnsured = false
let bootRecoveryStatus: { status: 'not-checked' | 'verified' | 'failed'; message: string } = {
  status: 'not-checked', message: 'Boot Recovery task has not been verified'
}
export function getBootRecoveryRegistrationStatus() { return { ...bootRecoveryStatus } }

export function getBootRecoveryScriptPath(packaged = app.isPackaged): string {
  return packaged
    ? join(process.resourcesPath, 'vpnte-recover.ps1')
    : join(process.cwd(), 'resources', 'vpnte-recover.ps1')
}

export function buildBootRecoveryTaskCommand(recoverScript: string): string {
  const script = `& '${recoverScript.replace(/'/g, "''")}' -RegisterTask`
  return `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ${Buffer.from(script, 'utf16le').toString('base64')}`
}

const LOGIN_TASK_NAME = 'VPN Tunnel Enforcer'

// schtasks /Query exits with 1 for "not found" but also for other errors (e.g. access denied), and its text is localised,
// so the exit code cannot tell them apart. The cmdlet reports a missing task as a locale-independent ObjectNotFound
// category; any other failure propagates as an unknown state.
const LOGIN_TASK_QUERY_SCRIPT = [
  '# LOGIN_TASK_QUERY',
  'try { $null = Get-ScheduledTask -TaskName ' + "'" + LOGIN_TASK_NAME + "'" + ' -ErrorAction Stop; Write-Output PRESENT }',
  "catch { if ($_.CategoryInfo.Category -eq 'ObjectNotFound') { Write-Output ABSENT } else { throw } }"
].join('\n')

/** Whether the autostart scheduled task exists; any answer other than PRESENT/ABSENT is an unknown state and throws. */
async function loginTaskExists(): Promise<boolean> {
  const encoded = Buffer.from(LOGIN_TASK_QUERY_SCRIPT, 'utf16le').toString('base64')
  const { stdout } = await execElevated(
    `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ${encoded}`,
    { timeout: 15000 }
  )
  const answer = String(stdout ?? '').trim()
  if (answer === 'PRESENT') return true
  if (answer === 'ABSENT') return false
  throw new Error('Autostart task state could not be read back')
}

/** Fresh readback after a create/delete. Only the packaged Windows build uses a scheduled task. */
async function verifyLoginTask(expected: boolean): Promise<void> {
  if (!(process.platform === 'win32' && app.isPackaged)) return
  if ((await loginTaskExists()) !== expected) {
    throw new Error(`Autostart task readback does not match the requested state (expected ${expected ? 'present' : 'absent'})`)
  }
}

/** Puts the OS task back to the previous state after a failed step; an unconfirmed restore is reported as unknown. */
async function restoreLoginTask(previous: boolean, cause: unknown): Promise<void> {
  try {
    await applyLoginItem(previous, { propagateTaskFailure: true })
    await verifyLoginTask(previous)
  } catch (restoreError) {
    const reason = (value: unknown) => (value instanceof Error ? value.message : String(value)).slice(0, 300)
    logEvent('error', 'settings', 'autostart state is unknown: restore after a failed change was not confirmed', { cause: reason(cause), restore: reason(restoreError) })
    // Keep both original errors reachable for higher-level handlers: the restore failure as the cause, the change failure alongside.
    throw Object.assign(
      new Error(`Autostart state is unknown: ${reason(cause)}; restoring the previous state failed: ${reason(restoreError)}`, { cause: restoreError }),
      { originalCause: cause }
    )
  }
}

/**
 * Applies the autostart state. By default the scheduled-task command is fire-and-forget (an unrelated settings save must
 * not wait for it or fail because of it). With `propagateTaskFailure` the returned promise settles with the command, so a
 * caller that needs to know whether the OS state really changed can await it.
 */
function applyLoginItem(autoStart: boolean, options: { ensureBootRecovery?: boolean; propagateTaskFailure?: boolean } = {}): Promise<void> | void {
  if (process.platform === 'win32' && app.isPackaged) {
    const taskName = LOGIN_TASK_NAME
    const exe = `\\"${process.execPath.replace(/"/g, '\\"')}\\"`
    app.setLoginItemSettings({ openAtLogin: false })

    const command = autoStart
      ? `schtasks /Create /TN "${taskName}" /SC ONLOGON /RL HIGHEST /TR "${exe}" /F`
      : `schtasks /Delete /TN "${taskName}" /F`

    const loginTask = execElevated(command, { timeout: 15000 })
    loginTask.catch(() => undefined)

    if (options.ensureBootRecovery && !bootRecoveryTaskEnsured) {
      // Reserve immediately so multiple settings operations in the same tick
      // cannot race and register the task twice. A failure clears the flag and
      // permits a later retry.
      bootRecoveryTaskEnsured = true
      // Register boot-time recovery task once per app process. It is
      // independent of autoStart and restores network settings if a crash or
      // BSOD left firewall/DNS state pinned.
      const recoverTask = buildBootRecoveryTaskCommand(getBootRecoveryScriptPath(true))
      let stage: 'register' | 'read-back' | 'report' = 'register'
      void execElevated(recoverTask, { timeout: 30000 })
        .then(async ({ stdout, stderr }) => {
          stage = 'read-back'
          if (!String(stdout).split(/\r?\n/).includes('RECOVERY_TASK_VERIFIED')) {
            throw Object.assign(new Error('Boot Recovery read-back marker missing'), { stderr })
          }
          stage = 'report'
          const report = await readBootRecoveryReport()
          bootRecoveryStatus = { status: 'verified', message: 'SYSTEM startup trigger, action and principal verified' }
          logEvent('info', 'boot-recovery', 'task and trusted report verification completed', { reportStatus: report?.status ?? 'absent' })
          if (report && report.status !== 'restored') {
            await dialog.showMessageBox({ type: 'warning', title: 'VPNTE: Boot Recovery',
              message: report.status === 'strict-retained' ? 'Строгая блокировка сохранена после перезагрузки.' : 'Восстановление сети после перезагрузки не завершено.',
              detail: 'Защита не подтверждена. Проверьте результат Boot Recovery в системной диагностике.', buttons: ['OK'] })
              .catch(error => logEvent('error', 'boot-recovery', 'recovery warning could not be displayed', { error }))
          }
        })
        .catch(error => {
          bootRecoveryTaskEnsured = false
          bootRecoveryStatus = { status: 'failed', message: `Boot Recovery verification failed at ${stage}` }
          // Command errors may carry a large stderr/encoded command. Bound the
          // diagnostic before the logger applies its existing secret redaction.
          logEvent('error', 'boot-recovery', 'verification failed; recovery is not confirmed', {
            stage,
            error: String(error instanceof Error ? error.message : error).slice(0, 1024),
            stderr: typeof error?.stderr === 'string' ? error.stderr.slice(0, 2048) : undefined,
            code: typeof error?.code === 'number' ? error.code : typeof error?.code === 'string' ? error.code.slice(0, 64) : undefined
          })
          const stageLabel = { register: 'Регистрация задачи', 'read-back': 'Проверка ответа регистрации', report: 'Проверка сохранённого отчёта' }[stage]
          void dialog.showMessageBox({ type: 'error', title: 'VPNTE: Boot Recovery',
            message: stage === 'report'
              ? 'Задача восстановления зарегистрирована, но сохранённый отчёт не прошёл проверку. Результат восстановления не подтверждён.'
              : 'Задача восстановления сети не подтверждена. Автовосстановление после перезагрузки не гарантировано.',
            detail: `Этап: ${stageLabel}. Подробности записаны в журнал (boot-recovery). Проверьте системную диагностику.`, buttons: ['OK'] })
            .catch(error => logEvent('error', 'boot-recovery', 'verification error could not be displayed', { error }))
        })
    }

    return options.propagateTaskFailure ? loginTask.then(() => undefined) : undefined
  }

  app.setLoginItemSettings({
    openAtLogin: autoStart,
    path: process.execPath,
    args: []
  })
}

export const settingsStore = {
  get(): AppSettings {
    return normalizeSettings(readSettingsWithMigration())
  },

  save(partial: Partial<AppSettings>): AppSettings {
    const previous = normalizeSettings(readSettingsWithMigration())
    const settings = normalizeSettings({ ...previous, ...partial })
    persistSettings(settings)
    if (!settings.domainEnrichmentEnabled && previous.domainEnrichmentEnabled) {
      domainEnrichmentService.setEnabled(false)
    }
    if (settings.autoStart !== previous.autoStart) {
      applyLoginItem(settings.autoStart, { ensureBootRecovery: true })
    }
    return settings
  },

  /**
   * Like setLoginItem, but settles only after the scheduled task was really created or deleted, and leaves the saved
   * setting untouched when that fails, so the stored value never claims an autostart state the OS does not have.
   */
  async setLoginItemChecked(openAtLogin: boolean): Promise<AppSettings> {
    const previous = normalizeSettings(readSettingsWithMigration()).autoStart
    await applyLoginItem(openAtLogin, { ensureBootRecovery: true, propagateTaskFailure: true })
    try {
      // The command finishing is not the task being in the requested state: read it back.
      await verifyLoginTask(openAtLogin)
      // Re-read after the awaits so a settings save that completed meanwhile is kept; only autoStart changes.
      const settings = normalizeSettings({ ...normalizeSettings(readSettingsWithMigration()), autoStart: openAtLogin })
      persistSettings(settings)
      return settings
    } catch (error) {
      await restoreLoginTask(previous, error)
      throw error
    }
  },

  setLoginItem(openAtLogin: boolean): AppSettings {
    const settings = normalizeSettings({ ...normalizeSettings(readSettingsWithMigration()), autoStart: openAtLogin })
    persistSettings(settings)
    applyLoginItem(settings.autoStart, { ensureBootRecovery: true })
    return settings
  },

  syncLoginItem() {
    applyLoginItem(this.get().autoStart, { ensureBootRecovery: true })
  }
}
