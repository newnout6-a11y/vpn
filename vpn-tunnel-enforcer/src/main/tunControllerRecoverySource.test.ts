import { readFile } from 'fs/promises'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'
import { describe, expect, it } from 'vitest'

const here = dirname(fileURLToPath(import.meta.url))

describe('tunController recovery cancellation guards', () => {
  it('keeps startup retry and post-trial failover cancelable by Stop', async () => {
    const source = await readFile(join(here, 'tunController.ts'), 'utf8')

    expect(source).toContain('let recoveryCancelGeneration = 0')
    expect(source).toContain('const generation = recoveryCancelGeneration')
    expect(source).toContain('generation !== recoveryCancelGeneration')
    expect(source).toContain('recoveryCancelGeneration += 1')
    expect(source).toContain('restartTimer = setTimeout(() => {')
    expect(source).toContain("WSAEACCES retry cancelled by stop")
  })

  it('validates localProxy full-tunnel before preparing runtime files', async () => {
    const source = await readFile(join(here, 'tunController.ts'), 'utf8')
    const validationIndex = source.indexOf('validateProxyFullTunnel(host, port, proxyType)')
    const fallbackRuntimeIndex = source.indexOf("runtimePromise = timePromise('prepare-runtime', prepareRuntime(", validationIndex)

    expect(validationIndex).toBeGreaterThan(0)
    expect(fallbackRuntimeIndex).toBeGreaterThan(validationIndex)
    expect(source).not.toContain("runtimePromise.catch(() => undefined)\n        await rollbackEarlyAdapterLockdown('proxy full-tunnel check failed")
  })

  it('publishes stopped after partial cleanup warnings instead of leaving UI connected', async () => {
    const source = await readFile(join(here, 'tunController.ts'), 'utf8')
    const stopSignature = source.indexOf('async stop(options: { preserveNetworkProtection?: boolean; preserveLastStartOptions?: boolean } = {})')
    const cleanupBranch = source.indexOf('if (cleanupErrors.length > 0)', stopSignature)
    const successReturn = source.lastIndexOf('return { success: true, warning }')
    const stoppedNotify = source.indexOf("notifyStatus('stopped')", cleanupBranch)
    const failureReturn = source.indexOf('return { success: false, error: cleanupErrors.join', cleanupBranch)

    expect(stopSignature).toBeGreaterThan(0)
    expect(cleanupBranch).toBeGreaterThan(stopSignature)
    expect(stoppedNotify).toBeGreaterThan(cleanupBranch)
    expect(stoppedNotify).toBeLessThan(successReturn)
    expect(successReturn).toBeGreaterThan(cleanupBranch)
    expect(failureReturn).toBe(-1)
  })

  it('suppresses false direct-VPN proxy-down when public IP was just confirmed', async () => {
    const source = await readFile(join(here, 'tunController.ts'), 'utf8')
    const watchdogStart = source.indexOf('function startServerWatchdog(host: string, port: number, label: string)')
    const watchdogEnd = source.indexOf('\n}', source.indexOf("}, 5000)", watchdogStart))
    const watchdogSource = source.slice(watchdogStart, watchdogEnd)

    expect(watchdogStart).toBeGreaterThan(0)
    expect(watchdogSource).toContain('hasRecentPublicIpConfirmation(DIRECT_VPN_WATCHDOG_SUPPRESS_MS)')
    expect(watchdogSource).toContain('suppressing direct VPN server probe failure')
    expect(watchdogSource).toContain('markProxyRecovered()')
    expect(watchdogSource.indexOf('hasRecentPublicIpConfirmation(DIRECT_VPN_WATCHDOG_SUPPRESS_MS)')).toBeLessThan(
      watchdogSource.indexOf('markProxyUnreachable(')
    )
  })

  it('uses the local PowerShell quote helper for owned runtime process cleanup', async () => {
    const source = await readFile(join(here, 'tunController.ts'), 'utf8')
    const helper = source.indexOf('function psSingleQuote(value: string): string')
    const cleanup = source.indexOf('export async function killOwnedTunRuntimeProcesses', helper)

    expect(helper).toBeGreaterThan(0)
    expect(cleanup).toBeGreaterThan(helper)
    expect(source).not.toContain('function psQuote(value: string): string')
  })

  it('keeps external proxy runtimes outside TUN process cleanup', async () => {
    const source = await readFile(join(here, 'tunController.ts'), 'utf8')
    const cleanup = source.slice(
      source.indexOf('export async function killOwnedTunRuntimeProcesses'),
      source.indexOf('async function killOwnedRuntimeProcesses')
    )

    expect(cleanup).toContain('const runtimeDir = getTunRuntimeDir()')
    expect(cleanup).toContain("$names = @(${psSingleQuote(RUNTIME_EXE_NAME)}, 'vpnte-etw-sidecar.exe')")
    expect(cleanup).toContain('$_.ExecutablePath')
    expect(cleanup).toContain('StartsWith($runtimeDir')
    expect(cleanup).not.toContain('vpnte-external-proxy.exe')
    expect(cleanup).not.toContain('external-proxy-runtime')
  })

  it('keeps public Wi-Fi compatibility from forcing DNS on physical adapters', async () => {
    const source = await readFile(join(here, 'tunController.ts'), 'utf8')
    const compatibility = source.indexOf('const publicWifiCompatibility =')
    const forceDns = source.indexOf('const adapterLockdownForceDns = !publicWifiCompatibility', compatibility)
    const lockdownCall = source.indexOf('applyPhysicalAdapterLockdown(TUN_IPV4_RESOLVER', forceDns)
    const option = source.indexOf('forceDns: adapterLockdownForceDns', lockdownCall)

    expect(compatibility).toBeGreaterThan(0)
    expect(forceDns).toBeGreaterThan(compatibility)
    expect(lockdownCall).toBeGreaterThan(forceDns)
    expect(option).toBeGreaterThan(lockdownCall)
    expect(source).not.toContain('applyPhysicalAdapterLockdown(TUN_IPV4_RESOLVER, {\n              forceDns: true')
  })

  it('preserves stealth mode across internal restarts and auto-recovery', async () => {
    const source = await readFile(join(here, 'tunController.ts'), 'utf8')
    const snapshot = source.indexOf('lastStartOptions = {')
    const stealth = source.indexOf('stealthMode: startOptions.stealthMode === true', snapshot)
    const freshSettings = source.indexOf('const nextSnapshot: StartOptions = {', stealth)
    const restart = source.indexOf('return this.start(nextSnapshot)')
    const recovery = source.indexOf('tunController.start(optsSnapshot)')

    expect(snapshot).toBeGreaterThan(0)
    expect(stealth).toBeGreaterThan(snapshot)
    expect(freshSettings).toBeGreaterThan(stealth)
    expect(restart).toBeGreaterThan(freshSettings)
    expect(recovery).toBeGreaterThan(0)
  })

  it('uses a protected lifecycle transition for adaptive compatibility changes', async () => {
    const source = await readFile(join(here, 'tunController.ts'), 'utf8')
    const transition = source.indexOf('async restartForAdaptiveChange(')
    const protectedStop = source.indexOf('preserveNetworkProtection: true', transition)
    const preservedSnapshot = source.indexOf('preserveLastStartOptions: true', transition)
    const cleanup = source.indexOf('await this.stop().catch', transition)

    expect(transition).toBeGreaterThan(0)
    expect(protectedStop).toBeGreaterThan(transition)
    expect(preservedSnapshot).toBeGreaterThan(protectedStop)
    expect(cleanup).toBeGreaterThan(preservedSnapshot)
  })

  it('allows the protected adaptive transition to replace only the Direct VPN profile', async () => {
    const source = await readFile(join(here, 'tunController.ts'), 'utf8')
    const transition = source.indexOf('async restartForAdaptiveChange(')
    const overrides = source.indexOf("overrides: Pick<StartOptions, 'vpnProfile'> = {}", transition)
    const restart = source.indexOf('this.start({ ...snapshot, ...overrides, adaptiveMode: nextMode })', transition)

    expect(overrides).toBeGreaterThan(transition)
    expect(restart).toBeGreaterThan(overrides)
  })

  it('cancels pending auto-restart if the setting is switched off during backoff', async () => {
    const source = await readFile(join(here, 'tunController.ts'), 'utf8')
    const timer = source.indexOf('restartTimer = setTimeout(() => {')
    const cancel = source.indexOf('settingsStore.get().autoRestartOnCrash === false', timer)
    const start = source.indexOf('tunController.start(optsSnapshot)', timer)

    expect(timer).toBeGreaterThan(0)
    expect(cancel).toBeGreaterThan(timer)
    expect(cancel).toBeLessThan(start)
    expect(source).toContain('auto-restart cancelled because setting is off')
  })
})
