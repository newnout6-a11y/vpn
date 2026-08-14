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

  it('uses confirmed egress for Direct VPN watchdog and logs only state transitions', async () => {
    const source = await readFile(join(here, 'tunController.ts'), 'utf8')
    const watchdogStart = source.indexOf('function startServerWatchdog(_host: string, _port: number, label: string)')
    const watchdogEnd = source.indexOf('\n}', source.indexOf('}, DIRECT_VPN_WATCHDOG_INTERVAL_MS)', watchdogStart))
    const watchdogSource = source.slice(watchdogStart, watchdogEnd)

    expect(watchdogStart).toBeGreaterThan(0)
    expect(watchdogSource).toContain('hasRecentPublicIpConfirmation(DIRECT_VPN_WATCHDOG_SUPPRESS_MS)')
    expect(watchdogSource).toContain('markProxyRecovered()')
    expect(watchdogSource).not.toContain('probeTcp(')
    expect(watchdogSource).not.toContain('logEvent(')
    expect(watchdogSource.indexOf('hasRecentPublicIpConfirmation(DIRECT_VPN_WATCHDOG_SUPPRESS_MS)')).toBeLessThan(
      watchdogSource.indexOf('markProxyUnreachable(')
    )
    expect(source).toMatch(/if \(currentStatus\.proxyReachable === false\) return\r?\n\s+logEvent\('warn', 'tun-watchdog', reason\)/)
    expect(source).toMatch(/if \(currentStatus\.proxyReachable !== false\) return\r?\n\s+logEvent\('info', 'tun-watchdog', 'upstream proxy recovered, traffic flowing again'\)/)
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

  // Regression: the WSAEACCES port-bind retry timer logged a bare `attempt`
  // identifier that is only declared in the *sibling* auto-restart scope
  // (`const attempt = restartAttempt + 1`). At runtime that threw a
  // ReferenceError on the very first line of the cancel branch, which skipped
  // the adapter-lockdown rollback, the orphaned-DNS repair, and the terminal
  // notifyStatus() below it — leaving the user with IPv6 off, DNS pinned to a
  // dead TUN resolver, and a stale "connected" UI. The port-bind retry timer
  // has no `attempt` binding of its own, so it may only use `restartAttempt`.
  it('never references an out-of-scope attempt counter in the port-bind retry timer', async () => {
    const source = await readFile(join(here, 'tunController.ts'), 'utf8')

    const retryStart = source.indexOf('const retryOpts = startOptions')
    expect(retryStart, 'port-bind retry block must exist').toBeGreaterThan(0)
    const retryEnd = source.indexOf("notifyStatus('restarting:1/1')", retryStart)
    expect(retryEnd, 'port-bind retry block must end with its status notify').toBeGreaterThan(
      retryStart
    )

    const retryBlock = source.slice(retryStart, retryEnd)
    expect(retryBlock).toContain('auto-restart cancelled because setting is off')
    // This block declares no `attempt` of its own. Strip comments, string
    // literals and `attempt:` property keys, then nothing named `attempt` may
    // remain as a value reference.
    const executable = retryBlock
      .replace(/\/\/[^\n]*/g, '')
      .replace(/'(?:[^'\\]|\\.)*'/g, "''")
      .replace(/`(?:[^`\\]|\\.)*`/g, '``')
      .replace(/\battempt\s*:/g, 'key:')
      .replace(/\brestartAttempt\b/g, '')
    expect(
      executable.match(/\battempt\b/g),
      'port-bind retry timer must not reference a bare `attempt` binding'
    ).toBeNull()
  })

  // The sibling backoff scope does declare `attempt`, so shorthand logging is
  // fine there — but only if the declaration really precedes the usage within
  // the same block.
  it('declares the attempt counter before logging it in the backoff scope', async () => {
    const source = await readFile(join(here, 'tunController.ts'), 'utf8')

    const backoffBlockStart = source.indexOf('const canAutoRestart =')
    expect(backoffBlockStart, 'backoff block must exist').toBeGreaterThan(0)

    const declaration = source.indexOf('const attempt = restartAttempt + 1', backoffBlockStart)
    expect(declaration, 'backoff scope must declare its attempt counter').toBeGreaterThan(backoffBlockStart)

    // The "user initiated stop" cancel branch is also inside the backoff block;
    // the declaration must precede it.
    const usage = source.indexOf('auto-restart cancelled', declaration)
    expect(usage, 'user-initiated stop cancel branch must appear after declaration').toBeGreaterThan(declaration)
  })
})
