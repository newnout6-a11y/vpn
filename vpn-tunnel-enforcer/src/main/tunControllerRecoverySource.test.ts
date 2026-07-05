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
    const stopSignature = source.indexOf('async stop(): Promise<{ success: boolean; error?: string; warning?: string }>')
    const cleanupBranch = source.indexOf('if (cleanupErrors.length > 0)', stopSignature)
    const successReturn = source.indexOf('return { success: true, warning }', cleanupBranch)
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
})
