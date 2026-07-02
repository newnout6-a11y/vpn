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
})
