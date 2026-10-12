// Entry bundled and run by electronRuntime.itest.ts under the real Electron runtime (ELECTRON_RUN_AS_NODE).
// It calls every native reader twice: a koffi misuse that Node tolerates (e.g. koffi.view external buffers)
// aborts the whole Electron process with a fatal N-API error, which no unit test under Node can see.
import { nativeActiveTunnels, nativeAdapterRows, nativeIpConfigRows, nativePhysicalIpv4Sources, nativeRouteRows } from './nativeNetworkReads'
import { createKoffiSource, readPhysicalAdaptersNative } from './physicalAdapterNative'
import { notifyWinInetSettingsChangedNative } from './winInet'

async function main(): Promise<void> {
  for (let round = 1; round <= 2; round++) {
    const lines: string[] = []
    const step = (name: string, fn: () => unknown) => { const r = fn(); lines.push(`${name}=${Array.isArray(r) ? r.length : 'ok'}`) }
    step('adapters', () => nativeAdapterRows())
    step('ipconfig', () => nativeIpConfigRows())
    step('routes', () => nativeRouteRows(['0.0.0.0/0']))
    step('physicalSources', () => nativePhysicalIpv4Sources())
    step('tunnels', () => nativeActiveTunnels({ vpnteAlias: 'VPNTE', vpnteIpv4Prefix: '10.250.' }))
    const snapshot = await readPhysicalAdaptersNative(createKoffiSource(new Map()))
    lines.push(`snapshot=${JSON.parse(snapshot) ? 'ok' : ''}`)
    await notifyWinInetSettingsChangedNative()
    lines.push('wininet=ok')
    console.log(`round${round} ${lines.join(' ')}`)
  }
  console.log('PROBE_DONE')
}
main().catch(error => { console.log(`PROBE_THROW ${(error as Error).message}`); process.exit(1) })
