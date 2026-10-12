// AT-03-005/006/010: main-process entry for the native physical adapter snapshot.
// The koffi reads live in physicalAdapterCore.ts and run in the native-read host (a utility process).
// Network profile names come from the already-warm elevated PowerShell helper, in main, and are passed along.
import { callNativeHost } from './nativeHost'
import { fetchNetworkProfiles } from './networkProfiles'
import { snapshotFromSource, type NativeAdapterSource } from './physicalAdapterCore'

export * from './physicalAdapterCore'

/**
 * JSON text equivalent to PHYSICAL_ADAPTER_SNAPSHOT_SCRIPT stdout. Rejects on anything unexpected.
 * With an explicit `source` the snapshot is built in-process (tests); otherwise it runs in the host.
 */
export async function readPhysicalAdaptersNative(source?: NativeAdapterSource): Promise<string> {
  if (source) return snapshotFromSource(source)
  const profiles = await fetchNetworkProfiles()
  return callNativeHost<string>('physical-snapshot', { profiles: [...profiles.entries()] })
}
