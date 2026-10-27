// AT-07-002 / AT-12-007: main-process access to the native-read host (an Electron utility process).
// Electron is required lazily so modules that import this file stay loadable in unit tests.
import { join } from 'path'
import { createHostClient, type HostClient, type HostProcess } from './hostClient'
import { NativeHostError, type HostOp } from './hostProtocol'

let client: HostClient | null = null
// Registry/adapter ownership can stall in native code. Its host must not hold
// up ordinary adapter, route or runtime reads after the caller switches to CIM.
let tunOwnershipClient: HostClient | null = null
// A sampler deadline must not kill pending adapter/route reads, and a slow
// inventory read must not queue ahead of the next traffic sample.
let trafficCountersClient: HostClient | null = null
let stopped = false

function log(level: 'info' | 'warn', message: string, details?: Record<string, unknown>): void {
  // appLogger pulls in Electron; load it only when something actually happened.
  void import('../appLogger').then(({ logEvent }) => logEvent(level, 'native-host', message, details)).catch(() => undefined)
}

function forkHost(): HostProcess {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { utilityProcess } = require('electron') as typeof import('electron')
  const child = utilityProcess.fork(join(__dirname, 'nativeHostWorker.js'), [], { serviceName: 'VPNTE native reads', stdio: 'ignore' })
  return child as unknown as HostProcess
}

function getClient(op: HostOp): HostClient {
  if (op === 'owned-tun-index') {
    tunOwnershipClient ??= createHostClient({ fork: forkHost, log })
    return tunOwnershipClient
  }
  if (op === 'traffic-counters') {
    trafficCountersClient ??= createHostClient({ fork: forkHost, log })
    return trafficCountersClient
  }
  client ??= createHostClient({ fork: forkHost, log })
  return client
}

/**
 * Runs a native read in the host. NativeHostError preserves unavailable/read-refused failures for the
 * caller's fallback policy; `wininet-false` is authoritative. Traffic sampling never replays failed reads.
 */
export async function callNativeHost<T>(op: HostOp, args?: unknown, timeoutMs?: number): Promise<T> {
  if (process.platform !== 'win32') throw new NativeHostError('unavailable', 'native reads are Windows-only')
  if (stopped) throw new NativeHostError('unavailable', 'native host stopped for application quit')
  if (process.env.VPNTE_DISABLE_NATIVE_NET === '1') throw new NativeHostError('unavailable', 'native reads disabled by VPNTE_DISABLE_NATIVE_NET')
  return getClient(op).call<T>(op, args, timeoutMs)
}

/** Stops the host for application quit. Later calls reject as unavailable instead of respawning a host while quitting. */
export function shutdownNativeHost(): void {
  stopped = true
  client?.shutdown()
  tunOwnershipClient?.shutdown()
  trafficCountersClient?.shutdown()
  client = null
  tunOwnershipClient = null
  trafficCountersClient = null
}
