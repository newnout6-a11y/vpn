// Entry bundled and run by nativeHost.itest.ts as the MAIN process of a tiny Electron app (not ELECTRON_RUN_AS_NODE).
// It forks the BUILT native-read host as a real utility process, runs every read twice, then makes the host die
// with a fatal koffi error on purpose. The main process must survive, the pending request must reject as
// `unavailable`, and the next call must respawn a working host. Results go to a file: a GUI-subsystem Electron
// binary does not reliably write to a piped stdout.
import { appendFileSync } from 'node:fs'
import { app, utilityProcess } from 'electron'
import { createHostClient, type HostProcess } from './hostClient'
import { NativeHostError, type HostOp } from './hostProtocol'

const workerPath = process.env.VPNTE_E2E_WORKER ?? ''
const outPath = process.env.VPNTE_E2E_OUT ?? ''
const note = (line: string): void => appendFileSync(outPath, `${line}\n`)

const client = createHostClient({
  fork: () => utilityProcess.fork(workerPath, [], {
    serviceName: 'VPNTE native reads e2e', stdio: 'ignore'
  }) as unknown as HostProcess,
  defaultTimeoutMs: 30_000,
  maxDeaths: 10,
  log: (level, message, details) => note(`log ${level} ${message} ${JSON.stringify(details ?? {})}`)
})

async function run(label: string, op: HostOp, args?: unknown): Promise<void> {
  try {
    const value = await client.call(op, args)
    note(`${label}=ok${Array.isArray(value) ? `(${value.length})` : ''}`)
  } catch (error) {
    // `read-refused` is the designed fail-closed answer (e.g. no physical adapter on a CI runner).
    const kind = error instanceof NativeHostError ? error.kind : 'other'
    note(`${label}=${kind === 'read-refused' ? 'refused' : kind.toUpperCase()}(${(error as Error).message.slice(0, 80)})`)
  }
}

app.whenReady().then(async () => {
  try {
    for (const round of [1, 2]) {
      await run(`r${round}.adapters`, 'adapters')
      await run(`r${round}.ipconfig`, 'ipconfig')
      await run(`r${round}.routes`, 'routes', { prefixes: ['0.0.0.0/0'] })
      await run(`r${round}.selected-routes`, 'selected-route-interfaces')
      await run(`r${round}.physical-sources`, 'physical-sources')
      await run(`r${round}.tunnels`, 'tunnels', { vpnteAlias: 'VPNTE', vpnteIpv4Prefix: '10.250.' })
      await run(`r${round}.physical-snapshot`, 'physical-snapshot', { profiles: [] })
      await run(`r${round}.wininet`, 'wininet')
    }
    if (process.env.VPNTE_E2E_SKIP_ABORT !== '1') {
      // The (test-only) host dies with a fatal N-API error here. If main survives to write the next line, the isolation works.
      await run('abort', 'abort-for-test')
      note(`main-alive-after-abort pid=${process.pid}`)
    }
    await run('respawn.adapters', 'adapters')
    note('E2E_DONE')
  } catch (error) {
    note(`E2E_FAILED ${(error as Error).message}`)
  } finally {
    client.shutdown()
    app.quit()
  }
})
