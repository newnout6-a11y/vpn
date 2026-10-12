// AT-07-002 / AT-12-007: entry of the native-read host, run as an Electron utility process (see hostClient.ts).
// A fatal koffi/N-API error kills THIS process only; the main process sees an exit and callers use PowerShell.
import { serveHost } from './hostServer'
import { runNativeOp } from './nativeOps'

serveHost(runNativeOp)
