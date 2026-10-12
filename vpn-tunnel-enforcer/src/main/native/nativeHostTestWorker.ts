// TEST ONLY - bundled solely by nativeHost.itest.ts, never by electron.vite.config.ts, so it is not in any release.
// The production host plus one extra op that makes the host die the way #26 did (koffi.view over foreign memory is a
// fatal N-API error under Electron), followed by an explicit abort. It proves the main process survives a host crash.
import { serveHost } from './hostServer'
import { runNativeOp } from './nativeOps'

function crashLikeIssue26(): never {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const koffi = require('koffi')
    koffi.view(koffi.alloc('int32_t', 4), 8)
  } catch { /* fall through to the explicit abort */ }
  process.abort()
}

serveHost(async (op, args) => (op === 'abort-for-test' ? crashLikeIssue26() : runNativeOp(op, args)))
