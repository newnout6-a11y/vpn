import { logEvent } from './appLogger'

export type PsSpawnKind = 'cold-ps' | 'elevated-exec'

// Measurement only: records how long each PowerShell call took and whether it
// paid for a fresh process. Never inspects or logs the script text itself.
export async function timePs<T>(kind: PsSpawnKind, label: string, run: () => Promise<T>): Promise<T> {
  const started = Date.now()
  let ok = false
  try {
    const result = await run()
    ok = true
    return result
  } finally {
    logEvent('info', 'perf', 'powershell call', { kind, label, ms: Date.now() - started, ok })
  }
}

export async function timePhase<T>(phase: string, run: () => Promise<T>): Promise<T> {
  const started = Date.now()
  try {
    return await run()
  } finally {
    logEvent('info', 'perf', 'phase', { phase, ms: Date.now() - started })
  }
}
