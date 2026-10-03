function pause(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise(resolve => {
    if (signal.aborted) { resolve(); return }
    const finish = () => { clearTimeout(timer); signal.removeEventListener('abort', finish); resolve() }
    const timer = setTimeout(finish, ms)
    signal.addEventListener('abort', finish, { once: true })
  })
}

/** Stop at every async boundary; stale samples must never drive a fallback. */
export async function collectAdaptiveSamples(
  isCurrent: () => boolean,
  signal: AbortSignal,
  probe: (signal: AbortSignal) => Promise<number | null>
): Promise<number[] | null> {
  const current = () => !signal.aborted && isCurrent()
  if (!current()) return null
  await pause(20_000, signal)
  if (!current()) return null
  const samples: number[] = []
  for (let attempt = 0; attempt < 3; attempt++) {
    if (!current()) return null
    const sample = await probe(signal)
    if (!current()) return null
    if (sample !== null) samples.push(sample)
    if (attempt < 2) await pause(2500, signal)
  }
  return current() ? samples : null
}
