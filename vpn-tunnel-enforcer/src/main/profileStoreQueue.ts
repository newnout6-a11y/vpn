/** One commit queue shared by subscription refresh and profile import.
 * Network work stays outside; callers re-read the current snapshot inside. */
let pending: Promise<void> = Promise.resolve()

export function withProfileStoreWriteLock<T>(operation: () => T | Promise<T>): Promise<T> {
  const run = pending.then(operation, operation)
  pending = run.then(() => undefined, () => undefined)
  return run
}
