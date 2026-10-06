import fs from 'node:fs'
import { basename, dirname, isAbsolute, resolve } from 'node:path'

/** AT-01-001/010: failed cleanup cannot mask a failed acceptance run or yield PASS. */
export async function runWithCleanup(operation, cleanup) {
  const errors = []
  let result
  try { result = await operation() } catch (error) { errors.push(error) }
  try { await cleanup() } catch (error) { errors.push(error) }
  if (errors.length === 2) {
    throw new AggregateError(errors, 'WP1 run failed and cleanup also failed', { cause: errors[0] })
  }
  if (errors.length === 1) throw errors[0]
  return result
}

function samePath(left, right) {
  return process.platform === 'win32' ? left.toLowerCase() === right.toLowerCase() : left === right
}

/** Remove only an owned mkdtemp child, never a parent, sibling, or redirected path. */
export function removeWp1WorkDirectory(work, tempRoot) {
  if (!isAbsolute(work) || !isAbsolute(tempRoot) || !samePath(work, resolve(work)) ||
      !samePath(tempRoot, resolve(tempRoot)) || !samePath(dirname(work), tempRoot) ||
      !/^wp1-(?:native|migration)-[A-Za-z0-9]{6}$/.test(basename(work))) {
    throw new Error('Unexpected WP1 cleanup path')
  }
  const parent = fs.lstatSync(tempRoot)
  const child = fs.lstatSync(work)
  if (!parent.isDirectory() || parent.isSymbolicLink() || !child.isDirectory() || child.isSymbolicLink()) {
    throw new Error('WP1 cleanup requires real directories, not links')
  }
  const realParent = fs.realpathSync(tempRoot)
  const realWork = fs.realpathSync(work)
  if (!samePath(realParent, tempRoot) || !samePath(realWork, work) || !samePath(dirname(realWork), realParent)) {
    throw new Error('WP1 cleanup path was redirected')
  }
  fs.rmSync(work, { recursive: true, force: true })
}
