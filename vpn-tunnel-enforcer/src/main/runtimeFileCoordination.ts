// AT-01-009: an ACL tree snapshot must not observe our temporary staging files
// being renamed/deleted. This coordinates live operations, never caches trust.
import { isAbsolute, relative, resolve, win32 } from 'path'

type Kind = 'inspect' | 'stage' | 'mutate'
interface Access { path: string; kind: Kind; run: () => void }
const active = new Set<Access>()
const pending: Access[] = []
function normalize(path: string): string {
  return process.platform === 'win32' || /^(?:[a-z]:[\\/]|\\\\)/i.test(path) ? win32.resolve(path).toLowerCase() : resolve(path)
}
function contains(parent: string, child: string): boolean {
  const difference = /^(?:[a-z]:[\\/]|\\\\)/i.test(parent) ? win32.relative(parent, child) : relative(parent, child)
  return !difference || (difference !== '..' && !/^\.\.[\\/]/.test(difference) && !isAbsolute(difference) && !win32.isAbsolute(difference))
}
function conflicts(a: Access, b: Access): boolean {
  if (a.kind === 'inspect' && b.kind === 'inspect') return false
  if (a.kind === 'stage' && b.kind === 'stage') return a.path === b.path
  return contains(a.path, b.path) || contains(b.path, a.path)
}
function drain(): void {
  for (let index = 0; index < pending.length;) {
    const request = pending[index]
    // A later writer cannot keep overtaking an already waiting tree scan.
    if ([...active].some(other => conflicts(request, other)) || pending.slice(0, index).some(other => conflicts(request, other))) { index++; continue }
    pending.splice(index, 1)
    active.add(request)
    request.run()
  }
}
function coordinate<T>(path: string, kind: Kind, operation: () => Promise<T>): Promise<T> {
  return new Promise<T>((resolveResult, reject) => {
    const request: Access = { path: normalize(path), kind, run: () => {
      Promise.resolve().then(operation).then(resolveResult, reject).finally(() => { active.delete(request); drain() })
    } }
    pending.push(request)
    drain()
  })
}
export const withRuntimeArtifactStage = <T>(path: string, operation: () => Promise<T>): Promise<T> => coordinate(path, 'stage', operation)
export const withRuntimeDirectoryInspection = <T>(path: string, operation: () => Promise<T>): Promise<T> => coordinate(path, 'inspect', operation)
export const withRuntimeDirectoryMutation = <T>(path: string, operation: () => Promise<T>): Promise<T> => coordinate(path, 'mutate', operation)
