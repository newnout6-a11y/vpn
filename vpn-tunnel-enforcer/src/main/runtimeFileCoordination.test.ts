// AT-01-009: live scan/staging exclusion, including nested directories and faults.
import { join, resolve } from 'path'
import { describe, expect, it } from 'vitest'
import { withRuntimeArtifactStage, withRuntimeDirectoryInspection, withRuntimeDirectoryMutation } from './runtimeFileCoordination'

function deferred() {
  let resolve!: () => void
  const promise = new Promise<void>(done => { resolve = done })
  return { promise, resolve }
}
const root = resolve('.tmp/runtime-coordination-fixture')

describe('runtime file operation coordination', () => {
  it('lets distinct artifacts stage concurrently, then scans their stable parent tree', async () => {
    const release = deferred(), started = deferred()
    const events: string[] = []
    const first = withRuntimeArtifactStage(join(root, 'first.exe'), async () => { events.push('first'); started.resolve(); await release.promise })
    await started.promise
    const second = withRuntimeArtifactStage(join(root, 'nested/second.dll'), async () => { events.push('second'); await release.promise })
    const scan = withRuntimeDirectoryInspection(root, async () => { events.push('scan') })
    await Promise.resolve()
    expect(events).toEqual(['first', 'second'])
    release.resolve()
    await Promise.all([first, second, scan])
    expect(events).toEqual(['first', 'second', 'scan'])
  })
  it('blocks nested staging during a scan and prevents later staging from starving the next scan', async () => {
    const release = deferred(), started = deferred(), events: string[] = []
    const first = withRuntimeArtifactStage(join(root, 'first.exe'), async () => { events.push('first'); started.resolve(); await release.promise })
    await started.promise
    const scan = withRuntimeDirectoryInspection(root, async () => { events.push('scan') })
    const later = withRuntimeArtifactStage(join(root, 'nested/later.exe'), async () => { events.push('later') })
    await Promise.resolve()
    expect(events).toEqual(['first'])
    release.resolve()
    await Promise.all([first, scan, later])
    expect(events).toEqual(['first', 'scan', 'later'])
  })
  it('serializes identical destinations without blocking sibling runtimes', async () => {
    const release = deferred(), started = deferred(), events: string[] = []
    const first = withRuntimeArtifactStage(join(root, 'same.exe'), async () => { started.resolve(); await release.promise; events.push('first') })
    await started.promise
    const same = withRuntimeArtifactStage(join(root, 'same.exe'), async () => { events.push('same') })
    await withRuntimeDirectoryInspection(root + '-sibling', async () => { events.push('sibling') })
    expect(events).toEqual(['sibling'])
    release.resolve()
    await Promise.all([first, same])
    expect(events).toEqual(['sibling', 'first', 'same'])
  })
  it('matches Windows case and separators while keeping different volumes independent', async () => {
    const release = deferred(), started = deferred(), events: string[] = []
    const first = withRuntimeArtifactStage('C:\\runtime\\nested\\worker.exe', async () => { started.resolve(); await release.promise })
    await started.promise
    const scan = withRuntimeDirectoryInspection('c:/RUNTIME', async () => { events.push('scan') })
    await withRuntimeDirectoryInspection('D:\\runtime', async () => { events.push('other-volume') })
    expect(events).toEqual(['other-volume'])
    release.resolve()
    await Promise.all([first, scan])
    expect(events).toEqual(['other-volume', 'scan'])
  })
  it.each(['stage', 'inspect', 'mutate'] as const)('releases coordination after a failed %s operation', async kind => {
    const run = { stage: withRuntimeArtifactStage, inspect: withRuntimeDirectoryInspection, mutate: withRuntimeDirectoryMutation }[kind]
    const release = deferred(), started = deferred()
    const failed = run(root, async () => { started.resolve(); await release.promise; throw new Error('fixture failure') })
    const rejected = expect(failed).rejects.toThrow('fixture failure')
    await started.promise
    let ran = false
    const next = withRuntimeDirectoryMutation(root, async () => { ran = true })
    await Promise.resolve()
    expect(ran).toBe(false)
    release.resolve()
    await Promise.all([rejected, next])
    expect(ran).toBe(true)
  })
})
