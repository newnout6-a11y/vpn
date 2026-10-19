// AT-00-003: real Electron document events and production registry/lifetime.
// Only the long-running I/O is controlled; no VPN or external traffic is used.
import { app, BrowserWindow } from 'electron'
import assert from 'node:assert/strict'
import { once } from 'node:events'
import { join } from 'node:path'
import { requestDocumentLifetime } from '../../src/main/requestDocumentLifetime'
import { OperationRegistry } from '../../src/main/operationRegistry'

const directory = process.env.VPNTE_SMOKE_DIR!
app.setPath('userData', join(directory, 'requester-user-data'))
const watchdog = setTimeout(() => app.exit(1), 30_000)
const windows = new Set<BrowserWindow>()
function window() {
  const view = new BrowserWindow({ show: false, webPreferences: { sandbox: true, contextIsolation: true, nodeIntegration: false } })
  windows.add(view)
  return view
}

app.whenReady().then(async () => {
  const foreign = window()
  await foreign.loadFile(join(directory, 'renderer.html'))
  for (const trigger of ['reload', 'destroy'] as const) {
    const view = window(), sender = view.webContents
    await view.loadFile(join(directory, 'renderer.html'))
    const events = ['destroyed', 'render-process-gone', 'did-start-navigation']
    const baseline = events.map(event => sender.listenerCount(event))
    const lifetime = requestDocumentLifetime(sender)
    const observed: string[] = []
    const registry = new OperationRegistry(operation => { observed.push(operation.status) })
    let release!: () => void, commits = 0
    const held = new Promise<void>(done => { release = done })
    const run = registry.run('import', async lease => {
      await lease.wait(held)
      return lease.commit(() => ++commits)
    }, { signal: lifetime.signal })
    const cancelled = assert.rejects(run, (error: any) => error.category === 'cancelled')
    if (trigger === 'reload') {
      const loaded = once(foreign.webContents, 'did-finish-load')
      foreign.webContents.reload(); await loaded
      assert.equal(lifetime.signal.aborted, false, 'another document must not cancel this request')
      const inPage = once(sender, 'did-navigate-in-page')
      await sender.executeJavaScript('location.hash = "requester-fixture"')
      await inPage
      assert.equal(lifetime.signal.aborted, false, 'same-document navigation must retain the request')
    }
    const start = performance.now()
    const loaded = trigger === 'reload' ? once(sender, 'did-finish-load') : undefined
    if (trigger === 'reload') sender.reload()
    else view.destroy()
    await cancelled
    assert.ok(performance.now() - start < 900, 'request cancellation must be prompt')
    assert.equal(registry.isBusy('import'), true, 'physical I/O retains its lease')
    await loaded
    release(); await registry.close()
    lifetime.dispose()
    assert.equal(commits, 0)
    assert.deepEqual(observed, ['running', 'cancelled'])
    assert.deepEqual(events.map(event => sender.listenerCount(event)), baseline)
    if (!view.isDestroyed()) view.destroy()
  }
  console.log('REQUEST_DOCUMENT_NATIVE_PASS', JSON.stringify({ electron: process.versions.electron,
    checks: ['real reload/destroy cancel within 900 ms; retained drain and no late commit',
      'foreign reload and same-document navigation retain ownership', 'listeners disposed after terminal'] }))
}).then(() => { clearTimeout(watchdog); app.exit(0) }).catch(error => {
  console.error(error)
  for (const view of windows) if (!view.isDestroyed()) view.destroy()
  clearTimeout(watchdog); app.exit(1)
})
