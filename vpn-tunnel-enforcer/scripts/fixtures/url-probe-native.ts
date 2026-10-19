// AT-00-003: actual Electron navigation/executeJavaScript/close semantics.
import { app, BrowserWindow, session } from 'electron'
import { createServer } from 'node:http'
import { strict as assert } from 'node:assert'
import { mkdirSync } from 'node:fs'
import { join } from 'node:path'
import { probePageSignal } from '../../src/main/urlAvailability'

const wait = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms))
app.on('window-all-closed', () => {})
const directory = join(process.env.VPNTE_SMOKE_DIR!, 'url-user-data')
mkdirSync(directory, { recursive: true }); app.setPath('userData', directory)

app.whenReady().then(async () => {
  const windows: BrowserWindow[] = [], sessions: Electron.Session[] = []
  let scripts = 0
  app.on('browser-window-created', (_event, window) => {
    windows.push(window); sessions.push(window.webContents.session)
    const execute = window.webContents.executeJavaScript.bind(window.webContents)
    window.webContents.executeJavaScript = (...args) => { scripts++; return execute(...args) }
  })
  const server = createServer((request, response) => {
    if (request.url === '/hang') return // Deliberately never stop main-frame loading.
    response.setHeader('Content-Type', 'text/html')
    response.end('<script>setTimeout(()=>location.href="/hang",100)</script>native fixture')
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  const url = `http://127.0.0.1:${(server.address() as { port: number }).port}/page`
  const controller = new AbortController()
  const checks = [0, 1].map(() => probePageSignal(url, 'direct://', controller.signal).catch(error => error))
  try {
    const deadline = Date.now() + 5000
    while (scripts < 2 && Date.now() < deadline) await wait(20)
    assert.equal(scripts, 2)
    assert(windows.every(window => window.webContents.isLoadingMainFrame()))
    assert.notEqual(sessions[0], session.defaultSession)
    assert.notEqual(sessions[1], session.defaultSession)
    assert.notEqual(sessions[0], sessions[1])
    const started = performance.now()
    controller.abort()
    let timer!: ReturnType<typeof setTimeout>
    const results = await Promise.race([
      Promise.all(checks),
      new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(new Error('Window close did not drain probe')), 900) })
    ]).finally(() => clearTimeout(timer))
    assert(results.every(result => result.category === 'cancelled'))
    assert(windows.every(window => window.isDestroyed()))
    console.log('URL_PROBE_NATIVE_PASS', JSON.stringify({ electron: process.versions.electron,
      checks: ['two private sessions; default session unchanged', 'real pending executeJavaScript during redirect',
        'actual window close revokes both probes; no hung shutdown drain'], cancelMs: Math.round(performance.now() - started) }))
  } finally {
    controller.abort()
    for (const window of windows) if (!window.isDestroyed()) window.destroy()
    server.closeAllConnections()
    await new Promise<void>(resolve => server.close(() => resolve()))
  }
  app.exit(0)
}).catch(error => { console.error(error); app.exit(1) })
