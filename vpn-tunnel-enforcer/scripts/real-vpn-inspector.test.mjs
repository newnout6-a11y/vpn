// AT-00-005: exercise the transport against a harmless real Electron main, with no VPN modules.
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { createRequire } from 'node:module'
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises'
import { createServer } from 'node:net'
import { createServer as createHttpServer } from 'node:http'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'
import { connectInspector } from './real-vpn-inspector.mjs'
import { deadline } from './real-vpn-scenario.mjs'

test('an inspector with a stalled WebSocket handshake has a bounded deadline', { timeout: 5000 }, async () => {
  const sockets = new Set()
  const server = createHttpServer((_req, res) => {
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify([{ type: 'node', webSocketDebuggerUrl: `ws://127.0.0.1:${server.address().port}/inspector` }]))
  })
  server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)) })
  server.on('upgrade', () => { /* Deliberately never complete this fixture's handshake. */ })
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  try {
    await assert.rejects(connectInspector(server.address().port, 0, 100), /inspector connection: deadline exceeded/)
  } finally {
    for (const socket of sockets) socket.destroy()
    await new Promise(resolve => server.close(resolve))
  }
})

test('real Electron context, PID binding, concurrent calls and safe transport errors', { timeout: 20_000 }, async t => {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
  await mkdir(join(root, '.tmp'), { recursive: true })
  const dir = await mkdtemp(join(root, '.tmp/real-vpn-inspector-test-'))
  await mkdir(join(dir, 'profile'))
  await mkdir(join(dir, 'renderer'))
  await writeFile(join(dir, 'renderer/index.html'), '<!doctype html><title>Harmless renderer fixture</title>')
  await writeFile(join(dir, 'main.cjs'), `const {app}=require('electron');
    app.setPath('userData',require('path').join(__dirname,'profile'));setInterval(()=>{},1000)`)
  const server = createServer()
  await new Promise((ok, no) => { server.once('error', no); server.listen(0, '127.0.0.1', ok) })
  const port = server.address().port
  await new Promise(ok => server.close(ok))
  const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE
  const child = spawn(createRequire(import.meta.url)('electron'), [`--inspect=127.0.0.1:${port}`, join(dir, 'main.cjs')],
    { cwd: root, env, windowsHide: true, stdio: 'ignore' })
  const exited = new Promise(resolve => child.once('exit', resolve))
  // This fallback applies ONLY to this disposable fixture, which never loads VPN or system modules.
  t.after(() => { if (child.exitCode === null) child.kill() })
  await assert.rejects(connectInspector(port, child.pid + 1, 5000), /another process/)
  const inspector = await connectInspector(port, child.pid, 5000)
  t.after(() => inspector.close())
  assert.deepEqual(await Promise.all([inspector.evaluate('Promise.resolve(7)'), inspector.evaluate('Promise.resolve(8)')]), [7, 8])
  assert.equal(await inspector.evaluate('__realVpnElectron.BrowserWindow.getAllWindows().length'), 0)
  assert.equal(await inspector.renderer('true'), null, 'No window is not a ready preload')
  await inspector.evaluate(`globalThis.fixtureWindow = new __realVpnElectron.BrowserWindow({show:false}); true`)
  assert.equal(await inspector.renderer('true'), null, 'Blank/unrelated windows must not receive test IPC')
  await inspector.evaluate(`fixtureWindow.loadFile(${JSON.stringify(join(dir, 'renderer/index.html'))}).then(()=>true)`)
  assert.equal(await inspector.renderer('Promise.resolve(27)'), 27, 'Hidden, fully loaded app renderer is callable')
  await inspector.evaluate(`globalThis.unrelatedWindow = new __realVpnElectron.BrowserWindow({show:false}); true`)
  assert.equal(await inspector.renderer('28'), 28, 'A later unrelated window cannot replace the app renderer')
  await assert.rejects(inspector.evaluate('throw new Error("FAKE-PRIVATE-PAYLOAD")'), error => !error.message.includes('FAKE-PRIVATE-PAYLOAD'))
  await inspector.evaluate('setTimeout(()=>__realVpnElectron.app.exit(0),30);true')
  inspector.close()
  assert.equal(await deadline(exited, 5000, 'fixture exit'), 0)
})
