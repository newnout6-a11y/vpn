// Node's built-in WebSocket; no browser automation, production hooks or extra dependencies.
import { setTimeout as delay } from 'node:timers/promises'
import { deadline } from './real-vpn-scenario.mjs'

export async function connectInspector(port, expectedPid, timeoutMs = 30_000) {
  const until = Date.now() + timeoutMs
  let target
  while (Date.now() < until) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/list`, { signal: AbortSignal.timeout(500) })
      target = (await response.json()).find(item => item.type === 'node')
      if (target) break
    } catch { /* Inspector is not listening yet. */ }
    await delay(100)
  }
  if (!target || !target.webSocketDebuggerUrl?.startsWith(`ws://127.0.0.1:${port}/`)) {
    throw new Error('Local Electron main inspector did not become ready')
  }
  const socket = new WebSocket(target.webSocketDebuggerUrl)
  try {
    await deadline(new Promise((resolve, reject) => {
      socket.addEventListener('open', resolve, { once: true })
      socket.addEventListener('error', () => reject(new Error('Inspector connection failed')), { once: true })
    }), timeoutMs, 'inspector connection')
  } catch (error) { socket.close(); throw error }
  let nextId = 0
  let contextId
  const contexts = []
  const requests = new Map()
  let disconnected = false
  const closed = () => {
    disconnected = true
    for (const request of requests.values()) request.reject(new Error('Electron inspector disconnected'))
    requests.clear()
  }
  socket.addEventListener('close', closed)
  socket.addEventListener('error', closed)
  socket.addEventListener('message', ({ data }) => {
    const message = JSON.parse(data)
    if (message.method === 'Runtime.executionContextCreated') contexts.push(message.params.context)
    const request = requests.get(message.id)
    if (!request) return
    requests.delete(message.id)
    if (message.error || message.result?.exceptionDetails) request.reject(new Error('Electron evaluation failed; see application log'))
    else request.resolve(message.result?.result?.value)
  })
  const request = (method, params = {}) => {
    if (disconnected || socket.readyState !== WebSocket.OPEN) return Promise.reject(new Error('Electron inspector disconnected'))
    const id = ++nextId
    const promise = new Promise((resolve, reject) => {
      requests.set(id, { resolve, reject })
      socket.send(JSON.stringify({ id, method, params }))
    })
    return deadline(promise, timeoutMs, 'Electron evaluation').finally(() => requests.delete(id))
  }
  const evaluate = expression => request('Runtime.evaluate', { expression, contextId, awaitPromise: true, returnByValue: true })
  const close = () => { socket.close(); closed() }
  try {
    await request('Runtime.enable')
    const contextDeadline = Date.now() + timeoutMs
    while (!contexts.some(c => c.auxData?.isDefault)) {
      if (Date.now() >= contextDeadline) throw new Error('Electron main execution context not found')
      await delay(50)
    }
    contextId = contexts.find(c => c.auxData?.isDefault).id
    if (await evaluate('process.pid') !== expectedPid) throw new Error('Inspector belongs to another process')
    await evaluate(`globalThis.__realVpnElectron = process.mainModule.require('electron'); true`)
    const renderer = expression => evaluate(`(() => {
      const w = __realVpnElectron.BrowserWindow.getAllWindows().find(w => !w.isDestroyed()
        && !w.webContents.isLoadingMainFrame() && w.webContents.getURL().endsWith('/renderer/index.html'));
      return w ? w.webContents.executeJavaScript(${JSON.stringify(expression)}) : null;
    })()`)
    return { evaluate, renderer, close }
  } catch (error) { close(); throw error }
}
