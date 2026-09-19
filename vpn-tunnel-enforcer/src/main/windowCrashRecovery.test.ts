import { readFileSync } from 'fs'
import { join } from 'path'
import { describe, expect, it } from 'vitest'

const mainIndexSource = () => readFileSync(join(process.cwd(), 'src', 'main', 'index.ts'), 'utf8')
const traySource = () => readFileSync(join(process.cwd(), 'src', 'main', 'tray.ts'), 'utf8')
const preloadSource = () => readFileSync(join(process.cwd(), 'src', 'preload', 'index.ts'), 'utf8')
const rendererMainSource = () => readFileSync(join(process.cwd(), 'src', 'renderer', 'main.tsx'), 'utf8')

describe('Window Crash & Sleep Lifecycle Recovery Regressions', () => {
  it('disables background throttling so Chromium does not freeze background render pipeline', () => {
    const source = mainIndexSource()
    const createWindowStart = source.indexOf('function createWindow()')
    const webPrefsStart = source.indexOf('webPreferences:', createWindowStart)
    const webPrefsEnd = source.indexOf('backgroundColor:', webPrefsStart)
    const webPrefs = source.slice(webPrefsStart, webPrefsEnd)

    expect(webPrefs).toContain('backgroundThrottling: false')
  })

  it('handles render-process-gone and auto-recovers renderer process', () => {
    const source = mainIndexSource()
    expect(source).toContain("mainWindow.webContents.on('render-process-gone'")
    expect(source).toContain('loadRenderer()')
  })

  it('detects GPU child process crashes and invalidates window surface', () => {
    const source = mainIndexSource()
    expect(source).toContain("app.on('child-process-gone'")
    expect(source).toContain("details.type === 'GPU'")
    expect(source).toContain('mainWindow.webContents.invalidate()')
  })

  it('re-synchronizes renderer and checks crashed state upon system wake', () => {
    const source = mainIndexSource()
    expect(source).toContain("powerMonitor.on('resume'")
    expect(source).toContain("powerMonitor.on('unlock-screen'")
    expect(source).toContain('mainWindow.webContents.isCrashed()')
    expect(source).toContain("'app:resumed-from-sleep'")
  })

  it('unminimizes and reloads crashed webContents in tray showWindow', () => {
    const source = traySource()
    const showWindowStart = source.indexOf('function showWindow()')
    const showWindowEnd = source.indexOf('function runAction', showWindowStart)
    const showWindow = source.slice(showWindowStart, showWindowEnd)

    expect(showWindow).toContain('trayWindow.isMinimized()')
    expect(showWindow).toContain('trayWindow.restore()')
    expect(showWindow).toContain('trayWindow.webContents.isCrashed()')
    expect(showWindow).toContain('trayWindow.webContents.reload()')
    expect(showWindow).toContain('trayWindow.webContents.invalidate()')
  })

  it('exposes onAppResumedFromSleep in preload IPC bridge', () => {
    const source = preloadSource()
    expect(source).toContain('onAppResumedFromSleep?: (callback: () => void) => () => void')
    expect(source).toContain("ipcRenderer.on('app:resumed-from-sleep'")
  })

  it('mounts RootErrorBoundary at the React DOM root in main.tsx', () => {
    const source = rendererMainSource()
    expect(source).toContain('<RootErrorBoundary>')
    expect(source).toContain('</RootErrorBoundary>')
    expect(source).toContain("window.addEventListener('error'")
    expect(source).toContain("window.addEventListener('unhandledrejection'")
  })
})
