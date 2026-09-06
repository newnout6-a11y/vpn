import { app } from 'electron'
import { readFile, unlink } from 'fs/promises'
import { join } from 'path'
import { logEvent } from './appLogger'

/**
 * Heal a Windows taskbar-icon hijack left behind by running this app from source.
 *
 * In dev (unpackaged) Electron auto-creates
 *   %APPDATA%\Microsoft\Windows\Start Menu\Programs\Electron.lnk
 * the first time a toast fires — target `node_modules\electron\dist\electron.exe`,
 * icon the Electron atom, display name "Electron" — and stamps it with the
 * AppUserModelID passed to `app.setAppUserModelId()`. Older dev builds used the
 * production AUMID, so on a machine that ran one, Windows binds the *installed*
 * app's taskbar button to that shortcut: atom icon instead of the real one.
 * (The window's own icon is unaffected — only the taskbar button, which the
 * shell resolves through the AUMID -> matching Start Menu shortcut.)
 *
 * main/index.ts now uses a `.dev`-suffixed AUMID in dev so this can't recur.
 * This sweep removes the shortcut a previous build already dropped. It is
 * deliberately narrow: packaged + win32 only, and it deletes `Electron.lnk`
 * only when the bytes still reference a node_modules Electron dist — never a
 * shortcut the user made to some other Electron app.
 */
export async function removeHijackingDevShortcut(): Promise<void> {
  if (process.platform !== 'win32' || !app.isPackaged) return

  const appData = process.env.APPDATA
  if (!appData) return

  const candidate = join(
    appData,
    'Microsoft',
    'Windows',
    'Start Menu',
    'Programs',
    'Electron.lnk'
  )

  let buf: Buffer
  try {
    buf = await readFile(candidate)
  } catch (err) {
    if ((err as NodeJS.ErrnoException)?.code !== 'ENOENT') {
      logEvent('warn', 'app', 'Electron.lnk sweep: read failed', {
        error: (err as Error)?.message ?? String(err)
      })
    }
    return
  }

  // .lnk keeps the target path both as UTF-16LE and (often) ANSI in different
  // sections; test both decodings so we match regardless of which one carries it.
  const haystack = `${buf.toString('utf16le')}\n${buf.toString('latin1')}`
  const looksLikeDevElectron =
    /node_modules[\\/]electron[\\/]dist[\\/]electron\.exe/i.test(haystack)
  if (!looksLikeDevElectron) return

  try {
    await unlink(candidate)
    logEvent(
      'info',
      'app',
      'removed stale dev Electron.lnk that was hijacking the taskbar icon',
      { path: candidate }
    )
  } catch (err) {
    if ((err as NodeJS.ErrnoException)?.code !== 'ENOENT') {
      logEvent('warn', 'app', 'Electron.lnk sweep: delete failed', {
        error: (err as Error)?.message ?? String(err)
      })
    }
  }
}
