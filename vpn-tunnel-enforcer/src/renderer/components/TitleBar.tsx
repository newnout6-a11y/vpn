import '../styles/swiss.css'

/**
 * «Пломба» title bar: a 36px paper strip that moves the window (app-region:
 * drag). Windows draws its own minimise / maximise / close buttons over the
 * right end (Window Controls Overlay, colours from main/themeManager.ts), so
 * snap, resize, double-click maximise and rounded corners stay native.
 */
export function TitleBar() {
  return <div className="c-swiss swiss-titlebar" aria-hidden="true" />
}
