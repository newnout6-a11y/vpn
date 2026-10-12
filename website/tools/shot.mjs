// Проверка в реальном Chrome: скриншоты, ошибки консоли, горизонтальный оверфлоу.
// node tools/shot.mjs <path> [width] [height] [fullpage|viewport] [scrollY]
import puppeteer from 'puppeteer-core'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { mkdirSync } from 'node:fs'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const OUT = join(ROOT, '..', '.tmp', 'shots')
mkdirSync(OUT, { recursive: true })
const [, , path = '/', w = '1440', h = '900', mode = 'viewport', sy = '0'] = process.argv
const CHROME = process.env.CHROME || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'

const http = await import('node:http')
const fs = await import('node:fs')
const { extname, resolve, sep } = await import('node:path')
const DIST = join(ROOT, 'dist')
const T = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.png': 'image/png', '.txt': 'text/plain' }
// Только файлы внутри dist; битый %-код — 400, выход за dist — 403.
function safeFile(url) {
  let p
  try { p = decodeURIComponent(new URL(url, 'http://x').pathname) } catch { return { code: 400 } }
  const file = resolve(DIST, '.' + p)
  return file === DIST || file.startsWith(DIST + sep) ? { file } : { code: 403 }
}
const srv = http.createServer((req, res) => {
  const r = safeFile(req.url)
  if (r.code) { res.writeHead(r.code).end(); return }
  let f = r.file
  if (fs.existsSync(f) && fs.statSync(f).isDirectory()) f = join(f, 'index.html')
  if (!fs.existsSync(f)) { res.writeHead(404); res.end(fs.readFileSync(join(DIST, '404.html'))); return }
  res.writeHead(200, { 'Content-Type': T[extname(f)] || 'application/octet-stream' }); res.end(fs.readFileSync(f))
})
await new Promise((r) => srv.listen(0, '127.0.0.1', r))
const port = srv.address().port

const browser = await puppeteer.launch({ executablePath: CHROME, headless: true, args: ['--no-sandbox', '--enable-unsafe-swiftshader'] })
const page = await browser.newPage()
await page.setViewport({ width: +w, height: +h, deviceScaleFactor: 1 })
// REDUCE=1 — проверка статичной версии для prefers-reduced-motion.
if (process.env.REDUCE) await page.emulateMediaFeatures([{ name: 'prefers-reduced-motion', value: 'reduce' }])
// EVAL="js" — выполнить код на странице перед снимком (например, нажать рубильник).
const evalJs = process.env.EVAL
const errors = []
page.on('console', (m) => { if (['error', 'warning'].includes(m.type())) errors.push(`[${m.type()}] ${m.text()}`) })
page.on('pageerror', (e) => errors.push(`[pageerror] ${e.message}`))
page.on('requestfailed', (r) => errors.push(`[reqfail] ${r.url()}`))
await page.goto(`http://localhost:${port}${path}`, { waitUntil: 'networkidle0' })
await new Promise((r) => setTimeout(r, 1800))

if (mode === 'fullpage') {
  // прокрутить страницу целиком, чтобы сработали reveal-анимации
  const total = await page.evaluate(() => document.documentElement.scrollHeight)
  for (let y = 0; y < total; y += 500) { await page.evaluate((v) => window.scrollTo(0, v), y); await new Promise((r) => setTimeout(r, 140)) }
  await page.evaluate(() => window.scrollTo(0, 0)); await new Promise((r) => setTimeout(r, 700))
} else if (+sy) {
  await page.evaluate((v) => window.scrollTo(0, v), +sy); await new Promise((r) => setTimeout(r, 1600))
}
if (evalJs) { await page.evaluate(evalJs); await new Promise((r) => setTimeout(r, +(process.env.EVAL_WAIT || 1200))) }
const overflow = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth, total: document.documentElement.scrollHeight }))
const name = `${path.replace(/\W+/g, '_') || 'home'}_${w}${process.env.TAG ? '_' + process.env.TAG : ''}${mode === 'fullpage' ? '_full' : sy !== '0' ? '_y' + sy : ''}.png`
await page.screenshot({ path: join(OUT, name), fullPage: mode === 'fullpage' })
console.log(`shot: ${name}  overflowX: ${overflow.sw > overflow.cw ? 'YES ' + overflow.sw + '>' + overflow.cw : 'no'}  height: ${overflow.total}`)
console.log(errors.length ? errors.join('\n') : 'console: clean')
await browser.close(); srv.close()
