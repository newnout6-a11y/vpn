// Проверка шрифтов в реальном Chrome без скриншотов: какие семейства реально применены и загружены,
// есть ли горизонтальный оверфлоу и ошибки консоли. node tools/fontcheck.mjs
import puppeteer from 'puppeteer-core'
import { join, dirname, extname, normalize } from 'node:path'
import { fileURLToPath } from 'node:url'
import http from 'node:http'
import fs from 'node:fs'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const DIST = join(ROOT, 'dist')
const T = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.png': 'image/png', '.txt': 'text/plain' }
const srv = http.createServer((req, res) => {
  const p = decodeURIComponent(new URL(req.url, 'http://x').pathname)
  let f = normalize(join(DIST, p))
  if (fs.existsSync(f) && fs.statSync(f).isDirectory()) f = join(f, 'index.html')
  if (!fs.existsSync(f)) { res.writeHead(404); res.end(fs.readFileSync(join(DIST, '404.html'))); return }
  res.writeHead(200, { 'Content-Type': T[extname(f)] || 'application/octet-stream' }); res.end(fs.readFileSync(f))
}).listen(0)
const port = srv.address().port

const PAGES = ['/', '/features/', '/how-it-works/', '/protocols/', '/security/', '/roadmap/', '/download/', '/faq/', '/nope-404/']
const EXPECT = ['Bitter', 'Golos Text', 'Fira Mono']
const browser = await puppeteer.launch({ executablePath: process.env.CHROME || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', headless: true, args: ['--no-sandbox', '--enable-unsafe-swiftshader'] })
let bad = 0
for (const w of [1440, 390]) {
  const page = await browser.newPage()
  await page.setViewport({ width: w, height: 900 })
  const errors = []
  page.on('console', (m) => { if (['error', 'warning'].includes(m.type())) errors.push(m.text()) })
  page.on('pageerror', (e) => errors.push('pageerror: ' + e.message))
  page.on('requestfailed', (r) => errors.push('reqfail: ' + r.url()))
  for (const path of PAGES) {
    await page.goto(`http://localhost:${port}${path}`, { waitUntil: 'networkidle0' })
    await new Promise((r) => setTimeout(r, 900))
    const r = await page.evaluate(async (expect) => {
      await document.fonts.ready
      const first = (sel) => { const e = document.querySelector(sel); return e ? getComputedStyle(e).fontFamily.split(',')[0].replace(/"/g, '').trim() : null }
      const loaded = [...new Set([...document.fonts].filter((f) => f.status === 'loaded').map((f) => f.family.replace(/"/g, '')))]
      const all = [...new Set([...document.fonts].map((f) => f.family.replace(/"/g, '')))]
      return {
        body: first('body'), h1: first('h1'), mono: first('code, .eyebrow, .tag'),
        loaded, all, foreign: all.filter((f) => !expect.includes(f)),
        sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth
      }
    }, EXPECT)
    const problems = []
    if (r.body !== 'Golos Text') problems.push('body=' + r.body)
    if (r.h1 !== 'Bitter') problems.push('h1=' + r.h1)
    if (r.mono && r.mono !== 'Fira Mono') problems.push('mono=' + r.mono)
    if (r.foreign.length) problems.push('чужие @font-face: ' + r.foreign.join(','))
    for (const f of ['Bitter', 'Golos Text']) if (!r.loaded.includes(f)) problems.push('не загружен ' + f)
    if (r.sw > r.cw) problems.push(`оверфлоу ${r.sw}>${r.cw}`)
    if (problems.length) bad++
    console.log(`${w} ${path.padEnd(16)} ${problems.length ? '✘ ' + problems.join('; ') : '✔'}  [загружено: ${r.loaded.join(', ')}]`)
  }
  const uniq = [...new Set(errors)]
  console.log(`${w} консоль: ${uniq.length ? uniq.join('\n   ') : 'чисто'}`)
  await page.close()
}
await browser.close(); srv.close()
process.exit(bad ? 1 : 0)
