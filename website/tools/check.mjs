// Проверки поведения в реальном Chrome, которые не видны на скриншоте. node tools/check.mjs
//  1. аварийный режим: site.js заблокирован — контент обязан появиться сам (класс js-fail);
//  2. рубильник: обрыв и авторестарт проходят полный цикл и возвращают исходный заголовок;
//  3. пролёт hero: закрепление даёт прогресс, после него страница продолжается;
//  4. каждая страница на 1440, 1024, 768 и 390: чистая консоль, нет горизонтального оверфлоу.
import puppeteer from 'puppeteer-core'
import http from 'node:http'
import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs'
import { join, dirname, extname, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const DIST = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist')
const CHROME = process.env.CHROME || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
const T = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.png': 'image/png', '.txt': 'text/plain' }
const srv = http.createServer((req, res) => {
  let p
  try { p = decodeURIComponent(new URL(req.url, 'http://x').pathname) } catch { res.writeHead(400).end(); return }
  let f = resolve(DIST, '.' + p)
  if (f !== DIST && !f.startsWith(DIST + sep)) { res.writeHead(403).end(); return }
  if (existsSync(f) && statSync(f).isDirectory()) f = join(f, 'index.html')
  if (!existsSync(f)) { res.writeHead(404).end(); return }
  res.writeHead(200, { 'Content-Type': T[extname(f)] || 'application/octet-stream' }); res.end(readFileSync(f))
})
await new Promise((r) => srv.listen(0, '127.0.0.1', r))
const origin = `http://localhost:${srv.address().port}`
const browser = await puppeteer.launch({ executablePath: CHROME, headless: true, args: ['--no-sandbox', '--enable-unsafe-swiftshader'] })
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
let failed = 0
const check = (ok, name, detail = '') => { console.log(`${ok ? '✔' : '✘'} ${name}${detail ? ' — ' + detail : ''}`); if (!ok) failed++ }

// 1. site.js не загрузился
{
  const page = await browser.newPage()
  await page.setViewport({ width: 1440, height: 900 })
  await page.setRequestInterception(true)
  page.on('request', (r) => (r.url().endsWith('/js/site.js') ? r.abort() : r.continue()))
  await page.goto(origin + '/', { waitUntil: 'domcontentloaded' })
  await sleep(5000) // 3 с до включения js-fail + время перехода
  const r = await page.evaluate(() => ({
    cls: document.documentElement.className,
    hidden: [...document.querySelectorAll('[data-reveal]')].filter((e) => getComputedStyle(e).opacity !== '1').length,
    h1: getComputedStyle(document.querySelector('.mega__l')).visibility
  }))
  check(r.cls.includes('js-fail') && r.hidden === 0 && r.h1 === 'visible', 'без site.js контент виден', JSON.stringify(r))
  await page.close()
}

// 2 и 3. рубильник и пролёт
{
  const page = await browser.newPage()
  const errors = []
  page.on('pageerror', (e) => errors.push(e.message))
  await page.setViewport({ width: 1440, height: 900 })
  await page.goto(origin + '/', { waitUntil: 'networkidle0' })
  await sleep(1500)
  const text = () => page.evaluate(() => [...document.querySelectorAll('.mega__l')].map((l) => l.textContent).join(' | '))
  const before = await text()
  await page.click('#lever')
  await sleep(1500)
  const down = await page.evaluate(() => ({ cls: document.querySelector('#hero').className, s: document.querySelector('#console').dataset.s, alarm: document.querySelector('#alarm').className, n: document.querySelector('#alarm-n').textContent }))
  const mid = await text()
  check(down.cls.includes('is-down') && down.s === 'down' && down.alarm.includes('on') && down.n !== '0' && mid !== before, 'рубильник обрывает туннель', `${mid} · пакетов ${down.n}`)
  await sleep(5200)
  const after = await page.evaluate(() => ({ cls: document.querySelector('#hero').className, s: document.querySelector('#console').dataset.s, alarm: document.querySelector('#alarm').className }))
  check(!after.cls.includes('is-down') && after.s === 'ok' && !after.alarm.includes('on') && (await text()) === before, 'авторестарт возвращает исходное состояние', await text())

  const top = () => page.evaluate(() => Math.round(document.querySelector('.hero__pin').getBoundingClientRect().top))
  await page.evaluate(() => window.scrollTo(0, 500)); await sleep(900)
  const pinned = await top()
  const op = await page.evaluate(() => getComputedStyle(document.querySelector('.hero__foot')).opacity)
  await page.evaluate(() => window.scrollTo(0, 1500)); await sleep(900)
  const released = await top()
  check(pinned === 0 && op === '0' && released < 0, 'hero закреплён на время пролёта и отпускается', `top@500=${pinned}, opacity=${op}, top@1500=${released}`)
  check(errors.length === 0, 'главная: нет ошибок скрипта', errors.join('; '))
  await page.close()
}

// 3б. якорь из другой страницы: закрепление hero добавляет экран высоты уже после перехода браузера к #routing
{
  const page = await browser.newPage()
  await page.setViewport({ width: 1440, height: 900 })
  await page.goto(origin + '/#routing', { waitUntil: 'networkidle0' })
  await sleep(1800)
  const top = await page.evaluate(() => Math.round(document.querySelector('#routing').getBoundingClientRect().top))
  check(top > -40 && top < 200, 'переход по /#routing попадает на секцию', `top=${top}`)
  await page.close()
}

// 4. все страницы
const pages = ['/', ...readdirSync(DIST).filter((d) => existsSync(join(DIST, d, 'index.html'))).map((d) => `/${d}/`), '/404.html']
for (const w of [1440, 1024, 768, 390]) {
  for (const path of pages) {
    const page = await browser.newPage()
    const errors = []
    page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()) })
    page.on('pageerror', (e) => errors.push(e.message))
    page.on('requestfailed', (r) => errors.push('reqfail ' + r.url()))
    await page.setViewport({ width: w, height: w === 390 ? 844 : 900 })
    await page.goto(origin + path, { waitUntil: 'networkidle0' })
    const total = await page.evaluate(() => document.documentElement.scrollHeight)
    for (let y = 0; y < total; y += 600) { await page.evaluate((v) => window.scrollTo(0, v), y); await sleep(60) }
    await sleep(900)
    const r = await page.evaluate(() => ({
      over: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      hidden: [...document.querySelectorAll('[data-reveal]')].filter((e) => !e.classList.contains('is-in')).length
    }))
    check(errors.length === 0 && r.over <= 0 && r.hidden === 0, `${path} @${w}`, errors.length || r.over > 0 || r.hidden ? `ошибок ${errors.length}, оверфлоу ${r.over}px, не появилось ${r.hidden}` : '')
    await page.close()
  }
}

await browser.close(); srv.close()
console.log(failed ? `Провалено проверок: ${failed}` : 'Все проверки пройдены')
process.exit(failed ? 1 : 0)
