// Генерирует public/assets/og.png (1200x630) из HTML-карточки через Chrome. npm run og
import puppeteer from 'puppeteer-core'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const font = (f) => readFileSync(join(ROOT, 'public/assets/fonts', f)).toString('base64')
const logo = readFileSync(join(ROOT, 'public/assets/logo.svg')).toString('base64')

const CYR = 'U+0301,U+0400-045F,U+0490-0491,U+04B0-04B1,U+2116'
const LAT = 'U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+2000-206F,U+2122,U+2212'
const face = (fam, file, range, w = '100 900') =>
  `@font-face{font-family:"${fam}";font-weight:${w};src:url(data:font/woff2;base64,${font(file)}) format("woff2");unicode-range:${range}}`

// те же арки туннеля, что и в блоке CTA на сайте
const arches = [30, 60, 90, 120, 150, 180].map((r) => `<path d='M${200 - r} 400V200a${r} ${r} 0 0 1 ${r * 2} 0v200'/>`).join('')
const archSvg = `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 400 400' fill='none' stroke='#15140e' stroke-width='3'>${arches}</svg>`

const html = `<!doctype html><meta charset="utf-8"><style>
${face('Unbounded', 'unbounded-cyrillic-wght.woff2', CYR)}
${face('Unbounded', 'unbounded-latin-wght.woff2', LAT)}
${face('Golos Text', 'golos-text-cyrillic-wght.woff2', CYR, '400 900')}
${face('Golos Text', 'golos-text-latin-wght.woff2', LAT, '400 900')}
${face('Fira Mono', 'fira-mono-cyrillic-500.woff2', CYR, '500')}
${face('Fira Mono', 'fira-mono-latin-500.woff2', LAT, '500')}
*{box-sizing:border-box}
body{margin:0;width:1200px;height:630px;background:#efebe2;color:#15140e;font-family:"Golos Text",sans-serif;position:relative;overflow:hidden}
.arch{position:absolute;right:-70px;bottom:-110px;width:640px;height:640px;opacity:.22;background:url("data:image/svg+xml;base64,${Buffer.from(archSvg).toString('base64')}") center/contain no-repeat}
.c{position:absolute;left:80px;top:64px;right:80px;bottom:64px;display:flex;flex-direction:column;justify-content:space-between;border-top:2px solid #15140e;padding-top:28px}
.b{display:flex;align-items:center;gap:16px;font:600 24px/1 "Unbounded",sans-serif;letter-spacing:-.03em}
.b img{width:48px;height:48px}
.b small{margin-left:auto;font:500 16px/1 "Fira Mono",monospace;letter-spacing:.12em;text-transform:uppercase;color:#5a5748}
h1{margin:0;font:600 72px/1.06 "Unbounded",sans-serif;letter-spacing:-.05em;max-width:900px}
h1 span{color:#c23a05}
p{margin:0;font-size:28px;line-height:1.4;color:#4a4739;max-width:760px}
.row{display:flex;align-items:center;gap:22px}
.dot{width:12px;height:12px;background:#ff5a1f;flex:none}
</style><div class="arch"></div>
<div class="c">
<div class="b"><img src="data:image/svg+xml;base64,${logo}">Tunnel Enforcer<small>Windows · sing-box</small></div>
<h1 id="h">Туннель упал? <span>Интернет — тоже.</span></h1>
<div class="row"><i class="dot"></i><p>Windows-клиент с fail-closed kill-switch · 10 протоколов · открытый код</p></div>
</div>`

const b = await puppeteer.launch({ executablePath: process.env.CHROME || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', headless: true })
const p = await b.newPage()
await p.setViewport({ width: 1200, height: 630 })
await p.setContent(html)
await p.evaluate(() => document.fonts.ready)
await new Promise((r) => setTimeout(r, 500))

// страховка: шрифты загрузились, заголовок не вылезает за карточку
const check = await p.evaluate(() => ({
  bitter: document.fonts.check('600 72px Unbounded', 'Туннель'),
  golos: document.fonts.check('400 28px "Golos Text"', 'Windows-клиент'),
  h1Bottom: document.getElementById('h').getBoundingClientRect().bottom,
  rowTop: document.querySelector('.row').getBoundingClientRect().top
}))
if (!check.bitter || !check.golos) throw new Error('Шрифты не загрузились: ' + JSON.stringify(check))
if (check.h1Bottom > check.rowTop - 8) throw new Error('Заголовок налезает на подпись: ' + JSON.stringify(check))

await p.screenshot({ path: join(ROOT, 'public/assets/og.png') })
await b.close()
console.log('✔ public/assets/og.png')
