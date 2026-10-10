// Генерирует public/assets/og.png (1200x630) из HTML-карточки через Chrome. npm run og
import puppeteer from 'puppeteer-core'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const font = (f) => readFileSync(join(ROOT, 'public/assets/fonts', f)).toString('base64')
const logo = readFileSync(join(ROOT, 'public/assets/logo.svg')).toString('base64')
const html = `<!doctype html><meta charset="utf-8"><style>
@font-face{font-family:G;font-weight:100 900;src:url(data:font/woff2;base64,${font('geologica-cyrillic-wght-normal.woff2')});unicode-range:U+0400-04FF,U+2116}
@font-face{font-family:G;font-weight:100 900;src:url(data:font/woff2;base64,${font('geologica-latin-wght-normal.woff2')});unicode-range:U+0000-00FF,U+2000-206F}
*{box-sizing:border-box}body{margin:0;width:1200px;height:630px;background:#07060d;color:#efeef8;font-family:G,sans-serif;position:relative;overflow:hidden}
.g1{position:absolute;width:700px;height:700px;right:-160px;top:-120px;border-radius:50%;background:#7c5cff;filter:blur(120px);opacity:.55}
.g2{position:absolute;width:420px;height:420px;right:120px;bottom:-200px;border-radius:50%;background:#34e08a;filter:blur(120px);opacity:.25}
.grid{position:absolute;inset:0;background-image:linear-gradient(rgba(255,255,255,.06) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.06) 1px,transparent 1px);background-size:60px 60px;mask-image:radial-gradient(ellipse 80% 80% at 70% 40%,#000,transparent 75%)}
.c{position:absolute;left:80px;top:70px;right:80px;bottom:70px;display:flex;flex-direction:column;justify-content:space-between}
.b{display:flex;align-items:center;gap:18px;font-size:30px;font-weight:600}.b img{width:56px;height:56px}
h1{margin:0;font-size:92px;line-height:1.02;letter-spacing:-.035em;font-weight:650;max-width:900px}
h1 span{background:linear-gradient(100deg,#fff,#c9bdff 45%,#7ff0b8);-webkit-background-clip:text;color:transparent}
p{margin:0;font-size:28px;color:#a09db8}
</style><div class="g1"></div><div class="g2"></div><div class="grid"></div>
<div class="c"><div class="b"><img src="data:image/svg+xml;base64,${logo}">Tunnel Enforcer</div>
<h1>Туннель упал? <span>Интернет — тоже.</span></h1>
<p>Windows-клиент с fail-closed kill-switch · 10 протоколов · открытый код</p></div>`

const b = await puppeteer.launch({ executablePath: process.env.CHROME || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', headless: true })
const p = await b.newPage()
await p.setViewport({ width: 1200, height: 630 })
await p.setContent(html)
await new Promise((r) => setTimeout(r, 500))
await p.screenshot({ path: join(ROOT, 'public/assets/og.png') })
await b.close()
console.log('✔ public/assets/og.png')
