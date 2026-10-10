// Отладка: node tools/probe.mjs <path> "<js-выражение>" [width]
import puppeteer from 'puppeteer-core'
import { join, dirname, extname, normalize } from 'node:path'
import { fileURLToPath } from 'node:url'
import http from 'node:http'
import fs from 'node:fs'
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..'), DIST = join(ROOT, 'dist')
const T = { '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.woff2': 'font/woff2' }
const srv = http.createServer((req, res) => {
  let f = normalize(join(DIST, decodeURIComponent(new URL(req.url, 'http://x').pathname)))
  if (fs.existsSync(f) && fs.statSync(f).isDirectory()) f = join(f, 'index.html')
  if (!fs.existsSync(f)) { res.writeHead(404); res.end(); return }
  res.writeHead(200, { 'Content-Type': T[extname(f)] || 'application/octet-stream' }); res.end(fs.readFileSync(f))
}).listen(0)
const [, , path = '/', expr = 'document.title', w = '1440'] = process.argv
const b = await puppeteer.launch({ executablePath: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', headless: true, args: ['--no-sandbox'] })
const p = await b.newPage(); await p.setViewport({ width: +w, height: 900 })
await p.goto(`http://localhost:${srv.address().port}${path}`, { waitUntil: 'networkidle0' }); await new Promise((r) => setTimeout(r, 1500))
console.log(JSON.stringify(await p.evaluate(expr), null, 1))
await b.close(); srv.close()
