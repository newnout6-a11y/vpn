// Dev-сервер без зависимостей: собирает сайт, раздаёт dist/, пересобирает при изменениях.
import http from 'node:http'
import { readFileSync, existsSync, statSync, watch } from 'node:fs'
import { join, extname, dirname, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { build } from './build.mjs'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const DIST = join(ROOT, 'dist')
const PORT = Number(process.env.PORT || 4173)

const TYPES = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.woff2': 'font/woff2', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8', '.xml': 'application/xml'
}

build()

let timer
const rebuild = () => { clearTimeout(timer); timer = setTimeout(() => { try { build() } catch (e) { console.error(e.message) } }, 120) }
for (const d of ['src', 'public']) watch(join(ROOT, d), { recursive: true }, rebuild)

// Только файлы внутри dist: путь декодируется и разрешается до проверки. Битый %-код даёт 400, выход за dist — 403.
function safeFile(url) {
  let p
  try { p = decodeURIComponent(new URL(url, 'http://x').pathname) } catch { return { code: 400 } }
  const file = resolve(DIST, '.' + p)
  return file === DIST || file.startsWith(DIST + sep) ? { file } : { code: 403 }
}

http.createServer((req, res) => {
  const r = safeFile(req.url)
  if (r.code) { res.writeHead(r.code).end(); return }
  let file = r.file
  if (existsSync(file) && statSync(file).isDirectory()) file = join(file, 'index.html')
  if (!existsSync(file)) {
    res.writeHead(404, { 'Content-Type': TYPES['.html'] })
    res.end(existsSync(join(DIST, '404.html')) ? readFileSync(join(DIST, '404.html')) : 'Not found')
    return
  }
  res.writeHead(200, { 'Content-Type': TYPES[extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache' })
  res.end(readFileSync(file))
}).listen(PORT, () => console.log(`→ http://localhost:${PORT}`))
