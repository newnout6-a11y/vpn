// Проверка баланса тегов и целостности ссылок в dist/. node tools/lint-html.mjs
import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs'
import { join, dirname, normalize } from 'node:path'
import { fileURLToPath } from 'node:url'

const DIST = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist')
const VOID = new Set(['meta', 'link', 'img', 'br', 'hr', 'input', 'source', 'path', 'circle', 'rect', 'line', 'polyline', 'polygon', 'ellipse'])
const pages = []
const walk = (d) => readdirSync(d).forEach((f) => { const p = join(d, f); statSync(p).isDirectory() ? walk(p) : p.endsWith('.html') && pages.push(p) })
walk(DIST)

let problems = 0
for (const file of pages) {
  // raw — для ссылок (включая src у <script>), html без скриптов — для баланса тегов
  const raw = readFileSync(file, 'utf8').replace(/<!--[\s\S]*?-->/g, '')
  const html = raw.replace(/<script[\s\S]*?<\/script>/g, '')
  let pageProblem = false
  const stack = []
  const re = /<(\/?)([a-zA-Z][\w-]*)([^>]*?)(\/?)>/g
  let m
  while ((m = re.exec(html))) {
    const [, close, tag, , self] = m
    const t = tag.toLowerCase()
    if (VOID.has(t) || self) continue
    if (!close) stack.push(t)
    else {
      const top = stack.pop()
      if (top !== t) { console.log(`✘ ${file.replace(DIST, '')}: ожидался </${top}>, найден </${t}> (поз. ${m.index})`); problems++; pageProblem = true; break }
    }
  }
  if (stack.length && !pageProblem) { console.log(`✘ ${file.replace(DIST, '')}: не закрыты ${stack.slice(-3).join(',')}`); problems++ }
  if (/\{\{[^}]*\}\}/.test(html)) { console.log(`✘ ${file.replace(DIST, '')}: остались плейсхолдеры`); problems++ }
  // локальные ссылки
  for (const l of raw.matchAll(/(?:href|src)="([^"]+)"/g)) {
    const u = l[1].replace(/[?#].*$/, '') // query и fragment не влияют на файл
    if (!u || /^(https?:|mailto:|data:)/.test(u)) continue
    const target = u.startsWith('/') ? join(DIST, u) : normalize(join(dirname(file), u))
    const ok = existsSync(target) && (!statSync(target).isDirectory() || existsSync(join(target, 'index.html')))
    if (!ok) { console.log(`✘ ${file.replace(DIST, '')}: битая ссылка ${u}`); problems++ }
  }
}
console.log(problems ? `Проблем: ${problems}` : `✔ ${pages.length} страниц: теги сбалансированы, ссылки целы`)
process.exit(problems ? 1 : 0)
