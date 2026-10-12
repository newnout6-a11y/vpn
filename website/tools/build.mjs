// Микро-сборщик: src/pages/*.html + src/partials + src/layout.html -> dist/
// Без зависимостей. Относительные пути ({{base}}) — сайт работает на любом хостинге и в подпапке.
import { readFileSync, writeFileSync, mkdirSync, readdirSync, cpSync, rmSync, existsSync, statSync } from 'node:fs'
import { join, dirname, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const SRC = join(ROOT, 'src')
const PUB = join(ROOT, 'public')
const DIST = join(ROOT, 'dist')
const SITE_URL = (process.env.SITE_URL || '').replace(/\/$/, '')
// Путь развёртывания: «/» у корня домена, «/sub/» если SITE_URL указывает на подпапку.
const SITE_PATH = SITE_URL ? new URL(SITE_URL).pathname.replace(/\/$/, '') + '/' : '/'

const read = (p) => readFileSync(p, 'utf8')
// title и description попадают в атрибуты и в <title>: кавычка во front-matter не должна ломать разметку.
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;')

const iconCache = new Map()
function icon(name, cls = '') {
  if (!iconCache.has(name)) {
    const file = join(PUB, 'assets', 'icons', `${name}.svg`)
    if (!existsSync(file)) throw new Error(`Иконка не найдена: ${name}`)
    const svg = read(file)
      .replace(/<!--[\s\S]*?-->/g, '')
      .replace(/<svg\b[^>]*>/, (tag) => tag.replace(/\s(class|width|height)="[^"]*"/g, ''))
      .replace(/\s+/g, ' ')
      .replace(/<svg /, '<svg aria-hidden="true" focusable="false" ')
      .trim()
    iconCache.set(name, svg)
  }
  const svg = iconCache.get(name)
  return cls ? svg.replace('<svg ', `<svg class="${cls}" `) : svg
}

// Типограф для русского текста: короткие предлоги, союзы и частицы не остаются висеть в конце строки,
// тире не начинает строку. Теги, атрибуты, код и элементы с data-notypo не трогаются.
const SHORT = 'а|в|и|к|о|с|у|я|бы|во|да|до|же|за|из|ко|ли|на|не|ни|но|об|от|по|со|то|для|или|как|что|это|при|над|под|без'
const RE_SHORT = new RegExp(`(^|[\\s(«„>])(${SHORT}) (?=\\S)`, 'gi')
function typo(html) {
  let skip = null // имя тега, до закрытия которого текст пропускается
  return html.split(/(<[^>]+>)/).map((part) => {
    if (part.startsWith('<')) {
      const m = part.match(/^<(\/?)([a-zA-Z][\w-]*)/)
      if (!m) return part
      const [, close, tag] = m
      if (skip) { if (close && tag === skip) skip = null }
      else if (!close && (/^(pre|code|script|style|textarea|kbd)$/.test(tag) || / data-notypo\b/.test(part))) skip = tag
      return part
    }
    if (skip) return part
    // два прохода: «и в сети» — оба коротких слова подряд
    return part.replace(RE_SHORT, '$1$2\u00a0').replace(RE_SHORT, '$1$2\u00a0').replace(/ (—|–)(?= )/g, '\u00a0$1')
  }).join('')
}

function listPages(dir = join(SRC, 'pages')) {
  return readdirSync(dir).filter((f) => f.endsWith('.html')).map((f) => join(dir, f))
}

function parsePage(file) {
  const raw = read(file)
  const m = raw.match(/^<!--(\{[\s\S]*?\})-->\s*/)
  if (!m) throw new Error(`Нет front-matter в ${file}`)
  return { meta: JSON.parse(m[1]), body: raw.slice(m[0].length) }
}

function render(template, vars) {
  let out = template
  // partials (до трёх уровней вложенности)
  for (let i = 0; i < 3; i++) {
    out = out.replace(/\{\{>\s*([\w-]+)\s*\}\}/g, (_, name) => read(join(SRC, 'partials', `${name}.html`)))
  }
  out = out.replace(/\{\{icon:([\w-]+)(?:\|([^}]*))?\}\}/g, (_, n, c) => icon(n, c || ''))
  out = out.replace(/\{\{(\w+)\}\}/g, (m, k) => (k in vars ? String(vars[k]) : m))
  return out
}

function build() {
  const t0 = Date.now()
  rmSync(DIST, { recursive: true, force: true })
  cpSync(PUB, DIST, { recursive: true })

  const layout = read(join(SRC, 'layout.html'))
  const pages = listPages().map((f) => ({ file: f, ...parsePage(f) }))
  const sitemap = []

  for (const { file, meta, body } of pages) {
    const depth = meta.path === '/' ? 0 : meta.path.split('/').filter(Boolean).length
    // 404 отдаётся с любого адреса, поэтому относительные пути там не работают. Абсолютный путь известен
    // только при заданном SITE_URL; без него остаётся «/» — сайт в подпапке нужно собирать с SITE_URL.
    const base = meta.file === '404' ? SITE_PATH : depth === 0 ? '' : '../'.repeat(depth)
    const vars = {
      base,
      title: esc(meta.title),
      description: esc(meta.description),
      path: meta.path,
      nav: meta.nav || '',
      bodyClass: meta.bodyClass || '',
      robots: meta.robots || 'index,follow',
      canonical: SITE_URL ? `<link rel="canonical" href="${SITE_URL}${meta.path}">` : '',
      ogUrl: SITE_URL ? `<meta property="og:url" content="${SITE_URL}${meta.path}">` : '',
      ogImage: SITE_URL ? `${SITE_URL}/assets/og.png` : `${base}assets/og.png`
    }
    const content = render(body, vars)
    let html = typo(render(layout, { ...vars, content }))
    // aria-current для активного пункта навигации
    html = html.replace(/ data-nav="([\w-]+)"/g, (m, n) => (n === vars.nav ? `${m} aria-current="page"` : m))

    const outFile = meta.path === '/' || meta.file === '404'
      ? join(DIST, meta.file === '404' ? '404.html' : 'index.html')
      : join(DIST, meta.path, 'index.html')
    mkdirSync(dirname(outFile), { recursive: true })
    writeFileSync(outFile, html)
    if (meta.sitemap !== false) sitemap.push(meta.path)
  }

  if (SITE_URL) {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${sitemap
      .map((p) => `  <url><loc>${SITE_URL}${p}</loc></url>`)
      .join('\n')}\n</urlset>\n`
    writeFileSync(join(DIST, 'sitemap.xml'), xml)
    writeFileSync(join(DIST, 'robots.txt'), `User-agent: *\nAllow: /\nSitemap: ${SITE_URL}/sitemap.xml\n`)
  } else {
    writeFileSync(join(DIST, 'robots.txt'), `User-agent: *\nAllow: /\n`)
  }

  let bytes = 0
  const walk = (d) => readdirSync(d).forEach((f) => { const p = join(d, f); statSync(p).isDirectory() ? walk(p) : (bytes += statSync(p).size) })
  walk(DIST)
  console.log(`✔ ${pages.length} страниц, ${(bytes / 1024).toFixed(0)} КБ, ${Date.now() - t0} мс -> ${relative(process.cwd(), DIST) || 'dist'}`)
}

export { build }
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) build()
