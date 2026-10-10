// Генерирует точечную карту суши (равноплощадная сетка) из Natural Earth (world-atlas) -> public/js/world-data.js
// Запуск: npm run world
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createRequire } from 'node:module'
import { geoContains } from 'd3-geo'
import { feature } from 'topojson-client'

const require = createRequire(import.meta.url)
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const topo = JSON.parse(readFileSync(require.resolve('world-atlas/land-110m.json'), 'utf8'))
const land = feature(topo, topo.objects.land)

const STEP = 2.0 // градусов по широте
const pts = []
for (let lat = -84; lat <= 84; lat += STEP) {
  const k = Math.max(Math.cos((lat * Math.PI) / 180), 0.08)
  const lonStep = STEP / k
  for (let lon = -180; lon < 180; lon += lonStep) {
    if (geoContains(land, [lon, lat])) pts.push([Math.round(lon * 10) / 10, Math.round(lat * 10) / 10])
  }
}
const out = join(ROOT, 'public', 'js', 'world-data.js')
mkdirSync(dirname(out), { recursive: true })
writeFileSync(out, `window.__WORLD=${JSON.stringify(pts)};
`)
console.log(`✔ ${pts.length} точек -> ${out}`)
