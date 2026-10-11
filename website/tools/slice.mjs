// node tools/slice.mjs <png> <chunkHeight> — режет длинный скриншот на куски (для просмотра)
import puppeteer from 'puppeteer-core'
import { readFileSync } from 'node:fs'
import { join, dirname, basename } from 'node:path'
const [, , file, ch = '1500'] = process.argv
const b = await puppeteer.launch({ executablePath: process.env.CHROME || 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', headless: true })
const p = await b.newPage()
const data = readFileSync(file).toString('base64')
await p.setContent(`<img id="i" src="data:image/png;base64,${data}">`)
await p.waitForSelector('#i')
const dim = await p.evaluate(() => [document.getElementById('i').naturalWidth, document.getElementById('i').naturalHeight])
const n = Math.ceil(dim[1] / +ch)
for (let k = 0; k < n; k++) {
  const h = Math.min(+ch, dim[1] - k * +ch)
  await p.setViewport({ width: dim[0], height: h })
  await p.setContent(`<body style="margin:0"><div style="width:${dim[0]}px;height:${h}px;background:url(data:image/png;base64,${data}) 0 -${k * +ch}px no-repeat"></div>`)
  await p.screenshot({ path: join(dirname(file), basename(file, '.png') + `_s${k + 1}.png`) })
}
console.log('slices:', n)
await b.close()
