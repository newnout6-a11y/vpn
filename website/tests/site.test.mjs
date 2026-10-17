import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import vm from 'node:vm'

const source = readFileSync(new URL('../public/js/site.js', import.meta.url), 'utf8')
const start = source.indexOf('    const count = () => {')
const end = source.indexOf("    lever.addEventListener('click', toggle)", start)
assert.ok(start >= 0 && end > start)

function demo() {
  let now = 0, id = 0
  const timers = new Map()
  const element = () => ({ classList: { add() {}, remove() {} }, dataset: {}, setAttribute() {}, textContent: '' })
  const math = Object.create(Math)
  math.random = () => 0
  const context = {
    state: 'ok', timers: [], blocked: 0, nEl: element(), tunnel: {},
    hero: element(), con: element(), lever: element(), label: element(), alarm: element(), sr: element(), next: element(),
    document: { documentElement: element() }, Math: math, performance: { now: () => now }, upSince: 0,
    say() {}, setFlow() {}, retype() {}, log() {},
    setTimeout: (fn, ms) => { const key = ++id; timers.set(key, { fn, at: now + ms }); return key },
    clearTimeout: key => timers.delete(key)
  }
  context.after = (ms, fn) => context.timers.push(context.setTimeout(fn, ms))
  vm.runInNewContext(source.slice(start, end) + '\nthis.controls = { cut, restore };', context)
  const advance = ms => {
    const until = now + ms
    while (true) {
      const next = [...timers.entries()].sort((a, b) => a[1].at - b[1].at)[0]
      if (!next || next[1].at > until) break
      timers.delete(next[0]); now = next[1].at; next[1].fn()
    }
    now = until
  }
  return { ...context.controls, advance, blocked: () => context.blocked, state: () => context.state, pending: () => timers.size }
}

test('manual restoration cancels all callbacks belonging to the cut', () => {
  const h = demo()
  h.cut()
  h.advance(30)
  h.restore()
  assert.equal(h.pending(), 0)
  const blocked = h.blocked()
  h.advance(6000)
  assert.equal(h.blocked(), blocked)
  assert.equal(h.state(), 'ok')
})

test('rapid cut/restore/cut runs only one counter', () => {
  const h = demo()
  h.cut()
  h.advance(30)
  h.restore()
  h.advance(30)
  h.cut()
  h.advance(90)
  assert.equal(h.blocked(), 6)
  h.advance(90)
  assert.equal(h.blocked(), 9)
})

test('automatic restoration also cancels the counter before the next cut', () => {
  const h = demo()
  h.cut()
  h.advance(5200)
  assert.equal(h.state(), 'ok')
  assert.equal(h.pending(), 0)
  h.cut()
  h.advance(90)
  assert.equal(h.blocked(), 6)
})
