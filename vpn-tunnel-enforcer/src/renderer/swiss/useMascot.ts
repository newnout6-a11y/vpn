import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * «Пломбик» brain: maps real tunnel state and UI events to moods, effects,
 * short lines and hops between perches (see MascotStage for perches).
 */

export type MascotPhase = 'on' | 'off' | 'connecting'
export type Mood =
  | 'calm' | 'worried' | 'scan' | 'happy' | 'love' | 'squint'
  | 'think' | 'dizzy' | 'wink' | 'excited' | 'sleep' | 'scared'
export type Fx = 'confetti' | 'zzz' | 'dots' | 'sweat' | 'speed' | null
export type BodyAnim = 'm-jump' | 'm-shake' | 'm-spin' | 'm-lean' | 'm-startle' | ''
export type Speech = { id: number; text: string } | null

export interface MascotView {
  mood: Mood
  fx: Fx
  fxId: number
  body: BodyAnim
  bodyId: number
  speech: Speech
}

export interface MascotInput {
  phase: MascotPhase
  /** Wall-clock ms the tunnel started, or null. */
  startedAt: number | null
  /** Current download speed in Mbit/s. */
  downMbps: number
}

/** Window event other components dispatch to talk to the mascot. */
export const MASCOT_EVENT = 'vpnte:mascot'
export type MascotEvent = 'hover-in' | 'hover-out'

type ActOpts = { ms?: number; fx?: Fx; body?: BodyAnim; text?: string; textMs?: number }

const pick = <T,>(arr: T[]): T => arr[Math.floor(Math.random() * arr.length)]

const IDLE_MS = 30000
const EXPOSED_NAG_MS = 20000

const CONNECTED = ['Готово. Я на посту.', 'Туннель есть. Дышим ровно.', 'Защищено. Можно жить.']
const POKE_ON = ['Kill-switch держу крепко.', 'IPv6? Не, не слышал.', 'DNS перехвачен. Всё под контролем.', 'Watchdog сверяет IP каждые 15 с.', 'Щекотно!']
const POKE_OFF = ['Включи меня уже.', 'Провайдер всё видит…', 'Мне неспокойно.']
const WANDER: Array<[string, Mood, string]> = [
  ['toggle', 'happy', 'Посижу на кнопке. Тёплая.'],
  ['clock', 'calm', 'Который час? Ага.'],
  ['nav-servers', 'think', 'Проверю серверы.'],
  ['nav-logs', 'squint', 'Что там в журнале…']
]

// Greet once per app session, not every time the dashboard tab is reopened.
let greeted = false

function greeting(): [Mood, string] {
  const h = new Date().getHours()
  if (h < 5) return ['sleep', 'Ночь на дворе… Ты чего не спишь?']
  if (h < 12) return ['happy', 'Доброе утро! Я Пломбик.']
  if (h < 18) return ['happy', 'Привет! Я Пломбик. Ткни меня.']
  return ['calm', 'Добрый вечер. Я на посту.']
}

export function useMascot(input: MascotInput) {
  const { phase, startedAt, downMbps } = input
  const [speech, setSpeech] = useState<Speech>(null)
  const [emote, setEmote] = useState<{ mood: Mood; fx: Fx } | null>(null)
  const [hoverMood, setHoverMood] = useState<Mood | null>(null)
  const [fxId, setFxId] = useState(0)
  const [body, setBody] = useState<{ name: BodyAnim; id: number }>({ name: '', id: 0 })
  const [sleeping, setSleeping] = useState(false)
  const [perch, setPerch] = useState('home')
  const timers = useRef<Record<string, number>>({})
  const seq = useRef(0)

  const later = useCallback((key: string, fn: () => void, ms: number) => {
    window.clearTimeout(timers.current[key])
    timers.current[key] = window.setTimeout(fn, ms)
  }, [])
  useEffect(() => {
    const all = timers.current
    return () => Object.values(all).forEach(t => window.clearTimeout(t))
  }, [])

  const say = useCallback((text: string, ms = 3200) => {
    seq.current += 1
    setSpeech({ id: seq.current, text })
    later('speech', () => setSpeech(null), ms)
  }, [later])

  const act = useCallback((mood: Mood, o: ActOpts = {}) => {
    setEmote({ mood, fx: o.fx ?? null })
    if (o.fx) setFxId(i => i + 1)
    later('emote', () => setEmote(null), o.ms ?? 1800)
    if (o.body) setBody(b => ({ name: o.body ?? '', id: b.id + 1 }))
    if (o.text) say(o.text, o.textMs)
  }, [later, say])

  const hopTo = useCallback((name: string, stay = 3500) => {
    setPerch(name)
    if (name === 'home') window.clearTimeout(timers.current.home)
    else later('home', () => setPerch('home'), stay)
  }, [later])

  // Greeting
  useEffect(() => {
    if (greeted) return
    const t = window.setTimeout(() => {
      greeted = true
      const [mood, text] = greeting()
      act(mood, { text, ms: 2000, body: mood === 'sleep' ? '' : 'm-jump' })
    }, 700)
    return () => window.clearTimeout(t)
  }, [act])

  // Falls asleep after 30 s without input, startles awake
  const sleepingRef = useRef(false)
  useEffect(() => {
    let idle = window.setTimeout(goSleep, IDLE_MS)
    function goSleep() {
      sleepingRef.current = true
      setSleeping(true)
    }
    const onActivity = () => {
      window.clearTimeout(idle)
      idle = window.setTimeout(goSleep, IDLE_MS)
      if (sleepingRef.current) {
        sleepingRef.current = false
        setSleeping(false)
        act('scared', { body: 'm-startle', text: pick(['А? Я не спал!', 'Я просто моргнул.', 'Всё под контролем! Честно.']), ms: 1200 })
      }
    }
    const events = ['mousemove', 'mousedown', 'keydown', 'wheel'] as const
    events.forEach(e => window.addEventListener(e, onActivity, { passive: true }))
    return () => {
      window.clearTimeout(idle)
      events.forEach(e => window.removeEventListener(e, onActivity))
    }
  }, [act])

  // Tunnel state changes
  const prevPhase = useRef(phase)
  useEffect(() => {
    const prev = prevPhase.current
    prevPhase.current = phase
    if (prev === phase) return
    setHoverMood(null)
    if (phase !== 'connecting') hopTo('home')
    if (phase === 'on') act('happy', { fx: 'confetti', body: 'm-jump', text: pick(CONNECTED), ms: 2200 })
    else if (phase === 'off') {
      if (prev === 'connecting') act('worried', { text: 'Ну ладно, отбой.', ms: 1200 })
      else act('scared', { fx: 'sweat', body: 'm-shake', text: 'Эй! Ты без защиты.', ms: 2600 })
    } else say(prev === 'on' ? 'Переезжаем…' : 'Строю туннель…', 2600)
  }, [phase, act, say, hopTo])

  // Left exposed: hops onto the button once
  useEffect(() => {
    if (phase !== 'off') return
    const t = window.setTimeout(() => {
      hopTo('toggle', 4500)
      act('scared', { fx: 'sweat', text: 'Жми сюда! Ты всё ещё без защиты.', ms: 3000 })
    }, EXPOSED_NAG_MS)
    return () => window.clearTimeout(t)
  }, [phase, act, hopTo])

  // Session milestones every 10 min, checked without re-rendering every second
  useEffect(() => {
    if (phase !== 'on' || !startedAt) return
    let lastMark = Math.floor((Date.now() - startedAt) / 600000)
    const id = window.setInterval(() => {
      const mark = Math.floor((Date.now() - startedAt) / 600000)
      if (mark <= lastMark) return
      lastMark = mark
      const min = mark * 10
      if (min % 60 === 0) act('love', { fx: 'confetti', body: 'm-jump', text: min / 60 + ' ч без единой утечки!' })
      else act('happy', { body: 'm-jump', text: 'Уже ' + min + ' минут на посту.' })
    }, 5000)
    return () => window.clearInterval(id)
  }, [phase, startedAt, act])

  // Speed spikes
  const lastSpike = useRef(0)
  useEffect(() => {
    if (phase !== 'on' || downMbps < 75) return
    const now = Date.now()
    if (now - lastSpike.current < 30000) return
    lastSpike.current = now
    act('excited', { fx: 'speed', text: 'Летим! ' + downMbps.toFixed(0) + ' Мбит/с', ms: 2200 })
  }, [downMbps, phase, act])

  // Back to the window
  useEffect(() => {
    let hiddenAt = 0
    const onVis = () => {
      if (document.hidden) hiddenAt = Date.now()
      else if (hiddenAt && Date.now() - hiddenAt > 5000) act('love', { body: 'm-jump', text: 'С возвращением! Я всё сторожил.' })
    }
    document.addEventListener('visibilitychange', onVis)
    return () => document.removeEventListener('visibilitychange', onVis)
  }, [act])

  // Light / dark switch (ThemeProvider writes data-theme on <html>)
  useEffect(() => {
    const html = document.documentElement
    let theme = html.getAttribute('data-theme')
    const obs = new MutationObserver(() => {
      const next = html.getAttribute('data-theme')
      if (next === theme) return
      theme = next
      if (next === 'dark') act('calm', { text: 'Темно — как в туннеле. Уютно.' })
      else act('squint', { text: 'Ай, светло! Глаза щурятся.' })
    })
    obs.observe(html, { attributes: true, attributeFilter: ['data-theme'] })
    return () => obs.disconnect()
  }, [act])

  // Wanders on his own every 25–45 s while protected and idle
  const calmRef = useRef(false)
  useEffect(() => {
    calmRef.current = phase === 'on' && !sleeping && perch === 'home'
  }, [phase, sleeping, perch])
  useEffect(() => {
    let t = 0
    const schedule = () => {
      t = window.setTimeout(() => {
        if (calmRef.current) {
          const [spot, mood, text] = pick(WANDER)
          hopTo(spot, 4500)
          act(mood, { text, ms: 2500 })
        }
        schedule()
      }, 25000 + Math.random() * 20000)
    }
    schedule()
    return () => window.clearTimeout(t)
  }, [act, hopTo])

  // Events from the dashboard (power button hover)
  const phaseRef = useRef(phase)
  useEffect(() => {
    phaseRef.current = phase
  }, [phase])
  useEffect(() => {
    const onEvent = (e: Event) => {
      const kind = (e as CustomEvent<MascotEvent>).detail
      if (kind === 'hover-out') setHoverMood(null)
      else if (kind === 'hover-in') {
        if (phaseRef.current === 'off') setHoverMood('excited')
        else if (phaseRef.current === 'on') {
          setHoverMood('squint')
          say('Уверен?', 1400)
        }
      }
    }
    window.addEventListener(MASCOT_EVENT, onEvent)
    return () => window.removeEventListener(MASCOT_EVENT, onEvent)
  }, [say])

  // Poking
  const pokes = useRef<number[]>([])
  const poke = useCallback(() => {
    const now = Date.now()
    pokes.current = pokes.current.filter(t => now - t < 2500).concat(now)
    if (pokes.current.length >= 5) {
      pokes.current = []
      act('dizzy', { body: 'm-spin', text: 'Хватит! Голова кружится…', ms: 2600 })
      return
    }
    if (Math.random() < 0.25) {
      act('wink', { body: 'm-jump', text: pick(['Подмигиваю. Никому ни слова.', 'Мы с тобой команда.']) })
      return
    }
    const off = phaseRef.current === 'off'
    act(off ? 'worried' : 'happy', { body: 'm-jump', text: pick(off ? POKE_OFF : POKE_ON), ms: 1200 })
  }, [act])

  const base: Mood = sleeping ? 'sleep' : phase === 'on' ? 'calm' : phase === 'off' ? 'worried' : 'scan'
  const view: MascotView = {
    mood: emote?.mood ?? hoverMood ?? base,
    fx: emote?.fx ?? (sleeping ? 'zzz' : null),
    fxId,
    body: body.name,
    bodyId: body.id,
    speech
  }

  const goHome = useCallback(() => hopTo('home'), [hopTo])

  return { view, perch, goHome, poke }
}

export type MascotApi = ReturnType<typeof useMascot>
