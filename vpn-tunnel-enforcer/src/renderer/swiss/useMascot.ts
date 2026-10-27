import { useCallback, useEffect, useRef, useState } from 'react'
import { useTranslation } from 'react-i18next'

/**
 * «Пломбик» brain: maps real tunnel state and UI events to moods, effects,
 * short lines and hops between perches (see MascotStage for perches).
 *
 * Lines never claim a safeguard state (kill-switch, DNS, leaks) the mascot
 * doesn't actually know — they react to the dashboard's derived phase only.
 */

export type MascotPhase = 'on' | 'off' | 'connecting' | 'alert'
export type Mood =
  | 'calm' | 'worried' | 'scan' | 'happy' | 'love' | 'squint'
  | 'think' | 'dizzy' | 'wink' | 'excited' | 'sleep' | 'scared' | 'petted'
export type Fx = 'confetti' | 'zzz' | 'dots' | 'sweat' | 'speed' | 'hearts' | null
export type BodyAnim = 'm-jump' | 'm-shake' | 'm-spin' | 'm-lean' | 'm-startle' | ''
export type Speech = { id: number; text: string; announce: boolean } | null

export interface MascotView {
  mood: Mood
  fx: Fx
  fxId: number
  body: BodyAnim
  bodyId: number
  speech: Speech
}

export interface MascotInput {
  /** Derived by the dashboard: 'alert' = connected but something is wrong. */
  phase: MascotPhase
  /** Wall-clock ms the tunnel started, or null. */
  startedAt: number | null
  /** Download speed in Mbit/s, bucketed by the caller: 0 = idle or ordinary (nothing to say). */
  downMbps: number
}

/** Window event other components dispatch to talk to the mascot. */
export const MASCOT_EVENT = 'vpnte:mascot'
export type MascotEvent =
  | 'hover-in' | 'hover-out'
  | 'leak-start' | 'leak-ok' | 'leak-warn' | 'leak-fail'
  | 'smart-on' | 'smart-off'

type ActOpts = { ms?: number; fx?: Fx; body?: BodyAnim; text?: string; textMs?: number; announce?: boolean }

const IDLE_MS = 30000
const EXPOSED_NAG_MS = 20000

/** How many numbered variants each line family has in the locale files (mascot.<family><n>). */
const VARIANTS = { connected: 3, pokeOn: 5, pokeOff: 3, wink: 2, startle: 3, pet: 4 } as const
type Family = keyof typeof VARIANTS

const PET_ENOUGH_MS = 6000

const WANDER: Array<[string, Mood, string]> = [
  ['toggle', 'happy', 'mascot.wanderToggle'],
  ['clock', 'calm', 'mascot.wanderClock'],
  ['nav-servers', 'think', 'mascot.wanderServers'],
  ['journal', 'squint', 'mascot.wanderLogs']
]

// Greet once per app session, not every time the dashboard remounts.
let greeted = false

function greetingKey(): [Mood, string] {
  const h = new Date().getHours()
  if (h < 5) return ['sleep', 'mascot.greetNight']
  if (h < 12) return ['happy', 'mascot.greetMorning']
  if (h < 18) return ['happy', 'mascot.greetDay']
  return ['calm', 'mascot.greetEvening']
}

export function useMascot(input: MascotInput) {
  const { phase, startedAt, downMbps } = input
  const { t } = useTranslation()
  const [speech, setSpeech] = useState<Speech>(null)
  const [emote, setEmote] = useState<{ mood: Mood; fx: Fx } | null>(null)
  const [hoverMood, setHoverMood] = useState<Mood | null>(null)
  const [fxId, setFxId] = useState(0)
  const [body, setBody] = useState<{ name: BodyAnim; id: number }>({ name: '', id: 0 })
  const [sleeping, setSleeping] = useState(false)
  const [petting, setPetting] = useState(false)
  const [perch, setPerch] = useState('home')
  const timers = useRef<Record<string, number>>({})
  const seq = useRef(0)

  // Latest t without re-subscribing every effect on language change
  const tRef = useRef(t)
  useEffect(() => {
    tRef.current = t
  }, [t])
  const line = useCallback((family: Family) => tRef.current('mascot.' + family + Math.floor(Math.random() * VARIANTS[family])), [])

  const later = useCallback((key: string, fn: () => void, ms: number) => {
    window.clearTimeout(timers.current[key])
    timers.current[key] = window.setTimeout(fn, ms)
  }, [])
  useEffect(() => {
    const all = timers.current
    return () => Object.values(all).forEach(id => window.clearTimeout(id))
  }, [])

  /** announce: also read it out to screen readers (only for replies the user asked for). */
  const say = useCallback((text: string, ms = 3200, announce = false) => {
    seq.current += 1
    setSpeech({ id: seq.current, text, announce })
    later('speech', () => setSpeech(null), ms)
  }, [later])

  const act = useCallback((mood: Mood, o: ActOpts = {}) => {
    setEmote({ mood, fx: o.fx ?? null })
    if (o.fx) setFxId(i => i + 1)
    later('emote', () => setEmote(null), o.ms ?? 1800)
    if (o.body) setBody(b => ({ name: o.body ?? '', id: b.id + 1 }))
    if (o.text) say(o.text, o.textMs, o.announce)
  }, [later, say])

  const hopTo = useCallback((name: string, stay = 3500) => {
    setPerch(name)
    if (name === 'home') window.clearTimeout(timers.current.home)
    else later('home', () => setPerch('home'), stay)
  }, [later])

  // Greeting
  useEffect(() => {
    if (greeted) return
    const id = window.setTimeout(() => {
      greeted = true
      const [mood, key] = greetingKey()
      act(mood, { text: tRef.current(key), ms: 2000, body: mood === 'sleep' ? '' : 'm-jump' })
    }, 700)
    return () => window.clearTimeout(id)
  }, [act])

  // Falls asleep after 30 s without input, startles awake
  const sleepingRef = useRef(false)
  useEffect(() => {
    let idle = window.setTimeout(goSleep, IDLE_MS)
    function goSleep() {
      sleepingRef.current = true
      setSleeping(true)
    }
    const onActivity = (e: Event) => {
      window.clearTimeout(idle)
      idle = window.setTimeout(goSleep, IDLE_MS)
      if (sleepingRef.current) {
        sleepingRef.current = false
        setSleeping(false)
        // Woken by a stroke: wake gently, the petting reaction takes over
        const onMascot = e.target instanceof Element && e.target.closest('[data-mascot]')
        if (!onMascot) act('scared', { body: 'm-startle', text: line('startle'), ms: 1200 })
      }
    }
    const events = ['mousemove', 'mousedown', 'keydown', 'wheel'] as const
    events.forEach(e => window.addEventListener(e, onActivity, { passive: true }))
    // Coming back to the window counts as activity, but quietly: welcome-back handles the reaction
    const onVisible = () => {
      if (document.hidden) return
      window.clearTimeout(idle)
      idle = window.setTimeout(goSleep, IDLE_MS)
      sleepingRef.current = false
      setSleeping(false)
    }
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      window.clearTimeout(idle)
      events.forEach(e => window.removeEventListener(e, onActivity))
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [act, line])

  // Tunnel state changes
  const prevPhase = useRef(phase)
  useEffect(() => {
    const prev = prevPhase.current
    prevPhase.current = phase
    if (prev === phase) return
    setHoverMood(null)
    if (phase !== 'connecting') hopTo('home')
    const tr = tRef.current
    if (phase === 'on') act('happy', { fx: 'confetti', body: 'm-jump', text: line('connected'), ms: 2200 })
    else if (phase === 'alert') act('scared', { fx: 'sweat', body: 'm-shake', text: tr('mascot.alert'), ms: 2600 })
    else if (phase === 'off') {
      if (prev === 'connecting') act('worried', { text: tr('mascot.cancelled'), ms: 1200 })
      else act('scared', { fx: 'sweat', body: 'm-shake', text: tr('mascot.exposed'), ms: 2600 })
    } else say(prev === 'on' ? tr('mascot.switching') : tr('mascot.building'), 2600)
  }, [phase, act, say, hopTo, line])

  // Genuinely exposed (not merely degraded): hops onto the power button once
  useEffect(() => {
    if (phase !== 'off') return
    const id = window.setTimeout(() => {
      hopTo('toggle', 4500)
      act('scared', { fx: 'sweat', text: tRef.current('mascot.exposedNag'), ms: 3000 })
    }, EXPOSED_NAG_MS)
    return () => window.clearTimeout(id)
  }, [phase, act, hopTo])

  // Session milestones every 10 min, checked without re-rendering every second
  useEffect(() => {
    if (phase !== 'on' || !startedAt) return
    let lastMark = Math.floor((Date.now() - startedAt) / 600000)
    const id = window.setInterval(() => {
      const mark = Math.floor((Date.now() - startedAt) / 600000)
      if (mark <= lastMark) return
      lastMark = mark
      const minutes = mark * 10
      if (minutes % 60 === 0) act('love', { fx: 'confetti', body: 'm-jump', text: tRef.current('mascot.milestoneHour', { hours: minutes / 60 }) })
      else act('happy', { body: 'm-jump', text: tRef.current('mascot.milestoneMin', { minutes }) })
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
    act('excited', { fx: 'speed', text: tRef.current('mascot.speed', { mbps: downMbps.toFixed(0) }), ms: 2200 })
  }, [downMbps, phase, act])

  // Slow connection: something is downloading (> 0.3) but stays under 3 Mbit/s
  // for 30 s. Near-zero traffic means idle, not slow, so it doesn't count.
  const slow = phase === 'on' && downMbps > 0 && downMbps < 3
  const downRef = useRef(downMbps)
  useEffect(() => {
    downRef.current = downMbps
  }, [downMbps])
  const lastSlow = useRef(0)
  useEffect(() => {
    if (!slow) return
    const id = window.setTimeout(() => {
      if (Date.now() - lastSlow.current < 120000) return
      lastSlow.current = Date.now()
      act('think', { fx: 'dots', body: 'm-lean', text: tRef.current('mascot.slow', { mbps: downRef.current.toFixed(1) }), ms: 2600, textMs: 4500 })
    }, 30000)
    return () => window.clearTimeout(id)
  }, [slow, act])

  // Back to the window (hook stays mounted while the window is hidden)
  useEffect(() => {
    let hiddenAt = 0
    const onVis = () => {
      if (document.hidden) hiddenAt = Date.now()
      else if (hiddenAt && Date.now() - hiddenAt > 5000) act('love', { body: 'm-jump', text: tRef.current('mascot.welcomeBack') })
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
      if (next === 'dark') act('calm', { text: tRef.current('mascot.themeDark') })
      else act('squint', { text: tRef.current('mascot.themeLight') })
    })
    obs.observe(html, { attributes: true, attributeFilter: ['data-theme'] })
    return () => obs.disconnect()
  }, [act])

  // Wanders on his own every 25–45 s while protected and idle
  const calmRef = useRef(false)
  useEffect(() => {
    calmRef.current = phase === 'on' && !sleeping && perch === 'home' && !document.hidden
  }, [phase, sleeping, perch])
  useEffect(() => {
    let id = 0
    const schedule = () => {
      id = window.setTimeout(() => {
        if (calmRef.current && !document.hidden) {
          const [spot, mood, key] = WANDER[Math.floor(Math.random() * WANDER.length)]
          hopTo(spot, 4500)
          act(mood, { text: tRef.current(key), ms: 2500 })
        }
        schedule()
      }, 25000 + Math.random() * 20000)
    }
    schedule()
    return () => window.clearTimeout(id)
  }, [act, hopTo])

  // Events from the dashboard (power button hover)
  const phaseRef = useRef(phase)
  useEffect(() => {
    phaseRef.current = phase
  }, [phase])
  useEffect(() => {
    const onEvent = (e: Event) => {
      const kind = (e as CustomEvent<MascotEvent>).detail
      const tr = tRef.current
      switch (kind) {
        case 'hover-out':
          setHoverMood(null)
          break
        case 'hover-in':
          if (phaseRef.current === 'off') setHoverMood('excited')
          else if (phaseRef.current === 'on') {
            setHoverMood('squint')
            say(tr('mascot.hoverSure'), 1400)
          }
          break
        // Leak check: hop onto the cell, then react to the real verdict
        case 'leak-start':
          hopTo('leak', 2600)
          act('think', { fx: 'dots', body: 'm-lean', ms: 1500, text: tr('mascot.leakStart'), textMs: 1500 })
          break
        case 'leak-ok':
          act('happy', { body: 'm-jump', text: tr('mascot.leakOk') })
          break
        case 'leak-warn':
          act('think', { text: tr('mascot.leakWarn') })
          break
        case 'leak-fail':
          act('scared', { fx: 'sweat', body: 'm-shake', text: tr('mascot.leakFail'), ms: 2600 })
          break
        case 'smart-on':
        case 'smart-off':
          hopTo('smart', 2600)
          act(kind === 'smart-on' ? 'wink' : 'think', { text: tr(kind === 'smart-on' ? 'mascot.smartOn' : 'mascot.smartOff') })
          break
      }
    }
    window.addEventListener(MASCOT_EVENT, onEvent)
    return () => window.removeEventListener(MASCOT_EVENT, onEvent)
  }, [say, act, hopTo])

  // Poking (mouse or keyboard)
  const pokes = useRef<number[]>([])
  const poke = useCallback(() => {
    const now = Date.now()
    pokes.current = pokes.current.filter(p => now - p < 2500).concat(now)
    if (pokes.current.length >= 5) {
      pokes.current = []
      act('dizzy', { body: 'm-spin', text: tRef.current('mascot.dizzy'), ms: 2600, announce: true })
      return
    }
    if (Math.random() < 0.25) {
      act('wink', { body: 'm-jump', text: line('wink'), announce: true })
      return
    }
    const uneasy = phaseRef.current === 'off' || phaseRef.current === 'alert'
    act(uneasy ? 'worried' : 'happy', { body: 'm-jump', text: line(uneasy ? 'pokeOff' : 'pokeOn'), ms: 1200, announce: true })
  }, [act, line])

  // Petting: pointer strokes over him (stroke detection lives in Mascot)
  const petStart = useRef(0)
  const lastPetLine = useRef(0)
  const petCooldown = useRef(0)
  const pet = useCallback(() => {
    const now = Date.now()
    if (now < petCooldown.current) return
    if (!petStart.current) petStart.current = now
    if (now - petStart.current > PET_ENOUGH_MS) {
      petStart.current = 0
      petCooldown.current = now + 3000
      setPetting(false)
      act('squint', { text: tRef.current('mascot.petEnough'), ms: 1600, announce: true })
      return
    }
    setEmote(null)
    setPetting(true)
    if (now - lastPetLine.current > 3500) {
      lastPetLine.current = now
      say(line('pet'), 1800, true)
    }
    // Stops being petted shortly after the strokes stop
    later('pet', () => {
      setPetting(false)
      petStart.current = 0
    }, 800)
  }, [act, say, later, line])

  const goHome = useCallback(() => hopTo('home'), [hopTo])

  const base: Mood = sleeping ? 'sleep' : phase === 'on' ? 'calm' : phase === 'connecting' ? 'scan' : 'worried'
  const view: MascotView = {
    mood: emote?.mood ?? (petting ? 'petted' : hoverMood ?? base),
    fx: emote?.fx ?? (petting ? 'hearts' : sleeping ? 'zzz' : null),
    fxId,
    body: body.name,
    bodyId: body.id,
    speech
  }

  return { view, perch, goHome, poke, pet, name: t('mascot.name') }
}

export type MascotApi = ReturnType<typeof useMascot>
