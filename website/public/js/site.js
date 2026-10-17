/* VPN Tunnel Enforcer — поведение сайта.
   Зависимости (локальные): GSAP + ScrollTrigger, Lenis. Каждый блок включается только при наличии своей разметки
   и запускается изолированно: ошибка в одном не останавливает остальные. */
(() => {
  'use strict'
  const $ = (s, r = document) => r.querySelector(s)
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s))
  // Якорь из URL — это id элемента, а не селектор: «#2fa» не валидный селектор и бросает исключение.
  const hashTarget = (h) => { try { return document.getElementById(decodeURIComponent(h.slice(1))) } catch { return null } }
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches
  const fine = matchMedia('(hover:hover) and (pointer:fine)').matches
  const wide = matchMedia('(min-width:1021px)')
  const lerp = (a, b, t) => a + (b - a) * t
  const clamp = (v, a, b) => Math.min(b, Math.max(a, v))
  const smooth = (a, b, v) => { const t = clamp((v - a) / (b - a), 0, 1); return t * t * (3 - 2 * t) }
  const hasGsap = () => typeof window.gsap !== 'undefined' && typeof window.ScrollTrigger !== 'undefined'
  const ICON = {
    vpn: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" class="icon"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/></svg>',
    direct: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" class="icon"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>',
    block: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" class="icon"><circle cx="12" cy="12" r="10"/><path d="m4.9 4.9 14.2 14.2"/></svg>',
    dns: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" class="icon"><circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>'
  }
  // Общее состояние скролла: vel — сглаженная скорость в px за кадр, её читают туннель и бегущие строки.
  const S = { vel: 0 }

  /* ---------- плавный скролл + прогресс + шапка ---------- */
  let lenis = null
  const header = $('#header')
  const progress = $('.progress')
  function initScroll() {
    if (typeof window.Lenis !== 'undefined' && !reduce) {
      lenis = new window.Lenis({ lerp: 0.1, wheelMultiplier: 0.9, smoothWheel: true })
      if (hasGsap()) {
        gsap.registerPlugin(ScrollTrigger)
        lenis.on('scroll', ScrollTrigger.update)
        gsap.ticker.add((t) => lenis.raf(t * 1000))
        gsap.ticker.lagSmoothing(0)
      } else {
        const raf = (t) => { lenis.raf(t); requestAnimationFrame(raf) }
        requestAnimationFrame(raf)
      }
    } else if (hasGsap()) {
      gsap.registerPlugin(ScrollTrigger)
    }
    let lastY = 0, prevY = window.scrollY, travel = 0
    const onScroll = () => {
      const y = window.scrollY
      const max = document.documentElement.scrollHeight - innerHeight
      if (progress) progress.style.transform = `scaleX(${max > 0 ? clamp(y / max, 0, 1) : 0})`
      if (header) {
        header.classList.toggle('is-scrolled', y > 24)
        const open = $('#nav')?.classList.contains('is-open')
        // travel — путь в текущем направлении. Раньше решение принималось по одному событию: плавный скролл
        // шлёт их десятками, и на мелких шагах шапка мигала.
        const d = y - lastY
        travel = Math.sign(d) === Math.sign(travel) ? travel + d : d
        if (y < 520 || open || travel < -90) header.classList.remove('is-hidden')
        else if (travel > 40) header.classList.add('is-hidden')
      }
      lastY = y
    }
    addEventListener('scroll', onScroll, { passive: true })
    onScroll()
    if (!reduce) {
      const tick = () => { const y = window.scrollY; S.vel = lerp(S.vel, y - prevY, 0.2); prevY = y; requestAnimationFrame(tick) }
      requestAnimationFrame(tick)
    }
    $$('a[href^="#"]').forEach((a) => a.addEventListener('click', (e) => {
      const id = a.getAttribute('href')
      if (id.length < 2) return
      const t = hashTarget(id)
      if (!t) return
      e.preventDefault()
      lenis ? lenis.scrollTo(t, { offset: -80 }) : t.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth' })
    }))
  }

  function initNav() {
    const burger = $('#burger'), nav = $('#nav')
    if (!burger || !nav) return
    const set = (open) => {
      burger.setAttribute('aria-expanded', String(open))
      burger.setAttribute('aria-label', open ? 'Закрыть меню' : 'Открыть меню')
      nav.classList.toggle('is-open', open)
      lenis && (open ? lenis.stop() : lenis.start())
      document.body.style.overflow = open ? 'hidden' : ''
    }
    burger.addEventListener('click', () => set(burger.getAttribute('aria-expanded') !== 'true'))
    addEventListener('keydown', (e) => { if (e.key === 'Escape') set(false) })
    // Фаза capture: меню закрывается (и Lenis запускается) раньше обработчика якоря,
    // который вызывает lenis.scrollTo; иначе скролл пришёл бы в уже остановленный Lenis.
    nav.addEventListener('click', (e) => { if (e.target.closest('a')) set(false) }, true)
    // Окно растянули до десктопа с открытым меню — бургер исчез, блокировку скролла нужно снять.
    wide.addEventListener('change', () => { if (wide.matches) set(false) })
  }

  /* ---------- переходы между страницами: арка ---------- */
  function initTransitions() {
    const veil = $('.veil')
    if (!veil) return
    addEventListener('pageshow', () => veil.classList.remove('on'))
    if (reduce) return
    document.addEventListener('click', (e) => {
      const a = e.target.closest('a')
      if (!a || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return
      if (a.target && a.target !== '_self') return
      const href = a.getAttribute('href')
      if (!href || href.startsWith('#') || href.startsWith('mailto:') || a.hasAttribute('download')) return
      const u = new URL(a.href, location.href)
      if (u.origin !== location.origin || (u.pathname === location.pathname && u.hash)) return
      e.preventDefault()
      try { sessionStorage.setItem('vt', '1') } catch { /* приватный режим: входящей арки не будет */ }
      veil.classList.add('on')
      setTimeout(() => { location.href = a.href }, 480)
    })
  }

  /* ---------- буквы: разбиение, scramble, жирность за курсором ---------- */
  const GLYPHS = '█▓▒░<>/\\#01'
  // Буквы — отдельные спаны, слова — неразрывные группы: строка переносится только по пробелам.
  function splitChars(el, text = el.textContent) {
    el.textContent = ''
    el.dataset.split = '1'
    const chars = []
    let word = null
    Array.from(text).forEach((c, i) => {
      const s = document.createElement('span'); s.className = 'ch'; s.textContent = c; s.style.setProperty('--i', i)
      chars.push(s)
      if (c === ' ') { word = null; el.appendChild(s); return }
      if (!word) { word = document.createElement('span'); word.className = 'wd'; el.appendChild(word) }
      word.appendChild(s)
    })
    return chars
  }
  // Проявляет только что разбитую строку: слева направо, через мусорные глифы.
  function scrambleChars(chars, step = 34) {
    if (reduce) return
    const to = chars.map((s) => s.textContent)
    const t0 = performance.now()
    const tick = (now) => {
      if (!chars[0]?.isConnected) return // строку уже перебили заново
      let busy = false
      chars.forEach((s, i) => {
        const k = (now - t0 - i * step) / 260
        if (k >= 1 || to[i] === ' ') { s.textContent = to[i] ?? ''; s.classList.remove('is-scr') }
        else if (k > 0) { s.textContent = GLYPHS[(Math.random() * GLYPHS.length) | 0]; s.classList.add('is-scr'); busy = true }
        else busy = true
      })
      if (busy) requestAnimationFrame(tick)
    }
    requestAnimationFrame(tick)
  }
  function scrambleText(el) {
    if (reduce || el.children.length) return
    const text = el.textContent, t0 = performance.now()
    const tick = (now) => {
      const k = (now - t0) / 520
      if (k >= 1) { el.textContent = text; return }
      el.textContent = Array.from(text).map((c, i) => (c === ' ' || i / text.length < k ? c : GLYPHS[(Math.random() * GLYPHS.length) | 0])).join('')
      requestAnimationFrame(tick)
    }
    requestAnimationFrame(tick)
  }
  // Жирность вариативного шрифта тянется за курсором: ближе — жирнее. Цикл идёт, только пока есть что доводить.
  // getChars — функция: набор букв может меняться (заголовок hero перебивается рубильником).
  function initWeight(host, getChars, o) {
    if (!fine || reduce) return
    let mx = 0, my = 0, inside = false, raf = 0
    const cur = new WeakMap(), near = new WeakMap() // near — сглаженная близость курсора (0…1), от неё считается яркость
    const frame = () => {
      raf = 0
      let moving = false
      getChars().forEach((s) => {
        let w = cur.get(s) ?? o.rest
        let want = o.rest, f = 0
        if (inside) {
          const r = s.getBoundingClientRect()
          f = 1 - clamp(Math.hypot(mx - (r.left + r.width / 2), my - (r.top + r.height / 2)) / o.radius, 0, 1)
          want = lerp(o.far, o.near, f * f * (3 - 2 * f))
        }
        w = lerp(w, want, 0.14); cur.set(s, w)
        if (Math.abs(w - want) > 1) moving = true
        s.style.setProperty('--w', Math.round(w))
        // Яркость зависит от близости курсора, а не от жирности: иначе буквы в покое (жирность rest) светились бы
        // ярче, чем под курсором вдали от них.
        if (o.alpha) {
          const n = lerp(near.get(s) ?? 0, f, 0.14); near.set(s, n)
          if (Math.abs(n - f) > 0.004) moving = true
          s.style.setProperty('--a', lerp(o.alpha[0], o.alpha[1], n * n * (3 - 2 * n)).toFixed(3))
        }
      })
      if (moving) raf = requestAnimationFrame(frame)
    }
    const kick = () => { if (!raf) raf = requestAnimationFrame(frame) }
    host.addEventListener('pointermove', (e) => { mx = e.clientX; my = e.clientY; inside = true; kick() })
    host.addEventListener('pointerleave', () => { inside = false; kick() })
  }

  /* ---------- reveal, split-words, одометры ---------- */
  function initReveal() {
    // Заголовки секций появляются по словам, как и h1.
    $$('.h2').forEach((el) => el.classList.add('split-words'))
    $$('.split-words').forEach((el) => {
      if (el.dataset.split) return
      el.dataset.split = '1'
      let i = 0
      const walk = (node) => {
        Array.from(node.childNodes).forEach((n) => {
          if (n.nodeType === 3) {
            const frag = document.createDocumentFragment()
            n.textContent.split(/(\s+)/).forEach((tok) => {
              if (!tok) return
              if (/^\s+$/.test(tok)) { frag.appendChild(document.createTextNode(' ')); return }
              const w = document.createElement('span'); w.className = 'w'
              const s = document.createElement('span'); s.textContent = tok; s.style.setProperty('--i', i++)
              w.appendChild(s); frag.appendChild(w)
            })
            n.replaceWith(frag)
          } else if (n.nodeType === 1) walk(n)
        })
      }
      walk(el)
    })
    $$('.cmp tbody tr').forEach((tr, i) => tr.style.setProperty('--r', i))
    $$('[data-count]').forEach(buildOdo)
    const items = $$('[data-reveal],.split-words,.proto,[data-count],.eyebrow')
    const show = (el) => {
      el.classList.add('is-in')
      if (el.hasAttribute('data-count')) rollOdo(el)
      if (el.classList.contains('eyebrow')) scrambleText(el)
    }
    if (!('IntersectionObserver' in window)) { items.forEach(show); return }
    const io = new IntersectionObserver((entries) => {
      entries.forEach((en) => {
        if (!en.isIntersecting) return
        show(en.target)
        io.unobserve(en.target)
      })
    }, { threshold: 0.14, rootMargin: '0px 0px -6% 0px' })
    items.forEach((e) => io.observe(e))
    $$('[data-stagger]').forEach((g) => $$('[data-reveal]', g).forEach((c, i) => c.style.setProperty('--d', `${i * 0.08}s`)))
  }
  // Одометр: каждая цифра — колонка из двух кругов 0–9, которая проезжает минимум полный оборот.
  // В разметке уже стоит итоговое число, так что без JS и при reduced-motion цифра верная.
  function buildOdo(el) {
    if (reduce) return
    const str = el.textContent.trim()
    const sr = document.createElement('span'); sr.className = 'sr-only'; sr.textContent = str
    const odo = document.createElement('span'); odo.className = 'odo'; odo.setAttribute('aria-hidden', 'true')
    let i = 0
    Array.from(str).forEach((c) => {
      if (!/\d/.test(c)) { const g = document.createElement('span'); g.className = 'odo__sep'; odo.appendChild(g); return }
      const col = document.createElement('span'); col.className = 'odo__c'; col.dataset.d = c; col.style.setProperty('--i', i++)
      for (let k = 0; k < 20; k++) { const d = document.createElement('span'); d.textContent = k % 10; col.appendChild(d) }
      odo.appendChild(col)
    })
    el.textContent = ''
    el.append(sr, odo)
  }
  function rollOdo(el) {
    $$('.odo__c', el).forEach((c) => { c.style.transform = `translateY(-${10 + Number(c.dataset.d)}em)` })
  }

  /* ---------- магнитные кнопки, пятно света на карточках, наклон пульта ---------- */
  function initPointerFx() {
    if (!fine || reduce) return
    addEventListener('pointermove', (e) => {
      const card = e.target.closest?.('.card')
      if (card) { const r = card.getBoundingClientRect(); card.style.setProperty('--px', `${e.clientX - r.left}px`); card.style.setProperty('--py', `${e.clientY - r.top}px`) }
    }, { passive: true })

    $$('[data-magnet]').forEach((el) => {
      el.addEventListener('pointermove', (e) => {
        const r = el.getBoundingClientRect()
        el.style.setProperty('--mx', `${((e.clientX - r.left - r.width / 2) * 0.22).toFixed(1)}px`)
        el.style.setProperty('--my', `${((e.clientY - r.top - r.height / 2) * 0.3).toFixed(1)}px`)
      })
      el.addEventListener('pointerleave', () => { el.style.setProperty('--mx', '0px'); el.style.setProperty('--my', '0px') })
    })
    $$('[data-tilt]').forEach((el) => {
      const host = el.closest('.hero') || el
      host.addEventListener('pointermove', (e) => {
        const r = el.getBoundingClientRect()
        el.style.setProperty('--ry', `${clamp((e.clientX - r.left - r.width / 2) / r.width, -1.2, 1.2) * 5}deg`)
        el.style.setProperty('--rx', `${clamp((e.clientY - r.top - r.height / 2) / r.height, -1.2, 1.2) * -5}deg`)
      })
      host.addEventListener('pointerleave', () => { el.style.setProperty('--rx', '0deg'); el.style.setProperty('--ry', '0deg') })
    })
  }

  /* ---------- туннель из арок (canvas): общий рисовальщик для hero и внутренних страниц ---------- */
  // st.p — прогресс пролёта (0…1, задаёт скролл), st.down — туннель оборван, st.shock — момент обрыва.
  function createTunnel(cv, o = {}) {
    const ctx = cv.getContext('2d')
    const st = { p: 0, down: false, shock: -1e9 }
    let w = 0, h = 0, dpr = 1, vx = 0, vy = 0, mx = 0, my = 0, tmx = 0, tmy = 0, run = true, t = 0, d = 0, last = performance.now()
    const N = 22, P = 38
    const parts = Array.from({ length: P }, () => ({ a: Math.random() * Math.PI * 2, r: 0.12 + Math.random() * 0.5, z: Math.random(), s: 0.3 + Math.random() * 0.9 }))
    const mix = (c1, c2, k) => c1.map((v, i) => Math.round(lerp(v, c2[i], k)))
    const INK = [21, 20, 14], PAPER = [242, 238, 228], ACC = [255, 90, 31], RED = [255, 107, 99]
    // Точка на контуре арки единичной ширины (k: 0 — низ левой стойки, 0.5 — замок свода, 1 — низ правой).
    // По этим точкам идут «рельсы» — линии вдоль туннеля, которые дают глубину.
    const HR = 1.2 / 0.95, LEG = 0.58 * HR, ARC = Math.PI / 2, TOT = LEG * 2 + ARC
    const unit = (k) => {
      const q = k * TOT
      if (q < LEG) return [-0.5, 0.5 * HR - q]
      if (q < LEG + ARC) { const th = Math.PI + (q - LEG) / 0.5; return [0.5 * Math.cos(th), -0.08 * HR + 0.5 * Math.sin(th)] }
      return [0.5, -0.08 * HR + (q - LEG - ARC)]
    }
    const RAILS = [0, 0.19, 0.31, 0.42, 0.5, 0.58, 0.69, 0.81, 1].map(unit)
    const resize = () => {
      dpr = Math.min(devicePixelRatio || 1, 2)
      const r = cv.getBoundingClientRect(); w = r.width; h = r.height
      cv.width = w * dpr; cv.height = h * dpr
      vx = w * (o.side ? 0.68 : 0.5); vy = h * (o.side ? 0.52 : w > 1020 ? 0.5 : 0.56)
    }
    new ResizeObserver(resize).observe(cv); resize()
    ;(o.host || cv).addEventListener('pointermove', (e) => {
      const r = cv.getBoundingClientRect(); tmx = (e.clientX - r.left) / r.width - 0.5; tmy = (e.clientY - r.top) / r.height - 0.5
    })
    new IntersectionObserver((e) => { run = e[0].isIntersecting }, { threshold: 0 }).observe(cv)
    const arch = (cx, cy, W, H) => {
      ctx.beginPath()
      ctx.moveTo(cx - W / 2, cy + H * 0.5)
      ctx.lineTo(cx - W / 2, cy - H * 0.08)
      ctx.arc(cx, cy - H * 0.08, W / 2, Math.PI, 0)
      ctx.lineTo(cx + W / 2, cy + H * 0.5)
    }
    const draw = (now) => {
      const dt = Math.min((now - last) / 1000, 0.05); last = now
      d = lerp(d, st.down ? 1 : 0, reduce ? 1 : 0.08)
      const speed = reduce ? 0 : (0.05 + Math.min(Math.abs(S.vel), 60) * 0.004) * (1 - d)
      t += dt * speed
      mx = lerp(mx, tmx, 0.05); my = lerp(my, tmy, 0.05)
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      ctx.clearRect(0, 0, w, h)
      const base = Math.min(w, h) * 0.5 * (1 + st.p * 1.7)
      const jx = d > 0.5 && !reduce ? (Math.random() - 0.5) * 1.6 : 0
      const cxs = vx + mx * 60 + jx, cys = vy + my * 40
      const near = mix(INK, PAPER, d), far = mix(ACC, RED, d)
      ctx.lineJoin = 'round'; ctx.lineCap = 'round'
      // свечение выхода
      const glow = ctx.createRadialGradient(cxs, cys, 0, cxs, cys, base * 0.6)
      glow.addColorStop(0, `rgba(${far[0]},${far[1]},${far[2]},${0.2 * (1 - st.p)})`); glow.addColorStop(1, `rgba(${far[0]},${far[1]},${far[2]},0)`)
      ctx.fillStyle = glow; ctx.fillRect(0, 0, w, h)
      // рельсы
      const at = (f, u) => { const Wf = base * 0.95 * (0.03 + f * 2.7); return [cxs + (1 - f) * -mx * 120 + u[0] * Wf, cys + (1 - f) * -my * 80 + u[1] * Wf] }
      ctx.lineWidth = 1
      for (const u of RAILS) {
        const [xa, ya] = at(0.004, u), [xb, yb] = at(0.7, u)
        const gr = ctx.createLinearGradient(xa, ya, xb, yb)
        gr.addColorStop(0, `rgba(${far[0]},${far[1]},${far[2]},.5)`); gr.addColorStop(0.18, `rgba(${near[0]},${near[1]},${near[2]},.16)`); gr.addColorStop(1, `rgba(${near[0]},${near[1]},${near[2]},0)`)
        ctx.strokeStyle = gr; ctx.beginPath(); ctx.moveTo(xa, ya); ctx.lineTo(xb, yb); ctx.stroke()
      }
      for (let i = 0; i < N; i++) {
        const z = (i / N + t + st.p * 0.9) % 1
        const f = Math.pow(z, 2.5)
        const s = 0.03 + f * 2.7
        const W = base * 0.95 * s, H = base * 1.2 * s
        const ox = (1 - f) * -mx * 120, oy = (1 - f) * -my * 80
        const col = mix(far, near, smooth(0.0, 0.7, f))
        const a = smooth(0, 0.07, f) * (1 - smooth(0.5, 0.88, f)) * (0.8 - st.p * 0.3)
        ctx.strokeStyle = `rgba(${col[0]},${col[1]},${col[2]},${a})`
        ctx.lineWidth = 0.7 + f * 2.1
        arch(cxs + ox, cys + oy, W, H); ctx.stroke()
        // шпала: пол туннеля
        ctx.globalAlpha = 0.4; ctx.beginPath(); ctx.moveTo(cxs + ox - W / 2, cys + oy + H * 0.5); ctx.lineTo(cxs + ox + W / 2, cys + oy + H * 0.5); ctx.stroke(); ctx.globalAlpha = 1
      }
      // пакеты: летят к зрителю; при обрыве упираются в стену и гаснут
      const wallZ = 0.52
      for (const p of parts) {
        p.z += dt * (reduce ? 0 : 0.16 * p.s * (1 + st.p * 2))
        if (p.z > 1) { p.z = 0; p.a = Math.random() * Math.PI * 2; p.r = 0.12 + Math.random() * 0.5 }
        const z = d > 0.3 ? Math.min(p.z, wallZ) : p.z
        const f0 = Math.pow(z, 2.5), f1 = Math.pow(Math.max(z - 0.03, 0), 2.5)
        const R0 = base * 1.1 * p.r * (0.03 + f0 * 2.7), R1 = base * 1.1 * p.r * (0.03 + f1 * 2.7)
        const x0 = cxs + Math.cos(p.a) * R0, y0 = cys + Math.sin(p.a) * R0 * 1.15
        const x1 = cxs + Math.cos(p.a) * R1, y1 = cys + Math.sin(p.a) * R1 * 1.15
        const a = smooth(0, 0.1, f0) * (1 - smooth(0.45, 0.8, f0)) * 0.9
        ctx.strokeStyle = `rgba(${far[0]},${far[1]},${far[2]},${d > 0.3 && p.z >= wallZ ? 0.9 : a})`
        ctx.lineWidth = 0.8 + f0 * 1.4
        ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x0, y0); ctx.stroke()
        ctx.fillStyle = ctx.strokeStyle; ctx.beginPath(); ctx.arc(x0, y0, 1 + f0 * 2.2, 0, Math.PI * 2); ctx.fill()
      }
      // стена kill-switch и ударная волна в момент обрыва
      if (d > 0.02) {
        const fw = Math.pow(wallZ, 2.5), sw = 0.03 + fw * 2.7
        ctx.strokeStyle = `rgba(255,107,99,${d * (0.75 + 0.25 * Math.sin(now / 160))})`
        ctx.lineWidth = 3
        ctx.setLineDash([14, 9]); ctx.lineDashOffset = reduce ? 0 : -now / 50
        arch(cxs, cys, base * 0.95 * sw, base * 1.2 * sw); ctx.stroke(); ctx.setLineDash([])
        const k = (now - st.shock) / 900
        if (k > 0 && k < 1 && !reduce) {
          const ss = 0.1 + k * 3
          ctx.strokeStyle = `rgba(255,107,99,${(1 - k) * 0.9})`; ctx.lineWidth = 6 * (1 - k) + 1
          arch(cxs, cys, base * ss, base * 1.26 * ss); ctx.stroke()
        }
      }
      // «выход» в конце туннеля
      ctx.fillStyle = `rgb(${far[0]},${far[1]},${far[2]})`
      ctx.beginPath(); ctx.arc(cxs, cys - base * 0.02, base * 0.034 * (1 - d * 0.6), 0, Math.PI * 2); ctx.fill()
      if (!reduce && d < 0.5) for (let i = 0; i < 2; i++) { // выход «дышит»
        const k = (now / 2200 + i / 2) % 1
        ctx.strokeStyle = `rgba(${far[0]},${far[1]},${far[2]},${(1 - k) * 0.5})`; ctx.lineWidth = 1.2
        ctx.beginPath(); ctx.arc(cxs, cys - base * 0.02, base * (0.034 + k * 0.1), 0, Math.PI * 2); ctx.stroke()
      }
      // пролёт: тёмная арка растёт из точки схода, пока не закроет экран — дальше идёт тёмная секция
      if (st.p > 0.28) {
        const k = Math.pow(smooth(0.28, 1, st.p), 5)
        if (k > 0.9) { ctx.fillStyle = '#0f0e0b'; ctx.fillRect(0, 0, w, h) }
        else {
          const W = lerp(base * 0.07, Math.hypot(w, h) * 1.7, k)
          arch(cxs, cys, W, W * 1.26)
          ctx.fillStyle = '#0f0e0b'; ctx.fill()
          ctx.strokeStyle = `rgba(255,90,31,${1 - k})`; ctx.lineWidth = 2 + k * 6; ctx.stroke()
        }
      }
    }
    const frame = (now) => {
      requestAnimationFrame(frame)
      if (!run || document.hidden) { last = now; return }
      draw(now)
    }
    requestAnimationFrame(frame)
    return st
  }

  /* ---------- hero: пролёт, рубильник, журнал ---------- */
  function initHero() {
    const hero = $('#hero'), cv = $('#tunnel'); if (!hero || !cv) return
    const tunnel = createTunnel(cv, { host: hero })
    const pin = $('.hero__pin', hero), inner = $('.hero__in', hero), hint = $('.hero__scroll', hero)
    const lines = $$('.mega__l', hero).map((el) => ({ el, chars: splitChars(el) }))
    initWeight(hero, () => lines.flatMap((l) => l.chars), { rest: 600, far: 300, near: 900, radius: 320 })
    const retype = (key) => lines.forEach((l) => { l.chars = splitChars(l.el, l.el.dataset[key]); scrambleChars(l.chars) })

    // пролёт: hero закреплён, скролл ведёт камеру сквозь арки и разводит строки заголовка
    const fly = (p) => {
      tunnel.p = p
      const k = smooth(0, 0.55, p)
      lines.forEach((l, i) => { l.el.style.transform = p ? `translate3d(${(i ? 1 : -1) * k * 34}vw,0,0) scale(${1 + k * 0.5})` : ''; l.el.style.opacity = p ? String(1 - smooth(0.12, 0.5, p)) : '' })
      $$('.hero__badge,.hero__foot', inner).forEach((el) => { el.style.opacity = p ? String(1 - smooth(0, 0.22, p)) : ''; el.style.pointerEvents = p > 0.2 ? 'none' : '' })
      if (hint) hint.style.opacity = String(1 - smooth(0, 0.08, p))
      pin.style.setProperty('--veil', String(1 - smooth(0, 0.25, p)))
    }
    let trig = null
    const mode = () => {
      trig?.kill(true); trig = null; fly(0)
      if (hasGsap() && wide.matches && !reduce) {
        trig = ScrollTrigger.create({ trigger: pin, start: 'top top', end: '+=100%', pin: true, onUpdate: (self) => fly(self.progress) })
      }
    }
    mode()
    wide.addEventListener('change', mode)

    // журнал в пульте
    const box = $('#hero-log')
    const t0 = performance.now()
    const stamp = () => { const s = (performance.now() - t0) / 1000; return `${String(Math.floor(s / 60)).padStart(2, '0')}:${(s % 60).toFixed(1).padStart(4, '0')}` }
    const buf = []
    const log = (tag, cls, msg) => {
      if (!box) return
      buf.push(`<p><span class="t">${stamp()}</span> <span class="v">${tag}</span> <span class="${cls}">${msg}</span></p>`)
      if (buf.length > 5) buf.shift()
      box.innerHTML = buf.join('')
    }
    const BOOT = [
      ['preflight', '', 'чужих TUN-адаптеров нет'],
      ['lockdown', '', 'IPv6 off · DNS → 192.168.250.254'],
      ['runtime', '', 'SHA-256 sing-box сверен'],
      ['config', '', 'sing-box check -c  OK'],
      ['tun', 'g', 'Status=Up · 192.168.250.252/30'],
      ['killswitch', 'g', 'DefaultOutboundAction=Block'],
      ['egress', 'g', 'IP выхода ≠ IP провайдера ✓'],
      ['watchdog', '', 'проверка egress каждые 15 с'],
      ['leak-test', 'g', 'физический адаптер заблокирован ✓']
    ]
    let bi = 0, state = 'ok', timers = [], blocked = 0
    if (reduce) BOOT.slice(-5).forEach((l) => log(...l))
    else setInterval(() => { if (state === 'ok' && !document.hidden) { log(...BOOT[bi]); bi = (bi + 1) % BOOT.length } }, 1100)

    // рубильник
    const lever = $('#lever'), con = $('#console'), alarm = $('#alarm'), sr = $('#alarm-sr')
    if (!lever || !con) return
    const title = $('#console-title'), sub = $('#console-sub'), label = $('.lever__label', lever)
    const nEl = $('#alarm-n'), next = $('#alarm-next')
    const after = (ms, fn) => timers.push(setTimeout(fn, ms))
    // осциллограф: условный поток через туннель. Это иллюстрация состояния, а не измерение.
    const scope = $('#scope'), flow = $('#scope-v'), upEl = $('#console-up')
    const wave = Array(96).fill(0.5)
    let upSince = performance.now(), st = 0
    const paintScope = () => {
      if (!scope) return
      const r = scope.getBoundingClientRect(), dp = Math.min(devicePixelRatio || 1, 2)
      if (scope.width !== Math.round(r.width * dp)) { scope.width = Math.round(r.width * dp); scope.height = Math.round(r.height * dp) }
      const c = scope.getContext('2d'), sw = r.width, sh = r.height
      const col = state === 'ok' ? '95,208,154' : state === 'down' ? '255,107,99' : '240,178,74'
      c.setTransform(dp, 0, 0, dp, 0, 0); c.clearRect(0, 0, sw, sh)
      c.strokeStyle = 'rgba(242,238,228,.07)'; c.lineWidth = 1
      for (let x = sw % 24; x < sw; x += 24) { c.beginPath(); c.moveTo(x, 0); c.lineTo(x, sh); c.stroke() }
      c.beginPath()
      wave.forEach((v, i) => { const x = (i / (wave.length - 1)) * sw, y = sh - 4 - v * (sh - 10); i ? c.lineTo(x, y) : c.moveTo(x, y) })
      c.strokeStyle = `rgb(${col})`; c.lineWidth = 1.8; c.lineJoin = 'round'; c.stroke()
      c.lineTo(sw, sh); c.lineTo(0, sh); c.closePath()
      const g = c.createLinearGradient(0, 0, 0, sh); g.addColorStop(0, `rgba(${col},.28)`); g.addColorStop(1, `rgba(${col},0)`)
      c.fillStyle = g; c.fill()
    }
    const tickScope = () => {
      st += 0.12
      const v = state === 'ok' ? 0.52 + 0.2 * Math.sin(st * 1.3) + 0.13 * Math.sin(st * 3.7 + 1) + Math.random() * 0.1
        : state === 'down' ? 0.02 : Math.random() < 0.12 ? 0.15 + Math.random() * 0.3 : 0.03
      wave.push(clamp(v, 0, 1)); wave.shift()
      paintScope()
      if (upEl) { const s = Math.floor((performance.now() - upSince) / 1000); upEl.textContent = state === 'ok' ? `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}` : '--:--' }
    }
    if (reduce) paintScope(); else setInterval(() => { if (!document.hidden) tickScope() }, 60)
    const setFlow = (text) => { if (flow) flow.textContent = text; if (reduce) { wave.fill(state === 'ok' ? 0.5 : 0.02); paintScope() } }
    const say = (t, s) => { title.textContent = t; sub.textContent = s }
    const count = () => {
      if (state === 'ok') return
      blocked += 3 + Math.floor(Math.random() * 9)
      if (nEl) nEl.textContent = blocked.toLocaleString('ru-RU')
      after(90, count)
    }
    const restore = () => {
      timers.forEach(clearTimeout); timers = []
      state = 'ok'; tunnel.down = false
      hero.classList.remove('is-down', 'is-cut'); con.dataset.s = 'ok'
      document.documentElement.classList.remove('tunnel-down')
      lever.setAttribute('aria-pressed', 'false'); label.textContent = 'Оборвать туннель'
      say('Защищено', 'Hard Mode · directVpn · TUN Up'); upSince = performance.now(); setFlow('идёт')
      alarm?.classList.remove('on')
      retype('a')
      log('tun', 'g', 'Status=Up · туннель восстановлен'); log('egress', 'g', 'IP выхода ≠ IP провайдера ✓')
      if (sr) sr.textContent = 'Туннель восстановлен, трафик снова идёт через VPN.'
    }
    const cut = () => {
      state = 'down'; tunnel.down = true; tunnel.shock = performance.now(); blocked = 0
      hero.classList.add('is-down', 'is-cut'); con.dataset.s = 'down'
      document.documentElement.classList.add('tunnel-down')
      after(600, () => hero.classList.remove('is-cut'))
      lever.setAttribute('aria-pressed', 'true'); label.textContent = 'Восстановить туннель'
      say('Туннель упал', 'kill-switch держит блокировку'); setFlow('0 · заблокирован')
      alarm?.classList.add('on'); if (next) next.textContent = '· авторестарт через 2 с'
      retype('b')
      log('core', 'r', 'sing-box завершился · TUN Down')
      log('killswitch', 'g', 'блокировка сохранена, наружу 0 пакетов')
      if (sr) sr.textContent = 'Демонстрация: туннель оборван, kill-switch блокирует весь трафик вне VPN.'
      count()
      after(2400, () => {
        state = 'recover'; con.dataset.s = 'recover'
        say('Авторестарт', 'бэкофф 2 / 5 / 10 с · защита не снята'); setFlow('восстановление')
        if (next) next.textContent = '· авторестарт: попытка 1'
        log('watchdog', '', 'авторестарт, бэкофф 2 с')
      })
      after(5200, restore)
    }
    const toggle = () => (state === 'ok' ? cut() : restore())
    lever.addEventListener('click', toggle)
    addEventListener('keydown', (e) => {
      // Одиночная буква без модификатора мешала бы голосовому вводу и клавиатурным командам (WCAG 2.1.4) — только Shift+K.
      if (e.code !== 'KeyK' || !e.shiftKey || e.metaKey || e.ctrlKey || e.altKey || e.repeat) return
      if (/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName) || document.activeElement?.isContentEditable) return
      // Клавиша работает, пока hero на экране: дальше по странице она бы меняла то, чего не видно.
      const r = hero.getBoundingClientRect()
      if (r.bottom > 80 && r.top < innerHeight) toggle()
    })
  }

  /* ---------- внутренние страницы: туннель в шапке страницы ---------- */
  function initPageHero() {
    const ph = $('.page-hero'); if (!ph || $('#tunnel')) return
    const cv = document.createElement('canvas'); cv.className = 'page-hero__canvas'; cv.setAttribute('aria-hidden', 'true')
    ph.insertBefore(cv, ph.firstChild)
    createTunnel(cv, { host: ph, side: true })
  }

  /* ---------- подвал: слово, которое тяжелеет под курсором ---------- */
  function initFooterWord() {
    const el = $('.footer__word'); if (!el || !fine || reduce) return
    const chars = splitChars(el)
    initWeight(el.closest('.footer'), () => chars, { rest: 400, far: 400, near: 900, radius: 360, alpha: [0.14, 0.95] })
  }

  /* ---------- бегущие строки: скорость и наклон от скорости скролла ---------- */
  function initMarquee() {
    const root = $('#marquee'); if (!root || reduce) return
    const rows = $$('.marquee__row', root).map((el, i) => {
      const own = Array.from(el.children), dir = i % 2 ? 1 : -1
      const row = { el, own, dir, x: 0, setW: 0, copies: 1 }
      const fill = () => {
        $$('[data-clone]', el).forEach((c) => c.remove())
        row.setW = el.scrollWidth; row.copies = 1
        if (!row.setW) return
        while (row.setW * row.copies < innerWidth + row.setW * 1.2) {
          own.forEach((li) => { const c = li.cloneNode(true); c.dataset.clone = '1'; c.setAttribute('aria-hidden', 'true'); el.appendChild(c) })
          row.copies++
        }
      }
      row.fill = fill; fill()
      return row
    })
    let rt = 0
    addEventListener('resize', () => { clearTimeout(rt); rt = setTimeout(() => rows.forEach((r) => r.fill()), 200) })
    document.fonts?.ready.then(() => rows.forEach((r) => r.fill()))
    let run = true, last = performance.now(), skew = 0
    new IntersectionObserver((e) => { run = e[0].isIntersecting }, { threshold: 0 }).observe(root)
    const frame = (now) => {
      requestAnimationFrame(frame)
      const dt = Math.min((now - last) / 1000, 0.05); last = now
      if (!run || document.hidden) return
      const v = clamp(S.vel, -80, 80)
      skew = lerp(skew, clamp(v * 0.22, -9, 9), 0.1)
      rows.forEach((r) => {
        if (!r.setW) return
        r.x += r.dir * (46 + Math.abs(v) * 26) * dt
        r.x = ((r.x % r.setW) + r.setW) % r.setW
        r.el.style.transform = `translate3d(${(r.x - r.setW).toFixed(1)}px,0,0) skewX(${(r.dir * -skew).toFixed(2)}deg)`
      })
    }
    requestAnimationFrame(frame)
  }

  /* ---------- стопка карточек: нижние уходят вглубь, когда на них наезжает следующая ---------- */
  function initStack() {
    const cards = $$('#stack .scard'); if (!cards.length || !hasGsap() || reduce) return
    cards.forEach((c, i) => {
      if (i === cards.length - 1) return
      gsap.to(c, { scale: 0.92 + i * 0.008, ease: 'none', scrollTrigger: { trigger: cards[i + 1], start: 'top 88%', end: 'top 22%', scrub: true } })
    })
  }

  /* ---------- симулятор kill-switch (canvas) ---------- */
  // Две дорожки с одним сценарием: туннель-труба из арок рассыпается при обрыве. У «типичного клиента» пакеты
  // сворачивают в обход и доходят до сети; у Enforcer падает стена WFP, пакеты разбиваются об неё.
  function initKillSwitch() {
    const root = $('#ks'); if (!root) return
    const PAPER = '242,238,228', OK = '95,208,154', BAD = '255,107,99', WARN = '240,178,74', ACC = '255,90,31'
    const RIBS = 11, PK = 16
    let auto = true, tAuto = 0, phase = 'normal'
    const sims = $$('.ks__lane', root).map((lane) => {
      const cv = $('.ks__cv', lane)
      const s = {
        lane, cv, ctx: cv.getContext('2d'), kind: lane.dataset.kind, state: $('.ks__state span', lane), num: $('.ks__num b', lane),
        W: 0, H: 0, dpr: 1, t: 0, pipe: 1, wall: 0, wallV: 0, count: 0, shown: -1, hit: -1e9,
        pk: Array.from({ length: PK }, (_, i) => ({ u: i / PK, lane: (i % 3) - 1, sp: 0.8 + Math.random() * 0.4, dip: 0, dead: 0 })),
        sparks: [], debris: []
      }
      const resize = () => { s.dpr = Math.min(devicePixelRatio || 1, 2); const r = cv.getBoundingClientRect(); s.W = r.width; s.H = r.height; cv.width = s.W * s.dpr; cv.height = s.H * s.dpr; if (reduce) draw(s, 0, performance.now()) }
      new ResizeObserver(resize).observe(cv)
      s.resize = resize
      return s
    })
    const geo = (s) => {
      const { W, H } = s
      return { pcX: W * 0.09, webX: W * 0.91, midY: H * 0.44, x0: W * 0.27, x1: W * 0.73, ph: H * 0.17, wallX: W * 0.2, r: Math.min(W * 0.06, H * 0.12), f: Math.max(10, Math.min(W * 0.028, 15)) }
    }
    const pkPos = (s, g, p) => {
      const x = lerp(g.pcX, g.webX, p.u)
      return [x, g.midY + p.lane * g.ph * 0.42 * (1 - p.dip) + Math.sin(Math.PI * p.u) * s.H * 0.4 * p.dip]
    }
    const burst = (s, x, y, col, n = 7) => {
      if (reduce) return
      for (let i = 0; i < n; i++) { const a = Math.random() * Math.PI * 2, v = 40 + Math.random() * 110; s.sparks.push({ x, y, vx: Math.cos(a) * v - 60, vy: Math.sin(a) * v, life: 1, col }) }
    }
    function draw(s, dt, now) {
      const { ctx, W, H } = s; if (!W) return
      const g = geo(s), plain = s.kind === 'plain', down = phase !== 'normal'
      const mono = (px, w = 500) => `${w} ${px}px "Fira Mono", ui-monospace, monospace`
      s.t += dt
      // труба: целостность 1 → 0 при обрыве, собирается обратно при авторестарте
      const pipeTo = phase === 'down' ? 0 : 1
      s.pipe = reduce ? pipeTo : phase === 'recover' ? Math.min(1, s.pipe + dt / 1.9) : lerp(s.pipe, pipeTo, phase === 'down' ? 0.3 : 0.12)
      // стена: пружина с перелётом
      const wallTo = !plain && down ? 1 : 0
      if (reduce) s.wall = wallTo
      else { s.wallV += ((wallTo - s.wall) * 190 - s.wallV * 15) * dt; s.wall += s.wallV * dt }

      ctx.setTransform(s.dpr, 0, 0, s.dpr, 0, 0); ctx.clearRect(0, 0, W, H)
      ctx.lineCap = 'round'; ctx.lineJoin = 'round'

      // направляющие: путь через туннель и путь в обход
      ctx.setLineDash([3, 7]); ctx.lineWidth = 1.2
      ctx.strokeStyle = `rgba(${PAPER},.16)`; ctx.beginPath(); ctx.moveTo(g.pcX, g.midY); ctx.lineTo(g.webX, g.midY); ctx.stroke()
      ctx.strokeStyle = plain && down ? `rgba(${BAD},.5)` : `rgba(${PAPER},.1)`
      ctx.beginPath(); for (let i = 0; i <= 40; i++) { const u = i / 40, x = lerp(g.pcX, g.webX, u), y = g.midY + Math.sin(Math.PI * u) * H * 0.4; i ? ctx.lineTo(x, y) : ctx.moveTo(x, y) } ctx.stroke()
      ctx.setLineDash([])

      // труба туннеля из рёбер-арок
      const pipeCol = phase === 'recover' ? WARN : PAPER
      const rib = (x, a, col) => { ctx.strokeStyle = `rgba(${col},${a})`; ctx.lineWidth = 1.6; ctx.beginPath(); ctx.roundRect(x - g.ph * 0.36, g.midY - g.ph, g.ph * 0.72, g.ph * 2, g.ph * 0.36); ctx.stroke() }
      for (let i = 0; i < RIBS; i++) {
        const k = phase === 'recover' ? i / RIBS : (i / RIBS + (reduce ? 0 : s.t * 0.09)) % 1
        if (k > s.pipe) continue
        rib(lerp(g.x0, g.x1, k), (0.25 + 0.55 * Math.sin(Math.PI * k)) * (phase === 'recover' ? 1 : s.pipe), pipeCol)
      }
      if (s.pipe < 0.98) {
        ctx.setLineDash([6, 6]); ctx.lineWidth = 1.4; ctx.strokeStyle = `rgba(${phase === 'recover' ? WARN : BAD},${0.75 * (1 - s.pipe) + 0.15})`
        ctx.beginPath(); ctx.roundRect(g.x0 - g.ph * 0.36, g.midY - g.ph, g.x1 - g.x0 + g.ph * 0.72, g.ph * 2, g.ph * 0.5); ctx.stroke(); ctx.setLineDash([])
      }
      ctx.font = mono(g.f); ctx.textAlign = 'center'; ctx.textBaseline = 'middle'
      ctx.fillStyle = phase === 'down' ? `rgb(${BAD})` : phase === 'recover' ? `rgb(${WARN})` : `rgba(${PAPER},.7)`
      ctx.fillText(phase === 'down' ? 'ТУННЕЛЬ УПАЛ' : phase === 'recover' ? 'авторестарт…' : 'TUN · sing-box', (g.x0 + g.x1) / 2, g.midY - g.ph - g.f * 1.3)

      // обломки рёбер
      s.debris = s.debris.filter((d) => d.life > 0)
      for (const d of s.debris) {
        d.vy += 520 * dt; d.x += d.vx * dt; d.y += d.vy * dt; d.rot += d.vr * dt; d.life -= dt * 0.9
        ctx.save(); ctx.translate(d.x, d.y); ctx.rotate(d.rot); ctx.strokeStyle = `rgba(${BAD},${Math.max(0, d.life)})`; ctx.lineWidth = 1.6
        ctx.beginPath(); ctx.roundRect(-g.ph * 0.36, -g.ph, g.ph * 0.72, g.ph * 2, g.ph * 0.36); ctx.stroke(); ctx.restore()
      }

      // пакеты
      const wallU = (g.wallX - g.pcX) / (g.webX - g.pcX), inU = (g.x0 - g.pcX) / (g.webX - g.pcX), outU = (g.x1 - g.pcX) / (g.webX - g.pcX)
      for (const p of s.pk) {
        const leaking = plain && down
        p.dip = reduce ? (leaking ? 1 : 0) : lerp(p.dip, leaking && !p.dead ? 1 : 0, 0.09)
        if (!reduce && !(p.dead && !plain)) p.u += dt * 0.3 * p.sp
        // у стены следующий пакет выходит с паузой, иначе счётчик остановленных растёт неправдоподобно быстро
        if (p.dead) { p.dead -= dt * 2.4; if (p.dead <= 0) { p.dead = 0; p.u = !plain && down ? -Math.random() * 0.9 : 0 } }
        if (p.u >= 1) { if (leaking && p.dip > 0.5) s.count++; p.u = 0; p.dead = 0 }
        if (!plain && down && !p.dead && p.u >= wallU - 0.012) {
          if (p.u < wallU + 0.02) { s.count++; s.hit = now; const [x, y] = pkPos(s, g, p); burst(s, x, y, OK) }
          p.dead = 1; p.u = Math.min(p.u, wallU - 0.012)
        }
        const [x, y] = pkPos(s, g, p)
        const col = p.dip > 0.4 ? BAD : phase === 'recover' && !plain ? WARN : OK
        const a = (p.dead ? Math.max(0, p.dead) : 1) * smooth(0, 0.05, p.u) * (1 - smooth(0.95, 1, p.u))
        if (a <= 0.01) continue
        const [tx, ty] = pkPos(s, g, { ...p, u: Math.max(0, p.u - 0.035) })
        ctx.strokeStyle = `rgba(${col},${a * 0.45})`; ctx.lineWidth = 2.4; ctx.beginPath(); ctx.moveTo(tx, ty); ctx.lineTo(x, y); ctx.stroke()
        ctx.fillStyle = `rgba(${col},${a})`; ctx.beginPath(); ctx.arc(x, y, 3.4, 0, Math.PI * 2); ctx.fill()
      }
      // пакеты, которых обрыв застал внутри трубы, пропадают вместе с ней
      if (down) for (const p of s.pk) if (!p.dead && p.dip < 0.3 && p.u > inU && p.u < outU && s.pipe < 0.5) p.dead = 1

      // искры
      s.sparks = s.sparks.filter((k) => k.life > 0)
      for (const k of s.sparks) {
        k.x += k.vx * dt; k.y += k.vy * dt; k.vy += 260 * dt; k.life -= dt * 2.6
        ctx.fillStyle = `rgba(${k.col},${Math.max(0, k.life)})`; ctx.fillRect(k.x - 1.3, k.y - 1.3, 2.6, 2.6)
      }

      // стена WFP
      if (s.wall > 0.01) {
        const top = H * 0.05, full = H * 0.9, hgt = full * clamp(s.wall, 0, 1.12), ww = Math.max(8, W * 0.016)
        const flash = clamp(1 - (now - s.hit) / 260, 0, 1)
        ctx.save(); ctx.beginPath(); ctx.roundRect(g.wallX - ww / 2, top, ww, hgt, 3); ctx.clip()
        ctx.fillStyle = `rgb(${OK})`; ctx.fillRect(g.wallX - ww, top, ww * 2, hgt)
        ctx.strokeStyle = 'rgba(15,14,11,.45)'; ctx.lineWidth = 3
        for (let y = top - ww + ((reduce ? 0 : s.t * 22) % 12); y < top + hgt + ww; y += 12) { ctx.beginPath(); ctx.moveTo(g.wallX - ww, y + ww); ctx.lineTo(g.wallX + ww, y - ww); ctx.stroke() }
        ctx.restore()
        if (flash > 0) { ctx.strokeStyle = `rgba(${OK},${flash * 0.8})`; ctx.lineWidth = 2; ctx.beginPath(); ctx.roundRect(g.wallX - ww / 2 - 4 - (1 - flash) * 8, top - 4, ww + 8 + (1 - flash) * 16, hgt + 8, 6); ctx.stroke() }
        ctx.globalAlpha = clamp(s.wall, 0, 1); ctx.fillStyle = `rgb(${OK})`; ctx.font = mono(g.f); ctx.textAlign = 'left'
        ctx.fillText('WFP · BLOCK', g.wallX + ww + 8, top + full - g.f * 0.6); ctx.globalAlpha = 1
      }

      // узлы
      const node = (x, label, col, sub, pulse) => {
        if (pulse && !reduce) { const k = (now / 900) % 1; ctx.strokeStyle = `rgba(${col},${(1 - k) * 0.7})`; ctx.lineWidth = 1.5; ctx.beginPath(); ctx.arc(x, g.midY, g.r * (1 + k * 0.8), 0, Math.PI * 2); ctx.stroke() }
        ctx.beginPath(); ctx.arc(x, g.midY, g.r, 0, Math.PI * 2); ctx.fillStyle = '#17160f'; ctx.fill()
        ctx.strokeStyle = `rgba(${col},.9)`; ctx.lineWidth = 1.6; ctx.stroke()
        ctx.fillStyle = `rgb(${PAPER})`; ctx.font = mono(g.f, 500); ctx.textAlign = 'center'; ctx.fillText(label, x, g.midY + 1)
        if (sub) { ctx.fillStyle = `rgba(${col},.95)`; ctx.font = mono(g.f * 0.82, 400); ctx.fillText(sub, clamp(x, 60, W - 60), g.midY - g.r - g.f) }
      }
      node(g.pcX, 'ПК', PAPER)
      if (plain && down) node(g.webX, 'WEB', BAD, 'видит ваш IP', true)
      else if (down) node(g.webX, 'WEB', PAPER, 'тишина')
      else node(g.webX, 'WEB', OK, 'видит IP VPN')

      if (s.shown !== s.count) { s.shown = s.count; s.num.textContent = s.count.toLocaleString('ru-RU') }
    }
    const setState = (s, key, msg) => { s.lane.dataset.s = key; s.state.textContent = msg }
    const apply = () => sims.forEach((s) => {
      const plain = s.kind === 'plain'
      if (phase === 'normal') setState(s, 'ok', 'Трафик идёт через туннель')
      if (phase === 'down') setState(s, plain ? 'leak' : 'blocked', plain ? 'Утечка: пакеты ушли напрямую, виден реальный IP' : 'Fail-closed: kill-switch блокирует всё вне VPN')
      if (phase === 'recover') setState(s, 'recover', plain ? 'Переподключение… часть трафика уже утекла' : 'Авторестарт с бэкоффом 2/5/10 с, защита не снята')
    })
    const toggleBtn = $('[data-ks-toggle]', root), autoBtn = $('[data-ks-auto]', root)
    const setPhase = (p) => {
      const was = phase; phase = p
      if (p === 'down' && was === 'normal') sims.forEach((s) => {
        s.count = 0
        if (reduce) return
        const g = geo(s)
        for (let i = 0; i < RIBS; i++) s.debris.push({ x: lerp(g.x0, g.x1, i / (RIBS - 1)), y: g.midY, vx: (Math.random() - 0.5) * 160, vy: -90 - Math.random() * 190, rot: 0, vr: (Math.random() - 0.5) * 7, life: 1 })
        burst(s, (g.x0 + g.x1) / 2, g.midY, BAD, 26)
      })
      if (p === 'recover') sims.forEach((s) => { s.pipe = 0 })
      apply()
      toggleBtn.textContent = p === 'normal' ? 'Оборвать туннель' : 'Восстановить туннель'
      if (reduce) sims.forEach((s) => draw(s, 0, performance.now()))
    }
    // Скринридеру состояния объявляются только в ручном режиме: авто-цикл меняет их каждые несколько секунд.
    const live = () => sims.forEach((s) => s.state.parentElement.setAttribute('aria-live', auto ? 'off' : 'polite'))
    toggleBtn.addEventListener('click', () => { auto = false; live(); autoBtn.setAttribute('aria-pressed', 'false'); setPhase(phase === 'normal' ? 'down' : 'normal') })
    autoBtn.addEventListener('click', (e) => { auto = !auto; live(); e.currentTarget.setAttribute('aria-pressed', String(auto)); tAuto = 0 })
    sims.forEach((s) => s.resize())
    apply()
    if (reduce) return
    let run = true, last = performance.now()
    new IntersectionObserver((e) => { run = e[0].isIntersecting }, { threshold: 0.1 }).observe(root)
    const frame = (now) => {
      requestAnimationFrame(frame)
      if (!run || document.hidden) { last = now; return }
      const dt = Math.min((now - last) / 1000, 0.05); last = now
      if (auto) {
        tAuto += dt
        const cyc = tAuto % 12
        const want = cyc < 3 ? 'normal' : cyc < 7.6 ? 'down' : cyc < 9.6 ? 'recover' : 'normal'
        if (want !== phase) setPhase(want)
      }
      sims.forEach((s) => draw(s, dt, now))
    }
    requestAnimationFrame(frame)
  }

  /* ---------- глобус ---------- */
  function initGlobe() {
    const wrap = $('#globe'); if (!wrap || !window.__WORLD) return
    const cv = $('canvas', wrap), ctx = cv.getContext('2d')
    const pts = window.__WORLD.map(([lo, la]) => [lo * Math.PI / 180, la * Math.PI / 180])
    const cities = [
      ['Франкфурт', 8.68, 50.11], ['Амстердам', 4.9, 52.37], ['Хельсинки', 24.94, 60.17], ['Нью-Йорк', -74, 40.7],
      ['Сингапур', 103.82, 1.35], ['Токио', 139.69, 35.68], ['Сан-Паулу', -46.63, -23.55], ['Дубай', 55.27, 25.2], ['Стамбул', 28.98, 41.0], ['Йоханнесбург', 28.04, -26.2]
    ].map(([n, lo, la]) => ({ n, lo: lo * Math.PI / 180, la: la * Math.PI / 180 }))
    const you = { lo: 37.6 * Math.PI / 180, la: 55.75 * Math.PI / 180 }
    let W = 0, dpr = 1, rot = 0.2, tilt = 0.38, vel = 0.0016, drag = false, lx = 0, run = true, cur = 0, arcT = 0
    const resize = () => { dpr = Math.min(devicePixelRatio || 1, 2); const r = cv.getBoundingClientRect(); W = r.width; cv.width = W * dpr; cv.height = W * dpr }
    new ResizeObserver(resize).observe(cv); resize()
    new IntersectionObserver((e) => { run = e[0].isIntersecting }, { threshold: 0 }).observe(cv)
    wrap.addEventListener('pointerdown', (e) => { drag = true; lx = e.clientX; wrap.setPointerCapture(e.pointerId) })
    // pointercancel приходит вместо pointerup, когда браузер забирает жест под вертикальный скролл.
    for (const ev of ['pointerup', 'pointercancel', 'lostpointercapture']) wrap.addEventListener(ev, () => { drag = false })
    wrap.addEventListener('pointermove', (e) => { if (!drag) return; const d = e.clientX - lx; lx = e.clientX; rot -= d * 0.006; vel = -d * 0.0006 })
    const proj = (lo, la, R, lift = 1) => {
      const dl = lo - rot, c = Math.cos(la)
      const x = c * Math.sin(dl), y = Math.cos(tilt) * Math.sin(la) - Math.sin(tilt) * c * Math.cos(dl), z = Math.sin(tilt) * Math.sin(la) + Math.cos(tilt) * c * Math.cos(dl)
      return { x: W / 2 + x * R * lift, y: W / 2 - y * R * lift, z }
    }
    const vec = (lo, la) => [Math.cos(la) * Math.cos(lo), Math.cos(la) * Math.sin(lo), Math.sin(la)]
    const arcPoint = (a, b, u) => {
      const A = vec(a.lo, a.la), B = vec(b.lo, b.la)
      const d = Math.acos(clamp(A[0] * B[0] + A[1] * B[1] + A[2] * B[2], -1, 1)) || 0.0001
      const k1 = Math.sin((1 - u) * d) / Math.sin(d), k2 = Math.sin(u * d) / Math.sin(d)
      const v = [k1 * A[0] + k2 * B[0], k1 * A[1] + k2 * B[1], k1 * A[2] + k2 * B[2]]
      const lift = 1 + 0.28 * Math.sin(Math.PI * u) * Math.min(1, d)
      return { lo: Math.atan2(v[1], v[0]), la: Math.asin(clamp(v[2], -1, 1)), lift }
    }
    const label = $('#globe-label')
    const frame = () => {
      requestAnimationFrame(frame)
      if (!run || document.hidden) return
      if (!drag) { vel = lerp(vel, reduce ? 0 : 0.0016, 0.02) }
      rot += vel
      arcT += 0.006
      if (arcT >= 1.25) { arcT = 0; cur = (cur + 1) % cities.length; label && (label.textContent = cities[cur].n) }
      const R = W * 0.4
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, W, W)
      const halo = ctx.createRadialGradient(W / 2, W / 2, R * 0.9, W / 2, W / 2, R * 1.35)
      halo.addColorStop(0, 'rgba(255,90,31,.13)'); halo.addColorStop(1, 'rgba(255,90,31,0)')
      ctx.fillStyle = halo; ctx.fillRect(0, 0, W, W)
      const body = ctx.createRadialGradient(W / 2 - R * 0.3, W / 2 - R * 0.35, R * 0.1, W / 2, W / 2, R)
      body.addColorStop(0, '#26241b'); body.addColorStop(1, '#0c0b08')
      ctx.beginPath(); ctx.arc(W / 2, W / 2, R, 0, Math.PI * 2); ctx.fillStyle = body; ctx.fill()
      ctx.strokeStyle = 'rgba(242,238,228,.28)'; ctx.lineWidth = 1; ctx.stroke()
      for (const [lo, la] of pts) {
        const p = proj(lo, la, R)
        if (p.z <= 0) continue
        const a = 0.25 + p.z * 0.75
        ctx.fillStyle = `rgba(242,238,228,${a * 0.85})`
        const s = 0.9 + p.z * 1.1
        ctx.fillRect(p.x - s / 2, p.y - s / 2, s, s)
      }
      cities.forEach((c, i) => {
        const p = proj(c.lo, c.la, R); if (p.z <= 0) return
        ctx.beginPath(); ctx.arc(p.x, p.y, i === cur ? 3.6 : 2.4, 0, Math.PI * 2)
        ctx.fillStyle = i === cur ? '#ff5a1f' : '#f2eee4'; ctx.fill()
      })
      const yp = proj(you.lo, you.la, R)
      if (yp.z > 0) { ctx.beginPath(); ctx.arc(yp.x, yp.y, 4.5, 0, Math.PI * 2); ctx.fillStyle = '#fff'; ctx.fill(); ctx.strokeStyle = 'rgba(255,255,255,.4)'; ctx.stroke() }
      // дуга «вы → сервер»
      const target = cities[cur], u = clamp(arcT, 0, 1), steps = 48
      ctx.lineWidth = 2; ctx.lineCap = 'round'
      let prev = null
      for (let i = 0; i <= steps * u; i++) {
        const q = arcPoint(you, target, i / steps), p = proj(q.lo, q.la, R, q.lift)
        const vis = proj(q.lo, q.la, R, 1).z > -0.05
        if (prev && vis) { ctx.strokeStyle = `rgba(255,90,31,${0.15 + 0.85 * (i / (steps * u || 1))})`; ctx.beginPath(); ctx.moveTo(prev.x, prev.y); ctx.lineTo(p.x, p.y); ctx.stroke() }
        prev = p
      }
      if (prev && u < 1) { ctx.beginPath(); ctx.arc(prev.x, prev.y, 4, 0, Math.PI * 2); ctx.fillStyle = '#ffd2bd'; ctx.shadowColor = '#ff5a1f'; ctx.shadowBlur = 8; ctx.fill(); ctx.shadowBlur = 0 }
    }
    label && (label.textContent = cities[0].n)
    requestAnimationFrame(frame)
  }
  /* ---------- закреплённая история запуска туннеля ---------- */
  // Тот же визуальный язык, что у симулятора обрыва: труба из рёбер-арок, пакеты со шлейфами, полосатая стена.
  // До шага «TUN» трафик приложений идёт в обход через физический адаптер; на пятом шаге он переезжает в трубу,
  // на шестом обходной путь перекрывает стена.
  function initStory() {
    const root = $('#story'); if (!root) return
    const cv = $('canvas', root), ctx = cv.getContext('2d')
    const steps = $$('.step', root), caption = $('.story__caption', root)
    const CAP = [
      'pre-flight: чужих TUN-адаптеров нет — можно продолжать',
      'lockdown: физический адаптер подчинён туннелю',
      'доверенный runtime: бинарники сверены по SHA-256',
      'sing-box check -c → запуск ядра',
      'Wintun: Status=Up — трафик приложений завёрнут в TUN',
      'только теперь — kill-switch: всё вне VPN заблокировано'
    ]
    const PAPER = '242,238,228', OK = '95,208,154', BAD = '255,107,99', WARN = '240,178,74', ACC = '255,122,69'
    const RIBS = 9
    let W = 0, H = 0, dpr = 1, target = 0, run = true, t = 0, last = performance.now(), wall = 0, wallV = 0, hit = -1e9
    const anim = Array(6).fill(0)
    const pk = Array.from({ length: 14 }, (_, i) => ({ u: i / 14, sp: 0.8 + Math.random() * 0.4, lane: (i % 3) - 1 }))
    const probe = Array.from({ length: 3 }, (_, i) => ({ u: 0.5 + i * 0.08, dead: 0 }))
    let sparks = []
    const resize = () => { dpr = Math.min(devicePixelRatio || 1, 2); const r = cv.getBoundingClientRect(); W = r.width; H = r.height; cv.width = W * dpr; cv.height = H * dpr; if (reduce) draw(0, performance.now()) }
    const mono = (px, w = 500) => `${w} ${px}px "Fira Mono", ui-monospace, monospace`
    const geo = () => ({ ax: W * 0.1, tx: W * 0.9, y: H * 0.33, x0: W * 0.26, x1: W * 0.55, cx: W * 0.71, ph: H * 0.085, r: W * 0.066, ny: H * 0.72, f: Math.max(10, W * 0.024) })
    // обходной путь: приложения → физический адаптер → сеть
    const bez = (g, u) => { const k = 1 - u, cy = g.y + 2 * (g.ny - g.y); return [k * k * g.ax + 2 * k * u * W * 0.5 + u * u * g.tx, k * k * g.y + 2 * k * u * cy + u * u * g.y] }
    const WALL_U = 0.77

    function draw(dt, now) {
      if (!W) return
      const g = geo()
      t += dt
      for (let i = 0; i < 6; i++) anim[i] = reduce ? (target >= i ? 1 : 0) : lerp(anim[i], target >= i ? 1 : 0, 0.07)
      const wallTo = target >= 5 ? 1 : 0
      if (reduce) wall = wallTo
      else { wallV += ((wallTo - wall) * 170 - wallV * 14) * dt; wall += wallV * dt }
      const inTun = smooth(0.15, 0.9, anim[4]) // доля трафика, уже переехавшего в трубу

      ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, W, H)
      ctx.lineCap = 'round'; ctx.lineJoin = 'round'; ctx.textAlign = 'center'; ctx.textBaseline = 'middle'

      // рамка политики брандмауэра
      if (anim[5] > 0.02) {
        ctx.globalAlpha = anim[5]
        ctx.beginPath(); ctx.roundRect(W * 0.02, H * 0.1, W * 0.96, H * 0.8, 22)
        ctx.fillStyle = `rgba(${OK},.04)`; ctx.fill()
        ctx.strokeStyle = `rgba(${OK},.7)`; ctx.lineWidth = 1.6; ctx.setLineDash([10, 8]); ctx.lineDashOffset = reduce ? 0 : -t * 24; ctx.stroke(); ctx.setLineDash([])
        ctx.fillStyle = `rgb(${OK})`; ctx.font = mono(g.f * 0.92); ctx.textAlign = 'left'
        ctx.fillText('WFP · DefaultOutboundAction=Block', W * 0.02 + 18, H * 0.1 + 22); ctx.textAlign = 'center'
        ctx.globalAlpha = 1
      }

      // направляющие: прямой путь через туннель и обход через физический адаптер
      ctx.setLineDash([3, 7]); ctx.lineWidth = 1.2
      ctx.strokeStyle = `rgba(${PAPER},.16)`; ctx.beginPath(); ctx.moveTo(g.ax, g.y); ctx.lineTo(g.tx, g.y); ctx.stroke()
      const bypass = target >= 5 ? `rgba(${OK},.35)` : target === 4 ? `rgba(${WARN},.6)` : `rgba(${PAPER},.3)`
      ctx.strokeStyle = bypass; ctx.beginPath()
      for (let i = 0; i <= 40; i++) { const [x, y] = bez(g, i / 40); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y) }
      ctx.stroke(); ctx.setLineDash([])
      if (target === 4 && !reduce) { const [bx, by] = bez(g, 0.26); ctx.fillStyle = `rgb(${WARN})`; ctx.font = mono(g.f * 0.82, 400); ctx.fillText('обход ещё открыт', bx + g.f * 2, by + g.f * 2.2) }

      // место под TUN: пусто → сканирование → рёбра трубы
      const slot = (col, a) => { ctx.setLineDash([5, 6]); ctx.lineWidth = 1.3; ctx.strokeStyle = `rgba(${col},${a})`; ctx.beginPath(); ctx.roundRect(g.x0 - g.ph * 0.4, g.y - g.ph, g.x1 - g.x0 + g.ph * 0.8, g.ph * 2, g.ph * 0.5); ctx.stroke(); ctx.setLineDash([]) }
      if (anim[4] < 0.97) {
        const a = 1 - anim[4]
        slot(target === 0 ? WARN : PAPER, (target === 0 ? 0.8 : 0.3) * a)
        ctx.font = mono(g.f, 500)
        if (target === 0) {
          const k = reduce ? 0.5 : (t * 0.55) % 1, x = lerp(g.x0 - g.ph * 0.3, g.x1 + g.ph * 0.3, k)
          const grad = ctx.createLinearGradient(x - 40, 0, x, 0); grad.addColorStop(0, `rgba(${WARN},0)`); grad.addColorStop(1, `rgba(${WARN},.35)`)
          ctx.fillStyle = grad; ctx.fillRect(x - 40, g.y - g.ph + 2, 40, g.ph * 2 - 4)
          ctx.strokeStyle = `rgb(${WARN})`; ctx.lineWidth = 1.6; ctx.beginPath(); ctx.moveTo(x, g.y - g.ph + 2); ctx.lineTo(x, g.y + g.ph - 2); ctx.stroke()
          ctx.fillStyle = `rgb(${WARN})`; ctx.fillText('чужой TUN?', (g.x0 + g.x1) / 2, g.y - g.ph - g.f * 1.2)
        } else {
          ctx.fillStyle = `rgba(${OK},${0.9 * a})`; ctx.fillText('свободно ✓', (g.x0 + g.x1) / 2, g.y - g.ph - g.f * 1.2)
        }
      }
      for (let i = 0; i < RIBS; i++) {
        const k = i / (RIBS - 1)
        if (k > anim[4] * 1.15) continue
        const x = lerp(g.x0, g.x1, reduce || anim[4] < 0.95 ? k : (k + t * 0.05) % 1)
        ctx.strokeStyle = `rgba(${ACC},${0.35 + 0.5 * Math.sin(Math.PI * k)})`; ctx.lineWidth = 1.6
        ctx.beginPath(); ctx.roundRect(x - g.ph * 0.36, g.y - g.ph, g.ph * 0.72, g.ph * 2, g.ph * 0.36); ctx.stroke()
      }
      if (anim[4] > 0.5) { ctx.globalAlpha = anim[4]; ctx.fillStyle = `rgb(${ACC})`; ctx.font = mono(g.f, 500); ctx.fillText('Wintun · Status=Up', (g.x0 + g.x1) / 2, g.y - g.ph - g.f * 1.2); ctx.globalAlpha = 1 }

      // ядро → сеть
      if (anim[3] > 0.02) { ctx.strokeStyle = `rgba(${OK},${0.6 * anim[3]})`; ctx.lineWidth = 1.8; ctx.beginPath(); ctx.moveTo(g.cx, g.y); ctx.lineTo(lerp(g.cx, g.tx, anim[3]), g.y); ctx.stroke() }

      // пакеты приложений: в обход, пока нет TUN; затем переезжают в трубу
      for (const p of pk) {
        if (!reduce) p.u += dt * 0.22 * p.sp
        if (p.u >= 1) p.u = 0
        const pos = (u) => { const [bx, by] = bez(g, u); return [bx, lerp(by, g.y + p.lane * g.ph * 0.42, inTun)] }
        const [x, y] = pos(p.u), [x2, y2] = pos(Math.max(0, p.u - 0.035))
        const a = smooth(0, 0.06, p.u) * (1 - smooth(0.94, 1, p.u)) * (target >= 5 && inTun < 0.5 ? 0 : 1)
        if (a < 0.02) continue
        const col = inTun > 0.5 ? OK : PAPER
        ctx.strokeStyle = `rgba(${col},${a * 0.4})`; ctx.lineWidth = 2.2; ctx.beginPath(); ctx.moveTo(x2, y2); ctx.lineTo(x, y); ctx.stroke()
        ctx.fillStyle = `rgba(${col},${a * (inTun > 0.5 ? 1 : 0.7)})`; ctx.beginPath(); ctx.arc(x, y, 3.2, 0, Math.PI * 2); ctx.fill()
      }

      // kill-switch: стена на обходном пути и пробные пакеты, которые об неё разбиваются
      const [wx, wy] = bez(g, WALL_U)
      if (wall > 0.5 && !reduce) for (const p of probe) {
        if (p.dead > 0) { p.dead -= dt * 1.4; if (p.dead <= 0) p.u = 0.5; continue }
        p.u += dt * 0.16
        const [x, y] = bez(g, p.u)
        if (p.u >= WALL_U - 0.015) {
          p.dead = 1; hit = now
          for (let i = 0; i < 8; i++) { const an = Math.random() * Math.PI * 2, v = 30 + Math.random() * 90; sparks.push({ x, y, vx: Math.cos(an) * v - 50, vy: Math.sin(an) * v, life: 1 }) }
          continue
        }
        ctx.fillStyle = `rgba(${BAD},.95)`; ctx.beginPath(); ctx.arc(x, y, 3.2, 0, Math.PI * 2); ctx.fill()
      }
      sparks = sparks.filter((s) => s.life > 0)
      for (const s of sparks) { s.x += s.vx * dt; s.y += s.vy * dt; s.vy += 240 * dt; s.life -= dt * 2.6; ctx.fillStyle = `rgba(${OK},${Math.max(0, s.life)})`; ctx.fillRect(s.x - 1.3, s.y - 1.3, 2.6, 2.6) }
      if (wall > 0.01) {
        const hh = H * 0.2 * clamp(wall, 0, 1.12), ww = Math.max(8, W * 0.018), top = wy - H * 0.1
        ctx.save(); ctx.translate(wx, 0); ctx.beginPath(); ctx.roundRect(-ww / 2, top, ww, hh, 3); ctx.clip()
        ctx.fillStyle = `rgb(${OK})`; ctx.fillRect(-ww, top, ww * 2, hh)
        ctx.strokeStyle = 'rgba(15,14,11,.45)'; ctx.lineWidth = 3
        for (let yy = top - ww + ((reduce ? 0 : t * 22) % 12); yy < top + hh + ww; yy += 12) { ctx.beginPath(); ctx.moveTo(-ww, yy + ww); ctx.lineTo(ww, yy - ww); ctx.stroke() }
        ctx.restore()
        const fl = clamp(1 - (now - hit) / 260, 0, 1)
        if (fl > 0) { ctx.strokeStyle = `rgba(${OK},${fl * 0.8})`; ctx.lineWidth = 2; ctx.beginPath(); ctx.roundRect(wx - ww / 2 - 5, top - 5, ww + 10, hh + 10, 6); ctx.stroke() }
        ctx.globalAlpha = clamp(wall, 0, 1); ctx.fillStyle = `rgb(${OK})`; ctx.font = mono(g.f * 0.9); ctx.fillText('обход закрыт', wx, top + H * 0.2 + g.f * 1.3); ctx.globalAlpha = 1
      }

      // узлы
      const node = (x, y, r, label, col, a = 1, sub = '', subCol = PAPER) => {
        if (a < 0.02) return
        ctx.globalAlpha = a
        ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2); ctx.fillStyle = '#17160f'; ctx.fill()
        ctx.strokeStyle = `rgba(${col},.9)`; ctx.lineWidth = 1.6; ctx.stroke()
        ctx.fillStyle = `rgb(${PAPER})`; ctx.font = mono(g.f, 500); ctx.fillText(label, x, y + 1)
        if (sub) { ctx.fillStyle = `rgba(${subCol},.9)`; ctx.font = mono(g.f * 0.82, 400); ctx.fillText(sub, clamp(x, 70, W - 70), y + r + g.f * 1.2) }
        ctx.globalAlpha = 1
      }
      node(g.ax, g.y, g.r, 'ПК', PAPER, 1, 'приложения')
      node(g.tx, g.y, g.r, 'WEB', anim[4] > 0.5 ? OK : PAPER)
      const [nx, nyy] = bez(g, 0.5)
      node(nx, nyy, g.r, 'NIC', anim[1] > 0.5 ? WARN : PAPER, 1, anim[1] > 0.5 ? 'IPv6 off · DNS → .254' : 'физический адаптер', anim[1] > 0.5 ? WARN : PAPER)
      if (anim[1] > 0.05) { // замок lockdown
        const lx = nx - g.r - 16, ly = nyy
        ctx.globalAlpha = anim[1]; ctx.strokeStyle = `rgb(${WARN})`; ctx.lineWidth = 2
        ctx.beginPath(); ctx.arc(lx, ly - 4, 5.5, Math.PI, 0); ctx.stroke(); ctx.fillStyle = `rgb(${WARN})`; ctx.beginPath(); ctx.roundRect(lx - 7.5, ly - 4, 15, 11, 2); ctx.fill(); ctx.globalAlpha = 1
      }
      const coreOk = anim[3] > 0.5
      node(g.cx, g.y, g.r * (0.7 + 0.3 * anim[2]), 'sing-box', coreOk ? OK : PAPER, anim[2], anim[2] > 0.6 ? 'SHA-256 ✓' + (coreOk ? ' · check ✓' : '') : '', coreOk ? OK : PAPER)
      if (target === 2 && !reduce) { // идёт сверка бинарников
        ctx.strokeStyle = `rgb(${ACC})`; ctx.lineWidth = 2.2; ctx.beginPath(); ctx.arc(g.cx, g.y, g.r + 6, t * 4, t * 4 + 1.6); ctx.stroke()
      }
    }

    new ResizeObserver(resize).observe(cv); resize()
    new IntersectionObserver((e) => { run = e[0].isIntersecting }, { threshold: 0 }).observe(cv)
    const setStep = (i) => {
      target = clamp(i, 0, steps.length - 1)
      steps.forEach((s, k) => { s.classList.toggle('is-active', k === target); s.classList.toggle('is-done', k < target) })
      if (caption) caption.textContent = CAP[target]
      if (reduce) draw(0, performance.now())
    }
    setStep(0)
    if (!reduce) {
      const frame = (now) => {
        requestAnimationFrame(frame)
        if (!run || document.hidden) { last = now; return }
        const dt = Math.min((now - last) / 1000, 0.05); last = now
        draw(dt, now)
      }
      requestAnimationFrame(frame)
    }

    // Режим зависит от ширины окна, поэтому пересчитывается при каждой смене медиа-запроса.
    let i = 0, trig = null, timer = null
    steps.forEach((s, k) => s.addEventListener('click', () => { if (trig) return; i = k; setStep(k) }))
    const mode = () => {
      clearInterval(timer); timer = null
      trig?.kill(true); trig = null
      header?.classList.remove('is-parked')
      if (hasGsap() && wide.matches && !reduce) {
        const pin = $('.story__pin', root)
        trig = ScrollTrigger.create({
          trigger: pin, start: 'top top', end: () => `+=${steps.length * 70}%`, pin: true, scrub: true,
          // Пока история закреплена, шапка убрана: она закрывала бы первый шаг и мигала бы при прокрутке.
          onToggle: (self) => header?.classList.toggle('is-parked', self.isActive),
          onUpdate: (self) => setStep(Math.min(steps.length - 1, Math.floor(self.progress * steps.length * 0.999)))
        })
      } else {
        timer = setInterval(() => { if (run && !reduce) { i = (i + 1) % steps.length; setStep(i) } }, 3200)
      }
    }
    mode()
    wide.addEventListener('change', mode)
  }

  /* ---------- FAQ: фильтры и поиск ---------- */
  function initFaq() {
    const root = $('#faq'); if (!root) return
    const items = $$('details', root), btns = $$('.faq-cats [data-cat]', document)
    const empty = $('#faq-empty'), q = $('#faq-q')
    let cat = 'all'
    const apply = () => {
      const s = (q?.value || '').trim().toLowerCase()
      let shown = 0
      items.forEach((d) => {
        const ok = (cat === 'all' || d.dataset.cat === cat) && (!s || d.textContent.replace(/\u00a0/g, ' ').toLowerCase().includes(s))
        d.hidden = !ok; if (ok) shown++
      })
      if (empty) empty.hidden = shown > 0
    }
    btns.forEach((b) => b.addEventListener('click', () => { cat = b.dataset.cat; btns.forEach((x) => x.setAttribute('aria-pressed', String(x === b))); apply() }))
    q?.addEventListener('input', apply)
    if (location.hash) { const t = hashTarget(location.hash); if (t && t.tagName === 'DETAILS') t.open = true }
  }

  /* ---------- протоколы: фильтр ---------- */
  function initProtoFilter() {
    const bar = $('#proto-filter'), grid = $('#proto-grid'); if (!bar || !grid) return
    const cards = $$('[data-pt]', grid), btns = $$('[data-pf]', bar), empty = $('#proto-empty')
    btns.forEach((b) => b.addEventListener('click', () => {
      const f = b.dataset.pf
      btns.forEach((x) => x.setAttribute('aria-pressed', String(x === b)))
      let n = 0
      cards.forEach((c) => { const ok = f === 'all' || c.dataset.pt.split(' ').includes(f); c.hidden = !ok; if (ok) { n++; c.classList.add('is-in') } })
      if (empty) empty.hidden = n > 0
    }))
  }

  /* ---------- копирование команд ---------- */
  function initCopy() {
    $$('[data-copy]').forEach((b) => {
      let original = null, timer = null // исходная подпись запоминается один раз, повторный клик не сохраняет временный текст
      const restore = () => { clearTimeout(timer); timer = setTimeout(() => (b.innerHTML = original), 1600) }
      b.addEventListener('click', async () => {
        const src = $(b.dataset.copy); if (!src) return
        original ??= b.innerHTML
        try {
          await navigator.clipboard.writeText(src.innerText.replace(/^\$ /gm, ''))
          b.textContent = 'Скопировано ✓'
        } catch { b.textContent = 'Выделите вручную' }
        restore()
      })
    })
  }

  /* ---------- симулятор маршрутизации ---------- */
  // Порядок правил повторяет route.rules из tunController.ts; Smart RU — порядок из smartRoute.ts
  // (сначала закреплённые IP-чекеры, потом RU-направления).
  function initRouting() {
    const root = $('#rt'); if (!root) return
    const input = $('#rt-input'), list = $('#rt-rules'), out = $('#rt-verdict')
    const smartToggle = $('#rt-smart'), quicToggle = $('#rt-quic')
    const RU = /(^|\.)(gosuslugi\.ru|nalog\.gov\.ru|mos\.ru|sberbank\.ru|yandex\.ru|ya\.ru|vk\.com|ozon\.ru)$|\.gov\.ru$/
    const RULES = [
      { id: 'loop', name: 'Loopback и диагностический вход', code: 'mixed-direct-in', test: (q) => /^(127\.|localhost$|\[?::1\]?$)/.test(q.host), v: 'direct', why: 'Локальный трафик не покидает машину — идёт напрямую.' },
      { id: 'core', name: 'Процессы прокси-ядер (анти-петля)', code: 'process_name', test: (q) => /^(xray|happ|sing-box)(\.exe)?$/.test(q.raw), v: 'direct', why: 'Ядро само ходит к серверу напрямую, иначе трафик зациклился бы в собственном туннеле.' },
      { id: 'quic', name: 'UDP/443 (QUIC/HTTP3)', code: 'udp:443 → reject', test: (q, o) => o.quic && q.udp && q.port === 443, v: 'block', why: 'Для профилей, которые не умеют надёжно нести UDP, QUIC отклоняется — браузер откатывается на TCP. Нативные UDP-протоколы оставляют QUIC включённым.' },
      { id: 'dns', name: 'DNS: перехват', code: 'hijack-dns', test: (q) => q.port === 53 || /^dns:/.test(q.raw), v: 'dns', why: 'Любой DNS из TUN уходит в резолвер sing-box (DoH через туннель) — запрос не достаёт до провайдера.' },
      { id: 'priv', name: 'Частные сети (ip_is_private)', code: 'direct-out', test: (q) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/.test(q.host), v: 'direct', why: 'Локальная сеть остаётся доступной. Правило стоит строго после перехвата DNS, чтобы DNS на шлюз не уходил мимо.' },
      { id: 'stun', name: 'STUN (анти-WebRTC)', code: 'udp 19302 / 3478', test: (q) => q.port === 19302 || q.port === 3478 || /^stun\./.test(q.host), v: 'vpn', why: 'WebRTC не может обойти туннель и выдать реальный адрес — STUN-запросы идут в туннель.' },
      { id: 'checker', name: 'Smart RU: IP-чекеры закреплены', code: '2ip.ru, ipify → proxy-out', test: (q, o) => o.smart && /(^|\.)(2ip\.ru|ipify\.org)$/.test(q.host), v: 'vpn', why: 'Чекер обязан показать адрес VPN, даже если хостится в России, поэтому он закреплён за туннелем раньше региональных правил.' },
      { id: 'smart', name: 'Smart RU: российские направления', code: 'geoip-ru / gov-ru', test: (q, o) => o.smart && RU.test(q.host), v: 'direct', why: 'Госсервисы, банки и всё, что хостится в России, видят реальный российский адрес и не ломаются. В клиенте решает geoip-ru и список gov-ru, здесь — несколько известных адресов.' },
      { id: 'final', name: 'Всё остальное', code: 'final → proxy-out', test: () => true, v: 'vpn', why: 'По умолчанию — через туннель. Что не доказано безопасным, не идёт напрямую.' }
    ]
    list.innerHTML = RULES.map((r) => `<li class="rule" data-id="${r.id}"><span>${r.name}</span><code>${r.code}</code></li>`).join('')
    const parse = (input) => {
      const src = input.trim().toLowerCase()
      let s = src, udp = false
      if (/^udp[:/]/.test(s)) { udp = true; s = s.replace(/^udp:\/*/, '') }
      s = s.replace(/^https?:\/\//, '').replace(/^tcp:\/*/, '')
      let port = src.startsWith('https') ? 443 : src.startsWith('http') ? 80 : 0
      const hostPart = s.split('/')[0]
      // Голый IPv6 («::1») содержит несколько двоеточий и порта не несёт.
      const m = (hostPart.match(/:/g) || []).length > 1 && !hostPart.startsWith('[') ? null : hostPart.match(/^(\[[^\]]+\]|[^:]+)(?::(\d+))?$/)
      const host = m ? m[1] : hostPart
      if (m && m[2]) port = Number(m[2])
      if (src.startsWith('dns:')) port = 53
      return { raw: s, host, port, udp }
    }
    let token = 0
    const run = async (value) => {
      const my = ++token
      const o = { smart: smartToggle.getAttribute('aria-pressed') === 'true', quic: quicToggle?.getAttribute('aria-pressed') === 'true' }
      const rows = $$('.rule', list)
      rows.forEach((r) => r.classList.remove('is-hit', 'is-scan', 'is-skip'))
      if (!value.trim()) { out.dataset.v = ''; out.innerHTML = `<span class="muted">Введите адрес или выберите пример — увидите, какое правило сработает первым.</span>`; return }
      const q = parse(value)
      let hit = RULES.length - 1
      for (let i = 0; i < RULES.length; i++) { if (RULES[i].test(q, o)) { hit = i; break } }
      for (let i = 0; i <= hit; i++) {
        if (my !== token) return
        rows[i].classList.add('is-scan')
        if (!reduce) await new Promise((r) => setTimeout(r, 120))
        if (my !== token) return
        rows[i].classList.remove('is-scan')
        if (i < hit) rows[i].classList.add('is-skip')
      }
      rows[hit].classList.add('is-hit')
      rows.forEach((r, i) => { if (i > hit) r.classList.add('is-skip') })
      const R = RULES[hit]
      const title = { vpn: 'Через VPN-туннель', direct: 'Напрямую, мимо туннеля', block: 'Отклонён', dns: 'Перехвачен резолвером туннеля' }[R.v]
      out.dataset.v = R.v === 'dns' ? 'vpn' : R.v
      out.innerHTML = `${ICON[R.v]}<div><b>${title}</b><small>${R.why}</small></div>`
    }
    input.addEventListener('input', () => run(input.value))
    $$('[data-rt-sample]', root).forEach((b) => b.addEventListener('click', () => { input.value = b.dataset.rtSample; run(input.value) }))
    const bind = (btn, on, off) => btn?.addEventListener('click', () => {
      const v = btn.getAttribute('aria-pressed') !== 'true'
      btn.setAttribute('aria-pressed', String(v))
      btn.textContent = v ? on : off
      run(input.value)
    })
    bind(smartToggle, 'Smart RU: включён', 'Smart RU: выключен')
    bind(quicToggle, 'QUIC: блок', 'QUIC: разрешён')
    input.value = 'gosuslugi.ru'; run(input.value)
  }

  /* ---------- параллакс блоков ---------- */
  function initParallax() {
    if (!hasGsap() || reduce) return
    $$('[data-parallax]').forEach((el) => {
      gsap.to(el, { yPercent: parseFloat(el.dataset.parallax) || -10, ease: 'none', scrollTrigger: { trigger: el, start: 'top bottom', end: 'bottom top', scrub: true } })
    })
  }

  const boot = () => {
    // Порядок важен только для первых двух: скролл и появление контента. Дальше блоки независимы.
    const blocks = [initScroll, initReveal, initNav, initTransitions, initHero, initPageHero, initMarquee, initStack, initPointerFx,
      initFooterWord, initKillSwitch, initRouting, initGlobe, initStory, initFaq, initProtoFilter, initCopy, initParallax]
    for (const fn of blocks) {
      try {
        fn()
        // Контент показан — таймер в layout.html больше не включает аварийный режим js-fail.
        if (fn === initReveal) window.__siteReady = true
      } catch (e) { console.error(`[site] ${fn.name}:`, e) }
    }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot()
  addEventListener('load', () => {
    if (!hasGsap()) return
    ScrollTrigger.refresh()
    // Закрепление hero добавляет высоту уже после того, как браузер перешёл к якорю из URL, — доводим до цели заново.
    const t = location.hash.length > 1 ? hashTarget(location.hash) : null
    if (t) requestAnimationFrame(() => (lenis ? lenis.scrollTo(t, { offset: -80, immediate: true }) : t.scrollIntoView()))
  })
})()
