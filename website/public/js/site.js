/* VPN Tunnel Enforcer — поведение сайта.
   Зависимости (локальные): GSAP + ScrollTrigger, Lenis. Каждый блок включается только при наличии своей разметки. */
(() => {
  'use strict'
  const $ = (s, r = document) => r.querySelector(s)
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s))
  // Якорь из URL — это id элемента, а не селектор: «#2fa» не валидный селектор и бросает исключение.
  const hashTarget = (h) => { try { return document.getElementById(decodeURIComponent(h.slice(1))) } catch { return null } }
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches
  const fine = matchMedia('(hover:hover) and (pointer:fine)').matches
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
    let lastY = 0
    const onScroll = () => {
      const y = window.scrollY
      const max = document.documentElement.scrollHeight - innerHeight
      if (progress) progress.style.transform = `scaleX(${max > 0 ? clamp(y / max, 0, 1) : 0})`
      if (header) {
        header.classList.toggle('is-scrolled', y > 24)
        const open = $('#nav')?.classList.contains('is-open')
        header.classList.toggle('is-hidden', y > 520 && y > lastY + 4 && !open)
        if (y < lastY - 4) header.classList.remove('is-hidden')
      }
      lastY = y
    }
    addEventListener('scroll', onScroll, { passive: true })
    onScroll()
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
  }

  /* ---------- переходы между страницами ---------- */
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
      veil.classList.add('on')
      setTimeout(() => { location.href = a.href }, 340)
    })
  }

  /* ---------- reveal, split-words, счётчики ---------- */
  function initReveal() {
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
    const items = $$('[data-reveal],.split-words,.proto,[data-count]')
    if (!('IntersectionObserver' in window)) { items.forEach((e) => e.classList.add('is-in')); return }
    const io = new IntersectionObserver((entries) => {
      entries.forEach((en) => {
        if (!en.isIntersecting) return
        en.target.classList.add('is-in')
        if (en.target.hasAttribute('data-count')) countUp(en.target)
        io.unobserve(en.target)
      })
    }, { threshold: 0.14, rootMargin: '0px 0px -6% 0px' })
    items.forEach((e) => io.observe(e))
    $$('[data-stagger]').forEach((g) => $$('[data-reveal]', g).forEach((c, i) => c.style.setProperty('--d', `${i * 0.08}s`)))
  }
  function countUp(el) {
    const end = parseFloat(el.dataset.count), dec = (el.dataset.count.split('.')[1] || '').length
    const suf = el.dataset.suffix || '', sep = el.dataset.sep !== undefined
    const fmt = (v) => { let s = v.toFixed(dec); if (sep) s = s.replace(/\B(?=(\d{3})+(?!\d))/g, '\u202f'); return s + suf }
    if (reduce) { el.textContent = fmt(end); return }
    const t0 = performance.now(), dur = 1600
    const tick = (t) => { const k = clamp((t - t0) / dur, 0, 1); el.textContent = fmt(end * (1 - Math.pow(1 - k, 4))); if (k < 1) requestAnimationFrame(tick) }
    requestAnimationFrame(tick)
  }

  /* ---------- hero: туннель из арок (canvas) ---------- */
  function initTunnel() {
    const cv = $('#tunnel'); if (!cv) return
    const ctx = cv.getContext('2d')
    let w = 0, h = 0, dpr = 1, vx = 0, vy = 0, mx = 0, my = 0, tmx = 0, tmy = 0, run = true, t = 0, last = performance.now()
    const N = 20, P = 34
    const parts = Array.from({ length: P }, () => ({ a: Math.random() * Math.PI * 2, r: 0.12 + Math.random() * 0.5, z: Math.random(), s: 0.3 + Math.random() * 0.9 }))
    const mix = (c1, c2, k) => c1.map((v, i) => Math.round(lerp(v, c2[i], k)))
    const VIO = [21, 20, 14], GRN = [255, 90, 31] // VIO — ближние арки (чернила), GRN — дальние (сигнальный оранжевый)
    const resize = () => {
      dpr = Math.min(devicePixelRatio || 1, 2)
      const r = cv.getBoundingClientRect(); w = r.width; h = r.height
      cv.width = w * dpr; cv.height = h * dpr
      vx = w > 1020 ? w * 0.7 : w * 0.5; vy = h * (w > 1020 ? 0.5 : 0.42)
    }
    new ResizeObserver(resize).observe(cv); resize()
    $('.hero')?.addEventListener('pointermove', (e) => {
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
    const frame = (now) => {
      requestAnimationFrame(frame)
      if (!run || document.hidden) { last = now; return }
      const dt = Math.min((now - last) / 1000, 0.05); last = now
      t += dt * (reduce ? 0 : 0.05)
      mx = lerp(mx, tmx, 0.05); my = lerp(my, tmy, 0.05)
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
      ctx.clearRect(0, 0, w, h)
      const base = Math.min(w, h) * 0.5
      const cxs = vx + mx * 60, cys = vy + my * 40
      ctx.lineJoin = 'round'; ctx.lineCap = 'round'
      for (let i = 0; i < N; i++) {
        const z = (i / N + t) % 1
        const f = Math.pow(z, 2.5)
        const s = 0.03 + f * 2.7
        const W = base * 0.95 * s, H = base * 1.2 * s
        const ox = (1 - f) * -mx * 120, oy = (1 - f) * -my * 80
        const col = mix(GRN, VIO, smooth(0.0, 0.7, f))
        const a = smooth(0, 0.07, f) * (1 - smooth(0.5, 0.88, f)) * 0.8
        ctx.strokeStyle = `rgba(${col[0]},${col[1]},${col[2]},${a})`
        ctx.lineWidth = 0.7 + f * 2.1
        arch(cxs + ox, cys + oy, W, H); ctx.stroke()
      }
      // «выход» в конце туннеля — плотная оранжевая точка
      ctx.fillStyle = '#ff5a1f'; ctx.beginPath(); ctx.arc(cxs, cys - base * 0.02, base * 0.034, 0, Math.PI * 2); ctx.fill()
      // пакеты
      for (const p of parts) {
        p.z += dt * (reduce ? 0 : 0.16 * p.s)
        if (p.z > 1) { p.z = 0; p.a = Math.random() * Math.PI * 2; p.r = 0.12 + Math.random() * 0.5 }
        const f0 = Math.pow(p.z, 2.5), f1 = Math.pow(Math.max(p.z - 0.03, 0), 2.5)
        const R0 = base * 1.1 * p.r * (0.03 + f0 * 2.7), R1 = base * 1.1 * p.r * (0.03 + f1 * 2.7)
        const x0 = cxs + Math.cos(p.a) * R0, y0 = cys + Math.sin(p.a) * R0 * 1.15
        const x1 = cxs + Math.cos(p.a) * R1, y1 = cys + Math.sin(p.a) * R1 * 1.15
        ctx.strokeStyle = `rgba(255,90,31,${smooth(0, 0.1, f0) * (1 - smooth(0.45, 0.8, f0)) * 0.85})`
        ctx.lineWidth = 0.8 + f0 * 1.4
        ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x0, y0); ctx.stroke()
      }
    }
    requestAnimationFrame(frame)
  }

  /* ---------- hero: живой лог в окне приложения ---------- */
  function initLog() {
    const box = $('#hero-log'); if (!box) return
    const lines = [
      ['t', '00:00.0', 'v', 'preflight', '', 'чужих TUN-адаптеров нет'],
      ['t', '00:00.4', 'v', 'lockdown', '', 'IPv6 off · DNS → 192.168.250.254'],
      ['t', '00:01.1', 'v', 'runtime', '', 'SHA-256 sing-box сверен'],
      ['t', '00:01.6', 'v', 'config', '', 'sing-box check -c  OK'],
      ['t', '00:02.3', 'v', 'tun', 'g', 'Status=Up · маршрут 192.168.250.0/30'],
      ['t', '00:02.9', 'v', 'killswitch', 'g', 'DefaultOutboundAction=Block'],
      ['t', '00:03.4', 'v', 'egress', 'g', 'IP выхода ≠ IP провайдера ✓'],
      ['t', '00:18.4', 'v', 'watchdog', '', 'проверка egress каждые 15 с'],
      ['t', '00:33.4', 'v', 'leak-test', 'g', 'физический адаптер заблокирован ✓']
    ]
    const render = (n) => {
      box.innerHTML = lines.slice(Math.max(0, n - 6), n).map((l) => `<p><span class="t">${l[1]}</span> <span class="${l[2]}">${l[3]}</span> <span class="${l[4]}">${l[5]}</span></p>`).join('')
    }
    if (reduce) { render(lines.length); return }
    let n = 0
    const step = () => { n = (n % (lines.length + 3)) + 1; render(Math.min(n, lines.length)); setTimeout(step, n > lines.length ? 1400 : 950) }
    step()
  }

  /* ---------- симулятор kill-switch ---------- */
  function initKillSwitch() {
    const root = $('#ks'); if (!root) return
    const lanes = $$('.ks__lane', root)
    const NS = 'http://www.w3.org/2000/svg'
    const topPath = [[34, 75], [78, 36], [222, 36], [266, 75]]
    const botPath = [[34, 75], [78, 116], [222, 116], [266, 75]]
    const pos = (pts, u) => {
      const lens = []; let tot = 0
      for (let i = 1; i < pts.length; i++) { const l = Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]); lens.push(l); tot += l }
      let d = u * tot
      for (let i = 0; i < lens.length; i++) { if (d <= lens[i]) { const k = d / lens[i]; return [lerp(pts[i][0], pts[i + 1][0], k), lerp(pts[i][1], pts[i + 1][1], k)] } d -= lens[i] }
      return pts[pts.length - 1]
    }
    const mk = (tag, attrs, parent) => { const e = document.createElementNS(NS, tag); for (const k in attrs) e.setAttribute(k, attrs[k]); parent && parent.appendChild(e); return e }
    const poly = (pts) => pts.map((p) => p.join(',')).join(' ')
    let auto = true, tAuto = 0, phase = 'normal'
    const sims = lanes.map((lane) => {
      const kind = lane.dataset.kind
      const svg = $('.ks__svg', lane)
      svg.innerHTML = ''
      mk('polyline', { points: poly(topPath), fill: 'none', stroke: 'rgba(242,238,228,.28)', 'stroke-width': 1.5, 'stroke-dasharray': '4 5' }, svg)
      const bot = mk('polyline', { points: poly(botPath), fill: 'none', stroke: 'rgba(255,255,255,.12)', 'stroke-width': 1.5, 'stroke-dasharray': '4 5' }, svg)
      const tun = mk('rect', { x: 118, y: 22, width: 64, height: 28, rx: 8, fill: '#1b1a13', stroke: 'rgba(242,238,228,.55)' }, svg)
      const tunT = mk('text', { x: 150, y: 40, 'text-anchor': 'middle', fill: '#f2eee4', 'font-size': 10, 'font-family': 'Fira Mono, monospace' }, svg); tunT.textContent = 'TUN · sing-box'
      mk('circle', { cx: 34, cy: 75, r: 15, fill: '#1b1a13', stroke: 'rgba(255,255,255,.3)' }, svg)
      const pc = mk('text', { x: 34, y: 79, 'text-anchor': 'middle', fill: '#f2eee4', 'font-size': 10, 'font-family': 'Fira Mono, monospace' }, svg); pc.textContent = 'ПК'
      mk('circle', { cx: 266, cy: 75, r: 15, fill: '#1b1a13', stroke: 'rgba(255,255,255,.3)' }, svg)
      const net = mk('text', { x: 266, y: 79, 'text-anchor': 'middle', fill: '#f2eee4', 'font-size': 9.5, 'font-family': 'Fira Mono, monospace' }, svg); net.textContent = 'WEB'
      const wall = mk('g', { opacity: 0 }, svg)
      mk('rect', { x: 146, y: 98, width: 8, height: 36, rx: 3, fill: '#5fd09a' }, wall)
      const wt = mk('text', { x: 150, y: 148, 'text-anchor': 'middle', fill: '#5fd09a', 'font-size': 9, 'font-family': 'Fira Mono, monospace' }, wall); wt.textContent = 'WFP: BLOCK'
      const pkts = Array.from({ length: 5 }, (_, i) => ({ u: i / 5, el: mk('circle', { r: 3.4, class: 'ks__pkt', cx: -10, cy: -10 }, svg), route: 'top', dead: 0 }))
      const state = $('.ks__state span', lane)
      return { lane, kind, svg, tun, tunT, bot, wall, pkts, state }
    })
    const setState = (s, text) => { s.lane.dataset.s = text.key; s.state.textContent = text.msg }
    const apply = () => {
      sims.forEach((s) => {
        if (phase === 'normal') { s.tun.setAttribute('stroke', 'rgba(242,238,228,.55)'); s.tun.setAttribute('fill', '#1b1a13'); s.tunT.textContent = 'TUN · sing-box'; s.wall.setAttribute('opacity', 0); s.bot.setAttribute('stroke', 'rgba(255,255,255,.12)')
          setState(s, { key: 'ok', msg: 'Трафик идёт через туннель' }) }
        if (phase === 'down') {
          s.tun.setAttribute('stroke', '#ff6b63'); s.tun.setAttribute('fill', 'rgba(255,107,99,.14)'); s.tunT.textContent = 'ТУННЕЛЬ УПАЛ'
          if (s.kind === 'plain') { s.bot.setAttribute('stroke', 'rgba(255,107,99,.6)'); setState(s, { key: 'leak', msg: 'Утечка: пакеты ушли напрямую, виден реальный IP' }) }
          else { s.wall.setAttribute('opacity', 1); setState(s, { key: 'blocked', msg: 'Fail-closed: kill-switch блокирует всё вне VPN' }) }
        }
        if (phase === 'recover') {
          s.tun.setAttribute('stroke', '#f0b24a'); s.tun.setAttribute('fill', 'rgba(240,178,74,.1)'); s.tunT.textContent = 'авторестарт…'
          s.wall.setAttribute('opacity', s.kind === 'plain' ? 0 : 1); s.bot.setAttribute('stroke', 'rgba(255,255,255,.12)')
          setState(s, { key: 'recover', msg: s.kind === 'plain' ? 'Переподключение… часть трафика уже утекла' : 'Авторестарт с бэкоффом 2/5/10 с, защита не снята' })
        }
      })
    }
    const setPhase = (p) => { phase = p; apply(); $('[data-ks-toggle]', root).textContent = p === 'normal' ? 'Оборвать туннель' : 'Восстановить туннель' }
    $('[data-ks-toggle]', root).addEventListener('click', () => { auto = false; $('[data-ks-auto]', root).setAttribute('aria-pressed', 'false'); setPhase(phase === 'normal' ? 'down' : 'normal') })
    $('[data-ks-auto]', root).addEventListener('click', (e) => { auto = !auto; e.currentTarget.setAttribute('aria-pressed', String(auto)); tAuto = 0 })
    let run = true, last = performance.now()
    new IntersectionObserver((e) => { run = e[0].isIntersecting }, { threshold: 0.1 }).observe(root)
    const frame = (now) => {
      requestAnimationFrame(frame)
      if (!run) { last = now; return }
      const dt = Math.min((now - last) / 1000, 0.05); last = now
      if (auto && !reduce) {
        tAuto += dt
        const cyc = tAuto % 11
        const want = cyc < 3 ? 'normal' : cyc < 7.4 ? 'down' : cyc < 9.4 ? 'recover' : 'normal'
        if (want !== phase) setPhase(want)
      }
      sims.forEach((s) => s.pkts.forEach((p) => {
        p.u += dt * 0.42
        if (p.u >= 1) { p.u = 0; p.dead = 0; p.route = phase === 'down' && s.kind === 'plain' ? 'bot' : 'top' }
        let route = p.route
        if (phase === 'normal' || phase === 'recover') route = 'top'
        if (phase === 'down') route = 'bot'
        const pts = route === 'top' ? topPath : botPath
        let u = p.u
        let visible = true
        if (phase === 'down' && s.kind === 'shield') { u = Math.min(u, 0.34); visible = p.u < 0.37 }
        const [x, y] = pos(pts, u)
        p.el.setAttribute('cx', x); p.el.setAttribute('cy', y)
        p.el.setAttribute('opacity', visible ? (phase === 'down' && s.kind === 'shield' && p.u > 0.3 ? 0.9 - (p.u - 0.3) * 12 : 1) : 0)
        p.el.setAttribute('class', phase === 'down' && s.kind === 'plain' ? 'ks__pkt ks__pkt--out' : 'ks__pkt')
        p.el.style.fill = phase === 'down' && s.kind === 'plain' ? '#ff6b63' : phase === 'recover' ? '#f0b24a' : ''
      }))
    }
    apply(); requestAnimationFrame(frame)
  }

  /* ---------- симулятор маршрутизации ---------- */
  function initRouting() {
    const root = $('#rt'); if (!root) return
    const input = $('#rt-input'), list = $('#rt-rules'), out = $('#rt-verdict')
    const smartToggle = $('#rt-smart')
    const RULES = [
      { id: 'loop', name: 'Loopback и диагностический вход', code: 'mixed-direct-in', test: (q) => /^(127\.|localhost|\[::1\])/.test(q.host), v: 'direct', why: 'Локальный трафик не покидает машину — идёт напрямую.' },
      { id: 'core', name: 'Процессы прокси-ядер (анти-петля)', code: 'process_name', test: (q) => /(xray|happ|sing-box)(\.exe)?$/.test(q.raw), v: 'direct', why: 'Ядро само ходит к серверу напрямую, иначе трафик зациклился бы в собственном туннеле.' },
      { id: 'quic', name: 'UDP/443 (QUIC/HTTP3)', code: 'udp:443 → reject', test: (q) => q.udp && q.port === 443, v: 'block', why: 'QUIC отклоняется — браузер откатывается на TCP, который контролируется туннелем целиком.' },
      { id: 'dns', name: 'DNS: перехват', code: 'hijack-dns', test: (q) => q.port === 53 || /^dns:/.test(q.raw), v: 'dns', why: 'Любой DNS из TUN уходит в резолвер sing-box (DoH через туннель) — запрос не достаёт до провайдера.' },
      { id: 'priv', name: 'Частные сети (ip_is_private)', code: 'direct', test: (q) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/.test(q.host), v: 'direct', why: 'Локальная сеть остаётся доступной. Правило стоит строго после перехвата DNS, чтобы DNS на шлюз не уходил мимо.' },
      { id: 'stun', name: 'STUN (анти-WebRTC)', code: 'port 19302 / 3478', test: (q) => q.port === 19302 || q.port === 3478 || /^stun\./.test(q.host), v: 'vpn', why: 'WebRTC не может обойти туннель и выдать реальный адрес — STUN-запросы идут в туннель.' },
      { id: 'smart', name: 'Smart RU: региональные правила', code: 'geosite / geoip-ru', test: (q, s) => s && (/\.(ru|su|рф|xn--p1ai)$/.test(q.host) || /(^|\.)gosuslugi\./.test(q.host)), v: 'direct', why: 'Российские сервисы видят реальный российский адрес и не ломаются — идут напрямую.' },
      { id: 'checker', name: 'IP-чекеры, Google, медиа', code: 'Smart RU → proxy-out', test: (q, s) => s && /(ipify|ifconfig|icanhazip|2ip|google|youtube|netflix|spotify|twitch)/.test(q.host), v: 'vpn', why: 'Сервисы, которые обязаны видеть адрес VPN, принудительно идут через туннель.' },
      { id: 'final', name: 'Всё остальное', code: 'final → proxy-out', test: () => true, v: 'vpn', why: 'По умолчанию — через туннель. Что не доказано безопасным, не идёт напрямую.' }
    ]
    list.innerHTML = RULES.map((r) => `<li class="rule" data-id="${r.id}"><span>${r.name}</span><code>${r.code}</code></li>`).join('')
    const parse = (raw) => {
      let s = raw.trim().toLowerCase(), udp = false
      if (/^udp[:/]/.test(s)) { udp = true; s = s.replace(/^udp:\/*/, '') }
      s = s.replace(/^(https?|tcp):\/\//, (m) => { return m }).replace(/^https?:\/\//, '').replace(/^tcp:\/*/, '')
      let port = /^https?/.test(raw.trim().toLowerCase()) ? (raw.trim().toLowerCase().startsWith('https') ? 443 : 80) : 0
      const hostPart = s.split('/')[0]
      const m = hostPart.match(/^(\[[^\]]+\]|[^:]+)(?::(\d+))?$/)
      const host = m ? m[1] : hostPart
      if (m && m[2]) port = Number(m[2])
      if (/^dns:/.test(raw.trim().toLowerCase())) port = 53
      return { raw: s, host, port, udp }
    }
    let token = 0
    const run = async (value) => {
      const my = ++token
      const smart = smartToggle.getAttribute('aria-pressed') === 'true'
      const rows = $$('.rule', list)
      rows.forEach((r) => r.classList.remove('is-hit', 'is-scan', 'is-skip'))
      if (!value.trim()) { out.dataset.v = ''; out.innerHTML = `<span class="muted">Введите адрес или выберите пример — увидите, какое правило сработает первым.</span>`; return }
      const q = parse(value)
      let hit = RULES.length - 1
      for (let i = 0; i < RULES.length; i++) { if (RULES[i].test(q, smart)) { hit = i; break } }
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
    smartToggle.addEventListener('click', () => {
      const on = smartToggle.getAttribute('aria-pressed') !== 'true'
      smartToggle.setAttribute('aria-pressed', String(on))
      smartToggle.textContent = on ? 'Smart RU: включён' : 'Smart RU: выключен'
      run(input.value)
    })
    input.value = 'gosuslugi.ru'; run(input.value)
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
    wrap.addEventListener('pointerup', () => { drag = false })
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
    let W = 0, H = 0, dpr = 1, target = 0, cur = 0, anim = Array(10).fill(0), t0 = performance.now(), run = true
    const resize = () => { dpr = Math.min(devicePixelRatio || 1, 2); const r = cv.getBoundingClientRect(); W = r.width; H = r.height; cv.width = W * dpr; cv.height = H * dpr }
    new ResizeObserver(resize).observe(cv); resize()
    new IntersectionObserver((e) => { run = e[0].isIntersecting }, { threshold: 0 }).observe(cv)
    const setStep = (i) => {
      target = clamp(i, 0, steps.length - 1)
      steps.forEach((s, k) => { s.classList.toggle('is-active', k === target); s.classList.toggle('is-done', k < target) })
      if (caption) caption.textContent = CAP[target]
    }
    setStep(0)
    const N = {
      apps: [0.13, 0.42], tun: [0.38, 0.42], core: [0.64, 0.42], net: [0.89, 0.42], nic: [0.64, 0.74]
    }
    const px = (n) => [N[n][0] * W, N[n][1] * H]
    const mono = (s, w = 400) => `${w} ${s}px "Fira Mono", ui-monospace, monospace`
    const node = (n, label, a, o = {}) => {
      if (a <= 0.01) return
      const [x, y] = px(n), r = (o.r || 0.075) * Math.min(W, H) * 1.35
      ctx.globalAlpha = a
      ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2)
      ctx.fillStyle = o.fill || '#1b1a13'; ctx.fill()
      ctx.strokeStyle = o.stroke || 'rgba(242,238,228,.55)'; ctx.lineWidth = o.lw || 1.6; ctx.stroke()
      ctx.fillStyle = o.text || '#f2eee4'; ctx.font = mono(Math.max(10, W * 0.026), 500); ctx.textAlign = 'center'; ctx.textBaseline = 'middle'
      ctx.fillText(label, x, y)
      if (o.sub) { ctx.fillStyle = '#a8a496'; ctx.font = mono(Math.max(9, W * 0.022)); ctx.fillText(o.sub, x, y + r + W * 0.035) }
      ctx.globalAlpha = 1
    }
    const link = (a, b, al, o = {}) => {
      if (al <= 0.01) return
      const [x1, y1] = px(a), [x2, y2] = px(b)
      ctx.globalAlpha = al; ctx.strokeStyle = o.c || 'rgba(242,238,228,.4)'; ctx.lineWidth = 1.6
      ctx.setLineDash(o.dash || [5, 6]); ctx.lineDashOffset = -((performance.now() - t0) / 60) % 11
      ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke(); ctx.setLineDash([])
      if (o.packets) {
        for (let k = 0; k < 3; k++) {
          const u = (((performance.now() - t0) / 1600) + k / 3) % 1
          ctx.beginPath(); ctx.arc(lerp(x1, x2, u), lerp(y1, y2, u), 3.2, 0, Math.PI * 2); ctx.fillStyle = o.pc || '#5fd09a'; ctx.fill()
        }
      }
      ctx.globalAlpha = 1
    }
    const frame = () => {
      requestAnimationFrame(frame)
      if (!run || document.hidden) return
      for (let i = 0; i < anim.length; i++) { const want = target >= i ? 1 : 0; anim[i] = lerp(anim[i], want, 0.08) }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, W, H)
      const now = performance.now() - t0
      // шаг 0: пустое место под TUN со сканированием
      const scanA = target === 0 ? 1 : 0.0
      if (scanA || anim[4] < 0.99) {
        const [x, y] = px('tun'), r = 0.075 * Math.min(W, H) * 1.35
        ctx.globalAlpha = (1 - anim[4]) * (0.5 + 0.5 * Math.sin(now / 300))
        ctx.setLineDash([4, 5]); ctx.strokeStyle = 'rgba(240,178,74,.8)'; ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2); ctx.stroke(); ctx.setLineDash([])
        ctx.fillStyle = '#f0b24a'; ctx.font = mono(Math.max(10, W * 0.026), 500); ctx.textAlign = 'center'; ctx.textBaseline = 'middle'; ctx.fillText('?', x, y)
        ctx.globalAlpha = 1
      }
      // связи
      link('apps', 'tun', anim[4], { packets: true, pc: '#ff7a45' })
      link('tun', 'core', anim[4], { packets: true })
      link('core', 'net', anim[3], { packets: anim[4] > 0.9, c: 'rgba(95,208,154,.55)' })
      // физический адаптер → интернет: напрямую, пока нет kill-switch
      const blocked = anim[5]
      if (anim[0] > 0.01) {
        const [x1, y1] = px('nic'), [x2, y2] = px('net')
        ctx.globalAlpha = anim[0] * 0.8; ctx.strokeStyle = blocked > 0.5 ? 'rgba(255,107,99,.55)' : 'rgba(255,255,255,.22)'; ctx.setLineDash([4, 6])
        ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke(); ctx.setLineDash([])
        const mx = (x1 + x2) / 2, my = (y1 + y2) / 2
        if (blocked > 0.4) { ctx.globalAlpha = blocked; ctx.strokeStyle = '#ff6b63'; ctx.lineWidth = 3; ctx.beginPath(); ctx.moveTo(mx - 9, my - 9); ctx.lineTo(mx + 9, my + 9); ctx.moveTo(mx + 9, my - 9); ctx.lineTo(mx - 9, my + 9); ctx.stroke(); ctx.lineWidth = 1.6 }
        ctx.globalAlpha = 1
      }
      // узлы
      node('apps', 'Приложения', 1, { r: 0.09, sub: '' })
      node('nic', 'NIC', anim[0], { stroke: blocked > 0.5 ? '#ff6b63' : 'rgba(255,255,255,.4)', sub: anim[1] > 0.5 ? 'IPv6 off · DNS → .254' : 'физический адаптер' })
      node('core', 'sing-box', anim[2], { stroke: anim[3] > 0.5 ? '#5fd09a' : 'rgba(242,238,228,.55)', sub: anim[2] > 0.5 ? 'SHA-256 ✓' + (anim[3] > 0.5 ? ' · check ✓' : '') : '' })
      node('tun', 'TUN', anim[4], { stroke: '#ff7a45', sub: 'Wintun · Up' })
      node('net', 'Сеть', Math.max(anim[0], 1) * 1, { stroke: 'rgba(255,255,255,.4)' })
      // lockdown замок
      if (anim[1] > 0.05) {
        const [x, y] = px('nic'), r = 0.075 * Math.min(W, H) * 1.35
        ctx.globalAlpha = anim[1]; ctx.strokeStyle = '#f0b24a'; ctx.lineWidth = 2
        ctx.beginPath(); ctx.arc(x - r - 18, y - 6, 6, Math.PI, 0); ctx.stroke(); ctx.fillStyle = '#f0b24a'; ctx.fillRect(x - r - 25, y - 6, 14, 10); ctx.globalAlpha = 1; ctx.lineWidth = 1.6
      }
      // kill-switch: щит вокруг всей схемы
      if (blocked > 0.02) {
        ctx.globalAlpha = blocked * 0.9
        const x = W * 0.04, y = H * 0.1, w = W * 0.92, h = H * 0.86, rad = 26
        ctx.beginPath(); ctx.roundRect(x, y, w, h, rad)
        ctx.strokeStyle = '#5fd09a'; ctx.lineWidth = 2; ctx.setLineDash([10, 7]); ctx.lineDashOffset = -now / 40; ctx.stroke(); ctx.setLineDash([])
        ctx.fillStyle = 'rgba(95,208,154,.05)'; ctx.fill()
        ctx.fillStyle = '#5fd09a'; ctx.font = mono(Math.max(10, W * 0.024), 500); ctx.textAlign = 'left'; ctx.textBaseline = 'alphabetic'
        ctx.fillText('WFP · DefaultOutboundAction=Block', x + 18, y + 24)
        ctx.globalAlpha = 1; ctx.lineWidth = 1.6
      }
    }
    requestAnimationFrame(frame)

    // Режим зависит от ширины окна, поэтому пересчитывается при каждой смене медиа-запроса.
    const wide = matchMedia('(min-width:1021px)')
    let i = 0, trig = null, timer = null
    steps.forEach((s, k) => s.addEventListener('click', () => { if (trig) return; i = k; setStep(k) }))
    const mode = () => {
      clearInterval(timer); timer = null
      trig?.kill(true); trig = null
      if (hasGsap() && wide.matches && !reduce) {
        const pin = $('.story__pin', root)
        trig = ScrollTrigger.create({
          trigger: pin, start: 'top top', end: () => `+=${steps.length * 70}%`, pin: true, scrub: true,
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
        const ok = (cat === 'all' || d.dataset.cat === cat) && (!s || d.textContent.toLowerCase().includes(s))
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

  /* ---------- параллакс блоков ---------- */
  function initParallax() {
    if (!hasGsap() || reduce) return
    $$('[data-parallax]').forEach((el) => {
      gsap.to(el, { yPercent: parseFloat(el.dataset.parallax) || -10, ease: 'none', scrollTrigger: { trigger: el, start: 'top bottom', end: 'bottom top', scrub: true } })
    })
    const mq = $('#hero-win')
    if (mq) gsap.to(mq, { yPercent: -8, scale: 0.97, ease: 'none', scrollTrigger: { trigger: '.hero', start: 'top top', end: 'bottom top', scrub: true } })
  }

  const boot = () => {
    initScroll(); initNav(); initTransitions(); initReveal(); initTunnel(); initLog()
    initKillSwitch(); initRouting(); initGlobe(); initStory(); initFaq(); initProtoFilter(); initCopy(); initParallax()
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot()
  addEventListener('load', () => { hasGsap() && ScrollTrigger.refresh() })
})()
