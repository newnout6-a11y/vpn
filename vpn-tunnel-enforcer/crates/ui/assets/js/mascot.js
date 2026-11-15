// mascot.js — page half of vpnte_ui::mascot (the stage, `MascotStage.tsx` + the pointer parts of
// `Mascot.tsx`): finds `data-perch` spots, hops between them along a parabola, picks his palette
// from the surface under him, makes the pupils follow the pointer and detects strokes.
// Rust decides where he goes; this file decides how he moves, at frame rate, without round trips.
// Geometry goes to CSS custom properties on the host's overlay root ([data-mascot-stage=id]); the markup
// reads them with var(), so Rust and this file never write the same inline style.
// Protocol (src/mascot/stage.rs): Rust -> {cmd:'perch',name} | {cmd:'active',value} | {cmd:'glue'};
// page -> {ev:'geo',placed,airborne,surface,below,land} | {ev:'home'} | {ev:'pet'} |
//         {ev:'activity',mascot} | {ev:'visible',value}.
(() => {
  'use strict';

  // Mascot box (body + feet); the seal tag sticks out ~24px above it.
  const W = 96;
  const H = 89;
  const TAG = 24;
  // Pointer/key activity is reported on the leading edge, then at most once per this window.
  const ACTIVITY_MS = 1000;

  /**
   * Any element with data-perch="name" is a spot the mascot can sit on.
   *   data-perch-x     0..1 preferred horizontal anchor (default 0.5)
   *   data-perch-y     "top" (sits on the top edge, default) | "bottom" (stands inside, on the bottom edge)
   *   data-perch-scale size multiplier (default 1)
   *   data-perch-fit   "gap": only land in a horizontal gap free of text/icons; no gap = not available
   */
  function measure(name) {
    const el = document.querySelector('[data-perch="' + name + '"]');
    if (!el) return null;
    const r = el.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) return null; // hidden page / display:none
    const ax = Number(el.dataset.perchX ?? 0.5);
    const y = el.dataset.perchY === 'bottom' ? r.bottom : r.top;
    const scale = Number(el.dataset.perchScale ?? 1);
    const prefer = r.left + r.width * ax;
    if (el.dataset.perchFit !== 'gap') return { x: prefer, y, scale };
    const x = freeSpotX(el, r, W * scale + 4, prefer);
    return x === null ? null : { x, y, scale };
  }

  /** x-centre of the free horizontal slot (no glyphs, no icons) closest to prefer. */
  function freeSpotX(el, r, need, prefer) {
    const taken = [];
    const range = document.createRange();
    const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      if (!n.textContent || !n.textContent.trim()) continue;
      range.selectNodeContents(n);
      for (const box of Array.from(range.getClientRects())) if (box.width > 0) taken.push([box.left, box.right]);
    }
    // Text-less leaves: icons, status squares (but not full-width background layers)
    el.querySelectorAll('*').forEach((c) => {
      if (c.children.length > 0 || (c.textContent && c.textContent.trim())) return;
      const box = c.getBoundingClientRect();
      if (box.width > 0 && box.height > 0 && box.width < r.width * 0.6) taken.push([box.left, box.right]);
    });
    taken.sort((a, b) => a[0] - b[0]);
    const pad = 6;
    const gaps = [];
    let cursor = r.left + pad;
    for (const [a, b] of taken) {
      if (a - pad > cursor) gaps.push([cursor, a - pad]);
      cursor = Math.max(cursor, b + pad);
    }
    if (r.right - pad > cursor) gaps.push([cursor, r.right - pad]);
    let best = null;
    for (const [a, b] of gaps) {
      if (b - a < need) continue;
      const x = Math.min(Math.max(prefer, a + need / 2), b - need / 2);
      if (best === null || Math.abs(x - prefer) < Math.abs(best - prefer)) best = x;
    }
    return best;
  }

  const reducedMotion = () => window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function parseColor(value) {
    const s = value.trim();
    const hex = /^#([0-9a-f]{6})$/i.exec(s);
    if (hex) {
      const n = parseInt(hex[1], 16);
      return [(n >> 16) & 255, (n >> 8) & 255, n & 255, 1];
    }
    const fn = /^rgba?\(([^)]+)\)$/.exec(s);
    if (!fn) return null;
    const p = fn[1].split(/[\s,/]+/).filter(Boolean).map(Number);
    return [p[0] ?? 0, p[1] ?? 0, p[2] ?? 0, p[3] ?? 1];
  }
  const channel = (v) => {
    const c = v / 255;
    return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  };
  const luminance = (c) => 0.2126 * channel(c[0]) + 0.7152 * channel(c[1]) + 0.0722 * channel(c[2]);
  const contrast = (a, b) => {
    const [x, y] = [luminance(a), luminance(b)];
    return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
  };

  /**
   * What he stands on decides his colours: orange slab = black body (signal),
   * an ink-filled surface such as the action button = light body (inverse),
   * otherwise the normal ink body. Standing inside (perch-y bottom) sees the
   * perch's own fill; sitting on top sees what is around it.
   */
  function surfaceOf(name) {
    const el = document.querySelector('[data-perch="' + name + '"]');
    if (!el) return 'paper';
    const vars = getComputedStyle(el);
    const ink = parseColor(vars.getPropertyValue('--ink'));
    const signal = parseColor(vars.getPropertyValue('--signal'));
    for (let node = el.dataset.perchY === 'bottom' ? el : el.parentElement; node; node = node.parentElement) {
      const bg = parseColor(getComputedStyle(node).backgroundColor);
      if (!bg || bg[3] < 0.5) continue;
      if (signal && Math.abs(bg[0] - signal[0]) + Math.abs(bg[1] - signal[1]) + Math.abs(bg[2] - signal[2]) < 60) return 'signal';
      return ink && contrast(ink, bg) < 3 ? 'inverse' : 'paper';
    }
    return 'paper';
  }

  /** Where the speech bubble hangs for a position (`Bubble` of the old stage). */
  function bubbleAt(pos) {
    const head = pos.y - (H + TAG) * pos.scale;
    const below = head < 80; // no room above: talk from underneath
    const k = pos.x < 280 ? 14 : 86; // which point of the bubble sits over the mascot
    return { below, k, top: below ? pos.y + 12 : head - 14 };
  }

  /** One running stage (one mounted host); a newer host replaces it. */
  class Stage {
    constructor(dioxus, id) {
      this.dioxus = dioxus;
      this.id = String(id); // value of this host's [data-mascot-stage]
      this.perch = null; // name of the current spot
      this.active = false; // the host wants him drawn (dashboard shown)
      this.pos = null; // {x, y, scale} last written; null = not placed
      this.flying = false;
      this.dir = 0; // -1 / 1 while airborne
      this.raf = 0;
      this.soonFrame = 0;
      this.surface = 'paper';
      this.land = 0;
      this.homeAsked = null; // perch we already asked Rust to give up
      this.sent = '';
      this.root = null;
      this.applied = null; // root the variables were last written to
      this.timer = 0;
      this.lastActivity = -Infinity;
      this.lookFrame = 0;
      this.stroke = { x: 0, y: 0, dirX: 0, dirY: 0, dist: 0, turns: 0, since: -Infinity };
      this.stopped = false;
      this.done = new Promise((resolve) => (this.finish = resolve));
      this.listeners = [];
      this.listen(window, 'scroll', () => this.soon(), true);
      this.listen(window, 'resize', () => this.soon());
      for (const type of ['mousemove', 'mousedown', 'keydown', 'wheel']) {
        this.listen(window, type, (e) => this.activity(e), { passive: true });
      }
      this.listen(window, 'mousemove', (e) => this.look(e), { passive: true });
      this.listen(window, 'pointermove', (e) => this.strokeMove(e), { passive: true });
      this.listen(document, 'visibilitychange', () => this.visibility());
      this.receive();
      // A start in the tray: the brain assumes a shown window until it hears otherwise.
      if (document.hidden) this.send({ ev: 'visible', value: false });
    }

    listen(target, type, fn, opts) {
      target.addEventListener(type, fn, opts);
      this.listeners.push([target, type, fn, opts]);
    }

    /** Ends the stage; a superseded one first empties its overlay (a second host never lingers). */
    stop(superseded = false) {
      if (this.stopped) return;
      this.active = false; // every pending frame / timeout callback is a no-op from here on
      if (superseded) {
        this.pos = null;
        this.report();
      }
      this.stopped = true;
      for (const [target, type, fn, opts] of this.listeners) target.removeEventListener(type, fn, opts);
      cancelAnimationFrame(this.raf);
      cancelAnimationFrame(this.lookFrame);
      cancelAnimationFrame(this.soonFrame);
      clearTimeout(this.timer);
      this.finish();
    }

    send(msg) {
      if (!this.stopped) this.dioxus.send(msg);
    }

    async receive() {
      while (!this.stopped) {
        const msg = await this.dioxus.recv();
        if (this.stopped || !msg) return;
        if (msg.cmd === 'perch') this.goTo(msg.name);
        else if (msg.cmd === 'active') this.setActive(msg.value);
        else if (msg.cmd === 'glue') this.regule();
      }
    }

    /** The overlay root (found lazily: it may render after this script starts). */
    stage() {
      if (this.root && this.root.isConnected) return this.root;
      const root = document.querySelector('[data-mascot-stage="' + this.id + '"]');
      if (!root && this.root) this.stop(); // the host is gone
      this.root = root;
      return root;
    }

    /** Re-sends the observed state when something changed. */
    report() {
      // Placed = the variables the markup reads are written on the live overlay root.
      const placed = this.active && this.pos !== null && this.applied !== null && this.applied === this.root;
      const below = placed ? bubbleAt(this.pos).below : false;
      const geo = { ev: 'geo', placed, airborne: this.flying, surface: this.surface, below, land: this.land };
      const json = JSON.stringify(geo);
      if (json === this.sent) return;
      this.sent = json;
      this.send(geo);
    }

    /** Writes the position (and the bubble anchor that follows it) to the overlay variables. */
    apply() {
      const root = this.stage();
      const p = this.pos;
      this.applied = root && p ? root : null;
      if (!this.applied) return;
      const b = bubbleAt(p);
      const s = root.style;
      s.setProperty('--mx', p.x + 'px');
      s.setProperty('--my', p.y + 'px');
      s.setProperty('--ms', String(p.scale));
      s.setProperty('--mr', (this.flying ? this.dir * 12 : 0) + 'deg');
      s.setProperty('--bx', p.x + 'px');
      s.setProperty('--by', b.top + 'px');
      s.setProperty('--bk', '-' + b.k + '%');
      s.setProperty('--bt', b.below ? '0px' : '-100%');
      s.setProperty('--bkl', b.k + '%');
    }

    // Stick to the current perch while it moves (scroll, resize, layout changes).
    // If the spot disappears (text grew into it), ask to go home: never snap.
    glue() {
      if (this.flying || !this.active || this.perch === null) return;
      const t = measure(this.perch);
      if (!t) {
        if (this.perch === 'home') {
          // The start page itself is gone (another page, collapsed layout): never float over it.
          this.pos = null;
          this.report();
        } else if (this.homeAsked !== this.perch) {
          this.homeAsked = this.perch;
          this.send({ ev: 'home' });
        }
        return;
      }
      const p = this.pos;
      const moved = !p || Math.abs(p.x - t.x) >= 0.5 || Math.abs(p.y - t.y) >= 0.5 || p.scale !== t.scale;
      if (moved) this.pos = t;
      if (moved || this.applied !== this.stage()) this.apply();
      this.report();
    }

    readSurface() {
      if (this.flying || !this.active || this.perch === null) return;
      this.surface = surfaceOf(this.perch);
      this.report();
    }

    /** Glue on the next frame (scroll and resize bursts collapse into one measurement). */
    soon() {
      if (this.soonFrame) return;
      this.soonFrame = requestAnimationFrame(() => {
        this.soonFrame = 0;
        this.glue();
      });
    }

    /**
     * After a phase change. The DOM update may land after this message, so the position is
     * glued twice; the surface is read once the slab's 0.5 s background transition is over
     * (read mid-transition, the old orange made him keep the "on the slab" palette).
     */
    regule() {
      requestAnimationFrame(() => this.glue());
      setTimeout(() => this.glue(), 150);
      setTimeout(() => {
        this.glue();
        this.readSurface();
      }, 600);
    }

    // Layout and text can change without scroll/resize (banners, ticking values). At home the check
    // is one cheap rect read; the text-gap scan only runs while he sits on a fit=gap perch, and
    // nothing runs while the window is hidden or the dashboard is not shown.
    schedule() {
      clearTimeout(this.timer);
      if (this.stopped || !this.active) return;
      this.timer = setTimeout(() => {
        if (!document.hidden && this.stage()) {
          this.glue();
          this.readSurface(); // surfaces recolour (slab turns orange, button state changes)
        }
        this.schedule();
      }, this.perch === 'home' ? 1500 : 500);
    }

    setActive(value) {
      if (value === this.active) return;
      this.active = value;
      if (!value) {
        // Out of sight: drop the flight and the placement; he is placed afresh on return.
        cancelAnimationFrame(this.raf);
        this.flying = false;
        this.dir = 0;
        this.pos = null;
        this.report();
        this.schedule();
        return;
      }
      this.glue();
      this.readSurface();
      this.regule(); // the page may still be laying out (first start, page switch)
      this.schedule();
    }

    goTo(name) {
      if (name === this.perch) return;
      this.perch = name;
      this.homeAsked = null;
      this.schedule();
      if (this.active) this.hop();
    }

    // Hop along a parabola to the current perch.
    hop() {
      const name = this.perch;
      const from = this.pos;
      const to = measure(name);
      if (!from || !to || reducedMotion()) {
        cancelAnimationFrame(this.raf);
        this.flying = false;
        this.dir = 0;
        this.glue();
        this.readSurface();
        return;
      }
      const dist = Math.hypot(to.x - from.x, to.y - from.y);
      const dur = Math.min(950, 420 + dist * 0.5);
      const lift = Math.min(170, 60 + dist * 0.22);
      const start = performance.now();
      this.flying = true;
      this.dir = to.x >= from.x ? 1 : -1;
      cancelAnimationFrame(this.raf);
      this.report();
      const step = (now) => {
        const t = Math.min(1, Math.max(0, (now - start) / dur));
        const e = t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2; // easeInOutQuad
        const tgt = measure(name) ?? to; // the target may move during the flight
        this.pos = {
          x: from.x + (tgt.x - from.x) * e,
          y: from.y + (tgt.y - from.y) * e - lift * 4 * t * (1 - t),
          scale: from.scale + (tgt.scale - from.scale) * e,
        };
        if (t < 1) {
          this.apply();
          this.report(); // sends only when the bubble side flips
          this.raf = requestAnimationFrame(step);
          return;
        }
        this.flying = false;
        this.dir = 0;
        this.land += 1; // replays the squash
        this.surface = surfaceOf(name);
        this.apply();
        this.report();
      };
      this.raf = requestAnimationFrame(step);
    }

    /** Window input re-arms his idle timer; a stroke on him wakes him gently. */
    activity(e) {
      if (!this.active) return; // the brain is paused anyway
      const now = performance.now();
      if (now - this.lastActivity < ACTIVITY_MS) return;
      this.lastActivity = now;
      const mascot = !!(e.target instanceof Element && e.target.closest('[data-mascot]'));
      this.send({ ev: 'activity', mascot });
    }

    /** Pupils follow the cursor (rAF-throttled), at most 4 px off centre. */
    look(e) {
      if (this.lookFrame || !this.active) return;
      this.lookFrame = requestAnimationFrame(() => {
        this.lookFrame = 0;
        const root = this.stage();
        // The 80x80 body is the first div inside the button.
        const body = root && root.querySelector('[data-mascot] div');
        if (!body) return;
        const r = body.getBoundingClientRect();
        const clamp = (v) => Math.max(-4, Math.min(4, v));
        root.style.setProperty('--lx', clamp((e.clientX - (r.left + r.width / 2)) / 45) + 'px');
        root.style.setProperty('--ly', clamp((e.clientY - (r.top + r.height / 2)) / 45) + 'px');
      });
    }

    /** A stroke = enough pointer travel with a change of direction within a short window. */
    strokeMove(e) {
      if (!this.active || !(e.target instanceof Element) || !e.target.closest('[data-mascot]')) return;
      const st = this.stroke;
      const now = performance.now();
      if (now - st.since > 900) Object.assign(st, { dist: 0, turns: 0, since: now, dirX: 0, dirY: 0, x: e.clientX, y: e.clientY });
      const dx = e.clientX - st.x;
      const dy = e.clientY - st.y;
      st.x = e.clientX;
      st.y = e.clientY;
      st.dist += Math.hypot(dx, dy);
      const sx = Math.sign(dx);
      const sy = Math.sign(dy);
      if (sx && st.dirX && sx !== st.dirX) st.turns += 1;
      if (sy && st.dirY && sy !== st.dirY) st.turns += 1;
      if (sx) st.dirX = sx;
      if (sy) st.dirY = sy;
      if (st.dist > 90 && st.turns >= 1) {
        this.send({ ev: 'pet' });
        Object.assign(st, { dist: 0, turns: 0, since: now });
      }
    }

    visibility() {
      this.send({ ev: 'visible', value: !document.hidden });
      if (!document.hidden) this.soon();
    }
  }

  let current = null;

  window.vpnteMascot = {
    /** Runs a stage for one host until its overlay leaves the document or a newer host starts. */
    run(dioxus, id) {
      if (current) current.stop(true);
      current = new Stage(dioxus, id);
      return current.done;
    },
    // Exposed for the CDP checks of demo_mascot.
    measure,
    surfaceOf,
  };
})();
