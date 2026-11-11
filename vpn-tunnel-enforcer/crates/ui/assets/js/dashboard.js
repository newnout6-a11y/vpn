// dashboard.js — page-side half of vpnte_ui::dashboard: what must run inside the page without a
// round trip to Rust. (1) FitWord: the big state word is sized so every word (SECURE, LINKING,
// EXPOSED…) is equally wide: its width is measured at 100 px in the display face (letter-spacing
// is in em, so width scales linearly) and capped at 15 % of the window height, 40–150 px.
// (2) Ctrl/Cmd+Enter presses the power button, with the same confirm / cancel rules as a click.
(() => {
  'use strict';

  const MAX = 150;
  const MIN = 40;
  const HEIGHT_SHARE = 0.15;
  const sizes = new WeakMap();
  const observed = new WeakSet();
  const boxes = new ResizeObserver((entries) => entries.forEach((e) => fit(e.target)));

  // The size for a word `at100` px wide at 100 px in a `box` px wide box, `current` the size in use
  // (null before the first fit). Same rule as vpnte_view::swiss::fit_word.
  function fitSize(at100, box, windowHeight, current) {
    // not laid out (the page is hidden): keep the size, the observer fires when it shows again
    if (at100 <= 0) return current;
    const cap = Math.min(MAX, windowHeight * HEIGHT_SHARE);
    const next = Math.max(MIN, Math.min(cap, (box / at100) * 100 * 0.98));
    // hysteresis: a sub-pixel change would feed the resize observer forever
    return current != null && Math.abs(current - next) < 0.5 ? current : next;
  }

  function fit(wrap) {
    const probe = wrap.querySelector(':scope > span.swiss-word');
    const word = wrap.querySelector(':scope > div.swiss-word');
    if (!probe || !word) return;
    const at100 = probe.getBoundingClientRect().width;
    const size = fitSize(at100, wrap.clientWidth, window.innerHeight, sizes.get(wrap) ?? null);
    if (size == null) return;
    sizes.set(wrap, size);
    word.style.fontSize = size + 'px';
  }

  function fitAll() {
    document.querySelectorAll('.swiss-word-wrap').forEach((wrap) => {
      if (!observed.has(wrap)) {
        observed.add(wrap);
        boxes.observe(wrap);
      }
      fit(wrap);
    });
  }

  // A new word is a new (keyed) element; the busy dot changes the probe's text. Only those
  // mutations re-fit: the rest of the page changes every second (traffic bars).
  let queued = false;
  function schedule() {
    if (queued) return;
    queued = true;
    requestAnimationFrame(() => {
      queued = false;
      fitAll();
    });
  }
  const touchesWord = (node) =>
    node.nodeType === 1 &&
    (node.matches('.swiss-word-wrap') || node.querySelector('.swiss-word-wrap') !== null);
  new MutationObserver((records) => {
    for (const r of records) {
      const el = r.target.nodeType === 1 ? r.target : r.target.parentElement;
      if ((el && el.closest('.swiss-word-wrap')) || [...r.addedNodes].some(touchesWord)) {
        schedule();
        return;
      }
    }
  }).observe(document.documentElement, { childList: true, subtree: true, characterData: true });
  // height changes do not resize the box, but the cap depends on them
  window.addEventListener('resize', fitAll);
  // the bundled font's metrics differ from the fallback's
  document.fonts.ready.then(fitAll);

  const TEXT_CONTROLS = new Set(['INPUT', 'TEXTAREA', 'SELECT']);
  window.addEventListener('keydown', (e) => {
    if (!(e.ctrlKey || e.metaKey) || e.key !== 'Enter' || e.repeat || e.defaultPrevented) return;
    const power = document.querySelector('.swiss-skin .swiss-power');
    // no start page, or it is hidden behind another page
    if (!power || power.disabled || power.getClientRects().length === 0) return;
    const t = e.target;
    if (t instanceof Element) {
      if (t.isContentEditable || TEXT_CONTROLS.has(t.tagName)) return;
      // a focused control keeps its own Ctrl+Enter (e.g. «Отмена» in the confirm); dialogs own
      // the keyboard
      if (t !== power && t.closest('button, a, [role="dialog"], [aria-modal="true"], dialog')) return;
    }
    // a modal (the first-run wizard, a confirm dialog) covers the page: no toggling underneath
    if (document.querySelector('dialog[open], [aria-modal="true"]')) return;
    e.preventDefault();
    power.click();
  });

  window.vpnteDashboard = { fitAll, fitSize };
})();
