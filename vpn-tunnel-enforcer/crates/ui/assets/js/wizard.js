// ui-wizard: keeps the keyboard inside the first-run wizard while it is open. The wizard is not a
// native <dialog> with showModal(): that would make the window's HTML caption buttons inert. So
// focus that lands outside it (Tab from <body>, a click on a toast) is brought back, and Tab /
// Shift+Tab wrap at its edges; nothing underneath — the power button included — gets the focus.
(() => {
  const ROOT = '.wz-root';
  const TABBABLE =
    ':is(a[href], button, input, textarea, select, [tabindex]):not([disabled]):not([tabindex="-1"])';

  const tabbables = (root) =>
    [...root.querySelectorAll(TABBABLE)].filter((el) => el.getClientRects().length > 0);

  document.addEventListener(
    'focusin',
    (e) => {
      const root = document.querySelector(ROOT);
      if (!root || !(e.target instanceof Node) || root.contains(e.target)) return;
      (tabbables(root)[0] || root).focus({ preventScroll: true });
    },
    true,
  );

  document.addEventListener(
    'keydown',
    (e) => {
      if (e.key !== 'Tab' || e.ctrlKey || e.altKey || e.metaKey || e.defaultPrevented) return;
      const root = document.querySelector(ROOT);
      if (!root) return;
      const list = tabbables(root);
      const active = document.activeElement;
      if (list.length === 0) {
        e.preventDefault();
        root.focus();
        return;
      }
      // wrap when no tabbable control lies before / after the focus inside the wizard (the
      // focus may sit on a heading or on the overlay itself, which are not in the list)
      const inside = root.contains(active) && active !== root;
      const side = e.shiftKey ? Node.DOCUMENT_POSITION_PRECEDING : Node.DOCUMENT_POSITION_FOLLOWING;
      const more = inside && list.some((el) => el !== active && active.compareDocumentPosition(el) & side);
      if (!more) {
        e.preventDefault();
        (e.shiftKey ? list[list.length - 1] : list[0]).focus();
      }
    },
    true,
  );
})();
