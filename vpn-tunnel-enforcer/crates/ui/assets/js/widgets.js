// widgets.js — page-side half of vpnte_ui::widgets::Modal: what must happen synchronously inside
// the page (focus moves, the Tab trap) and cannot wait for a round trip to Rust.
// Rust calls window.vpnteWidgets.openModal(id) / closeModal(id) when a Modal's `open` changes.
(() => {
  'use strict';

  const FOCUSABLE = [
    'a[href]',
    'button:not([disabled])',
    'input:not([disabled]):not([type="hidden"])',
    'select:not([disabled])',
    'textarea:not([disabled])',
    '[tabindex]:not([tabindex="-1"])',
  ].join(',');

  const focusables = (root) =>
    [...root.querySelectorAll(FOCUSABLE)].filter(
      (el) => el.getClientRects().length > 0 && !el.closest('[inert]'),
    );

  const topModal = () => {
    const open = document.querySelectorAll('dialog[data-w-modal][open]');
    return open.length ? open[open.length - 1] : null;
  };

  // Tab / Shift+Tab cycle inside the top modal. showModal() makes the page inert, but Tab past
  // the last control would otherwise leave the document (and the WebView).
  document.addEventListener(
    'keydown',
    (e) => {
      if (e.defaultPrevented) return;
      const dialog = topModal();
      if (!dialog) return;
      if (e.key === 'Escape') {
        // The focus is outside the dialog (on the body once the focused button got disabled):
        // Rust's handler on the dialog would not see the key, and the browser's own close request
        // closes the dialog behind Rust's back on a repeated press (a second `cancel` is not
        // cancelable). Suppress that and hand the key to Rust, which decides.
        if (!dialog.contains(e.target)) {
          e.preventDefault();
          dialog.focus();
          dialog.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
        }
        return;
      }
      if (e.key !== 'Tab') return;
      const list = focusables(dialog);
      if (list.length === 0) {
        e.preventDefault();
        dialog.focus();
        return;
      }
      const first = list[0];
      const last = list[list.length - 1];
      const active = document.activeElement;
      if (!dialog.contains(active) || active === dialog) {
        e.preventDefault();
        (e.shiftKey ? last : first).focus();
      } else if (e.shiftKey && active === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && active === last) {
        e.preventDefault();
        first.focus();
      }
    },
    true,
  );

  // Rust decides whether a modal closes (Escape handler, can_close); a native cancel would
  // close the element behind its back.
  document.addEventListener(
    'cancel',
    (e) => {
      if (e.target instanceof HTMLDialogElement && e.target.hasAttribute('data-w-modal')) {
        e.preventDefault();
      }
    },
    true,
  );

  window.vpnteWidgets = {
    openModal(id) {
      const dialog = document.getElementById(id);
      if (!dialog || dialog.open) return;
      dialog.wOpener = document.activeElement;
      dialog.showModal();
      const target = dialog.querySelector('[data-w-autofocus]') || focusables(dialog)[0] || dialog;
      target.focus();
    },
    closeModal(id) {
      const dialog = document.getElementById(id);
      if (!dialog) return;
      const opener = dialog.wOpener;
      const wasOpen = dialog.open;
      dialog.wOpener = null;
      if (wasOpen) dialog.close();
      if (!wasOpen && !opener) return;
      if (opener && opener.isConnected && typeof opener.focus === 'function') {
        opener.focus();
      } else {
        // The opener is gone (its row was deleted): land on the page's fallback anchor.
        document.querySelector('[data-w-focus-fallback]')?.focus();
      }
    },
  };
})();
