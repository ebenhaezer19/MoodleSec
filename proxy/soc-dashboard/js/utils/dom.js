/**
 * MoodleSec SOC Dashboard — DOM Utilities
 * Helpers for creating elements, toasts, modals, animated counters.
 */
const DOM = (() => {
  /** Create element with attributes and children */
  function el(tag, attrs = {}, ...children) {
    const element = document.createElement(tag);
    for (const [key, val] of Object.entries(attrs)) {
      if (key === 'className') element.className = val;
      else if (key === 'style' && typeof val === 'object') Object.assign(element.style, val);
      else if (key.startsWith('on') && typeof val === 'function') element.addEventListener(key.slice(2).toLowerCase(), val);
      else if (key === 'innerHTML') element.innerHTML = val;
      else if (key === 'textContent') element.textContent = val;
      else element.setAttribute(key, val);
    }
    for (const child of children) {
      if (typeof child === 'string') element.appendChild(document.createTextNode(child));
      else if (child instanceof Node) element.appendChild(child);
    }
    return element;
  }

  /** Shortcut: get element by id */
  function $(id) { return document.getElementById(id); }

  /** Shortcut: query selector */
  function $q(selector, parent = document) { return parent.querySelector(selector); }
  function $qa(selector, parent = document) { return parent.querySelectorAll(selector); }

  /** Set inner HTML safely */
  function setHTML(id, html) {
    const elem = typeof id === 'string' ? $(id) : id;
    if (elem) elem.innerHTML = html;
  }

  /** Show toast notification */
  function toast(message, type = 'info', duration = 4000) {
    const container = $('toast-container');
    if (!container) return;

    const iconMap = {
      success: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>',
      error: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
      warning: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/></svg>',
      info: '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>',
    };

    const toastEl = el('div', { className: `toast toast-${type}` },
      el('span', { innerHTML: iconMap[type] || iconMap.info }),
      el('span', { textContent: message })
    );

    container.appendChild(toastEl);

    setTimeout(() => {
      toastEl.classList.add('removing');
      setTimeout(() => toastEl.remove(), 200);
    }, duration);
  }

  /** Show confirmation modal. Returns a Promise<boolean>. */
  function confirm(title, message, confirmLabel = 'Confirm', confirmClass = 'btn-danger') {
    return new Promise((resolve) => {
      const overlay = $('confirm-modal');
      const titleEl = $('confirm-modal-title');
      const bodyEl = $('confirm-modal-body');
      const cancelBtn = $('confirm-modal-cancel');
      const confirmBtn = $('confirm-modal-confirm');

      titleEl.textContent = title;
      bodyEl.textContent = message;
      confirmBtn.textContent = confirmLabel;
      confirmBtn.className = `btn ${confirmClass}`;
      overlay.classList.add('active');

      function cleanup(result) {
        overlay.classList.remove('active');
        cancelBtn.removeEventListener('click', onCancel);
        confirmBtn.removeEventListener('click', onConfirm);
        resolve(result);
      }
      function onCancel() { cleanup(false); }
      function onConfirm() { cleanup(true); }

      cancelBtn.addEventListener('click', onCancel);
      confirmBtn.addEventListener('click', onConfirm);
    });
  }

  /** Animate counter from current to target value */
  function animateCounter(element, targetValue, duration = 600) {
    if (!element) return;
    const start = parseInt(element.textContent.replace(/,/g, '')) || 0;
    const target = Number(targetValue) || 0;
    if (start === target) { element.textContent = Formatters.number(target); return; }

    const startTime = performance.now();
    function step(currentTime) {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // ease-out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      const current = Math.round(start + (target - start) * eased);
      element.textContent = Formatters.number(current);
      if (progress < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

  /** Open the alert detail drawer */
  function openDrawer() {
    $('alert-detail-drawer').classList.add('open');
    $('drawer-backdrop').classList.add('active');
  }

  /** Close the alert detail drawer */
  function closeDrawer() {
    $('alert-detail-drawer').classList.remove('open');
    $('drawer-backdrop').classList.remove('active');
  }

  return { el, $, $q, $qa, setHTML, toast, confirm, animateCounter, openDrawer, closeDrawer };
})();
