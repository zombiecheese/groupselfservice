(function () {
  // Lightweight toast system. Reads ?flash=...&flashKind=... on load, shows a
  // toast, and strips the params from the URL so they don't survive
  // copy-paste or back-navigation. Also exposes window.Portal.toast(message,
  // kind, options) for in-page use after AJAX actions.

  var ROOT_ID = 'portal-toast-root';
  var DEFAULT_TIMEOUT_MS = 4500;
  var ERROR_TIMEOUT_MS = 7000;

  function getRoot() {
    var existing = document.getElementById(ROOT_ID);
    if (existing) return existing;
    var root = document.createElement('div');
    root.id = ROOT_ID;
    root.setAttribute('role', 'region');
    root.setAttribute('aria-label', 'Notifications');
    root.setAttribute('aria-live', 'polite');
    document.body.appendChild(root);
    return root;
  }

  function classifyKind(kind) {
    if (kind === 'error' || kind === 'fail') return 'error';
    if (kind === 'warn' || kind === 'warning') return 'warning';
    if (kind === 'info') return 'info';
    return 'success';
  }

  function showToast(message, kind, options) {
    if (!message) return;
    var resolved = classifyKind(kind);
    var opts = options || {};
    var ttl = typeof opts.timeoutMs === 'number'
      ? opts.timeoutMs
      : resolved === 'error' ? ERROR_TIMEOUT_MS : DEFAULT_TIMEOUT_MS;

    var root = getRoot();
    var toast = document.createElement('div');
    toast.className = 'portal-toast portal-toast-' + resolved;
    toast.setAttribute('role', resolved === 'error' ? 'alert' : 'status');

    var body = document.createElement('div');
    body.className = 'portal-toast-body';
    body.textContent = String(message);
    toast.appendChild(body);

    var close = document.createElement('button');
    close.type = 'button';
    close.className = 'portal-toast-close';
    close.setAttribute('aria-label', 'Dismiss notification');
    close.innerHTML = '&times;';
    toast.appendChild(close);

    root.appendChild(toast);
    // Force layout so the slide-in animation triggers.
    void toast.offsetWidth;
    toast.classList.add('portal-toast-visible');

    var dismissed = false;
    function dismiss() {
      if (dismissed) return;
      dismissed = true;
      toast.classList.remove('portal-toast-visible');
      toast.classList.add('portal-toast-hiding');
      setTimeout(function () {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
      }, 260);
    }
    close.addEventListener('click', dismiss);

    if (ttl > 0) {
      var timer = setTimeout(dismiss, ttl);
      // Pause auto-dismiss when the user hovers — accessibility nicety.
      toast.addEventListener('mouseenter', function () { clearTimeout(timer); });
      toast.addEventListener('mouseleave', function () { timer = setTimeout(dismiss, 1500); });
    }
    return dismiss;
  }

  // Pull flash params on first paint, then strip them so a refresh doesn't
  // re-fire the toast. We deliberately also remove `flashKind` and `tab`
  // remains intact (the tabs UI reads it on its own).
  function consumeFlashParams() {
    try {
      var url = new URL(window.location.href);
      var flash = url.searchParams.get('flash');
      var kind = url.searchParams.get('flashKind');
      if (!flash) return;
      showToast(flash, kind || 'success');
      url.searchParams.delete('flash');
      url.searchParams.delete('flashKind');
      window.history.replaceState(null, '', url.pathname + (url.search ? url.search : '') + url.hash);
    } catch (e) {
      /* Older browsers without URL constructor — silently skip. */
    }
  }

  // Expose a tiny global surface.
  window.Portal = window.Portal || {};
  window.Portal.toast = showToast;

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', consumeFlashParams);
  } else {
    consumeFlashParams();
  }
})();
