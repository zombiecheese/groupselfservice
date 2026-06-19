(function () {
  var meta = document.querySelector('meta[name="csrf-token"]');
  var csrf = meta ? meta.getAttribute('content') : '';

  var tabs = document.querySelectorAll('.tabs [data-tab]');
  var panes = document.querySelectorAll('.tab-pane');
  tabs.forEach(function (btn) {
    btn.addEventListener('click', function () {
      var target = btn.getAttribute('data-tab');
      tabs.forEach(function (t) { t.setAttribute('aria-selected', t === btn ? 'true' : 'false'); });
      panes.forEach(function (p) { p.classList.toggle('active', p.getAttribute('data-pane') === target); });
      try { history.replaceState(null, '', '/admin/settings?tab=' + target); } catch (e) {}
    });
  });

  var testState = { ad: false, entra: false, mail: false };

  function setStatus(key, ok, message) {
    var els = document.querySelectorAll('[data-test-status="' + key + '"]');
    if (!els.length) return;
    els.forEach(function (el) {
      el.classList.remove('ok', 'fail', 'pending');
      el.classList.add(ok ? 'ok' : 'fail');
      el.textContent = message;
    });
    testState[key] = !!ok;
    refreshGates();
  }

  function setPending(key, message) {
    var els = document.querySelectorAll('[data-test-status="' + key + '"]');
    if (!els.length) return;
    els.forEach(function (el) {
      el.classList.remove('ok', 'fail');
      el.classList.add('pending');
      el.textContent = message;
    });
    testState[key] = false;
    refreshGates();
  }

  function isEnabled(card) {
    var toggle = card.querySelector('[data-gate-toggle]');
    return !toggle || toggle.checked;
  }

  function refreshGates() {
    document.querySelectorAll('form[data-gate]').forEach(function (form) {
      var gate = form.getAttribute('data-gate');
      // Each form gates on a single integration key now (ad / entra / mail).
      // Older "directory" forms gated on both ad+entra; preserved here so any
      // markup that hasn't been updated keeps working.
      var keys;
      if (gate === 'directory') keys = ['ad', 'entra'];
      else if (gate === 'ad' || gate === 'entra' || gate === 'mail') keys = [gate];
      else keys = [];
      var save = form.querySelector('[data-save-button]');
      if (!save) return;
      var allOk = keys.every(function (key) {
        var card = form.querySelector('[data-test-card="' + key + '"]');
        if (!card) return true;
        if (!isEnabled(card)) return true;
        return testState[key] === true;
      });
      form.querySelectorAll('[data-save-button]').forEach(function (btn) {
        btn.disabled = !allOk;
      });
    });
  }

  document.querySelectorAll('[data-test-card]').forEach(function (card) {
    var key = card.getAttribute('data-test-card');
    card.querySelectorAll('[data-gate-input], [data-gate-toggle]').forEach(function (input) {
      input.addEventListener('change', function () { setPending(key, 'Re-test required'); });
      input.addEventListener('input', function () { setPending(key, 'Re-test required'); });
    });
  });

  function postJson(url, payload) {
    var body = new URLSearchParams();
    body.set('_csrf', csrf);
    Object.keys(payload).forEach(function (k) {
      var v = payload[k];
      if (v === undefined || v === null) return;
      body.set(k, String(v));
    });
    return fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
      body: body,
      credentials: 'same-origin'
    }).then(function (r) { return r.json(); });
  }

  function val(id) { var el = document.getElementById(id); return el ? el.value : ''; }
  function checked(name) { var el = document.querySelector('[name="' + name + '"]'); return el && el.checked ? 'on' : ''; }
  function radioVal(name) { var el = document.querySelector('[name="' + name + '"]:checked'); return el ? el.value : ''; }

  document.querySelectorAll('[data-test-button]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var key = btn.getAttribute('data-test-button');
      setPending(key, 'Testing...');
      // Disable the button and show a small spinner while the probe runs.
      // The probes can take 5-15 seconds (DNS + TCP + TLS + LDAP bind) and
      // unresponsive feedback is the most common UX complaint.
      var originalLabel = btn.dataset.originalLabel || btn.textContent;
      btn.dataset.originalLabel = originalLabel;
      btn.disabled = true;
      btn.classList.add('is-busy');
      btn.innerHTML = '<span class="spinner" aria-hidden="true"></span>Testing\u2026';
      var url, payload;
      if (key === 'ad') {
        url = '/admin/settings/test-ad';
        payload = {
          adLdapUrl: val('adLdapUrl'),
          adBaseDn: val('adBaseDn'),
          adTlsCaPem: val('adTlsCaPem'),
          adTlsServerName: val('adTlsServerName'),
          adTlsAllowUntrusted: checked('adTlsAllowUntrusted'),
          adTestUsername: val('adTestUsername'),
          adTestPassword: val('adTestPassword')
        };
      } else if (key === 'entra') {
        url = '/admin/settings/test-entra';
        payload = {
          entraTenantId: val('entraTenantId'),
          entraClientId: val('entraClientId'),
          entraClientSecret: val('entraClientSecret')
        };
      } else if (key === 'mail') {
        url = '/admin/settings/test-mail';
        payload = {
          mailMode: radioVal('mailMode') || 'smtp',
          mailSmtpHost: val('mailSmtpHost'),
          mailSmtpPort: val('mailSmtpPort'),
          mailSmtpSecure: checked('mailSmtpSecure'),
          mailSmtpIgnoreTls: checked('mailSmtpIgnoreTls'),
          mailSmtpAllowUntrustedTls: checked('mailSmtpAllowUntrustedTls'),
          mailSmtpRequireAuth: checked('mailSmtpRequireAuth'),
          mailSmtpUsername: val('mailSmtpUsername'),
          mailSmtpPassword: val('mailSmtpPassword'),
          mailEntraTenantId: val('mailEntraTenantId'),
          mailEntraClientId: val('mailEntraClientId'),
          mailEntraClientSecret: val('mailEntraClientSecret')
        };
      }
      postJson(url, payload).then(function (json) {
        setStatus(key, !!json.ok, json.message || (json.ok ? 'OK' : 'Failed'));
        var detailEl = document.querySelector('[data-test-detail="' + key + '"]');
        if (detailEl) {
          if (Array.isArray(json.steps) && json.steps.length) {
            detailEl.hidden = false;
            detailEl.textContent = json.steps.map(function (s) {
              return (s.ok ? '[OK] ' : '[FAIL] ') + s.step + ': ' + s.detail;
            }).join('\n');
          } else {
            detailEl.hidden = true;
            detailEl.textContent = '';
          }
        }
      }).catch(function (err) {
        setStatus(key, false, 'Test failed: ' + (err && err.message ? err.message : err));
      }).then(function () {
        // Re-enable the button regardless of outcome.
        btn.disabled = false;
        btn.classList.remove('is-busy');
        btn.textContent = btn.dataset.originalLabel || originalLabel;
      });
    });
  });

  document.querySelectorAll('[data-gate-toggle]').forEach(function (toggle) {
    toggle.addEventListener('change', refreshGates);
  });

  var fetchCaBtn = document.querySelector('[data-fetch-ca-button]');
  if (fetchCaBtn) {
    fetchCaBtn.addEventListener('click', function () {
      var statusEl = document.querySelector('[data-fetch-ca-status]');
      var detailEl = document.querySelector('[data-fetch-ca-detail]');
      var textarea = document.getElementById('adTlsCaPem');
      if (statusEl) {
        statusEl.classList.remove('ok', 'fail');
        statusEl.classList.add('pending');
        statusEl.textContent = 'Fetching...';
      }
      if (detailEl) { detailEl.hidden = true; detailEl.textContent = ''; }
      postJson('/admin/settings/fetch-ad-ca', {
        adLdapUrl: val('adLdapUrl'),
        adTlsServerName: val('adTlsServerName')
      }).then(function (json) {
        if (statusEl) {
          statusEl.classList.remove('pending');
          statusEl.classList.add(json.ok ? 'ok' : 'fail');
          statusEl.textContent = json.message || (json.ok ? 'OK' : 'Failed');
        }
        if (json.ok && textarea && json.pem) {
          textarea.value = json.pem;
          textarea.dispatchEvent(new Event('input', { bubbles: true }));
        }
        if (detailEl && json.summary) {
          detailEl.hidden = false;
          detailEl.textContent = json.summary;
        }
      }).catch(function (err) {
        if (statusEl) {
          statusEl.classList.remove('pending');
          statusEl.classList.add('fail');
          statusEl.textContent = 'Fetch failed: ' + (err && err.message ? err.message : err);
        }
      });
    });
  }

  refreshGates();

  var smtpAuthToggle = document.querySelector('[data-toggle-smtp-auth]');
  var smtpAuthFields = document.querySelector('[data-smtp-auth-fields]');
  if (smtpAuthToggle && smtpAuthFields) {
    var smtpAuthInputs = smtpAuthFields.querySelectorAll('input');
    var applySmtpAuthVisibility = function () {
      var show = !!smtpAuthToggle.checked;
      smtpAuthFields.hidden = !show;
      smtpAuthInputs.forEach(function (input) { input.disabled = !show; });
    };
    smtpAuthToggle.addEventListener('change', applySmtpAuthVisibility);
    applySmtpAuthVisibility();
  }

  // Delivery mode: show only the fields for the selected mail mode so the SMTP
  // and Entra blocks never appear at once. Hidden inputs still submit, so the
  // inactive mode's saved values are preserved on save.
  var mailModeInputs = document.querySelectorAll('[data-mail-mode]');
  var mailBlocks = document.querySelectorAll('[data-mail-block]');
  if (mailModeInputs.length && mailBlocks.length) {
    var applyMailMode = function () {
      var selected = 'smtp';
      mailModeInputs.forEach(function (radio) { if (radio.checked) selected = radio.value; });
      mailBlocks.forEach(function (block) {
        block.hidden = block.getAttribute('data-mail-block') !== selected;
      });
    };
    mailModeInputs.forEach(function (radio) { radio.addEventListener('change', applyMailMode); });
    applyMailMode();
  }

  // Delegated-admin group pickers (AD + Entra). Each picker has a search input,
  // an absolutely-positioned results list, a chip strip, and a hidden textarea
  // (`data-chip-store`) whose value is one chip value per line. The hidden
  // textarea is what the form posts, so the existing server parser keeps
  // working untouched.
  document.querySelectorAll('.picker').forEach(function (picker) {
    var kind = picker.getAttribute('data-picker'); // 'ad' | 'entra'
    var input = picker.querySelector('.picker-search');
    var results = picker.querySelector('.picker-results');
    var card = picker.closest('.card');
    var chipList = card.querySelector('[data-chip-list="' + kind + '"]');
    var store = card.querySelector('[data-chip-store="' + kind + '"]');
    var manualInput = picker.querySelector('[data-manual-input="' + kind + '"]');
    var manualAddBtn = picker.querySelector('[data-manual-add="' + kind + '"]');
    var manualError = picker.querySelector('[data-manual-error="' + kind + '"]');

    function syncStore() {
      var values = Array.prototype.map.call(
        chipList.querySelectorAll('.chip'),
        function (c) { return c.getAttribute('data-value'); }
      ).filter(Boolean);
      store.value = values.join('\n');
    }

    function makeChip(value, label, title) {
      var chip = document.createElement('span');
      chip.className = 'chip';
      chip.setAttribute('data-value', value);
      chip.setAttribute('title', title || value);
      var span = document.createElement('span');
      span.className = 'chip-label';
      span.textContent = label || value;
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'chip-remove';
      btn.setAttribute('aria-label', 'Remove');
      btn.innerHTML = '&times;';
      chip.appendChild(span);
      chip.appendChild(btn);
      return chip;
    }

    function addChip(value, label) {
      if (!value) return;
      var existing = chipList.querySelector('.chip[data-value="' + CSS.escape(value) + '"]');
      if (existing) return;
      chipList.appendChild(makeChip(value, label, value));
      syncStore();
    }

    chipList.addEventListener('click', function (event) {
      var btn = event.target.closest('.chip-remove');
      if (!btn) return;
      var chip = btn.closest('.chip');
      if (chip) {
        chip.parentNode.removeChild(chip);
        syncStore();
      }
    });

    function hideResults() {
      if (!results) return;
      results.hidden = true;
      results.innerHTML = '';
      results.classList.remove('empty');
    }

    function renderResults(items) {
      results.innerHTML = '';
      if (!items || items.length === 0) {
        results.classList.add('empty');
        results.textContent = 'No matches.';
        results.hidden = false;
        return;
      }
      results.classList.remove('empty');
      items.forEach(function (item) {
        var row = document.createElement('div');
        row.className = 'picker-result';
        var name = document.createElement('div');
        name.className = 'name';
        var sub = document.createElement('div');
        sub.className = 'sub';
        var value, label, secondary;
        if (kind === 'ad') {
          value = item.dn;
          label = item.name;
          secondary = item.dn;
        } else {
          value = item.id;
          label = item.displayName;
          secondary = item.id;
        }
        name.textContent = label;
        sub.textContent = secondary;
        row.appendChild(name);
        row.appendChild(sub);
        row.addEventListener('mousedown', function (event) {
          event.preventDefault();
          addChip(value, label);
          input.value = '';
          hideResults();
        });
        results.appendChild(row);
      });
      results.hidden = false;
    }

    function renderError(message) {
      results.innerHTML = '';
      results.classList.add('empty');
      results.textContent = message;
      results.hidden = false;
    }

    var debounce;
    if (input) {
      input.addEventListener('input', function () {
      window.clearTimeout(debounce);
      var q = input.value.trim();
      if (q.length < 2) {
        hideResults();
        return;
      }
      debounce = window.setTimeout(function () {
        var url = kind === 'ad'
          ? '/admin/lookup/ad-groups?q=' + encodeURIComponent(q)
          : '/admin/lookup/entra-groups?q=' + encodeURIComponent(q);
        fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json' } })
          .then(function (r) {
            if (r.status === 401) {
              renderError('Sign in to Entra to enable group search.');
              return null;
            }
            if (!r.ok) {
              return r.json().then(function (body) {
                renderError((body && body.message) || 'Lookup failed.');
                return null;
              }).catch(function () {
                renderError('Lookup failed (HTTP ' + r.status + ').');
                return null;
              });
            }
            return r.json();
          })
          .then(function (data) { if (data) renderResults(data); })
          .catch(function () { renderError('Lookup failed.'); });
      }, 250);
    });

    input.addEventListener('blur', function () {
      window.setTimeout(hideResults, 150);
    });
    input.addEventListener('focus', function () {
      if (input.value.trim().length >= 2) input.dispatchEvent(new Event('input'));
    });
    }

    if (manualAddBtn && manualInput) {
      function commitManual() {
        var raw = (manualInput.value || '').trim();
        if (manualError) { manualError.hidden = true; manualError.textContent = ''; }
        if (!raw) return;
        // Minimal DN sanity check: must contain at least one '=' and one ','.
        if (!/=/.test(raw) || !/,/.test(raw)) {
          if (manualError) {
            manualError.textContent = 'Enter a full distinguished name, e.g. CN=Group,OU=Groups,DC=example,DC=com';
            manualError.hidden = false;
          }
          return;
        }
        // Use the CN portion (before the first comma) as the chip label.
        var label = raw.replace(/^CN=/i, '').split(',')[0] || raw;
        addChip(raw, label);
        manualInput.value = '';
        manualInput.focus();
      }
      manualAddBtn.addEventListener('click', commitManual);
      manualInput.addEventListener('keydown', function (event) {
        if (event.key === 'Enter') {
          event.preventDefault();
          commitManual();
        }
      });
    }
  });

  // Theme palette preset buttons: clicking a preset fills the two color inputs
  // and marks the preset as active. The "Save" button persists the choice.
  var primaryInput = document.getElementById('brandingThemePrimary');
  var secondaryInput = document.getElementById('brandingThemeSecondary');
  var presets = document.querySelectorAll('#themePresets .theme-preset');
  function syncActivePreset() {
    if (!primaryInput || !secondaryInput) return;
    var p = (primaryInput.value || '').toLowerCase();
    var s = (secondaryInput.value || '').toLowerCase();
    presets.forEach(function (btn) {
      var match = btn.getAttribute('data-primary').toLowerCase() === p && btn.getAttribute('data-secondary').toLowerCase() === s;
      btn.classList.toggle('active', match);
    });
  }
  presets.forEach(function (btn) {
    btn.addEventListener('click', function () {
      if (!primaryInput || !secondaryInput) return;
      primaryInput.value = btn.getAttribute('data-primary');
      secondaryInput.value = btn.getAttribute('data-secondary');
      syncActivePreset();
    });
  });
  if (primaryInput) primaryInput.addEventListener('input', syncActivePreset);
  if (secondaryInput) secondaryInput.addEventListener('input', syncActivePreset);
  syncActivePreset();

  document.querySelectorAll('[data-import-textarea]').forEach(function (input) {
    input.addEventListener('change', function () {
      var file = input.files && input.files[0];
      if (!file) return;
      var targetId = input.getAttribute('data-import-textarea');
      var target = document.getElementById(targetId);
      if (!target) return;
      file.text().then(function (text) {
        target.value = text;
        target.dispatchEvent(new Event('input', { bubbles: true }));
      }).catch(function () {});
    });
  });

  document.querySelectorAll('[data-import-data-url]').forEach(function (input) {
    input.addEventListener('change', function () {
      var file = input.files && input.files[0];
      if (!file) return;
      var targetId = input.getAttribute('data-import-data-url');
      var previewId = input.getAttribute('data-preview-image');
      var target = document.getElementById(targetId);
      var preview = previewId ? document.getElementById(previewId) : null;
      var wrap = document.getElementById('brandingLogoPreviewWrap');
      var placeholder = document.getElementById('brandingLogoPlaceholder');
      var errorBox = document.getElementById('brandingLogoError');
      if (!target) return;

      function showError(message) {
        if (errorBox) {
          errorBox.textContent = message;
          errorBox.hidden = false;
        }
        // Reset the file input so the same oversized file can be re-picked
        // after compression without page reload.
        input.value = '';
      }
      function clearError() {
        if (errorBox) {
          errorBox.textContent = '';
          errorBox.hidden = true;
        }
      }

      // Match the server-side allow-list. The "accept" attribute is only a
      // hint; some browsers happily forward .bmp/.tiff anyway.
      var allowedTypes = [
        'image/png', 'image/jpeg', 'image/jpg', 'image/gif', 'image/webp', 'image/svg+xml'
      ];
      if (file.type && allowedTypes.indexOf(file.type.toLowerCase()) === -1) {
        showError('Unsupported file type "' + file.type + '". Choose a PNG, JPG, GIF, WebP, or SVG image.');
        return;
      }

      // Cap the raw file size at 1.5 MB. Base64 encoding inflates the payload
      // by ~33%, and the server rejects anything over 2 MB of encoded bytes.
      var maxRawBytes = 1_500_000;
      if (file.size > maxRawBytes) {
        var sizeMb = (file.size / (1024 * 1024)).toFixed(2);
        showError('Logo image is too large (' + sizeMb + ' MB). Choose a file under 1.5 MB or compress the image and try again.');
        return;
      }

      clearError();
      var reader = new FileReader();
      reader.onerror = function () {
        showError('Could not read the selected file. Please try again.');
      };
      reader.onload = function () {
        var result = typeof reader.result === 'string' ? reader.result : '';
        // Defensive secondary check on the encoded size.
        if (result.length > 2_000_000) {
          showError('Encoded logo exceeds the 2 MB limit. Compress the image and try again.');
          return;
        }
        target.value = result;
        target.dispatchEvent(new Event('input', { bubbles: true }));
        if (preview) {
          preview.src = result;
          preview.classList.remove('hidden');
        }
        if (placeholder) placeholder.classList.add('hidden');
        if (wrap) wrap.classList.remove('empty');
      };
      reader.readAsDataURL(file);
    });
  });

  var logoClear = document.getElementById('brandingLogoClear');
  if (logoClear) {
    logoClear.addEventListener('click', function () {
      var target = document.getElementById('brandingLogoDataUrl');
      var preview = document.getElementById('brandingLogoPreview');
      var wrap = document.getElementById('brandingLogoPreviewWrap');
      var placeholder = document.getElementById('brandingLogoPlaceholder');
      var input = document.getElementById('brandingLogoImport');
      var errorBox = document.getElementById('brandingLogoError');
      if (target) {
        target.value = '';
        target.dispatchEvent(new Event('input', { bubbles: true }));
      }
      if (preview) {
        preview.setAttribute('src', '');
        preview.classList.add('hidden');
      }
      if (placeholder) placeholder.classList.remove('hidden');
      if (wrap) wrap.classList.add('empty');
      if (input) input.value = '';
      if (errorBox) {
        errorBox.textContent = '';
        errorBox.hidden = true;
      }
    });
  }

  // ----- Health Status tab --------------------------------------------------
  // Fetches /admin/health and paints the four status cards plus the
  // performance metrics row. Auto-loads when the Health tab is activated; a
  // Refresh button re-runs the probes on demand.
  (function initHealthTab() {
    var refreshBtn = document.getElementById('healthRefresh');
    if (!refreshBtn) return;

    var statusLabels = {
      ok: 'OK',
      warn: 'Warning',
      fail: 'Failed',
      disabled: 'Disabled'
    };

    function setStatusBadge(key, status) {
      var badge = document.querySelector('[data-health-status="' + key + '"]');
      if (!badge) return;
      var cls = 'pending';
      if (status === 'ok') cls = 'ok';
      else if (status === 'fail') cls = 'fail';
      else if (status === 'warn') cls = 'pending';
      else if (status === 'disabled') cls = 'pending';
      badge.classList.remove('ok', 'fail', 'pending');
      badge.classList.add(cls);
      badge.textContent = statusLabels[status] || status || 'Unknown';
    }

    function setMessage(key, message) {
      var el = document.querySelector('[data-health-message="' + key + '"]');
      if (el) el.textContent = message || '';
    }

    function renderMeta(key, rows) {
      var dl = document.querySelector('[data-health-meta="' + key + '"]');
      if (!dl) return;
      dl.innerHTML = '';
      rows.forEach(function (row) {
        if (row.value === null || row.value === undefined || row.value === '') return;
        var dt = document.createElement('dt');
        dt.textContent = row.label;
        var dd = document.createElement('dd');
        dd.textContent = String(row.value);
        dl.appendChild(dt);
        dl.appendChild(dd);
      });
    }

    function setBusy(busy) {
      refreshBtn.disabled = !!busy;
      refreshBtn.textContent = busy ? 'Refreshing\u2026' : 'Refresh';
    }

    function renderError(message) {
      var box = document.getElementById('healthError');
      if (!box) return;
      if (!message) { box.hidden = true; box.textContent = ''; return; }
      box.hidden = false;
      box.textContent = message;
    }

    function fmtMs(value) {
      if (value === null || value === undefined) return null;
      return value + ' ms';
    }

    function fmtTimestamp(iso) {
      if (!iso) return null;
      try { return new Date(iso).toLocaleString(); } catch (e) { return iso; }
    }

    function paint(data) {
      // App
      setStatusBadge('app', data.app && data.app.status);
      setMessage('app', data.app && data.app.message);
      renderMeta('app', [
        { label: 'Uptime', value: data.app && (data.app.uptimeSeconds + ' s') },
        { label: 'Node', value: data.app && data.app.nodeVersion },
        { label: 'Platform', value: data.app && data.app.platform },
        { label: 'PID', value: data.app && data.app.pid },
        { label: 'Heap used', value: data.app && (data.app.heapUsedMb + ' MB') },
        { label: 'RSS', value: data.app && (data.app.rssMb + ' MB') },
        { label: 'Audit enabled', value: data.app && (data.app.auditEnabled ? 'yes' : 'no') }
      ]);

      // AD
      setStatusBadge('ad', data.ad && data.ad.status);
      setMessage('ad', data.ad && data.ad.message);
      renderMeta('ad', [
        { label: 'Enabled', value: data.ad && (data.ad.enabled ? 'yes' : 'no') },
        { label: 'LDAP URL', value: data.ad && data.ad.ldapUrl },
        { label: 'TLS validation', value: data.ad && data.ad.tlsRejectUnauthorized === false ? 'disabled (insecure)' : (data.ad && data.ad.enabled ? 'enabled' : null) },
        { label: 'Probe duration', value: fmtMs(data.ad && data.ad.durationMs) }
      ]);

      // Entra
      setStatusBadge('entra', data.entra && data.entra.status);
      setMessage('entra', data.entra && data.entra.message);
      renderMeta('entra', [
        { label: 'Enabled', value: data.entra && (data.entra.enabled ? 'yes' : 'no') },
        { label: 'Tenant ID', value: data.entra && data.entra.tenantId },
        { label: 'Admin signed-in token', value: data.entra && (data.entra.hasUserToken ? 'present' : 'not present') },
        { label: 'Member writes', value: data.entra && (data.entra.allowMemberWrites ? 'enabled' : 'disabled') },
        { label: 'Scope', value: data.entra && data.entra.scope },
        { label: 'Probe duration', value: fmtMs(data.entra && data.entra.durationMs) }
      ]);

      // Mail
      setStatusBadge('mail', data.mail && data.mail.status);
      setMessage('mail', data.mail && data.mail.message);
      renderMeta('mail', [
        { label: 'Enabled', value: data.mail && (data.mail.enabled ? 'yes' : 'no') },
        { label: 'Mode', value: data.mail && data.mail.mode },
        { label: 'From address', value: data.mail && data.mail.fromAddress },
        { label: 'SMTP host', value: data.mail && data.mail.smtpHost },
        { label: 'SMTP port', value: data.mail && data.mail.smtpPort },
        { label: 'SMTP auth required', value: data.mail && data.mail.smtpRequireAuth === undefined ? null : (data.mail.smtpRequireAuth ? 'yes' : 'no') },
        { label: 'Graph credentials', value: data.mail && data.mail.tenantConfigured === undefined ? null : (data.mail.tenantConfigured ? 'configured' : 'incomplete') }
      ]);

      // Metrics
      var metrics = data.metrics && data.metrics.groupList;
      if (metrics) {
        var status = metrics.count === 0 ? 'pending' : 'ok';
        setStatusBadge('metrics', status === 'pending' ? 'warn' : 'ok');
        setMessage('metrics', metrics.count === 0
          ? 'No samples yet. The first user to load /groups since startup will populate this.'
          : 'Aggregated over the last ' + metrics.count + ' render(s).');
        renderMeta('metrics', [
          { label: 'Samples', value: metrics.count },
          { label: 'Average', value: metrics.avgMs === null ? null : (metrics.avgMs + ' ms') },
          { label: 'p50 (median)', value: fmtMs(metrics.p50Ms) },
          { label: 'p95', value: fmtMs(metrics.p95Ms) },
          { label: 'Min', value: fmtMs(metrics.minMs) },
          { label: 'Max', value: fmtMs(metrics.maxMs) },
          { label: 'Last sample', value: fmtTimestamp(metrics.lastSampleAt) }
        ]);
      }

      var generated = document.getElementById('healthGenerated');
      if (generated) {
        generated.textContent = 'Last refreshed ' + fmtTimestamp(data.generatedAt) +
          ' (probe took ' + (data.generationDurationMs || 0) + ' ms).';
      }
    }

    function load() {
      renderError(null);
      setBusy(true);
      fetch('/admin/health', {
        method: 'GET',
        headers: { Accept: 'application/json' },
        credentials: 'same-origin'
      })
        .then(function (r) {
          if (!r.ok) throw new Error('HTTP ' + r.status);
          return r.json();
        })
        .then(paint)
        .catch(function (err) {
          renderError('Failed to load health snapshot: ' + (err && err.message ? err.message : err));
        })
        .then(function () { setBusy(false); });
    }

    refreshBtn.addEventListener('click', load);

    // Auto-load when the Health tab becomes active.
    var healthTabBtn = document.querySelector('.tabs [data-tab="health"]');
    if (healthTabBtn) {
      healthTabBtn.addEventListener('click', function () { load(); });
    }
    if (healthTabBtn && healthTabBtn.getAttribute('aria-selected') === 'true') {
      load();
    }
  })();
})();
