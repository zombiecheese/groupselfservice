(function () {
  var meta = document.querySelector('meta[name="csrf-token"]');
  var csrf = meta ? meta.getAttribute('content') : '';

  // ----- Generic confirm-on-submit (CSP-friendly replacement for inline
  // onsubmit handlers). Any <form data-confirm="..."> on this page now
  // shows a confirm() prompt before submitting, with no inline JS needed.
  document.addEventListener('submit', function (event) {
    var form = event.target;
    if (!form || form.nodeName !== 'FORM') return;
    var prompt = form.getAttribute('data-confirm');
    if (!prompt) return;
    if (!window.confirm(prompt)) {
      event.preventDefault();
    }
  });

  // ----- Sort & filter for the groups table ----------------------------------
  var groupsTable = document.getElementById('groupsTable');
  var filterInput = document.getElementById('groupsFilter');
  var sourceFilter = document.getElementById('groupsSourceFilter');
  var sortSelect = document.getElementById('groupsSort');
  var emptyState = document.getElementById('groupsEmptyState');
  var countEl = document.getElementById('groupsCount');

  if (groupsTable && filterInput && sourceFilter && sortSelect) {
    var tbody = groupsTable.tBodies[0];
    var allRows = Array.prototype.slice.call(tbody.querySelectorAll('[data-group-row]'));
    var totalRows = parseInt((countEl && countEl.getAttribute('data-total')) || allRows.length, 10);

    // ---- Favorites + recently-viewed ------------------------------------
    // Both lists persist per browser via localStorage. Favorites pin a group
    // to the top of the list regardless of the active sort; recently-viewed
    // is a 10-deep MRU updated whenever the user clicks Manage. Neither is
    // shared across browsers/devices — they're convenience, not state.
    var FAV_KEY = 'portal.groupsList.favorites.v1';
    var RECENT_KEY = 'portal.groupsList.recent.v1';
    var RECENT_MAX = 10;
    var favorites = new Set();
    var recents = [];
    try {
      var rawFav = localStorage.getItem(FAV_KEY);
      if (rawFav) {
        var parsedFav = JSON.parse(rawFav);
        if (Array.isArray(parsedFav)) favorites = new Set(parsedFav.filter(function (x) { return typeof x === 'string'; }));
      }
      var rawRec = localStorage.getItem(RECENT_KEY);
      if (rawRec) {
        var parsedRec = JSON.parse(rawRec);
        if (Array.isArray(parsedRec)) recents = parsedRec.filter(function (x) { return typeof x === 'string'; }).slice(0, RECENT_MAX);
      }
    } catch (e) { /* localStorage may be unavailable */ }

    function saveFavorites() {
      try { localStorage.setItem(FAV_KEY, JSON.stringify(Array.from(favorites))); } catch (e) { /* ignore */ }
    }
    function saveRecents() {
      try { localStorage.setItem(RECENT_KEY, JSON.stringify(recents)); } catch (e) { /* ignore */ }
    }
    function markRecent(dn) {
      if (!dn) return;
      recents = [dn].concat(recents.filter(function (x) { return x !== dn; })).slice(0, RECENT_MAX);
      saveRecents();
    }

    // Paint the favorite-button state on first render.
    allRows.forEach(function (row) {
      var dn = row.getAttribute('data-group-dn') || '';
      var btn = row.querySelector('[data-favorite-toggle]');
      if (!btn) return;
      var isFav = favorites.has(dn);
      btn.classList.toggle('is-favorite', isFav);
      btn.setAttribute('aria-pressed', isFav ? 'true' : 'false');
      var icon = btn.querySelector('.favorite-icon');
      if (icon) icon.innerHTML = isFav ? '&#9733;' : '&#9734;'; // ★ vs ☆
    });

    // Restore persisted preferences (per browser, not per server session).
    var PREF_KEY = 'portal.groupsList.prefs.v1';
    try {
      var raw = localStorage.getItem(PREF_KEY);
      if (raw) {
        var stored = JSON.parse(raw);
        if (stored && typeof stored === 'object') {
          if (typeof stored.q === 'string') filterInput.value = stored.q;
          if (typeof stored.source === 'string') sourceFilter.value = stored.source;
          if (typeof stored.sort === 'string') sortSelect.value = stored.sort;
        }
      }
    } catch (e) { /* localStorage may be unavailable in private mode */ }

    function savePrefs() {
      try {
        localStorage.setItem(PREF_KEY, JSON.stringify({
          q: filterInput.value || '',
          source: sourceFilter.value || 'all',
          sort: sortSelect.value || 'name-asc'
        }));
      } catch (e) { /* ignore quota / privacy errors */ }
    }

    function applyFilters() {
      var q = (filterInput.value || '').trim().toLowerCase();
      var src = sourceFilter.value;
      var visible = 0;
      allRows.forEach(function (row) {
        var name = row.getAttribute('data-name') || '';
        var description = row.getAttribute('data-description') || '';
        var rowSource = row.getAttribute('data-source') || '';
        var matchesQ = !q || name.indexOf(q) !== -1 || description.indexOf(q) !== -1;
        var matchesSrc = src === 'all' || rowSource === src;
        var show = matchesQ && matchesSrc;
        row.hidden = !show;
        if (show) visible++;
      });
      if (countEl) {
        countEl.textContent = visible === totalRows
          ? (totalRows + ' groups')
          : (visible + ' of ' + totalRows + ' groups');
      }
      if (emptyState) emptyState.hidden = visible !== 0;
    }

    function applySort() {
      var key = sortSelect.value;
      var sorted = allRows.slice();
      var ownerRank = { 'direct': 0, 'entra-owned': 1, 'nested': 2 };
      sorted.sort(function (a, b) {
        // Pinning rank: favorites first, then recently-viewed (capped at the
        // top 5 to avoid swamping the list), then the rest. Inside each rank
        // the active sort key applies. Recents stay in MRU order.
        var aDn = a.getAttribute('data-group-dn') || '';
        var bDn = b.getAttribute('data-group-dn') || '';
        var recentTop = recents.slice(0, 5);
        function rank(dn) {
          if (favorites.has(dn)) return 0;
          var idx = recentTop.indexOf(dn);
          if (idx !== -1) return 1;
          return 2;
        }
        var ar = rank(aDn);
        var br = rank(bDn);
        if (ar !== br) return ar - br;
        if (ar === 1 && br === 1) {
          // Within recents block keep MRU order.
          return recentTop.indexOf(aDn) - recentTop.indexOf(bDn);
        }
        if (key === 'name-asc' || key === 'name-desc') {
          var an = a.getAttribute('data-name') || '';
          var bn = b.getAttribute('data-name') || '';
          var cmp = an.localeCompare(bn);
          return key === 'name-desc' ? -cmp : cmp;
        }
        if (key === 'source') {
          var asrc = a.getAttribute('data-source') || '';
          var bsrc = b.getAttribute('data-source') || '';
          if (asrc !== bsrc) return asrc.localeCompare(bsrc);
          return (a.getAttribute('data-name') || '').localeCompare(b.getAttribute('data-name') || '');
        }
        if (key === 'ownership') {
          var ao = ownerRank[a.getAttribute('data-ownership')] || 99;
          var bo = ownerRank[b.getAttribute('data-ownership')] || 99;
          if (ao !== bo) return ao - bo;
          return (a.getAttribute('data-name') || '').localeCompare(b.getAttribute('data-name') || '');
        }
        if (key === 'type') {
          var atype = a.getAttribute('data-type') || '';
          var btype = b.getAttribute('data-type') || '';
          // Push rows with no type label to the bottom regardless of asc/desc.
          if (!atype && btype) return 1;
          if (atype && !btype) return -1;
          if (atype !== btype) return atype.localeCompare(btype);
          return (a.getAttribute('data-name') || '').localeCompare(b.getAttribute('data-name') || '');
        }
        return 0;
      });
      sorted.forEach(function (row) { tbody.appendChild(row); });
    }

    // Favorite toggle (per-row star button).
    tbody.addEventListener('click', function (e) {
      var btn = e.target.closest && e.target.closest('[data-favorite-toggle]');
      if (!btn) return;
      var row = btn.closest('[data-group-row]');
      if (!row) return;
      var dn = row.getAttribute('data-group-dn') || '';
      if (!dn) return;
      if (favorites.has(dn)) {
        favorites.delete(dn);
        btn.classList.remove('is-favorite');
        btn.setAttribute('aria-pressed', 'false');
      } else {
        favorites.add(dn);
        btn.classList.add('is-favorite');
        btn.setAttribute('aria-pressed', 'true');
      }
      var icon = btn.querySelector('.favorite-icon');
      if (icon) icon.innerHTML = favorites.has(dn) ? '&#9733;' : '&#9734;';
      saveFavorites();
      applySort();
      applyFilters();
    });

    filterInput.addEventListener('input', function () { applyFilters(); savePrefs(); });
    sourceFilter.addEventListener('change', function () { applyFilters(); savePrefs(); });
    sortSelect.addEventListener('change', function () {
      applySort();
      applyFilters();
      savePrefs();
    });
    applySort();
    applyFilters();

    // ---- Inline member counts ------------------------------------------
    // For each visible row, fetch the member count and paint it as a subtle
    // "N members" line under the group name. Uses the batched POST endpoint
    // so a 50-group page is one HTTP round-trip instead of 50. The server
    // caches each count for 60s anyway and enforces a per-batch upper
    // bound, so we chunk in case there are more visible rows than the
    // server allows in one call.
    var seenDns = new Set();
    var BATCH_SIZE = 50;

    function paintCount(dn, count) {
      var rows = allRows.filter(function (r) { return (r.getAttribute('data-group-dn') || '') === dn; });
      rows.forEach(function (row) {
        var slot = row.querySelector('[data-member-count]');
        if (!slot) return;
        if (typeof count === 'number') {
          slot.textContent = count === 1 ? '1 member' : (count + ' members');
        } else {
          slot.textContent = '';
        }
      });
    }

    function clearCount(dn) {
      var rows = allRows.filter(function (r) { return (r.getAttribute('data-group-dn') || '') === dn; });
      rows.forEach(function (row) {
        var slot = row.querySelector('[data-member-count]');
        if (slot) slot.textContent = '';
      });
    }

    function showPlaceholder(dns) {
      dns.forEach(function (dn) {
        var rows = allRows.filter(function (r) { return (r.getAttribute('data-group-dn') || '') === dn; });
        rows.forEach(function (row) {
          var slot = row.querySelector('[data-member-count]');
          if (slot && !slot.textContent) slot.textContent = '\u2026';
        });
      });
    }

    function fetchBatch(dns) {
      showPlaceholder(dns);
      return fetch('/groups/members/counts', {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'X-CSRF-Token': csrf
        },
        body: JSON.stringify({ _csrf: csrf, groupDns: dns })
      }).then(function (r) {
        if (!r.ok) throw new Error('count batch failed: ' + r.status);
        return r.json();
      }).then(function (j) {
        var results = (j && j.results) || [];
        results.forEach(function (entry) {
          if (typeof entry.count === 'number') {
            paintCount(entry.groupDn, entry.count);
          } else {
            clearCount(entry.groupDn);
          }
        });
      }).catch(function () {
        dns.forEach(clearCount);
      });
    }

    function enqueueVisible() {
      var dns = [];
      allRows.forEach(function (row) {
        if (row.hidden) return;
        var dn = row.getAttribute('data-group-dn') || '';
        if (!dn || seenDns.has(dn)) return;
        seenDns.add(dn);
        dns.push(dn);
      });
      while (dns.length > 0) {
        fetchBatch(dns.splice(0, BATCH_SIZE));
      }
    }
    setTimeout(enqueueVisible, 0);
  }

  // ----- Member-management modal --------------------------------------------
  var modal = document.querySelector('[data-group-modal]');
  if (!modal) return;

  var titleEl = modal.querySelector('#groupModalTitle');
  var subtitleEl = modal.querySelector('[data-modal-subtitle]');
  var statusEl = modal.querySelector('[data-modal-status]');
  var searchInput = modal.querySelector('[data-modal-search]');
  var searchResultsEl = modal.querySelector('[data-modal-search-results]');
  var memberListEl = modal.querySelector('[data-modal-member-list]');
  var memberCountEl = modal.querySelector('[data-modal-count]');
  var memberFilterEl = modal.querySelector('[data-modal-member-filter]');

  var currentGroupDn = null;
  var currentGroupSource = 'ad';
  var currentMemberRefs = new Set();
  var allMembersCache = [];
  var memberFilterValue = '';
  var previouslyFocused = null;
  var searchTimer = null;

  function toast(message, kind) {
    if (window.Portal && window.Portal.toast) {
      window.Portal.toast(message, kind);
    }
  }

  function escapeHtml(str) {
    return String(str == null ? '' : str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function setStatus(kind, message) {
    if (!statusEl) return;
    if (!message) {
      statusEl.hidden = true;
      statusEl.textContent = '';
      statusEl.classList.remove('ok', 'fail');
      return;
    }
    statusEl.hidden = false;
    statusEl.classList.remove('ok', 'fail');
    statusEl.classList.add(kind);
    statusEl.textContent = message;
  }

  function postForm(url, payload) {
    var body = new URLSearchParams();
    body.set('_csrf', csrf);
    Object.keys(payload).forEach(function (k) {
      var v = payload[k];
      if (v === undefined || v === null) return;
      body.set(k, String(v));
    });
    return fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
        'X-Requested-With': 'XMLHttpRequest'
      },
      body: body,
      credentials: 'same-origin'
    }).then(function (r) {
      return r.json().then(function (json) {
        return { status: r.status, json: json };
      });
    });
  }

  function getJson(url) {
    return fetch(url, {
      method: 'GET',
      headers: { Accept: 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      credentials: 'same-origin'
    }).then(function (r) {
      return r.json().then(function (json) { return { status: r.status, json: json }; });
    });
  }

  function memberKey(m) {
    // Server returns an AdUser (has dn) or a DirectoryMember (has ref).
    return (m && (m.ref || m.dn)) || '';
  }

  function highlightMatch(text, needle) {
    if (!needle) return escapeHtml(text);
    var lowerText = String(text).toLowerCase();
    var lowerNeedle = needle.toLowerCase();
    var idx = lowerText.indexOf(lowerNeedle);
    if (idx === -1) return escapeHtml(text);
    var before = String(text).slice(0, idx);
    var hit = String(text).slice(idx, idx + needle.length);
    var after = String(text).slice(idx + needle.length);
    return escapeHtml(before) + '<mark>' + escapeHtml(hit) + '</mark>' + escapeHtml(after);
  }

  function renderMembers(members) {
    allMembersCache = members ? members.slice() : [];
    currentMemberRefs = new Set();
    if (memberFilterEl) {
      memberFilterEl.hidden = !allMembersCache.length;
    }
    if (!allMembersCache.length) {
      memberListEl.innerHTML = '<li class="subtle empty">No members in this group yet.</li>';
      if (memberCountEl) memberCountEl.textContent = '(0)';
      return;
    }
    allMembersCache.forEach(function (m) {
      var key = memberKey(m);
      if (key) currentMemberRefs.add(key);
    });
    paintMemberList();
  }

  function paintMemberList() {
    if (!memberListEl) return;
    var needle = (memberFilterValue || '').trim().toLowerCase();
    var visible = needle
      ? allMembersCache.filter(function (m) {
          return (m.displayName || '').toLowerCase().indexOf(needle) !== -1
              || (m.samAccountName || '').toLowerCase().indexOf(needle) !== -1
              || (m.userPrincipalName || '').toLowerCase().indexOf(needle) !== -1
              || (m.mail || '').toLowerCase().indexOf(needle) !== -1;
        })
      : allMembersCache;
    if (memberCountEl) {
      memberCountEl.textContent = needle
        ? '(' + visible.length + ' of ' + allMembersCache.length + ')'
        : '(' + allMembersCache.length + ')';
    }
    if (!visible.length) {
      memberListEl.innerHTML = '<li class="subtle empty">No members match your filter.</li>';
      return;
    }
    var rows = visible.map(function (m) {
      var label = m.displayName || m.samAccountName || m.userPrincipalName || memberKey(m);
      var sub = m.userPrincipalName || m.samAccountName || m.mail || '';
      var ref = memberKey(m);
      return '<li data-member-row data-member-dn="' + escapeHtml(ref) + '">' +
        '<div class="principal-info">' +
        '<strong>' + highlightMatch(label, needle) + '</strong>' +
        (sub ? '<span>' + highlightMatch(sub, needle) + '</span>' : '') +
        '</div>' +
        '<button type="button" class="remove-btn" data-remove-member data-member-label="' + escapeHtml(label) + '" aria-label="Remove ' + escapeHtml(label) + '">&times;</button>' +
        '</li>';
    });
    memberListEl.innerHTML = rows.join('');
  }

  function loadMembers() {
    if (!currentGroupDn) return;
    memberListEl.innerHTML = '<li class="subtle loading"><span class="spinner" aria-hidden="true"></span>Loading members…</li>';
    if (memberCountEl) memberCountEl.textContent = '';
    if (memberFilterEl) memberFilterEl.hidden = true;
    getJson('/groups/members/list?groupDn=' + encodeURIComponent(currentGroupDn))
      .then(function (resp) {
        if (resp.status >= 200 && resp.status < 300 && resp.json && resp.json.ok) {
          renderMembers(resp.json.members || []);
        } else {
          memberListEl.innerHTML = '<li class="subtle">Failed to load members.</li>';
          toast((resp.json && resp.json.message) || 'Failed to load members.', 'error');
        }
      })
      .catch(function (err) {
        memberListEl.innerHTML = '<li class="subtle">Failed to load members.</li>';
        toast('Failed to load members: ' + (err && err.message ? err.message : err), 'error');
      });
  }

  function renderSearchResults(results, query) {
    if (!results || results.length === 0) {
      searchResultsEl.innerHTML = '';
      return;
    }
    var needle = (query || '').trim();
    var rows = results.map(function (m) {
      var ref = memberKey(m);
      var alreadyMember = currentMemberRefs.has(ref);
      var label = m.displayName || m.samAccountName || m.userPrincipalName || ref;
      var sub = m.userPrincipalName || m.samAccountName || m.mail || '';
      return '<li>' +
        '<div class="principal-info">' +
        '<strong>' + highlightMatch(label, needle) + '</strong>' +
        (sub ? '<span>' + highlightMatch(sub, needle) + '</span>' : '') +
        '</div>' +
        (alreadyMember
          ? '<span class="subtle">Already a member</span>'
          : '<button type="button" data-add-member data-member-dn="' + escapeHtml(ref) + '" data-member-label="' + escapeHtml(label) + '">Add</button>') +
        '</li>';
    });
    searchResultsEl.innerHTML = rows.join('');
  }

  function runSearch(q) {
    if (!q || q.length < 2) {
      searchResultsEl.innerHTML = '';
      return;
    }
    var url = '/groups/search?q=' + encodeURIComponent(q) +
      '&source=' + encodeURIComponent(currentGroupSource) +
      '&groupDn=' + encodeURIComponent(currentGroupDn || '');
    getJson(url)
      .then(function (resp) {
        if (resp.status >= 200 && resp.status < 300) {
          renderSearchResults(Array.isArray(resp.json) ? resp.json : [], q);
        }
      })
      .catch(function () { /* ignore transient search errors */ });
  }

  function openModal(groupDn, groupName, groupSource) {
    currentGroupDn = groupDn;
    currentGroupSource = groupSource === 'entra' ? 'entra' : 'ad';
    memberFilterValue = '';
    if (memberFilterEl) {
      memberFilterEl.value = '';
      memberFilterEl.hidden = true;
    }
    setStatus(null);
    if (titleEl) {
      var sourceLabel = currentGroupSource === 'entra' ? ' (Entra ID)' : '';
      titleEl.textContent = 'Manage members' + sourceLabel + ' \u2014 ' + (groupName || '');
    }
    if (subtitleEl) subtitleEl.textContent = groupDn;
    if (searchInput) {
      searchInput.value = '';
      searchInput.placeholder = currentGroupSource === 'entra'
        ? 'Search Entra users by name, UPN, or email'
        : 'Search by name, UPN, or sAMAccountName';
    }
    if (searchResultsEl) searchResultsEl.innerHTML = '';
    previouslyFocused = document.activeElement;
    modal.hidden = false;
    document.body.style.overflow = 'hidden';
    loadMembers();
    if (searchInput) {
      try { searchInput.focus(); } catch (e) { /* no-op */ }
    }
  }

  function closeModal() {
    modal.hidden = true;
    document.body.style.overflow = '';
    currentGroupDn = null;
    currentGroupSource = 'ad';
    currentMemberRefs = new Set();
    allMembersCache = [];
    memberFilterValue = '';
    if (memberFilterEl) {
      memberFilterEl.value = '';
      memberFilterEl.hidden = true;
    }
    if (searchResultsEl) searchResultsEl.innerHTML = '';
    setStatus(null);
    // Return keyboard focus to the element that opened the modal.
    if (previouslyFocused && typeof previouslyFocused.focus === 'function') {
      try { previouslyFocused.focus(); } catch (e) { /* no-op */ }
    }
    previouslyFocused = null;
  }

  // Wire open buttons
  document.querySelectorAll('[data-manage-group]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      // Bump this group to the top of the recently-viewed list (capped at
      // 10). Shared key with the favorites/sort block above; safe to write
      // even when localStorage is unavailable.
      try {
        var key = 'portal.groupsList.recent.v1';
        var dn = btn.getAttribute('data-group-dn') || '';
        if (dn) {
          var existing = [];
          try {
            var raw = localStorage.getItem(key);
            if (raw) {
              var parsed = JSON.parse(raw);
              if (Array.isArray(parsed)) existing = parsed.filter(function (x) { return typeof x === 'string'; });
            }
          } catch (e) { /* ignore */ }
          var next = [dn].concat(existing.filter(function (x) { return x !== dn; })).slice(0, 10);
          localStorage.setItem(key, JSON.stringify(next));
        }
      } catch (e) { /* ignore quota / privacy errors */ }
      openModal(
        btn.getAttribute('data-group-dn'),
        btn.getAttribute('data-group-name'),
        btn.getAttribute('data-group-source')
      );
    });
  });

  // Close handlers
  modal.addEventListener('click', function (e) {
    if (e.target === modal) closeModal();
    var closer = e.target.closest && e.target.closest('[data-modal-close]');
    if (closer) closeModal();
  });
  document.addEventListener('keydown', function (e) {
    if (modal.hidden) return;
    if (e.key === 'Escape') { closeModal(); return; }
    // Focus trap: keep Tab/Shift+Tab inside the modal card while it is open.
    if (e.key === 'Tab') {
      var modalCard = modal.querySelector('.modal-card') || modal;
      var focusables = modalCard.querySelectorAll(
        'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
      );
      if (!focusables.length) return;
      var first = focusables[0];
      var last = focusables[focusables.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        try { last.focus(); } catch (err) { /* no-op */ }
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        try { first.focus(); } catch (err) { /* no-op */ }
      }
    }
  });

  // Search debounce
  if (searchInput) {
    searchInput.addEventListener('input', function () {
      var q = searchInput.value.trim();
      if (searchTimer) clearTimeout(searchTimer);
      searchTimer = setTimeout(function () { runSearch(q); }, 250);
    });
  }

  // Member list â€” remove
  memberListEl.addEventListener('click', function (e) {
    var btn = e.target.closest && e.target.closest('[data-remove-member]');
    if (!btn) return;
    var row = btn.closest('[data-member-row]');
    if (!row || !currentGroupDn) return;
    var memberDn = row.getAttribute('data-member-dn');
    btn.disabled = true;
    setStatus(null);
    postForm('/groups/members/remove', { groupDn: currentGroupDn, memberDn: memberDn })
      .then(function (resp) {
        if (resp.status >= 200 && resp.status < 300 && resp.json && resp.json.ok) {
          setStatus('ok', 'Removed member.');
          loadMembers();
        } else {
          btn.disabled = false;
          setStatus('fail', (resp.json && resp.json.message) || 'Failed to remove member.');
        }
      })
      .catch(function (err) {
        btn.disabled = false;
        setStatus('fail', 'Failed to remove member: ' + (err && err.message ? err.message : err));
      });
  });

  // Search results â€” add
  searchResultsEl.addEventListener('click', function (e) {
    var btn = e.target.closest && e.target.closest('[data-add-member]');
    if (!btn || !currentGroupDn) return;
    var memberDn = btn.getAttribute('data-member-dn');
    btn.disabled = true;
    setStatus(null);
    postForm('/groups/members/add', { groupDn: currentGroupDn, memberDn: memberDn })
      .then(function (resp) {
        if (resp.status >= 200 && resp.status < 300 && resp.json && resp.json.ok) {
          setStatus('ok', 'Added member.');
          loadMembers();
          // Refresh search to update "Already a member" tags
          if (searchInput) runSearch(searchInput.value.trim());
        } else {
          btn.disabled = false;
          setStatus('fail', (resp.json && resp.json.message) || 'Failed to add member.');
        }
      })
      .catch(function (err) {
        btn.disabled = false;
        setStatus('fail', 'Failed to add member: ' + (err && err.message ? err.message : err));
      });
  });
})();
