(function () {
  'use strict';

  var API_BASE = 'https://appsecsanta.com';

  var form = document.getElementById('scan-form');
  var input = document.getElementById('domain-input');
  var btn = document.getElementById('scan-btn');
  var formError = document.getElementById('form-error');
  var formWrapper = document.getElementById('scan-form-wrapper');
  var resultsSection = document.getElementById('results-section');
  var heroSection = document.getElementById('hero-section');

  var lastScanTime = 0;
  var COOLDOWN_MS = 3000;

  // Save original form children as a DocumentFragment for safe restore
  var savedFormNodes = document.createDocumentFragment();
  if (formWrapper) {
    Array.prototype.slice.call(formWrapper.childNodes).forEach(function (node) {
      savedFormNodes.appendChild(node.cloneNode(true));
    });
  }

  var lastScannedDomain = '';
  var lastScanData = null;

  // -- Sort state --
  var currentSort = { key: 'name', dir: 'asc' };

  // -- DOM helper: create element with classes, text, and styles --
  function el(tag, opts) {
    var node = document.createElement(tag);
    if (opts) {
      if (opts.className) node.className = opts.className;
      if (opts.text) node.textContent = opts.text;
      if (opts.style) {
        Object.keys(opts.style).forEach(function (k) {
          node.style[k] = opts.style[k];
        });
      }
      if (opts.attrs) {
        Object.keys(opts.attrs).forEach(function (k) {
          node.setAttribute(k, opts.attrs[k]);
        });
      }
    }
    return node;
  }

  function showError(msg) {
    formError = document.getElementById('form-error');
    if (formError) {
      formError.textContent = msg;
      formError.classList.remove('hidden');
    }
  }

  function hideError() {
    formError = document.getElementById('form-error');
    if (formError) {
      formError.classList.add('hidden');
    }
  }

  function setLoading(on) {
    if (on) {
      // Save current form children
      savedFormNodes = document.createDocumentFragment();
      Array.prototype.slice.call(formWrapper.childNodes).forEach(function (node) {
        savedFormNodes.appendChild(node.cloneNode(true));
      });

      // Build loading spinner using DOM API
      while (formWrapper.firstChild) formWrapper.removeChild(formWrapper.firstChild);
      var wrapper = el('div', { className: 'flex flex-col items-center py-4' });
      var spinner = el('div', {
        className: 'inline-block w-12 h-12 border-4 border-border border-t-brand-red rounded-full',
        style: { animation: 'spin 0.8s linear infinite' }
      });
      var msg = el('p', {
        className: 'mt-4 text-text-secondary text-lg',
        text: 'Scanning Certificate Transparency logs...'
      });
      wrapper.appendChild(spinner);
      wrapper.appendChild(msg);
      formWrapper.appendChild(wrapper);
      resultsSection.classList.add('hidden');
    } else {
      // Restore saved form children
      while (formWrapper.firstChild) formWrapper.removeChild(formWrapper.firstChild);
      formWrapper.appendChild(savedFormNodes.cloneNode(true));
      form = document.getElementById('scan-form');
      input = document.getElementById('domain-input');
      btn = document.getElementById('scan-btn');
      formError = document.getElementById('form-error');
      bindFormEvents();
    }
  }

  // -- Scan History (localStorage) --
  var HISTORY_KEY = 'subdomainScanHistory';
  var MAX_HISTORY = 50;

  function getHistory() {
    try {
      return JSON.parse(localStorage.getItem(HISTORY_KEY)) || [];
    } catch (e) {
      return [];
    }
  }

  function saveToHistory(domain, count) {
    var history = getHistory();
    history.push({ domain: domain, count: count, timestamp: Date.now() });
    if (history.length > MAX_HISTORY) {
      history = history.slice(history.length - MAX_HISTORY);
    }
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    } catch (e) { /* storage full */ }
  }

  // -- Tabs --
  function initTabs() {
    var tabs = document.querySelectorAll('.result-tab');
    tabs.forEach(function (tab) {
      tab.addEventListener('click', function () {
        var target = tab.getAttribute('data-tab');
        tabs.forEach(function (t) {
          t.classList.remove('border-brand-red', 'text-brand-red', 'font-semibold');
          t.classList.add('border-transparent', 'text-text-muted', 'font-medium');
          t.setAttribute('aria-selected', 'false');
        });
        tab.classList.add('border-brand-red', 'text-brand-red', 'font-semibold');
        tab.classList.remove('border-transparent', 'text-text-muted', 'font-medium');
        tab.setAttribute('aria-selected', 'true');
        document.querySelectorAll('.tab-panel').forEach(function (p) {
          p.classList.add('hidden');
          p.setAttribute('aria-hidden', 'true');
        });
        var panel = document.getElementById('tab-' + target);
        if (panel) {
          panel.classList.remove('hidden');
          panel.setAttribute('aria-hidden', 'false');
        }
      });
    });
  }
  initTabs();

  // -- Sorting --
  function sortSubdomains(subdomains, key, dir) {
    var sorted = subdomains.slice();
    sorted.sort(function (a, b) {
      var valA, valB;
      if (key === 'certCount') {
        valA = a.certCount;
        valB = b.certCount;
      } else if (key === 'firstSeen') {
        valA = a.firstSeen || '';
        valB = b.firstSeen || '';
      } else if (key === 'lastSeen') {
        valA = a.lastSeen || '';
        valB = b.lastSeen || '';
      } else {
        valA = a.name;
        valB = b.name;
      }
      var cmp;
      if (typeof valA === 'number') {
        cmp = valA - valB;
      } else {
        cmp = valA.localeCompare(valB);
      }
      return dir === 'desc' ? -cmp : cmp;
    });
    return sorted;
  }

  function updateSortArrows() {
    var headers = document.querySelectorAll('#subdomain-table th[data-sort]');
    headers.forEach(function (th) {
      var arrow = th.querySelector('.sort-arrow');
      if (!arrow) return;
      var key = th.getAttribute('data-sort');
      if (key === currentSort.key) {
        arrow.textContent = currentSort.dir === 'asc' ? ' \u25B2' : ' \u25BC';
      } else {
        arrow.textContent = '';
      }
    });
  }

  // -- Render subdomain table using DOM API --
  function renderSubdomainTable(subdomains, filter) {
    var tbody = document.getElementById('subdomain-tbody');
    var noResults = document.getElementById('no-results-msg');
    if (!tbody) return;

    var filtered = subdomains;
    if (filter) {
      var q = filter.toLowerCase();
      filtered = subdomains.filter(function (s) {
        return s.name.toLowerCase().indexOf(q) !== -1;
      });
    }

    var sorted = sortSubdomains(filtered, currentSort.key, currentSort.dir);

    // Clear existing rows
    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);

    if (sorted.length === 0) {
      if (noResults) noResults.classList.remove('hidden');
      return;
    }

    if (noResults) noResults.classList.add('hidden');

    var fragment = document.createDocumentFragment();
    for (var i = 0; i < sorted.length; i++) {
      var sub = sorted[i];
      var tr = el('tr', { className: 'border-b border-border/50 hover:bg-surface-light/50 transition-colors' });

      var tdName = el('td', { className: 'py-2.5 px-4 font-mono text-sm', text: sub.name });
      var tdFirst = el('td', { className: 'py-2.5 px-4 text-text-secondary text-sm', text: sub.firstSeen || '\u2014' });
      var tdLast = el('td', { className: 'py-2.5 px-4 text-text-secondary text-sm', text: sub.lastSeen || '\u2014' });
      var tdCerts = el('td', { className: 'py-2.5 px-4 text-center text-sm font-medium', text: String(sub.certCount) });

      tr.appendChild(tdName);
      tr.appendChild(tdFirst);
      tr.appendChild(tdLast);
      tr.appendChild(tdCerts);
      fragment.appendChild(tr);
    }
    tbody.appendChild(fragment);
    updateSortArrows();
  }

  // -- Statistics tab using DOM API --
  function renderStatistics(data) {
    var container = document.getElementById('stats-content');
    if (!container) return;

    var subs = data.subdomains;
    var summary = data.summary;

    // Count depth levels
    var depthMap = {};
    for (var i = 0; i < subs.length; i++) {
      var parts = subs[i].name.split('.');
      var depth = parts.length - data.domain.split('.').length;
      var label = depth <= 0 ? 'Root domain' : depth === 1 ? '1 level deep' : depth + ' levels deep';
      depthMap[label] = (depthMap[label] || 0) + 1;
    }

    // Clear container
    while (container.firstChild) container.removeChild(container.firstChild);

    // Helper to build a stat card
    function buildStatCard(title, value, isLarge) {
      var card = el('div', { className: 'bg-surface-light rounded-xl border border-border p-5' });
      card.appendChild(el('div', {
        className: 'text-xs font-semibold text-text-muted uppercase tracking-wider mb-2',
        text: title
      }));
      card.appendChild(el('div', {
        className: (isLarge ? 'text-lg' : 'text-2xl') + ' font-bold text-text-primary',
        text: String(value)
      }));
      return card;
    }

    // Summary cards grid
    var grid = el('div', { className: 'grid sm:grid-cols-2 lg:grid-cols-4 gap-5 mb-6' });
    grid.appendChild(buildStatCard('Unique Subdomains', summary.uniqueCount, false));
    grid.appendChild(buildStatCard('Certificates Analyzed', summary.totalCertificates, false));
    grid.appendChild(buildStatCard('Earliest Certificate', summary.dateRange.earliest || '\u2014', true));
    grid.appendChild(buildStatCard('Latest Certificate', summary.dateRange.latest || '\u2014', true));
    container.appendChild(grid);

    // Depth breakdown
    var depthBox = el('div', { className: 'bg-surface-light rounded-xl border border-border p-5 mb-6' });
    depthBox.appendChild(el('div', {
      className: 'text-xs font-semibold text-text-muted uppercase tracking-wider mb-3',
      text: 'Subdomain Depth Breakdown'
    }));
    var depthList = el('div', { className: 'space-y-2' });
    var depthKeys = Object.keys(depthMap).sort();
    for (var j = 0; j < depthKeys.length; j++) {
      var k = depthKeys[j];
      var count = depthMap[k];
      var pct = summary.uniqueCount > 0 ? Math.round((count / summary.uniqueCount) * 100) : 0;

      var row = el('div', { className: 'flex items-center gap-3' });
      row.appendChild(el('span', {
        className: 'text-sm font-medium text-text-primary w-32 shrink-0',
        text: k
      }));

      var barOuter = el('div', { className: 'flex-1 bg-white rounded-full h-5 border border-border overflow-hidden' });
      var barInner = el('div', {
        className: 'h-full rounded-full',
        style: { width: Math.max(pct, 2) + '%', background: '#c41926' }
      });
      barOuter.appendChild(barInner);
      row.appendChild(barOuter);

      row.appendChild(el('span', {
        className: 'text-sm font-medium text-text-muted w-16 text-right',
        text: count + ' (' + pct + '%)'
      }));
      depthList.appendChild(row);
    }
    depthBox.appendChild(depthList);
    container.appendChild(depthBox);

    // Top subdomains by cert count
    if (subs.length > 0) {
      var byCerts = subs.slice().sort(function (a, b) { return b.certCount - a.certCount; });
      var top = byCerts.slice(0, 10);

      var topBox = el('div', { className: 'bg-surface-light rounded-xl border border-border p-5' });
      topBox.appendChild(el('div', {
        className: 'text-xs font-semibold text-text-muted uppercase tracking-wider mb-3',
        text: 'Most Certificates (Top 10)'
      }));
      var topList = el('div', { className: 'space-y-1.5' });
      for (var m = 0; m < top.length; m++) {
        var item = el('div', { className: 'flex items-center justify-between py-1.5 px-3 bg-white rounded-lg border border-border' });
        item.appendChild(el('span', {
          className: 'font-mono text-sm text-text-primary',
          text: top[m].name
        }));
        item.appendChild(el('span', {
          className: 'text-sm font-semibold text-text-muted',
          text: top[m].certCount + ' certs'
        }));
        topList.appendChild(item);
      }
      topBox.appendChild(topList);
      container.appendChild(topBox);
    }
  }

  // -- Copy all subdomains --
  function copyAllSubdomains() {
    if (!lastScanData || !lastScanData.subdomains) return;
    var text = lastScanData.subdomains.map(function (s) { return s.name; }).join('\n');
    navigator.clipboard.writeText(text).then(function () {
      var copyBtnEl = document.getElementById('copy-btn');
      if (copyBtnEl) {
        copyBtnEl.textContent = 'Copied!';
        setTimeout(function () { copyBtnEl.textContent = 'Copy All'; }, 2000);
      }
    }).catch(function () {
      var copyBtnEl = document.getElementById('copy-btn');
      if (copyBtnEl) {
        copyBtnEl.textContent = 'Failed';
        setTimeout(function () { copyBtnEl.textContent = 'Copy All'; }, 2000);
      }
    });
  }

  // -- Export CSV --
  function exportCSV() {
    if (!lastScanData || !lastScanData.subdomains) return;
    var lines = ['subdomain,first_seen,last_seen,cert_count'];
    for (var i = 0; i < lastScanData.subdomains.length; i++) {
      var s = lastScanData.subdomains[i];
      lines.push('"' + s.name.replace(/"/g, '""') + '","' + (s.firstSeen || '').replace(/"/g, '""') + '","' + (s.lastSeen || '').replace(/"/g, '""') + '",' + s.certCount);
    }
    var csv = lines.join('\n');
    var blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = lastScanData.domain + '-subdomains.csv';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // -- Render results --
  function renderResults(data) {
    lastScanData = data;
    lastScannedDomain = data.domain || '';

    // Domain display
    var hostEl = document.getElementById('scanned-host');
    if (hostEl) hostEl.textContent = data.domain;

    // Count badge
    var countNum = document.getElementById('count-number');
    if (countNum) countNum.textContent = data.summary.uniqueCount;

    // Metadata
    var subCount = document.getElementById('subdomain-count');
    if (subCount) subCount.textContent = data.summary.uniqueCount;

    var certCount = document.getElementById('cert-count');
    if (certCount) certCount.textContent = data.summary.totalCertificates;

    var dateRange = document.getElementById('date-range');
    if (dateRange) {
      if (data.summary.dateRange.earliest && data.summary.dateRange.latest) {
        dateRange.textContent = data.summary.dateRange.earliest + ' to ' + data.summary.dateRange.latest;
      } else {
        dateRange.textContent = '\u2014';
      }
    }

    // Color the badge based on count
    var badge = document.getElementById('count-badge');
    if (badge) {
      if (data.summary.uniqueCount === 0) {
        badge.style.background = 'rgb(254,226,226)';
        badge.style.borderColor = 'rgb(239,68,68)';
        countNum.style.color = 'rgb(153,27,27)';
      } else if (data.summary.uniqueCount <= 10) {
        badge.style.background = 'rgb(220,252,231)';
        badge.style.borderColor = 'rgb(22,163,74)';
        countNum.style.color = 'rgb(21,128,61)';
      } else if (data.summary.uniqueCount <= 50) {
        badge.style.background = 'rgb(217,249,195)';
        badge.style.borderColor = 'rgb(132,204,22)';
        countNum.style.color = 'rgb(63,98,18)';
      } else {
        badge.style.background = 'rgb(254,249,195)';
        badge.style.borderColor = 'rgb(234,179,8)';
        countNum.style.color = 'rgb(161,98,7)';
      }
    }

    // Render subdomain table
    currentSort = { key: 'name', dir: 'asc' };
    renderSubdomainTable(data.subdomains, '');

    // Render statistics
    renderStatistics(data);

    // Show results, hide hero + features
    heroSection.classList.add('hidden');
    var featuresSection = document.getElementById('features-section');
    if (featuresSection) featuresSection.classList.add('hidden');
    resultsSection.classList.remove('hidden');

    // Reset to Subdomains tab
    var firstTab = document.querySelector('.result-tab[data-tab="subdomains"]');
    if (firstTab) firstTab.click();

    // Save to history
    saveToHistory(data.domain, data.summary.uniqueCount);

    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function extractDomain(val) {
    var raw = val.trim().toLowerCase();
    raw = raw.replace(/^https?:\/\//, '');
    raw = raw.replace(/\/.*$/, '');
    raw = raw.replace(/:\d+$/, '');
    return raw;
  }

  function isValidDomain(domain) {
    if (!domain || domain.indexOf('.') === -1) return false;
    return /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/.test(domain);
  }

  function doScan(domainInput) {
    hideError();

    if (!domainInput) {
      showError('Please enter a domain.');
      return;
    }

    var domain = extractDomain(domainInput);

    if (!isValidDomain(domain)) {
      showError('Invalid domain. Enter a domain like example.com.');
      return;
    }

    var now = Date.now();
    if (now - lastScanTime < COOLDOWN_MS) {
      showError('Please wait a few seconds before scanning again.');
      return;
    }

    try {
      history.pushState(null, '', '?domain=' + encodeURIComponent(domain));
    } catch (e) { /* ignore */ }

    setLoading(true);
    lastScanTime = now;

    // Fetch challenge token, then query subdomains
    fetch(API_BASE + '/api/token')
    .then(function (tokenRes) {
      if (!tokenRes.ok) {
        throw new Error('token_failed');
      }
      return tokenRes.json();
    })
    .then(function (tokenData) {
      return fetch(API_BASE + '/api/subdomain-finder', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domain, token: tokenData.token })
      });
    })
    .then(function (res) {
      if (res.status === 403) {
        setLoading(false);
        showError('Access denied. This demo requires the AppSec Santa API to be available.');
        return null;
      }
      if (res.status === 429) {
        setLoading(false);
        showError('Too many scans. Please wait a while before scanning again.');
        return null;
      }
      if (!res.ok && res.status !== 400 && res.status !== 500 && res.status !== 502) {
        throw new Error('Server returned ' + res.status);
      }
      return res.text().then(function (text) {
        try {
          var json = JSON.parse(text);
          return { status: res.status, data: json };
        } catch (e) {
          if (res.status === 502) {
            return { status: 400, data: { error: 'This domain has too many certificates to process. Try scanning a more specific subdomain.' } };
          }
          throw new Error('Invalid response from server. Status: ' + res.status);
        }
      });
    })
    .then(function (result) {
      if (!result) return;
      setLoading(false);

      if (result.status !== 200) {
        showError(result.data.error || 'Something went wrong. Please try again.');
        return;
      }

      try {
        renderResults(result.data);
      } catch (renderErr) {
        console.error('Render error:', renderErr);
        showError('Failed to display results. Please try again.');
      }
    })
    .catch(function (err) {
      setLoading(false);
      console.error('Scan error:', err);
      var msg = (err && err.message) || '';
      if (msg === 'token_failed') {
        showError('Could not authenticate. The API may not allow cross-origin requests from this demo.');
      } else {
        showError('Network error. Please check your connection and try again.');
      }
    });
  }

  function handleSubmit(e) {
    e.preventDefault();
    input = document.getElementById('domain-input');
    var val = input ? input.value.trim() : '';
    doScan(val);
  }

  function handleKeydown(e) {
    if (e.key === 'Enter') {
      e.preventDefault();
      form = document.getElementById('scan-form');
      if (form) form.dispatchEvent(new Event('submit'));
    }
  }

  function bindFormEvents() {
    form = document.getElementById('scan-form');
    input = document.getElementById('domain-input');
    if (form) {
      form.addEventListener('submit', handleSubmit);
    }
    if (input) {
      input.addEventListener('keydown', handleKeydown);
    }
  }

  bindFormEvents();

  // Search filter
  var searchInput = document.getElementById('subdomain-search');
  if (searchInput) {
    searchInput.addEventListener('input', function () {
      if (lastScanData && lastScanData.subdomains) {
        renderSubdomainTable(lastScanData.subdomains, searchInput.value);
      }
    });
  }

  // Column sorting
  var sortHeaders = document.querySelectorAll('#subdomain-table th[data-sort]');
  sortHeaders.forEach(function (th) {
    th.addEventListener('click', function () {
      var key = th.getAttribute('data-sort');
      if (currentSort.key === key) {
        currentSort.dir = currentSort.dir === 'asc' ? 'desc' : 'asc';
      } else {
        currentSort.key = key;
        currentSort.dir = 'asc';
      }
      if (lastScanData && lastScanData.subdomains) {
        var filterVal = searchInput ? searchInput.value : '';
        renderSubdomainTable(lastScanData.subdomains, filterVal);
      }
    });
  });

  // Copy button
  var copyBtn = document.getElementById('copy-btn');
  if (copyBtn) {
    copyBtn.addEventListener('click', copyAllSubdomains);
  }

  // CSV button
  var csvBtn = document.getElementById('csv-btn');
  if (csvBtn) {
    csvBtn.addEventListener('click', exportCSV);
  }

  // Scan again button
  var scanAgainBtn = document.getElementById('scan-again-btn');
  if (scanAgainBtn) {
    scanAgainBtn.addEventListener('click', function () {
      history.pushState(null, '', window.location.pathname);
      resultsSection.classList.add('hidden');
      heroSection.classList.remove('hidden');
      var featuresSection = document.getElementById('features-section');
      if (featuresSection) featuresSection.classList.remove('hidden');
      input = document.getElementById('domain-input');
      if (input) {
        input.value = '';
        input.focus();
      }
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
  }

  // Rescan button
  var rescanBtn = document.getElementById('rescan-btn');
  if (rescanBtn) {
    rescanBtn.addEventListener('click', function () {
      if (lastScannedDomain) {
        doScan(lastScannedDomain);
      }
    });
  }

  // Browser back/forward
  window.addEventListener('popstate', function () {
    var hasDomain = new URLSearchParams(window.location.search).get('domain');
    if (!hasDomain) {
      resultsSection.classList.add('hidden');
      heroSection.classList.remove('hidden');
      var featuresSection = document.getElementById('features-section');
      if (featuresSection) featuresSection.classList.remove('hidden');
      window.scrollTo({ top: 0 });
    } else {
      input = document.getElementById('domain-input');
      if (input) input.value = hasDomain;
      doScan(hasDomain);
    }
  });

  // Auto-scan from URL param
  var params = new URLSearchParams(window.location.search);
  var domainParam = params.get('domain');
  if (domainParam) {
    input = document.getElementById('domain-input');
    if (input) {
      input.value = domainParam;
    }
    setTimeout(function () {
      doScan(domainParam);
    }, 100);
  }
})();
