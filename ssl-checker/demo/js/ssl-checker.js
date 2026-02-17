const API_BASE = window.SECURITY_TOOLS_API || '';
(function () {
  'use strict';

  var form = document.getElementById('scan-form');
  var input = document.getElementById('domain-input');
  var btn = document.getElementById('scan-btn');
  var formError = document.getElementById('form-error');
  var formWrapper = document.getElementById('scan-form-wrapper');
  var resultsSection = document.getElementById('results-section');
  var heroSection = document.getElementById('hero-section');

  var lastScanTime = 0;
  var COOLDOWN_MS = 3000;
  var savedFormHTML = formWrapper ? formWrapper.innerHTML : '';

  function escapeHtml(str) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
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
      savedFormHTML = formWrapper.innerHTML;
      formWrapper.innerHTML = '<div class="flex flex-col items-center py-4">' +
        '<div class="inline-block w-12 h-12 border-4 border-border border-t-brand-red rounded-full" style="animation: spin 0.8s linear infinite;"></div>' +
        '<p class="mt-4 text-text-secondary text-lg">Checking SSL/TLS configuration...</p>' +
        '</div>';
      resultsSection.classList.add('hidden');
    } else {
      formWrapper.innerHTML = savedFormHTML;
      form = document.getElementById('scan-form');
      input = document.getElementById('domain-input');
      btn = document.getElementById('scan-btn');
      formError = document.getElementById('form-error');
      bindFormEvents();
    }
  }

  // Grade colors — 13 grades
  var gradeColors = {
    'A+': { bg: 'rgb(220, 252, 231)', border: 'rgb(22, 163, 74)',  text: 'rgb(21, 128, 61)' },
    'A':  { bg: 'rgb(220, 252, 231)', border: 'rgb(34, 197, 94)',  text: 'rgb(21, 128, 61)' },
    'A-': { bg: 'rgb(209, 250, 229)', border: 'rgb(16, 185, 129)', text: 'rgb(6, 95, 70)' },
    'B+': { bg: 'rgb(217, 249, 195)', border: 'rgb(132, 204, 22)', text: 'rgb(63, 98, 18)' },
    'B':  { bg: 'rgb(254, 249, 195)', border: 'rgb(234, 179, 8)',  text: 'rgb(161, 98, 7)' },
    'B-': { bg: 'rgb(254, 243, 199)', border: 'rgb(245, 158, 11)', text: 'rgb(146, 64, 14)' },
    'C+': { bg: 'rgb(255, 237, 213)', border: 'rgb(249, 115, 22)', text: 'rgb(194, 65, 12)' },
    'C':  { bg: 'rgb(255, 237, 213)', border: 'rgb(234, 88, 12)',  text: 'rgb(154, 52, 18)' },
    'C-': { bg: 'rgb(255, 228, 200)', border: 'rgb(220, 70, 10)',  text: 'rgb(133, 44, 15)' },
    'D+': { bg: 'rgb(254, 226, 226)', border: 'rgb(248, 113, 113)', text: 'rgb(185, 28, 28)' },
    'D':  { bg: 'rgb(254, 226, 226)', border: 'rgb(239, 68, 68)',  text: 'rgb(153, 27, 27)' },
    'D-': { bg: 'rgb(254, 215, 215)', border: 'rgb(220, 38, 38)',  text: 'rgb(127, 29, 29)' },
    'F':  { bg: 'rgb(254, 202, 202)', border: 'rgb(185, 28, 28)',  text: 'rgb(99, 20, 20)' }
  };

  var testNames = {
    'https': 'HTTPS Available',
    'redirect': 'HTTP→HTTPS Redirect',
    'hsts': 'HSTS Configuration',
    'cert-expiry': 'Certificate Expiry',
    'cert-transparency': 'Certificate Transparency',
    'cert-issuer': 'Certificate Issuer',
    'dane': 'DANE/TLSA Records',
    'https-downgrade': 'HTTPS Downgrade Protection'
  };

  var learnAnchors = {
    'https': '#learn-https',
    'redirect': '#learn-redirect',
    'hsts': '#learn-hsts',
    'cert-expiry': '#learn-cert-expiry',
    'cert-transparency': '#learn-cert-transparency',
    'cert-issuer': '#learn-cert-issuer',
    'dane': '#learn-dane',
    'https-downgrade': '#learn-https-downgrade'
  };

  var testOrder = ['https', 'redirect', 'hsts', 'cert-expiry', 'cert-transparency', 'cert-issuer', 'dane', 'https-downgrade'];

  var lastScannedDomain = '';
  var lastScanData = null;

  function statusIcon(pass) {
    if (pass === true) return '<span class="inline-flex items-center justify-center w-5 h-5 rounded-full bg-green-100 text-green-600 text-xs font-bold" aria-label="Passed">&#10003;</span>';
    if (pass === false) return '<span class="inline-flex items-center justify-center w-5 h-5 rounded-full bg-red-100 text-red-600 text-xs font-bold" aria-label="Failed">&#10007;</span>';
    return '<span class="inline-flex items-center justify-center w-5 h-5 rounded-full bg-gray-100 text-gray-400 text-xs font-bold" aria-label="Neutral">&ndash;</span>';
  }

  // ── Scan History (localStorage) ──
  var HISTORY_KEY = 'sslScanHistory';
  var MAX_HISTORY = 50;

  function getHistory() {
    try {
      return JSON.parse(localStorage.getItem(HISTORY_KEY)) || [];
    } catch (e) {
      return [];
    }
  }

  function saveToHistory(domain, score, grade) {
    var history = getHistory();
    history.push({ domain: domain, score: score, grade: grade, timestamp: Date.now() });
    if (history.length > MAX_HISTORY) {
      history = history.slice(history.length - MAX_HISTORY);
    }
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    } catch (e) { /* storage full */ }
  }

  function getPreviousScan(domain) {
    var history = getHistory();
    for (var i = history.length - 1; i >= 0; i--) {
      if (history[i].domain === domain) return history[i];
    }
    return null;
  }

  function getTrendArrow(currentScore, previousScore) {
    if (currentScore > previousScore) {
      return ' <span style="color: rgb(34, 197, 94); font-weight: 600;" title="Improved from ' + escapeHtml(String(previousScore)) + '">&#8593;</span>';
    } else if (currentScore < previousScore) {
      return ' <span style="color: rgb(239, 68, 68); font-weight: 600;" title="Decreased from ' + escapeHtml(String(previousScore)) + '">&#8595;</span>';
    }
    return '';
  }

  function renderTestRow(key, test) {
    var name = testNames[key] || key;
    var anchor = learnAnchors[key];
    var modifier = test.scoreModifier;

    var html = '<tr class="border-b border-border/50 hover:bg-surface-light/50 transition-colors">';

    // Col 1: Test name
    html += '<td class="py-3 px-4 font-medium">';
    if (anchor) {
      html += '<a href="' + anchor + '" class="text-brand-red hover:underline">' + escapeHtml(name) + '</a>';
    } else {
      html += escapeHtml(name);
    }
    html += '</td>';

    // Col 2: Score + icon
    html += '<td class="py-3 px-4 text-center whitespace-nowrap">';
    if (test.pass === null) {
      html += '<span class="text-text-muted">&ndash;</span>';
    } else {
      var scoreLabel;
      if (modifier > 0) {
        scoreLabel = '+' + modifier;
      } else if (modifier < 0) {
        scoreLabel = String(modifier);
      } else {
        scoreLabel = '0';
      }
      var scoreColor = modifier > 0 ? 'color:rgb(21,128,61)' : modifier < 0 ? 'color:rgb(185,28,28)' : 'color:rgb(107,114,128)';
      html += '<span style="font-weight:600;' + scoreColor + '">' + scoreLabel + '</span> ';
      html += statusIcon(test.pass);
    }
    html += '</td>';

    // Col 3: Reason
    html += '<td class="py-3 px-4 text-text-secondary">';
    html += escapeHtml(test.description);
    if (test.recommendation) {
      html += '<div class="lg:hidden text-xs text-brand-red mt-1.5 font-medium">' + escapeHtml(test.recommendation) + '</div>';
    }
    html += '</td>';

    // Col 4: Recommendation (hidden on mobile)
    html += '<td class="py-3 px-4 text-text-secondary hidden lg:table-cell">';
    if (test.recommendation) {
      html += '<span class="text-brand-red text-xs font-medium">' + escapeHtml(test.recommendation) + '</span>';
    } else {
      html += '<span class="text-text-muted">None</span>';
    }
    html += '</td>';

    html += '</tr>';
    return html;
  }

  function renderCertificateDetails(data) {
    var container = document.getElementById('cert-details-content');
    if (!container) return;

    if (!data.certificateInfo) {
      container.innerHTML = '<p class="text-text-muted text-sm">Certificate details are unavailable. The crt.sh CT log service could not be reached during this scan.</p>';
      return;
    }

    var cert = data.certificateInfo;
    var html = '';

    // Certificate overview card
    html += '<div class="grid md:grid-cols-2 gap-5 mb-6">';

    // Issuer
    html += '<div class="bg-surface-light rounded-xl border border-border p-5">';
    html += '<div class="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">Issuer</div>';
    html += '<div class="text-lg font-bold text-text-primary">' + escapeHtml(cert.issuer) + '</div>';
    html += '</div>';

    // Days remaining
    html += '<div class="bg-surface-light rounded-xl border border-border p-5">';
    html += '<div class="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">Days Until Expiry</div>';
    var daysColor = cert.daysRemaining > 30 ? 'text-green-600' : cert.daysRemaining > 7 ? 'text-yellow-600' : 'text-red-600';
    html += '<div class="text-lg font-bold ' + daysColor + '">' + cert.daysRemaining + ' days</div>';
    html += '</div>';

    // Valid from
    html += '<div class="bg-surface-light rounded-xl border border-border p-5">';
    html += '<div class="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">Valid From</div>';
    html += '<div class="text-lg font-bold text-text-primary">' + escapeHtml(cert.validFrom) + '</div>';
    html += '</div>';

    // Valid to
    html += '<div class="bg-surface-light rounded-xl border border-border p-5">';
    html += '<div class="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">Valid To</div>';
    html += '<div class="text-lg font-bold text-text-primary">' + escapeHtml(cert.validTo) + '</div>';
    html += '</div>';

    html += '</div>';

    // Common Name
    html += '<div class="bg-surface-light rounded-xl border border-border p-5 mb-5">';
    html += '<div class="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">Common Name</div>';
    html += '<div class="font-mono text-sm text-text-primary">' + escapeHtml(cert.commonName) + '</div>';
    html += '</div>';

    // SANs
    if (cert.sans && cert.sans.length > 0) {
      html += '<div class="bg-surface-light rounded-xl border border-border p-5 mb-5">';
      html += '<div class="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">Subject Alternative Names (' + cert.sans.length + ')</div>';
      html += '<div class="flex flex-wrap gap-2">';
      for (var i = 0; i < cert.sans.length; i++) {
        html += '<span class="inline-block px-2.5 py-1 bg-white border border-border rounded-lg text-xs font-mono text-text-primary">' + escapeHtml(cert.sans[i]) + '</span>';
      }
      html += '</div>';
      html += '</div>';
    }

    // Redirect chain
    if (data.redirectChain) {
      var rc = data.redirectChain;
      html += '<div class="bg-surface-light rounded-xl border border-border p-5">';
      html += '<div class="text-xs font-semibold text-text-muted uppercase tracking-wider mb-3">Redirect Chain</div>';
      html += '<div class="space-y-2 text-sm">';
      if (rc.httpStatus !== null) {
        var redirectIcon = rc.httpToHttps ? '<span class="text-green-600">&#10003;</span>' : '<span class="text-yellow-600">&#9888;</span>';
        html += '<div class="flex items-center gap-2">' + redirectIcon + ' <span class="text-text-muted">HTTP:</span> <span class="font-medium text-text-primary">Status ' + escapeHtml(String(rc.httpStatus)) + (rc.httpToHttps ? ' (redirects to HTTPS)' : '') + '</span></div>';
      }
      if (rc.httpsStatus !== null) {
        html += '<div class="flex items-center gap-2"><span class="text-green-600">&#10003;</span> <span class="text-text-muted">HTTPS:</span> <span class="font-medium text-text-primary">Status ' + escapeHtml(String(rc.httpsStatus)) + '</span></div>';
      }
      html += '</div>';
      html += '</div>';
    }

    container.innerHTML = html;
  }

  // ── Tabs ──
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

  function renderResults(data) {
    lastScanData = data;
    lastScannedDomain = data.domain || '';

    // Domain display
    var hostEl = document.getElementById('scanned-host');
    if (hostEl) hostEl.textContent = data.domain;

    // Grade badge
    var gc = gradeColors[data.grade] || gradeColors['F'];
    var circle = document.getElementById('grade-circle');
    circle.style.backgroundColor = gc.bg;
    circle.style.borderColor = gc.border;
    var letter = document.getElementById('grade-letter');
    letter.style.color = gc.text;
    letter.textContent = data.grade;

    // Score with trend
    var scoreEl = document.getElementById('score-value');
    var trendEl = document.getElementById('score-trend');
    var prev = getPreviousScan(data.domain);
    scoreEl.textContent = data.score;
    if (trendEl) {
      trendEl.innerHTML = prev ? getTrendArrow(data.score, prev.score) : '';
    }

    // Scan time
    var scanTimeEl = document.getElementById('scan-time');
    if (scanTimeEl) scanTimeEl.textContent = 'just now';

    // Pass/total
    document.getElementById('pass-count').textContent = data.summary.passCount;
    document.getElementById('total-count').textContent = data.summary.totalTests;

    // ── Scoring table ──
    var tbody = document.getElementById('results-tbody');
    var html = '';
    for (var i = 0; i < testOrder.length; i++) {
      var key = testOrder[i];
      if (data.tests[key]) {
        html += renderTestRow(key, data.tests[key]);
      }
    }
    tbody.innerHTML = html;

    // ── Certificate Details tab ──
    renderCertificateDetails(data);

    // Show results, hide hero + features
    heroSection.classList.add('hidden');
    var featuresSection = document.getElementById('features-section');
    if (featuresSection) featuresSection.classList.add('hidden');
    resultsSection.classList.remove('hidden');

    // Reset to Scoring tab
    var firstTab = document.querySelector('.result-tab[data-tab="scoring"]');
    if (firstTab) firstTab.click();

    // Save to history
    saveToHistory(data.domain, data.score, data.grade);

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

    // Fetch challenge token, then check SSL
    fetch(API_BASE + '/api/token')
    .then(function (tokenRes) {
      if (!tokenRes.ok) {
        throw new Error('token_failed');
      }
      return tokenRes.json();
    })
    .then(function (tokenData) {
      return fetch(API_BASE + '/api/ssl-check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domain, token: tokenData.token })
      });
    })
    .then(function (res) {
      if (res.status === 403) {
        setLoading(false);
        showError('Access denied.');
        return null;
      }
      if (res.status === 429) {
        setLoading(false);
        showError('Too many scans. Please wait a while before scanning again.');
        return null;
      }
      if (!res.ok && res.status !== 400 && res.status !== 502) {
        throw new Error('Server returned ' + res.status);
      }
      return res.json().then(function (json) {
        return { status: res.status, data: json };
      }, function () {
        throw new Error('Invalid response from server. Status: ' + res.status);
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
        showError('Could not authenticate. Please try again.');
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
