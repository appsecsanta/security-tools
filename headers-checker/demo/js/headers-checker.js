const API_BASE = window.SECURITY_TOOLS_API || '';
(function () {
  'use strict';

  var form = document.getElementById('scan-form');
  var input = document.getElementById('url-input');
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

  // In-place loading: swap form with spinner
  function setLoading(on) {
    if (on) {
      savedFormHTML = formWrapper.innerHTML;
      formWrapper.innerHTML = '<div class="flex flex-col items-center py-4">' +
        '<div class="inline-block w-12 h-12 border-4 border-border border-t-brand-red rounded-full" style="animation: spin 0.8s linear infinite;"></div>' +
        '<p class="mt-4 text-text-secondary text-lg">Scanning headers...</p>' +
        '</div>';
      resultsSection.classList.add('hidden');
    } else {
      formWrapper.innerHTML = savedFormHTML;
      form = document.getElementById('scan-form');
      input = document.getElementById('url-input');
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

  // Human-readable test names
  var testNames = {
    'csp': 'Content Security Policy (CSP)',
    'cookies': 'Cookies',
    'cors': 'Cross Origin Resource Sharing (CORS)',
    'redirection': 'Redirection',
    'referrer-policy': 'Referrer Policy',
    'hsts': 'Strict Transport Security (HSTS)',
    'sri': 'Subresource Integrity',
    'x-content-type-options': 'X-Content-Type-Options',
    'x-frame-options': 'X-Frame-Options',
    'corp': 'Cross Origin Resource Policy',
    'permissions-policy': 'Permissions-Policy'
  };

  // Map test keys to educational section anchors
  var learnAnchors = {
    'csp': '#learn-csp',
    'cookies': '#learn-csp',
    'cors': '#learn-cors',
    'redirection': '#learn-redirection',
    'referrer-policy': '#learn-referrer-policy',
    'hsts': '#learn-hsts',
    'sri': '#learn-sri',
    'x-content-type-options': '#learn-x-content-type-options',
    'x-frame-options': '#learn-x-frame-options',
    'corp': '#learn-corp',
    'permissions-policy': '#learn-permissions-policy'
  };

  // Map test keys to MDN doc URLs
  var mdnLinks = {
    'csp': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP',
    'cookies': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies',
    'cors': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS',
    'redirection': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections',
    'referrer-policy': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy',
    'hsts': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security',
    'sri': 'https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity',
    'x-content-type-options': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options',
    'x-frame-options': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options',
    'corp': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy',
    'permissions-policy': 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy'
  };

  var currentUncurvedScore = 100;

  // Fixed display order matching Observatory
  var testOrder = ['csp', 'cookies', 'cors', 'redirection', 'referrer-policy', 'hsts', 'sri', 'x-content-type-options', 'x-frame-options', 'corp', 'permissions-policy'];

  var lastScannedUrl = '';
  var lastScanData = null;

  function statusIcon(pass) {
    if (pass) return '<span class="inline-flex items-center justify-center w-5 h-5 rounded-full bg-green-100 text-green-600 text-xs font-bold" aria-label="Passed">&#10003;</span>';
    return '<span class="inline-flex items-center justify-center w-5 h-5 rounded-full bg-red-100 text-red-600 text-xs font-bold" aria-label="Failed">&#10007;</span>';
  }

  function neutralIcon() {
    return '<span class="inline-flex items-center justify-center w-5 h-5 rounded-full bg-gray-100 text-gray-400 text-xs font-bold" aria-label="Neutral">&ndash;</span>';
  }

  function infoIcon() {
    return '<span style="color: rgb(107, 114, 128); font-size: 1.25rem; line-height: 1;" aria-label="Info">&#8505;</span>';
  }

  function warnIcon() {
    return '<span style="color: rgb(234, 179, 8); font-size: 1.25rem; line-height: 1;" aria-label="Warning">&#9888;</span>';
  }

  // Neutral results that show "-" instead of a score
  var neutralResults = {
    'cookies-not-found': true,
    'corp-not-implemented': true,
    'cors-test-failed': true
  };

  function renderTestRow(key, test) {
    var name = testNames[key] || key;
    var anchor = learnAnchors[key];
    var modifier = test.scoreModifier;
    var ineligible = modifier > 0 && currentUncurvedScore < 90;
    var isNeutral = neutralResults[test.result];

    var html = '<tr class="border-b border-border/50 hover:bg-surface-light/50 transition-colors">';

    // Col 1: Test name (linked)
    html += '<td class="py-3 px-4 font-medium">';
    if (anchor) {
      html += '<a href="' + anchor + '" class="text-brand-red hover:underline">' + escapeHtml(name) + '</a>';
    } else {
      html += escapeHtml(name);
    }
    html += '</td>';

    // Col 2: Score + pass/fail icon
    html += '<td class="py-3 px-4 text-center whitespace-nowrap">';
    if (isNeutral) {
      html += '<span class="text-text-muted">&ndash;</span>';
    } else {
      var scoreLabel;
      if (modifier > 0) {
        scoreLabel = ineligible ? '0*' : '+' + modifier;
      } else if (modifier < 0) {
        scoreLabel = String(modifier);
      } else {
        scoreLabel = '0';
      }
      var scoreColor = modifier > 0 && !ineligible ? 'color:rgb(21,128,61)' : modifier < 0 ? 'color:rgb(185,28,28)' : 'color:rgb(107,114,128)';
      html += '<span style="font-weight:600;' + scoreColor + '">' + scoreLabel + '</span> ';
      html += statusIcon(test.pass);
    }
    html += '</td>';

    // Col 3: Reason (description)
    html += '<td class="py-3 px-4 text-text-secondary">';
    html += escapeHtml(test.description);
    // On mobile, show recommendation inline since col 4 is hidden
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

  function renderInfoRow(name, value, description, icon) {
    icon = icon || infoIcon();
    var html = '<div class="flex items-center gap-3 px-4 py-3 bg-white text-sm">';
    html += '<span class="shrink-0">' + icon + '</span>';
    html += '<span class="font-medium text-text-primary whitespace-nowrap">' + escapeHtml(name) + '</span>';
    if (value) {
      html += '<span class="text-text-secondary break-all truncate" style="font-family: ui-monospace, monospace; font-size: 0.8125rem;">' + escapeHtml(value) + '</span>';
    }
    if (description && !value) {
      html += '<span class="text-text-muted">' + escapeHtml(description) + '</span>';
    }
    html += '</div>';
    return html;
  }

  function renderInfoCard(name, info) {
    var val = info.value || '';
    if (!val && info.description) val = '';
    return renderInfoRow(name, val || info.description, '', infoIcon());
  }

  function renderLeakageCard(issue) {
    var icon = issue.status === 'warn' ? warnIcon() : infoIcon();
    return renderInfoRow(issue.header, issue.value, issue.description, icon);
  }

  // ── Tabs ──
  function initTabs() {
    var tabs = document.querySelectorAll('.result-tab');
    tabs.forEach(function (tab) {
      tab.addEventListener('click', function () {
        var target = tab.getAttribute('data-tab');
        // Deactivate all tabs
        tabs.forEach(function (t) {
          t.classList.remove('border-brand-red', 'text-brand-red', 'font-semibold');
          t.classList.add('border-transparent', 'text-text-muted', 'font-medium');
        });
        // Activate clicked tab
        tab.classList.add('border-brand-red', 'text-brand-red', 'font-semibold');
        tab.classList.remove('border-transparent', 'text-text-muted', 'font-medium');
        // Show/hide panels
        document.querySelectorAll('.tab-panel').forEach(function (p) {
          p.classList.add('hidden');
        });
        var panel = document.getElementById('tab-' + target);
        if (panel) panel.classList.remove('hidden');
      });
    });
  }
  initTabs();

  // ── Trend arrows (localStorage) ──
  var HISTORY_KEY = 'headersScanHistory';
  var MAX_HISTORY = 50;

  function getHistory() {
    try {
      return JSON.parse(localStorage.getItem(HISTORY_KEY)) || [];
    } catch (e) {
      return [];
    }
  }

  function saveToHistory(host, score, grade) {
    var history = getHistory();
    history.push({ host: host, score: score, grade: grade, timestamp: Date.now() });
    if (history.length > MAX_HISTORY) {
      history = history.slice(history.length - MAX_HISTORY);
    }
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    } catch (e) { /* storage full */ }
  }

  function getPreviousScan(host) {
    var history = getHistory();
    for (var i = history.length - 1; i >= 0; i--) {
      if (history[i].host === host) return history[i];
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

  function renderRawHeaders(rawHeaders) {
    var pre = document.getElementById('raw-headers-pre');
    if (!pre || !rawHeaders) return;
    var lines = [];
    var keys = Object.keys(rawHeaders).sort();
    for (var i = 0; i < keys.length; i++) {
      lines.push('<span style="color: #93c5fd;">' + escapeHtml(keys[i]) + '</span><span style="color: #6b7280;">: </span><span style="color: #86efac;">' + escapeHtml(rawHeaders[keys[i]]) + '</span>');
    }
    pre.innerHTML = lines.join('\n');
  }

  function renderResults(data) {
    lastScanData = data;
    currentUncurvedScore = (typeof data.uncurvedScore === 'number') ? data.uncurvedScore : 100;
    lastScannedUrl = data.finalUrl || data.url || '';

    // Host display
    var host = '';
    try { host = new URL(data.finalUrl || data.url).hostname; } catch (e) { host = data.finalUrl || data.url; }
    var hostEl = document.getElementById('scanned-host');
    if (hostEl) hostEl.textContent = host;

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
    var prev = getPreviousScan(host);
    scoreEl.textContent = data.score;
    if (trendEl) {
      trendEl.innerHTML = prev ? getTrendArrow(data.score, prev.score) : '';
    }

    // URL
    document.getElementById('scanned-url').textContent = lastScannedUrl;

    // Scan time
    var scanTimeEl = document.getElementById('scan-time');
    if (scanTimeEl) scanTimeEl.textContent = 'just now';

    // Pass/total
    document.getElementById('pass-count').textContent = data.summary.passCount;
    document.getElementById('total-count').textContent = data.summary.totalTests;

    // Bonus note
    var bonusNote = document.getElementById('bonus-note');
    if (bonusNote) {
      if (currentUncurvedScore < 90) {
        bonusNote.textContent = '* Bonus not applied \u2014 base score must be 90+ for extra credit';
        bonusNote.classList.remove('hidden');
      } else {
        bonusNote.textContent = '';
        bonusNote.classList.add('hidden');
      }
    }

    // ── Scoring table (4-col) ──
    var tbody = document.getElementById('results-tbody');
    var html = '';
    for (var i = 0; i < testOrder.length; i++) {
      var key = testOrder[i];
      if (data.tests[key]) {
        html += renderTestRow(key, data.tests[key]);
      }
    }
    var testKeys = Object.keys(data.tests);
    for (var k = 0; k < testKeys.length; k++) {
      if (testOrder.indexOf(testKeys[k]) === -1) {
        html += renderTestRow(testKeys[k], data.tests[testKeys[k]]);
      }
    }
    tbody.innerHTML = html;

    // Show bonus footer
    var tfoot = document.getElementById('results-tfoot');
    if (tfoot) {
      if (currentUncurvedScore < 90) {
        tfoot.classList.remove('hidden');
      } else {
        tfoot.classList.add('hidden');
      }
    }

    // ── Raw Headers tab ──
    if (data.rawHeaders) {
      renderRawHeaders(data.rawHeaders);
    }

    // ── Info tab ──
    var infoSection = document.getElementById('info-section');
    var infoList = document.getElementById('info-list');
    var infoEmpty = document.getElementById('info-empty');
    var infoHtml = '';
    var hasInfo = false;

    if (data.informational) {
      if (data.informational.coop) {
        infoHtml += renderInfoCard('Cross-Origin-Opener-Policy', data.informational.coop);
        hasInfo = true;
      }
      if (data.informational.coep) {
        infoHtml += renderInfoCard('Cross-Origin-Embedder-Policy', data.informational.coep);
        hasInfo = true;
      }
      if (data.informational.infoLeakage && data.informational.infoLeakage.issues) {
        var issues = data.informational.infoLeakage.issues;
        for (var j = 0; j < issues.length; j++) {
          infoHtml += renderLeakageCard(issues[j]);
          hasInfo = true;
        }
      }
    }

    if (hasInfo) {
      infoList.innerHTML = infoHtml;
      infoSection.classList.remove('hidden');
      if (infoEmpty) infoEmpty.classList.add('hidden');
    } else {
      infoSection.classList.add('hidden');
      if (infoEmpty) infoEmpty.classList.remove('hidden');
    }

    // Show results, hide hero + features
    heroSection.classList.add('hidden');
    var featuresSection = document.getElementById('features-section');
    if (featuresSection) featuresSection.classList.add('hidden');
    resultsSection.classList.remove('hidden');

    // Reset to Scoring tab
    var firstTab = document.querySelector('.result-tab[data-tab="scoring"]');
    if (firstTab) firstTab.click();

    // Save to history
    saveToHistory(host, data.score, data.grade);

    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function doScan(url) {
    hideError();

    if (!url) {
      showError('Please enter a URL.');
      return;
    }

    var now = Date.now();
    if (now - lastScanTime < COOLDOWN_MS) {
      showError('Please wait a few seconds before scanning again.');
      return;
    }

    if (!/^https?:\/\//i.test(url)) {
      url = 'https://' + url;
    }

    try {
      var hostname = new URL(url).hostname;
      history.pushState(null, '', '?host=' + encodeURIComponent(hostname));
    } catch (e) { /* ignore */ }

    setLoading(true);
    lastScanTime = now;

    // Fetch challenge token, then scan
    fetch(API_BASE + '/api/token')
    .then(function (tokenRes) {
      if (!tokenRes.ok) {
        throw new Error('token_failed');
      }
      return tokenRes.json();
    })
    .then(function (tokenData) {
      return fetch(API_BASE + '/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url, token: tokenData.token })
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
      if (!res.ok && res.status !== 400 && res.status !== 408 && res.status !== 502) {
        throw new Error('Server returned ' + res.status);
      }
      return res.json().then(function (json) {
        return { status: res.status, data: json };
      }, function () {
        throw new Error('Invalid response from server (not JSON). Status: ' + res.status);
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
      } else if (msg.indexOf('not JSON') !== -1) {
        showError('Unexpected response from server. Please try again in a moment.');
      } else {
        showError('Network error. Please check your connection and try again.');
      }
    });
  }

  function handleSubmit(e) {
    e.preventDefault();
    input = document.getElementById('url-input');
    var url = input ? input.value.trim() : '';
    doScan(url);
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
    input = document.getElementById('url-input');
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
      input = document.getElementById('url-input');
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
      if (lastScannedUrl) {
        doScan(lastScannedUrl);
      }
    });
  }

  // Handle browser back/forward
  window.addEventListener('popstate', function () {
    var hasHost = new URLSearchParams(window.location.search).get('host');
    if (!hasHost) {
      resultsSection.classList.add('hidden');
      heroSection.classList.remove('hidden');
      var featuresSection = document.getElementById('features-section');
      if (featuresSection) featuresSection.classList.remove('hidden');
      window.scrollTo({ top: 0 });
    }
  });

  // Copy headers button
  var copyBtn = document.getElementById('copy-headers-btn');
  if (copyBtn) {
    copyBtn.addEventListener('click', function () {
      if (lastScanData && lastScanData.rawHeaders) {
        var text = '';
        var keys = Object.keys(lastScanData.rawHeaders).sort();
        for (var i = 0; i < keys.length; i++) {
          text += keys[i] + ': ' + lastScanData.rawHeaders[keys[i]] + '\n';
        }
        navigator.clipboard.writeText(text).then(function () {
          copyBtn.textContent = 'Copied!';
          setTimeout(function () { copyBtn.textContent = 'Copy'; }, 2000);
        });
      }
    });
  }

  // Auto-scan from URL param
  var params = new URLSearchParams(window.location.search);
  var hostParam = params.get('host');
  if (hostParam) {
    input = document.getElementById('url-input');
    if (input) {
      input.value = hostParam;
    }
    setTimeout(function () {
      doScan(hostParam);
    }, 100);
  }
})();
