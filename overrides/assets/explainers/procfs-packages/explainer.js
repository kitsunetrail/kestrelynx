/*
 * Interactive explainer: how one library loaded by a running container is
 * mapped to an OS package and matched with scanner findings through procfs.
 *
 * One nginx worker is followed in eight steps across four fixed columns: the
 * process as seen from the host, its executable mappings, the container's
 * dpkg records, and the match with Trivy findings. Values are taken from one
 * measurement of an nginx:1.27 container; listings are excerpts.
 *
 * User-visible text comes from window.KLX_TEXT (text-<lang>.js).
 */
(function () {
  'use strict';

  const root = document.querySelector('[data-klx-explainer="procfs-packages"]');
  const T = window.KLX_TEXT;
  if (!root || !T) return;

  const STEPS = 8;
  const PLAY_DELAY_MS = 5000;

  // ---------------------------------------------------------------- text

  function lookup(path) {
    return path.split('.').reduce((o, k) => (o == null ? undefined : o[k]), T);
  }

  function tx(path) {
    const v = lookup(path);
    if (v == null) {
      console.warn('klx explainer: missing text', path);
      return path;
    }
    return String(v);
  }

  function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    })[c]);
  }

  // Inline `code` and **strong** only; text files never carry raw HTML.
  function inline(s) {
    return esc(s)
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  }

  const t = (path) => inline(tx(path));

  // ---------------------------------------------------------------- data

  const PID = '2479938';
  const LIB = '/usr/lib/x86_64-linux-gnu/';
  const SSL = LIB + 'libssl.so.3';
  const CRYPTO = LIB + 'libcrypto.so.3';
  const PKG = 'libssl3';
  const VER = '3.0.16-1~deb12u1';
  const STARTTIME = '15146823';
  const STARTED_AT = '2026-09-11T23:39:27.070569713Z';

  // Field classes color the same kind of value wherever it appears.
  function f(text, cls, glow) {
    return '<span class="klx-f klx-f-' + cls + (glow ? ' is-glow' : '') + '">' + esc(text) + '</span>';
  }

  const pid = (glow) => f(PID, 'pid', glow);
  const path = (p, glow) => f(p, 'path', glow);
  const pkg = (glow) => f(PKG, 'pkg', glow);
  const ver = (glow) => f(VER, 'ver', glow);

  // Excerpt of /proc/<pid>/maps for the followed worker. Address ranges and
  // offsets are left out; the remaining columns are as recorded.
  const MAPS = [
    ['r-xp', '08:30', '915974', '/usr/sbin/nginx'],
    ['rw-p', '00:00', '0', '[heap]'],
    ['rw-p', '00:00', '0', ''],
    ['r--p', '08:30', '911959', LIB + 'libc.so.6'],
    ['r-xp', '08:30', '911959', LIB + 'libc.so.6'],
    ['r--p', '08:30', '915879', CRYPTO],
    ['r-xp', '08:30', '915879', CRYPTO],
    ['r--p', '08:30', '915949', SSL],
    ['r-xp', '08:30', '915949', SSL],
    ['r--p', '08:30', '915949', SSL],
    ['rw-p', '08:30', '915949', SSL],
  ];

  const KEPT = [
    '/usr/sbin/nginx',
    LIB + 'libc.so.6',
    LIB + 'libz.so.1.2.13',
    CRYPTO,
    SSL,
    LIB + 'libpcre2-8.so.0.11.2',
    LIB + 'libcrypt.so.1.1.0',
    LIB + 'ld-linux-x86-64.so.2',
  ];

  const keep = (m) => m[0].includes('x') && m[3].startsWith('/') && m[2] !== '0';

  // ---------------------------------------------------------------- helpers

  const row = (html, cls) => '<span class="klx-row' + (cls ? ' ' + cls : '') + '">' + html + '</span>';

  function listing(label, rows, cls) {
    return (label ? '<p class="klx-sub">' + label + '</p>' : '') +
      '<pre class="klx-pre' + (cls ? ' ' + cls : '') + '">' + rows.join('') + '</pre>';
  }

  const cmd = (s) => row('<span class="klx-prompt">$ ' + esc(s) + '</span>');
  const note = (key) => row('<span class="klx-c">' + t(key) + '</span>');

  function box(title, body, active) {
    return '<div class="klx-col' + (active ? ' is-active' : '') + '"><h3 class="klx-col-title">' + t(title) +
      '</h3><div class="klx-box">' + body + '</div></div>';
  }

  const empty = (key) => '<p class="klx-empty">' + t(key) + '</p>';
  const out = (html) => '<p class="klx-out">' + html + '</p>';

  // ---------------------------------------------------------------- column 1: process

  function procCol(step) {
    let html;
    if (step === 1) {
      html = listing('', [
        cmd('docker top nginx -eo pid,ppid'),
        row('PID       PPID'),
        row('2479853   2479829   ' + '<span class="klx-c">← ' + t('proc.master') + '</span>'),
        row('2479936   2479853   ' + '<span class="klx-c">← ' + t('proc.worker') + '</span>'),
        row('2479937   2479853'),
        row(pid(true) + '   2479853   ' + '<span class="klx-c">← ' + t('proc.followed') + '</span>', 'is-hit'),
        row('2479939   2479853'),
        note('proc.moreWorkers'),
      ]) + out(t('proc.hostPid'));
    } else if (step === 6) {
      const st = (glow) => f(STARTTIME, 'start', glow);
      html = '<p class="klx-sub">' + t('proc.starttime') + '</p>' +
        '<table class="klx-t"><tbody>' +
        '<tr><th>' + t('proc.before') + '</th><td>' + st(false) + '</td></tr>' +
        '<tr class="is-hit"><th>' + t('proc.after') + '</th><td>' + st(true) + '</td></tr>' +
        '</tbody></table>' +
        '<p class="klx-sub">' + t('proc.startedAt') + '</p>' +
        '<table class="klx-t"><tbody>' +
        '<tr><th>' + t('proc.before') + '</th><td><code>' + STARTED_AT + '</code></td></tr>' +
        '<tr class="is-hit"><th>' + t('proc.after') + '</th><td><code>' + STARTED_AT + '</code></td></tr>' +
        '</tbody></table>' +
        out(t('proc.same'));
    } else {
      html = out(t('proc.followedLabel') + ' ' + pid(false));
    }
    return box('cols.proc', html, step === 1 || step === 6);
  }

  // ---------------------------------------------------------------- column 2: maps

  function mapsCol(step) {
    let html;
    if (step < 2) {
      html = empty('maps.waiting');
    } else if (step === 2) {
      html = listing('', [cmd('cat /proc/' + PID + '/maps')].concat(MAPS.map((m) => {
        const k = keep(m);
        const p = m[3] === SSL && k ? path(m[3], true) : esc(m[3]);
        return row(esc(m[0]) + ' ' + esc(m[1]) + ' ' + esc(m[2]).padEnd(6, ' ') + ' ' + p,
          k ? (m[3] === SSL ? 'is-keep is-hit' : 'is-keep') : 'is-drop');
      }), [note('maps.excerpt')])) + out(t('maps.rule'));
    } else {
      html = listing(t('maps.kept'), KEPT.map((p) => row(
        p === SSL || p === CRYPTO ? path(p, step === 4 && p === SSL) : esc(p))));
    }
    return box('cols.maps', html, step === 2);
  }

  // ---------------------------------------------------------------- column 3: dpkg

  function dpkgCol(step) {
    if (step < 3) return box('cols.dpkg', empty('dpkg.waiting'), false);
    let html = listing(t('dpkg.where'), [
      cmd('ls /proc/' + PID + '/root/var/lib/dpkg'),
      row('info  status  …', step === 3 ? 'is-hit' : ''),
    ]);
    if (step === 3) {
      html += out(t('dpkg.rootNote'));
    } else {
      const hit = step === 4 ? 'is-hit' : '';
      html += listing(t('dpkg.listTitle'), [
        row(esc(LIB + 'engines-3/afalg.so')),
        row(path(CRYPTO), hit),
        row(path(SSL), hit),
        row(esc(LIB + 'ossl-modules/legacy.so')),
        row('…'),
      ]);
      html += listing(t('dpkg.indexTitle'), [
        row('/usr/sbin/nginx → ' + f('nginx', 'pkg')),
        row(path(CRYPTO) + ' → ' + pkg(false)),
        row(path(SSL, step === 4) + ' → ' + pkg(step === 4), hit),
        note('dpkg.indexMore'),
      ]);
    }
    if (step >= 5) {
      html += listing(t('dpkg.statusTitle'), [
        row('Package: ' + pkg(false)),
        row('Status: install ok installed'),
        row('Architecture: amd64'),
        row('Version: ' + ver(step === 5), step === 5 ? 'is-hit' : ''),
      ]);
    }
    return box('cols.dpkg', html, step >= 3 && step <= 5);
  }

  // ---------------------------------------------------------------- column 4: match

  function matchCol(step) {
    if (step < 7) return box('cols.match', empty('match.waiting'), false);
    const hit = step === 7 ? 'is-hit' : '';
    let html = listing(t('match.trivyTitle'), [
      row('"VulnerabilityID": "CVE-2025-15467",'),
      row('"PkgName": "' + pkg(step === 7) + '",', hit),
      row('"InstalledVersion": "' + ver(step === 7) + '",', hit),
      row('"FixedVersion": "3.0.18-1~deb12u2",'),
      row('"Severity": "HIGH"'),
    ]) + listing(t('match.observed'), [row(pkg(false) + '  ' + ver(false))]) +
      out(t('match.result'));
    if (step === 8) {
      html += listing(t('match.recordTitle'), [
        row('"package": "' + pkg(false) + '",'),
        row('"installed_version": "' + ver(false) + '",'),
        row('"finding_count": 32,'),
        row('"verdict": "<b>confirmed</b>",', 'is-hit'),
        row('"valid_samples": 10,'),
        row('"total_samples": 10,'),
        row('"observed_paths": ['),
        row('  "' + path(CRYPTO) + '",'),
        row('  "' + path(SSL) + '"'),
        row(']'),
      ]);
    }
    return box('cols.match', html, step >= 7);
  }

  // ---------------------------------------------------------------- DOM

  function h(tag, attrs, html) {
    const n = document.createElement(tag);
    if (attrs) for (const k in attrs) n.setAttribute(k, attrs[k]);
    if (html != null) n.innerHTML = html;
    return n;
  }

  root.innerHTML = '';
  root.classList.add('is-ready');

  const head = h('div', { class: 'klx-head' });
  const controls = h('div', { class: 'klx-controls' });
  // Icon-only buttons; the label stays available as a tooltip and accessible name.
  const ICONS = {
    play: '<path d="M8 5v14l11-7z"/>',
    pause: '<path d="M6 5h4v14H6zM14 5h4v14h-4z"/>',
    prev: '<path d="M6 5h2v14H6zM20 5v14L9 12z"/>',
    next: '<path d="M16 5h2v14h-2zM4 5v14l11-7z"/>',
    reset: '<path d="M12 5V1L7 6l5 5V7a5 5 0 1 1-5 5H5a7 7 0 1 0 7-7z"/>',
  };

  function iconButton(btn, name, label) {
    btn.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">' + ICONS[name] + '</svg>';
    btn.setAttribute('aria-label', label);
    btn.title = label;
  }

  const btnPlay = h('button', { type: 'button', class: 'klx-btn klx-btn-primary' });
  const btnPrev = h('button', { type: 'button', class: 'klx-btn' });
  const btnNext = h('button', { type: 'button', class: 'klx-btn' });
  const btnReset = h('button', { type: 'button', class: 'klx-btn' });
  iconButton(btnPrev, 'prev', tx('ui.prev'));
  iconButton(btnNext, 'next', tx('ui.next'));
  iconButton(btnReset, 'reset', tx('ui.reset'));
  const counter = h('span', { class: 'klx-counter', 'aria-live': 'polite' });
  controls.append(btnPlay, btnPrev, btnNext, btnReset, counter);
  const stage = h('div', { class: 'klx-stage' });
  const legend = h('p', { class: 'klx-legend-row' },
    ['pid', 'path', 'pkg', 'ver'].map((k) => f(tx('legend.' + k), k)).join(''));
  const explain = h('div', { class: 'klx-explain', 'aria-live': 'polite' });
  root.append(controls, head, stage, legend, explain);

  let step = 1;
  let timer = null;

  function render() {
    head.innerHTML = '<h3 class="klx-title">' + t('steps.' + step + '.title') + '</h3>';
    counter.textContent = tx('ui.counter').replace('{i}', step).replace('{n}', STEPS);
    btnPrev.disabled = step === 1;
    btnNext.disabled = step === STEPS;
    iconButton(btnPlay, timer ? 'pause' : 'play', tx(timer ? 'ui.pause' : 'ui.play'));

    stage.innerHTML = procCol(step) + mapsCol(step) + dpkgCol(step) + matchCol(step);

    // A body is a list of items; an item is a string or [lead, [sub-items]].
    const body = lookup('steps.' + step + '.body');
    const items = Array.isArray(body) ? body : [body == null ? tx('steps.' + step + '.body') : body];
    const list = (xs) => '<ul>' + xs.map((x) => Array.isArray(x)
      ? '<li>' + inline(x[0]) + list(x[1]) + '</li>'
      : '<li>' + inline(x) + '</li>').join('') + '</ul>';
    let html = list(items);
    const back = lookup('steps.' + step + '.back') || [];
    if (back.length) {
      html += '<p class="klx-back">' + t('ui.back') + ' ' + back.map(([label, href]) =>
        '<a href="' + esc(href) + '">' + esc(label) + '</a>').join(t('ui.backSep')) + '</p>';
    }
    explain.innerHTML = html;
  }

  // ---------------------------------------------------------------- playback

  function stop() {
    if (timer) clearInterval(timer);
    timer = null;
  }

  function go(n) {
    step = Math.max(1, Math.min(STEPS, n));
    if (step === STEPS) stop();
    render();
  }

  btnPlay.addEventListener('click', () => {
    if (timer) {
      stop();
      render();
      return;
    }
    if (step === STEPS) step = 1;
    timer = setInterval(() => go(step + 1), PLAY_DELAY_MS);
    render();
  });
  btnPrev.addEventListener('click', () => { stop(); go(step - 1); });
  btnNext.addEventListener('click', () => { stop(); go(step + 1); });
  btnReset.addEventListener('click', () => { stop(); go(1); });

  root.addEventListener('keydown', (e) => {
    if (e.target.closest('input, select, textarea')) return;
    if (e.key === 'ArrowRight') { stop(); go(step + 1); e.preventDefault(); }
    if (e.key === 'ArrowLeft') { stop(); go(step - 1); e.preventDefault(); }
  });

  // #step-N opens a step directly.
  function fromHash() {
    const m = /^#step-([1-8])$/.exec(location.hash);
    return m ? Number(m[1]) : null;
  }

  window.addEventListener('hashchange', () => {
    const n = fromHash();
    if (!n) return;
    stop();
    go(n);
    root.scrollIntoView();
  });

  // A link to the step already in the URL fires no hashchange.
  document.addEventListener('click', (e) => {
    const a = e.target.closest('a[href^="#step-"]');
    if (a && a.getAttribute('href') === location.hash) {
      e.preventDefault();
      stop();
      go(fromHash() || 1);
      root.scrollIntoView();
    }
  });

  const initial = fromHash();
  go(initial || 1);
  if (initial) root.scrollIntoView();
})();
