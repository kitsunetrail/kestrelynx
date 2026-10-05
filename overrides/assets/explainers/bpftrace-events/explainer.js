/*
 * Interactive explainer: how the measurement program turns a container's
 * exec and open activity into events.
 *
 * One curl run is followed in nine steps across four fixed columns: the
 * container, the bpftrace script, the lines it writes, and the converter
 * that later reads those lines and writes JSONL events. Steps 1-4 are the
 * script's work; steps 5-9 are the converter's. Values are illustrative; the
 * line layouts follow the script's output format.
 *
 * User-visible text comes from window.KLX_TEXT (text-<lang>.js).
 */
(function () {
  'use strict';

  const root = document.querySelector('[data-klx-explainer="bpftrace-events"]');
  const T = window.KLX_TEXT;
  if (!root || !T) return;

  const STEPS = 9;
  const PLAY_DELAY_MS = 4500;

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

  // Field classes color the same value wherever it appears. `src` names a
  // value so that an event field can point back at where it came from.
  const LINES = {
    E: [
      ['E'], ['1000000000'], ['4242'], ['4242', 'tid', 'e.tid'], ['57'], ['57'], ['4026532561'],
      ['11823', 'cg', 'e.cg'], ['999800000'], ['curl'], ['/usr/bin/curl', 'path', 'e.path'],
    ],
    O: [
      ['O'], ['1003000000', 'ts', 'o.ts'], ['4242'], ['4242', 'tid', 'o.tid'], ['57'], ['57'], ['4026532561'],
      ['11823', 'cg', 'o.cg'], ['999800000'], ['-100'], ['/etc/ssl/openssl.cnf', 'path', 'o.path'],
    ],
    X: [
      ['X'], ['1003050000'], ['4242'], ['4242', 'tid', 'x.tid'], ['57'], ['57'], ['4026532561'],
      ['3', 'ret', 'x.ret'], ['1003000000', 'ts', 'x.entry'],
    ],
  };

  // Event fields at step 9 and the values they were made from.
  const PROVENANCE = {
    ts: ['o.ts', 'boot'],
    tid: ['o.tid', 'x.tid'],
    path: ['o.path'],
    ok: ['x.ret'],
    ret: ['x.ret'],
    cgroup_id: ['o.cg'],
    container_id: ['o.cg', 'map.cg'],
  };

  function span(text, cls, src, extra) {
    if (!cls) return esc(text);
    return '<span class="klx-f klx-f-' + cls + (extra || '') + '"' + (src ? ' data-src="' + src + '"' : '') + '>' +
      esc(text) + '</span>';
  }

  // Render one script output line. `glow` lists src names to outline.
  function lineHTML(kind, opts) {
    const o = opts || {};
    const glow = o.glow || [];
    const parts = LINES[kind].map(([v, cls, src]) =>
      span(v, cls, src, src && glow.includes(src) ? ' is-glow' : ''));
    let cls = 'klx-rec';
    if (o.dim) cls += ' is-dim';
    if (o.fresh) cls += ' is-new';
    if (o.reading) cls += ' is-reading';
    let html = '<div class="' + cls + '">';
    if (o.reading) html += '<span class="klx-reading">' + t('ui.reading') + '</span>';
    html += '<code>' + parts.join('|') + '</code>';
    if (o.legend) html += '<span class="klx-legend">' + t('legend.' + kind) + '</span>';
    return html + '</div>';
  }

  function box(title, body, active) {
    return '<div class="klx-col' + (active ? ' is-active' : '') + '"><h3 class="klx-col-title">' + t(title) +
      '</h3><div class="klx-box">' + body + '</div></div>';
  }

  function act(key, opts) {
    const o = opts || {};
    return '<p class="klx-act' + (o.dim ? ' is-dim' : '') + (o.fresh ? ' is-new' : '') + '">' + t('container.' + key + '.label') +
      (o.note ? '<small>' + t('container.' + key + '.note') + '</small>' : '') + '</p>';
  }

  function table(head, rows, extraClass) {
    let html = '<table class="klx-t' + (extraClass ? ' ' + extraClass : '') + '"><thead><tr>' +
      head.map((x) => '<th>' + x + '</th>').join('') + '</tr></thead><tbody>';
    for (const r of rows) {
      html += '<tr' + (r.cls ? ' class="' + r.cls + '"' : '') + '>' + r.cells.map((c) => '<td>' + c + '</td>').join('') + '</tr>';
    }
    return html + '</tbody></table>';
  }

  function sub(key) {
    return '<p class="klx-sub">' + t(key) + '</p>';
  }

  function empty(key) {
    return '<p class="klx-empty">' + t(key) + '</p>';
  }

  // ---------------------------------------------------------------- observation columns (steps 1-4)

  function containerCol(step) {
    const items = [act('exec', { note: step === 1, fresh: step === 1, dim: step > 1 })];
    if (step >= 2) items.push(act('openTry', { note: step === 2, fresh: step === 2, dim: step > 2 }));
    if (step >= 3) items.push(act('opened', { note: step === 3, fresh: step === 3, dim: step > 3 }));
    if (step >= 4) items.push(act('exit', { note: step === 4, fresh: step === 4, dim: step > 4 }));
    return box('cols.container', items.join(''), step <= 4);
  }

  function rememberTable(step) {
    let body;
    if (step === 2) {
      body = table([t('script.remember.tid'), t('script.remember.start')],
        [{ cls: 'is-new', cells: [span('4242', 'tid'), span('1003000000', 'ts')] }]);
    } else if (step === 3) {
      body = table([t('script.remember.tid'), t('script.remember.start')],
        [{ cls: 'is-gone', cells: [span('4242', 'tid'), span('1003000000', 'ts', null, ' is-glow')] }]);
    } else {
      body = empty('script.remember.empty');
    }
    return sub('script.remember.title') + body;
  }

  const POINTS = ['exec', 'enter', 'exit'];

  function scriptCol(step) {
    let html = '';
    POINTS.forEach((key, i) => {
      const n = i + 1;
      if (step < n) return;
      if (step === n) {
        html += '<div class="klx-point">' + t('script.point') + '<b>' + t('script.' + key + '.point') + '</b>' +
          '<small><code>' + esc(tx('script.' + key + '.tracepoint')) + '</code></small></div>' +
          '<table class="klx-t klx-kv"><tbody>' +
          '<tr><th>' + t('script.readLabel') + '</th><td>' + t('script.' + key + '.read') + '</td></tr>' +
          '<tr><th>' + t('script.doLabel') + '</th><td>' + t('script.' + key + '.do') + '</td></tr>' +
          '</tbody></table>';
      } else {
        html += '<p class="klx-act is-dim">' + t('script.' + key + '.point') + ' → ' + t('script.' + key + '.wrote') + '</p>';
      }
    });
    if (step >= 2) html += rememberTable(step);
    return box('cols.script', html, step <= 3);
  }

  function linesCol(step, glow) {
    const reading = step >= 5 && step <= 7 ? { 5: 'E', 6: 'O', 7: 'X' }[step] : null;
    const dim = (kind) => (reading ? reading !== kind : step >= 8 ? kind === 'E' : (step >= 4 || { E: 1, O: 2, X: 3 }[kind] < step));
    const lines = [lineHTML('E', { fresh: step === 1, legend: step === 1, reading: reading === 'E', dim: dim('E') })];
    if (step >= 2) {
      lines.push(lineHTML('O', {
        fresh: step === 2, legend: step === 2, reading: reading === 'O', dim: dim('O'),
        glow: step === 6 ? ['o.tid', 'o.ts'] : glow,
      }));
    }
    if (step >= 3) {
      lines.push(lineHTML('X', {
        fresh: step === 3, legend: step === 3, reading: reading === 'X', dim: dim('X'),
        glow: step === 3 ? ['x.entry'] : step === 7 ? ['x.tid', 'x.entry'] : glow,
      }));
    }
    return box('cols.output', lines.join(''), step <= 7 && step !== 4);
  }

  // ---------------------------------------------------------------- conversion columns (steps 5-9)

  function pendingTable(step) {
    const key = span('4242', 'tid') + ' + ' + span('1003000000', 'ts');
    let body;
    if (step === 6 || step === 7) {
      body = table([t('convert.pending.key'), t('convert.pending.path')],
        [{ cls: step === 6 ? 'is-new' : 'is-gone', cells: [key, '<code>/etc/ssl/openssl.cnf</code>'] }]);
    } else {
      body = empty('convert.pending.empty');
    }
    return sub('convert.pending.title') + body;
  }

  function lookupTables(glow) {
    const g = (src) => (glow.includes(src) ? ' is-glow' : '');
    return sub('convert.cgmap.title') +
      table([t('convert.cgmap.id'), t('convert.cgmap.container'), t('convert.cgmap.valid')], [
        {
          cls: glow.includes('map.cg') ? 'is-hit' : '',
          cells: [span('11823', 'cg', 'map.cg', g('map.cg')), '<code>3f9c2a7b…</code>', t('convert.cgmap.whole')],
        },
        { cells: ['11907', '<code>8d01e5c2…</code>', t('convert.cgmap.whole')] },
      ]) +
      sub('convert.boot.title') +
      '<p class="klx-bootline' + g('boot') + '"><code>2026-09-16T05:00:00Z</code> + ' + span('1003000000', 'ts') + ' ' +
      t('convert.boot.unit') + '</p>';
  }

  function json(lines, fresh) {
    return '<pre class="klx-json' + (fresh ? ' is-new' : '') + '">' + lines.join('\n') + '</pre>';
  }

  function comment(key) {
    return '   <span class="klx-c">// ' + esc(tx(key)) + '</span>';
  }

  const EXEC_EVENT = '{"event": "exec", "path": "/usr/bin/curl", "ok": true, …}';

  function eventsHTML(step, selected) {
    if (step === 9) {
      const field = (name, value, cls) => '<button type="button" class="klx-field' + (selected === name ? ' is-selected' : '') +
        '" data-field="' + name + '" aria-pressed="' + (selected === name ? 'true' : 'false') + '">' + span(value, cls) + '</button>';
      let html = json([
        esc('{"record":"event","event":"exec","path":"/usr/bin/curl","ok":true,"container_id":"3f9c2a7b…",…}'),
        '{"record":"event","event":"open",' +
          '"ts":' + field('ts', '"2026-09-16T05:00:01.003Z"', 'ts') + ',' +
          '"tid":' + field('tid', '4242', 'tid') + ',' +
          '"path":' + field('path', '"/etc/ssl/openssl.cnf"', 'path') + ',' +
          '"ok":' + field('ok', 'true', 'ret') + ',' +
          '"ret":' + field('ret', '3', 'ret') + ',' +
          '"cgroup_id":' + field('cgroup_id', '11823', 'cg') + ',' +
          '"container_id":' + field('container_id', '"3f9c2a7b…"', 'cg') + ',…}',
      ], false);
      html += '<p class="klx-hint">' + t('convert.clickHint') + '</p>';
      if (selected) html += '<p class="klx-provenance">' + t('provenance.' + selected) + '</p>';
      return sub('convert.output') + html;
    }

    let html = sub('convert.events.title') + json([esc(EXEC_EVENT)], step === 5);
    if (step === 7) {
      html += sub('convert.combined') + json([
        '{',
        '  "event": "open",',
        '  "tid": ' + span('4242', 'tid') + ',',
        '  "raw_path": ' + span('"/etc/ssl/openssl.cnf"', 'path') + ',',
        '  "ok": ' + span('true', 'ret') + ',' + comment('convert.okComment'),
        '  "ret": ' + span('3', 'ret'),
        '}',
      ], true);
    } else if (step === 8) {
      const fill = (s) => '<span class="klx-fill">' + s + '</span>';
      html += sub('convert.finishing') + json([
        '{',
        '  "event": "open",',
        '  ' + fill('"ts": "2026-09-16T05:00:01.003Z",') + comment('convert.tsComment'),
        '  "tid": ' + span('4242', 'tid') + ',',
        '  "raw_path": ' + span('"/etc/ssl/openssl.cnf"', 'path') + ',',
        '  ' + fill('"path": ' + span('"/etc/ssl/openssl.cnf"', 'path') + ',') + comment('convert.pathComment'),
        '  ' + fill('"path_resolved": true,'),
        '  "ok": ' + span('true', 'ret') + ',',
        '  "ret": ' + span('3', 'ret') + ',',
        '  "cgroup_id": ' + span('11823', 'cg') + ',',
        '  ' + fill('"container_id": ' + span('"3f9c2a7b…"', 'cg') + ',') + comment('convert.containerComment'),
        '  ' + fill('"attribution": "container"'),
        '}',
      ], false);
    }
    return html;
  }

  function convertCol(step, glow, selected) {
    let html;
    if (step <= 4) {
      html = empty('convert.waiting');
    } else {
      if (step === 5) html = '<p class="klx-note">' + t('convert.execNote') + '</p>' + pendingTable(step);
      else if (step === 6 || step === 7) html = pendingTable(step);
      else html = lookupTables(glow);
      html += eventsHTML(step, selected);
    }
    return box('cols.convert', html, step >= 5);
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
  const explain = h('div', { class: 'klx-explain', 'aria-live': 'polite' });
  root.append(head, stage, controls, explain);

  let step = 1;
  let selected = null;
  let timer = null;

  function render() {
    head.innerHTML = '<h3 class="klx-title">' + t('steps.' + step + '.title') + '</h3>';
    counter.textContent = tx('ui.counter').replace('{i}', step).replace('{n}', STEPS);
    btnPrev.disabled = step === 1;
    btnNext.disabled = step === STEPS;
    iconButton(btnPlay, timer ? 'pause' : 'play', tx(timer ? 'ui.pause' : 'ui.play'));

    const glow = step === STEPS && selected ? PROVENANCE[selected] : [];
    stage.innerHTML = containerCol(step) + scriptCol(step) + linesCol(step, glow) + convertCol(step, glow, selected);

    const body = lookup('steps.' + step + '.body');
    const paras = Array.isArray(body) ? body : [body == null ? tx('steps.' + step + '.body') : body];
    explain.innerHTML = paras.map((p) => '<p>' + inline(p) + '</p>').join('');
  }

  // ---------------------------------------------------------------- playback

  function stop() {
    if (timer) clearInterval(timer);
    timer = null;
  }

  function go(n) {
    step = Math.max(1, Math.min(STEPS, n));
    if (step !== STEPS) selected = null;
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

  root.addEventListener('click', (e) => {
    const field = e.target.closest('[data-field]');
    if (field && root.contains(field)) {
      const name = field.dataset.field;
      selected = selected === name ? null : name;
      render();
      const again = root.querySelector('[data-field="' + name + '"]');
      if (again) again.focus();
      return;
    }
  });

  root.addEventListener('keydown', (e) => {
    if (e.target.closest('input, select, textarea')) return;
    if (e.key === 'ArrowRight') { stop(); go(step + 1); e.preventDefault(); }
    if (e.key === 'ArrowLeft') { stop(); go(step - 1); e.preventDefault(); }
  });

  // #step-N opens a step directly.
  function fromHash() {
    const m = /^#step-([1-9])$/.exec(location.hash);
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
