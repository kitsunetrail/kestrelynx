// Coverage-validation case 27: an Express web application whose
// package.json groups about 25 directly declared npm packages into three
// groups — used_at_startup, used_lazily, and unused (see the case
// definition's coverage_plan) — run as a workload for measuring how much
// of a package inventory this harness's sampling, added mapping, and
// event evidence can independently confirm.
//
// Four logs are written, mirroring case 26's Python fixture.
//
//   /var/log/usage.jsonl records, in the shared format, that a file was
//   loaded. Its "open" records come from a before/after diff of
//   require.cache, taken around each block of startup or lazy code.
//
//   /var/log/occurrences.jsonl records each individual require block with
//   an identifier of its own, mirroring case 17's per-require occurrences.
//
//   /var/log/operations.jsonl records each step of the firing procedure
//   itself, so an independently obtained ground-truth run started from
//   the same image can be checked against the same operation sequence.
//
//   /var/log/runtime-modules.jsonl is this runtime's own introspection:
//   one record per require.cache key, written at the startup, after-lazy,
//   and periodic checkpoints below.
//
// The used_lazily group is required only inside route handlers, which
// this program calls against its own local server once fired: requiring
// them at module load would put the whole thing before the observation is
// in place.

// used_at_startup: required at module load, before the firing signal.
const express = require('express');
const cors = require('cors');
const compression = require('compression');
const morgan = require('morgan');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');

const fs = require('fs');
const http = require('http');
const path = require('path');

const USAGE_LOG = '/var/log/usage.jsonl';
const OCCURRENCE_LOG = '/var/log/occurrences.jsonl';
const OPERATIONS_LOG = '/var/log/operations.jsonl';
const RUNTIME_MODULES_LOG = '/var/log/runtime-modules.jsonl';
const FIRE_DIR = process.env.FIRE_DIR || '/run/fire';
const CASE_ID = process.env.CASE_ID || '27';
const PORT = Number(process.env.PORT || 8080);
const PERIODIC_DUMP_MS = 30000;

let containerID = '';
let occurrenceSeq = 0;
let operationSeq = 0;

function selfStarttime() {
  try {
    const content = fs.readFileSync('/proc/self/stat', 'utf8');
    const tail = content.slice(content.lastIndexOf(')') + 1).trim().split(/\s+/);
    return Number(tail[19] || 0);
  } catch {
    return 0;
  }
}

function stamp() {
  const ms = Date.now();
  const ns = process.hrtime.bigint() % 1000000n;
  const base = new Date(ms).toISOString().slice(0, 19);
  const frac = String((ms % 1000) * 1000000 + Number(ns)).padStart(9, '0');
  return `${base}.${frac}Z`;
}

function append(file, record) {
  fs.appendFileSync(file, JSON.stringify(record) + '\n');
}

function logUsage(starttime, event, p, ok) {
  append(USAGE_LOG, { ts: stamp(), pid: process.pid, starttime, event, path: p, ok });
}

function logOperation(op, ok, detail) {
  operationSeq += 1;
  const record = {
    id: `${CASE_ID}-op-${String(operationSeq).padStart(6, '0')}`,
    ts: stamp(), op, ok,
  };
  if (detail) record.detail = detail;
  append(OPERATIONS_LOG, record);
}

// runRequireBlock loads a block of code and records exactly what it did,
// mirroring case 17's doRequire: whether anything was read is decided by
// which files appeared in require.cache, not by whether the call
// succeeded.
function runRequireBlock(starttime, label, action) {
  const before = new Set(Object.keys(require.cache));
  const start = stamp();
  let ok = true;
  try {
    action();
  } catch (err) {
    ok = false;
    process.stderr.write(`${label} failed: ${err}\n`);
  }
  const end = stamp();
  const files = Object.keys(require.cache).filter((f) => !before.has(f)).sort();
  occurrenceSeq += 1;
  append(OCCURRENCE_LOG, {
    id: `${CASE_ID}-load-${String(occurrenceSeq).padStart(6, '0')}`,
    kind: 'load',
    pid: process.pid,
    tid: process.pid,
    starttime,
    start,
    end,
    ok,
    cache_hit: files.length === 0,
    files,
    container_id: containerID,
  });
  for (const f of files) {
    logUsage(starttime, 'open', f, ok);
  }
  logOperation(label, ok);
}

function lazyLodash() {
  const _ = require('lodash');
  _.chunk([1, 2, 3, 4], 2);
}

function lazyDayjs() {
  const dayjs = require('dayjs');
  dayjs().format();
}

function lazyJsYaml() {
  const yaml = require('js-yaml');
  yaml.load('case: 27\n');
}

function lazyUuid() {
  const { v4 } = require('uuid');
  v4();
}

function lazyCsvParse() {
  const { parse } = require('csv-parse/sync');
  parse('a,b\n1,2\n');
}

function lazyMustache() {
  const mustache = require('mustache');
  mustache.render('hello {{name}}', { name: 'case27' });
}

function lazyIni() {
  const ini = require('ini');
  ini.parse('[case]\nid=27\n');
}

function lazyToml() {
  const toml = require('toml');
  toml.parse('id = 27\n');
}

const LAZY_ACTIONS = {
  lodash: lazyLodash, dayjs: lazyDayjs, 'js-yaml': lazyJsYaml, uuid: lazyUuid,
  'csv-parse': lazyCsvParse, mustache: lazyMustache, ini: lazyIni, toml: lazyToml,
};

const app = express();
app.use(helmet());
app.use(cors());
app.use(compression());
app.use(morgan('combined'));
app.use(cookieParser());

app.get('/health', (_req, res) => res.status(200).send('ok\n'));

let starttime = 0;
app.get('/lazy/:name', (req, res) => {
  const action = LAZY_ACTIONS[req.params.name];
  if (!action) {
    res.status(404).send('unknown\n');
    return;
  }
  runRequireBlock(starttime, `request_lazy_${req.params.name}`, action);
  res.status(200).send(`ok ${req.params.name}\n`);
});

function dumpRuntimeModules(phase) {
  const ts = stamp();
  for (const key of Object.keys(require.cache)) {
    append(RUNTIME_MODULES_LOG, { ts, phase, runtime: 'node', file: key, resolved: true });
  }
}

function waitForSignal() {
  const fifo = path.join(FIRE_DIR, 'fire');
  if (!fs.existsSync(fifo)) {
    return;
  }
  const fd = fs.openSync(fifo, 'r');
  const buf = Buffer.alloc(256);
  try {
    fs.readSync(fd, buf, 0, buf.length, null);
  } catch {
    // the writer closed without sending anything; start anyway
  } finally {
    fs.closeSync(fd);
  }
}

function readContainerID() {
  try {
    return fs.readFileSync(path.join(FIRE_DIR, 'container-id'), 'utf8').trim();
  } catch {
    return '';
  }
}

function requestPath(p) {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port: PORT, path: p }, (res) => {
      res.resume();
      res.on('end', resolve);
    }).on('error', reject);
  });
}

async function main() {
  starttime = selfStarttime();
  // Each container start is its own run; a log left by a previous one
  // would be ground truth for nothing.
  for (const f of [USAGE_LOG, OCCURRENCE_LOG, OPERATIONS_LOG, RUNTIME_MODULES_LOG]) {
    fs.writeFileSync(f, '');
  }
  logUsage(starttime, 'exec', process.execPath, true);
  dumpRuntimeModules('startup');

  process.on('SIGTERM', () => {
    dumpRuntimeModules('final');
    process.exit(0);
  });

  waitForSignal();
  containerID = readContainerID();
  logUsage(starttime, 'stage', 'fired', true);
  logOperation('fired', true);

  await new Promise((resolve) => {
    app.listen(PORT, '0.0.0.0', resolve);
  });

  for (const name of Object.keys(LAZY_ACTIONS)) {
    // eslint-disable-next-line no-await-in-loop
    await requestPath(`/lazy/${name}`);
  }

  dumpRuntimeModules('after_lazy');
  setInterval(() => dumpRuntimeModules('periodic'), PERIODIC_DUMP_MS).unref();
}

main();
