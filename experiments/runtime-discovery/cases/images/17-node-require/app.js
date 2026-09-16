// Requires a dependency on a signal, and records each require individually.
//
// Two logs are written, and they answer different questions.
//
//   /var/log/usage.jsonl records, in the shared format, that a file was in
//   use. Its records come from this process's own view of what it loaded.
//
//   /var/log/occurrences.jsonl records each individual require with an
//   identifier of its own: the span it covered, whether it succeeded,
//   whether it read any file at all, and which files it resolved. A
//   require of something already loaded reads nothing and is marked as
//   such, because counting it would record a missing observation for a
//   file read that never happened. This program requires the same package
//   twice on purpose, so both cases appear.
//
// The require is deliberately deferred to the moment the signal arrives.
// Requiring at startup would put the whole thing before the observation is
// in place, where a collector that works perfectly would still see nothing.
//
// Nothing here inspects this runtime's list of mapped files: a module
// loaded this way is read and closed, so it never appears there. That
// absence is a result this case exists to record, not an omission.

const fs = require('fs');
const http = require('http');
const path = require('path');

const USAGE_LOG = '/var/log/usage.jsonl';
const OCCURRENCE_LOG = '/var/log/occurrences.jsonl';
const FIRE_DIR = process.env.FIRE_DIR || '/run/fire';
const CASE_ID = process.env.CASE_ID || '17';
const TARGET = process.env.TARGET_MODULE || 'lodash';
const PORT = Number(process.env.PORT || 8080);

let containerID = '';
let occurrenceSeq = 0;

// starttime is field 22 of this process's status line. Field 2 is
// parenthesized and may itself contain ')', so parsing starts after the
// last one.
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
  // A nanosecond-resolution reading anchored to one wall-clock reading, so
  // the sub-second part is real rather than padded with zeros.
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

function logRequireOccurrence(starttime, start, end, ok, cacheHit, files) {
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
    cache_hit: cacheHit,
    files,
    container_id: containerID,
  });
}

// doRequire loads a module and records exactly what that load did.
//
// Whether it read anything is decided by which files appeared in the
// module cache, not by whether the call succeeded: a cached require
// succeeds too, and reads nothing.
function doRequire(starttime, name) {
  const before = new Set(Object.keys(require.cache));
  const cached = [...before].some((f) => f.includes(`/node_modules/${name}/`));
  const start = stamp();
  let ok = true;
  try {
    require(name);
  } catch (err) {
    ok = false;
    process.stderr.write(`require ${name} failed: ${err}\n`);
  }
  const end = stamp();
  const files = Object.keys(require.cache).filter((f) => !before.has(f)).sort();
  logRequireOccurrence(starttime, start, end, ok, cached || files.length === 0, files);
  for (const f of files) {
    logUsage(starttime, 'open', f, ok);
  }
  // The package's own manifest is read by the resolution itself and never
  // enters the module cache, so it is recorded separately rather than
  // being left out of the ground truth.
  for (const f of files) {
    const idx = f.lastIndexOf(`/node_modules/${name}/`);
    if (idx >= 0) {
      const manifest = path.join(f.slice(0, idx), 'node_modules', name, 'package.json');
      if (fs.existsSync(manifest)) {
        logUsage(starttime, 'open', manifest, ok);
      }
      break;
    }
  }
}

// waitForSignal blocks until something is written to the pipe. The read is
// synchronous and blocking, so the wait runs nothing and adds nothing to
// what is being counted.
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

function main() {
  const starttime = selfStarttime();
  // Each container start is its own run; a log left by a previous one
  // would be ground truth for nothing.
  fs.writeFileSync(USAGE_LOG, '');
  fs.writeFileSync(OCCURRENCE_LOG, '');
  logUsage(starttime, 'exec', process.execPath, true);

  waitForSignal();
  containerID = readContainerID();
  logUsage(starttime, 'stage', 'fired', true);

  // The first require reads the files; the second finds the module
  // already loaded and reads nothing. Both are recorded, and only the
  // first belongs in a denominator of expected file reads.
  doRequire(starttime, TARGET);
  doRequire(starttime, TARGET);

  http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('ok\n');
  }).listen(PORT, '0.0.0.0');
}

main();
