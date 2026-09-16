#!/usr/bin/env python3
"""Build a GT-B input for `match` from a run directory, resolving path ownership
independently of the collector (package DB and language-ecosystem manifests
copied out of the image with docker cp — never the collector's own mapping
code, and never by running the image).

Usage: mkgtb.py <run_dir> <image> usage_log|limited
  usage_log: uses <run_dir>/gtb-raw/usage.jsonl; maps every path in it to a package
  limited:   uses <run_dir>/gtb-raw/*.maps.txt and *.status.txt (resident processes)
Writes <run_dir>/gtb.json and <run_dir>/gtb-raw/ownership.txt

Beyond the operating-system package database (dpkg/apk), four more sources
are copied out of the image and consulted, each independent of the other:
  - Python: every site-packages/dist-packages directory found, read through
    each distribution's own RECORD (or, lacking one, installed-files.txt or
    top_level.txt for an egg-info install).
  - Node: the application's node_modules tree, read through the nearest
    enclosing package.json (this also covers pnpm's linked layout, since
    Node itself always resolves a require() to the real, already-linked
    file before this script ever sees the path).
  - JVM: any .jar this run has a local copy of, read through the Maven
    coordinates its own META-INF/maven/*/*/pom.properties entries carry
    (a fat jar can carry several), or guessed from its file name if it
    carries none.
  - Go: a statically linked binary, asked about with the host's own Go
    toolchain (`go version -m`).

A path that none of these, nor the OS database, can attribute to a package
is either left UNMAPPED (its own shape says a source above should have
been able to answer, or a resource that could have answered was never
actually read — the OS database was not copied out, or the Go toolchain
was unavailable — and either way, nothing here read enough to conclude
anything) or recorded as {"unowned": true} (its shape matches none of the
four conventions, every resource that could have answered it WAS actually
read, and none of them claimed it — an interpreter's own binary or
standard library file, say, that the image never installed through any
package manager at all). unowned is never produced from an unread or
unreachable resource standing in for a real finding.

The resolution functions below take their inputs as plain arguments rather
than closing over module state, so gtb_test.py can exercise each of them
directly, against small fixture directories, without Docker or an image.
"""
import csv, glob, io, json, os, re, shutil, subprocess, sys, tempfile, zipfile, zlib

ALIASES = [('/lib/', '/usr/lib/'), ('/lib64/', '/usr/lib64/'), ('/bin/', '/usr/bin/'), ('/sbin/', '/usr/sbin/')]

def sh(*a):
    return subprocess.run(a, capture_output=True, text=True)

def os_lookup(path, owners):
    """path -> (sorted package list, matched spelling) from the image's own
    dpkg/apk database, trying the usr-merge aliases either direction."""
    cands = [path]
    for a, b in ALIASES:
        if path.startswith(a): cands.append(b + path[len(a):])
        if path.startswith(b): cands.append(a + path[len(b):])
    for c in cands:
        if c in owners: return sorted(owners[c]), c
    return [], None

# --- Python: site-packages / dist-packages ----------------------------------

PY_SITE_CANDIDATES = (
    [f'/usr/local/lib/python3.{v}/site-packages' for v in range(6, 14)]
    + ['/usr/lib/python3/dist-packages']
    + [f'/app/.venv/lib/python3.{v}/site-packages' for v in range(6, 14)]
)

def normalize_py_name(name):
    # PEP 503: case and the choice among "-", "_" and "." are not
    # significant, and Trivy's own Python analyzer reports this form.
    return re.sub(r'[-_.]+', '-', name).lower()

def read_kv_metadata(path):
    """The first Name:/Version: lines of a METADATA or PKG-INFO file (an
    email-header-shaped format; the fields this needs are never
    continuation lines, so a line scan is enough)."""
    if not os.path.exists(path):
        return None, None
    name = version = None
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            if name is None and line.startswith('Name:'):
                name = line.split(':', 1)[1].strip()
            elif version is None and line.startswith('Version:'):
                version = line.split(':', 1)[1].strip()
            if name is not None and version is not None:
                break
    return name, version

def read_record(path):
    """The first column of every row of an installed-file RECORD: the path
    each row names, relative to the directory holding the .dist-info
    (usually site-packages itself, but a console script installed into
    bin/ is recorded as a "../"-relative path)."""
    out = []
    with open(path, newline='', encoding='utf-8', errors='replace') as f:
        for row in csv.reader(f):
            if row and row[0]:
                out.append(row[0])
    return out

def egg_info_metadata(egg_dir):
    name, version = read_kv_metadata(os.path.join(egg_dir, 'PKG-INFO'))
    if name:
        return name, version
    # No PKG-INFO (an editable/develop install can lack one): the
    # directory's own name is "<name>-<version>.egg-info", or just
    # "<name>.egg-info" with no version recorded at all.
    base = os.path.basename(egg_dir)[: -len('.egg-info')]
    m = re.match(r'^(.+)-([0-9][0-9A-Za-z.]*)$', base)
    return (m.group(1), m.group(2)) if m else (base, None)

def build_python_index(site_roots):
    """site_roots: [(image-absolute site-packages dir, local copy of it)].
    Returns (exact, prefixes): exact maps an absolute image path to the set
    of normalized distribution names that own it (from a RECORD or an
    egg-info's installed-files.txt); prefixes is a list of (directory,
    dist) pairs for the coarser egg-info fallback, where only
    top_level.txt's package/module names are known, not the files under
    them."""
    exact = {}
    prefixes = []
    for image_dir, local_dir in site_roots:
        if not os.path.isdir(local_dir):
            continue
        for entry in sorted(os.listdir(local_dir)):
            full = os.path.join(local_dir, entry)
            if entry.endswith('.dist-info') and os.path.isdir(full):
                name, _ = read_kv_metadata(os.path.join(full, 'METADATA'))
                record = os.path.join(full, 'RECORD')
                if name and os.path.exists(record):
                    dist = normalize_py_name(name)
                    for rel in read_record(record):
                        abs_path = os.path.normpath(os.path.join(image_dir, rel))
                        exact.setdefault(abs_path, set()).add(dist)
            elif entry.endswith('.egg-info') and os.path.isdir(full):
                # image_egg_dir is where this egg-info actually lives
                # inside the image, as opposed to full, which is only
                # where this run happened to copy it to on local disk.
                # installed-files.txt's relative entries are the egg-info
                # directory's own neighbors in the image, and resolving
                # them against the local copy's path instead would
                # produce a path nothing will ever observe.
                image_egg_dir = os.path.join(image_dir, entry)
                name, _ = egg_info_metadata(full)
                if not name:
                    continue
                dist = normalize_py_name(name)
                installed = os.path.join(full, 'installed-files.txt')
                top_level = os.path.join(full, 'top_level.txt')
                if os.path.exists(installed):
                    # Paths here are relative to the egg-info directory
                    # itself, per setuptools' own record-writer.
                    for line in open(installed, errors='replace'):
                        rel = line.strip()
                        if not rel:
                            continue
                        abs_path = rel if rel.startswith('/') else os.path.normpath(os.path.join(image_egg_dir, rel))
                        exact.setdefault(abs_path, set()).add(dist)
                elif os.path.exists(top_level):
                    for line in open(top_level, errors='replace'):
                        mod = line.strip()
                        if not mod:
                            continue
                        exact.setdefault(os.path.join(image_dir, mod + '.py'), set()).add(dist)
                        prefixes.append((os.path.join(image_dir, mod) + '/', dist))
    return exact, prefixes

def pycache_to_source(path):
    """The .py a compiled cache file was generated from. A RECORD often
    lists the .pyc directly (pip can compile on install), but an
    egg-info's coarser manifests do not, so a lookup on the compiled path
    alone can miss what the source path would have found."""
    if not path.endswith('.pyc'):
        return None
    d, base = os.path.split(path)
    if os.path.basename(d) != '__pycache__':
        return None
    name = base[:-len('.pyc')]
    dot = name.find('.')
    if dot >= 0:
        name = name[:dot]
    return os.path.join(os.path.dirname(d), name + '.py')

def python_owner(path, py_exact, py_prefixes):
    if path in py_exact:
        return sorted(py_exact[path])
    src = pycache_to_source(path)
    if src and src in py_exact:
        return sorted(py_exact[src])
    for prefix, dist in py_prefixes:
        if path == prefix.rstrip('/') or path.startswith(prefix):
            return [dist]
    return None

def looks_like_site_packages(path):
    return '/site-packages/' in path or '/dist-packages/' in path

# --- Node: node_modules ------------------------------------------------------

def app_local_path(app_local, image_path):
    if app_local is None or not image_path.startswith('/app/'):
        return None
    return os.path.join(app_local, image_path[len('/app/'):])

def node_package_dir(path):
    """The nearest enclosing node_modules package directory — the deepest
    "/node_modules/<name>/" (or scoped "@scope/<name>/") in the path, which
    is the same boundary both npm's plain layout and pnpm's
    content-addressed one resolve a require() to."""
    marker = '/node_modules/'
    idx = path.rfind(marker)
    if idx < 0:
        return None
    rest = path[idx + len(marker):]
    if not rest:
        return None
    parts = rest.split('/')
    name = parts[0]
    if name.startswith('@'):
        if len(parts) < 2:
            return None
        name = name + '/' + parts[1]
    return path[:idx + len(marker)] + name

def node_owner(path, app_local):
    pkg_dir = node_package_dir(path)
    if pkg_dir is None:
        return None
    local = app_local_path(app_local, pkg_dir + '/package.json')
    if local is None or not os.path.exists(local):
        return None
    try:
        with open(local, encoding='utf-8', errors='replace') as f:
            data = json.load(f)
    except (ValueError, OSError):
        return None
    name = data.get('name')
    return [name] if name else None

# --- JVM: jar archives --------------------------------------------------------

POM_PROPERTIES_RE = re.compile(r'^META-INF/maven/[^/]+/[^/]+/pom\.properties$')
JAR_NAME_RE = re.compile(r'^(?P<artifact>.+)-(?P<version>[0-9][0-9A-Za-z.+_-]*?)\.jar$')

def jar_filename_guess(path):
    """A name recovered from a jar's own file name — reference information
    only, never a real answer: Trivy's own name for a jar package is
    "group:artifact", and a bare artifact name guessed this way (with no
    group, and possibly not even the right artifact split) will not match
    that shape and must never be written into path_packages as if it did."""
    m = JAR_NAME_RE.match(os.path.basename(path))
    return m.group('artifact') if m else None

def _pom_properties_scan(zf):
    """Scans one open zip's own META-INF/maven/*/*/pom.properties entries
    — not ones inside a jar nested within it; the caller walks those
    separately. Returns (owners, incomplete): owners is every complete
    groupId:artifactId this zip's own pom.properties files name;
    incomplete is True when at least one pom.properties was found but did
    not carry both fields. A jar in that state is confirmed to be a real
    Maven-built artifact — nothing but Maven's own build writes this file
    at all — whose exact coordinates this run simply could not read
    completely, which must never be treated the same as a jar with no
    Maven bookkeeping in it whatsoever."""
    owners = set()
    incomplete = False
    for name in zf.namelist():
        if not POM_PROPERTIES_RE.match(name):
            continue
        props = {}
        try:
            raw = zf.read(name)
        except (zipfile.BadZipFile, OSError, RuntimeError, zlib.error):
            # A pom.properties that exists but cannot be read (CRC
            # mismatch, truncated member) is Maven bookkeeping whose
            # coordinates this run could not read: incomplete, never
            # "no bookkeeping".
            incomplete = True
            continue
        for line in raw.decode('utf-8', 'replace').splitlines():
            if '=' in line and not line.strip().startswith('#'):
                k, _, v = line.partition('=')
                props[k.strip()] = v.strip()
        group, artifact = props.get('groupId'), props.get('artifactId')
        if group and artifact:
            owners.add(f'{group}:{artifact}')
        else:
            incomplete = True
    return owners, incomplete

NESTED_JAR_MAX_DEPTH = 3

def _scan_jar_bytes(data, name_for_guess, depth):
    """Recursively scans one jar's already-read bytes for Maven
    coordinates, following a jar nested inside a jar up to
    NESTED_JAR_MAX_DEPTH levels deep (a Spring-Boot-style uber-jar can
    itself carry a nested jar that carries another).

    Returns (owners, ok). owners is every complete groupId:artifactId
    found anywhere in this jar or a nested one, within the depth limit.
    ok is False when anything here could not be fully accounted for:
    unreadable bytes, an incomplete pom.properties anywhere, a nested jar
    whose file name looks like a released artifact's but that carries no
    Maven bookkeeping of its own (indistinguishable from a real third
    party that lost its metadata), or nesting deeper than this scan
    follows. owners must never be read as the complete answer, nor may
    "no owners" be read as "unowned", when ok is False — the caller is
    expected to fall back to leaving the path for a human rather than
    guessing from a partial scan.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, OSError):
        return set(), False
    with zf:
        try:
            owners, incomplete = _pom_properties_scan(zf)
            entries = zf.namelist()
        except (zipfile.BadZipFile, OSError, RuntimeError, zlib.error):
            return set(), False
        ok = not incomplete
        for entry in entries:
            if not entry.endswith('.jar'):
                continue
            if depth >= NESTED_JAR_MAX_DEPTH:
                ok = False  # nested further than this scan is willing to follow
                continue
            try:
                nested_bytes = zf.read(entry)
            except (zipfile.BadZipFile, OSError, RuntimeError, zlib.error):
                ok = False
                continue
            nested_owners, nested_ok = _scan_jar_bytes(nested_bytes, entry, depth + 1)
            owners |= nested_owners
            if not nested_ok:
                ok = False
            elif not nested_owners and jar_filename_guess(entry):
                # A nested jar with no Maven bookkeeping of its own, but a
                # file name that still looks like a released artifact's:
                # a genuine third party that lost its metadata looks
                # exactly like this, so its absence cannot be trusted as
                # an answer either.
                ok = False
    return owners, ok

def jar_owner_at(local_jar_path, image_path):
    """Resolves a .jar this run has a local copy of. Returns one of:

      ('packages', [group:artifact, ...]) — at least one
        META-INF/maven/*/*/pom.properties was found and fully read,
        either directly in the jar or inside a jar nested within it (up
        to NESTED_JAR_MAX_DEPTH levels). A fat jar can pack its
        dependencies either way: as real nested .jar files (kept as
        stored zip entries, common for a Spring-Boot-style uber-jar), or
        unpacked class-by-class and metadata-file-by-metadata-file
        alongside its own (as this experiment's own nested-archive case
        does) — both are read, and a fat jar naming more than one package
        is the normal case, not an ambiguity.
      ('unowned', None) — the jar, and every jar nested within it, was
        read in full and accounted for completely, none of them carries
        any Maven coordinates anywhere, and the outer jar's own file name
        does not even look like a released artifact's: the case's own
        compiled program, built by the case's own Dockerfile with
        nothing else packed in, looks exactly like this.
      ('unmapped', hint) — nothing above applies: the jar could not be
        read as a zip at all; something in it or in a jar nested within
        it (an incomplete pom.properties, an unreadable or too-deeply
        nested entry, a versioned-looking nested jar with no bookkeeping
        of its own) could not be fully accounted for; or the outer jar
        carries no Maven coordinates but its own file name does look
        versioned, which a real third-party jar that lost its metadata
        would look like too and this cannot tell apart from the case's
        own. hint, when not None, is a name recovered from the outer
        jar's file name for a human to check by hand — never treated as
        a real answer (see jar_filename_guess).
    """
    try:
        with open(local_jar_path, 'rb') as f:
            data = f.read()
    except OSError:
        return 'unmapped', None
    owners, ok = _scan_jar_bytes(data, image_path, depth=0)
    if owners:
        return 'packages', sorted(owners)
    if not ok:
        return 'unmapped', None
    guess = jar_filename_guess(image_path)
    return ('unmapped', guess) if guess else ('unowned', None)

# --- Go: statically linked binaries ------------------------------------------

def parse_go_version_m(output):
    """Every dependency module `go version -m` lists for a binary, with a
    "=>" replace directive resolved to what it actually replaces to.

    `go version -m` prints each dependency as a "dep" line, and, only when
    a `replace` directive in the building module's go.mod applies to it,
    an immediately following "=>" line naming what it was replaced with
    (a module path and version, or — for a replace by filesystem path,
    which never appears in a built image since it names a path on the
    machine that built the binary, not one on this one — a local path and
    "(devel)"). Trivy's own Go binary analyzer reads the identical
    runtime/debug.BuildInfo structure and reports the replacement's
    coordinates whenever one is present, so this does the same rather
    than reporting the original, pre-replace module."""
    deps = []
    prev_was_dep = False
    for line in output.splitlines():
        parts = line.split('\t')
        if len(parts) < 3:
            prev_was_dep = False
            continue
        if parts[1] == 'dep':
            deps.append(parts[2])
            prev_was_dep = True
        elif parts[1] == '=>' and prev_was_dep:
            deps[-1] = parts[2]
            prev_was_dep = False
        else:
            prev_was_dep = False
    return sorted(set(deps))

def go_scope_present(gt_b_scope):
    """Whether the case's own scope names anything shaped like a Go module
    path (a host name, containing a ".", before the first "/") — the only
    thing a Go binary can ever be attributed to. Gates the (relatively
    expensive) per-path docker cp + `go version -m` probe so it is never
    attempted for a case with nothing for it to find."""
    return any('/' in s and '.' in s.split('/')[0] for s in gt_b_scope)

# --- the resolution cascade itself -------------------------------------------

def resolve_path(path, owners, os_db_available, py_exact, py_prefixes, app_local, go_check):
    """Resolves one observed path independent of the collector under test.

    os_db_available says whether the image's own dpkg/apk database was
    actually copied and read (never whether a path was found in it): a
    path this run never got a copy of the database for cannot be
    certified as "not in it".

    go_check, when the case's scope names nothing Go-shaped, is None and
    is not consulted at all. Otherwise it is a path -> (state, deps)
    callable: state is "deps" (a Go binary, with the dependency modules in
    deps), "not_go" (a local copy was read and the host's Go toolchain
    confirmed this is not a Go binary), or "unavailable" (this could not
    be checked at all — no local copy, or no Go toolchain on the host).
    main() supplies one backed by docker cp and `go version -m`; a test
    can supply a stub, or None to skip the check.

    Returns (packages, unowned, via). packages is every package name any
    source here independently confirmed for this path, sorted — several
    sources can each confirm a different one for the same path (an
    operating-system package and the finer-grained language package it
    happens to distribute, say), and all of them are kept rather than
    stopping at the first. unowned is True only when every resource that
    could possibly have answered was actually read and none of them
    claimed the path. via records which source(s) answered, or is an
    "UNMAPPED ..." string when none did and the path is left for a human
    to map by hand.
    """
    found = {}  # package name -> first source that named it
    via_order = []

    def note(names, source):
        if not names:
            return
        for name in names:
            found.setdefault(name, source)
        via_order.append(source)

    pk, _ = os_lookup(path, owners)
    note(pk, 'os-db')

    note(python_owner(path, py_exact, py_prefixes), 'python-record')

    if '/node_modules/' in path:
        note(node_owner(path, app_local), 'node-package')

    jar_state = jar_hint = None
    if path.endswith('.jar'):
        local = app_local_path(app_local, path)
        if local is not None and os.path.exists(local):
            jar_state, jar_value = jar_owner_at(local, path)
        else:
            jar_state, jar_value = 'unmapped', None
        if jar_state == 'packages':
            note(jar_value, 'jar-pom')
        elif jar_state == 'unmapped':
            jar_hint = jar_value

    go_state = None
    if go_check is not None:
        go_state, go_value = go_check(path)
        if go_state == 'deps':
            note(go_value, 'go-version-m')

    if found:
        return sorted(found), False, '+'.join(via_order)

    # Nothing above named an owner. Before either verdict below can say
    # "unowned", every resource that could possibly have named one for
    # THIS path must have actually been read — an OS database this run
    # never got a copy of, or (when the case's scope makes a Go binary
    # relevant at all) a Go probe this run could not even run, each leave
    # a real gap this path might fall into. unowned must never come from
    # an unread resource standing in for a real finding, whether the path
    # is a jar or shaped like nothing at all.
    resources_confirmed = os_db_available and go_state != 'unavailable'
    unavailable_reason = (
        ' (OS package database unavailable)' if not os_db_available else
        ' (Go toolchain probe unavailable)' if go_state == 'unavailable' else '')

    # A .jar always gets its own dedicated verdict: "unowned" only when it
    # (and everything nested in it) was read start to finish and
    # genuinely carries no Maven coordinates anywhere; "unmapped" (with a
    # filename guess kept only as a hint, never as a real answer)
    # otherwise — including when this run has no local copy to check at
    # all, or when jar_owner_at could not fully account for it.
    if path.endswith('.jar'):
        if jar_state == 'unowned' and resources_confirmed:
            return [], True, 'unowned'
        if jar_state == 'unowned':
            return [], False, 'UNMAPPED' + unavailable_reason
        hint = f' (jar file name suggests: {jar_hint}; no pom.properties found, so not used as the answer)' if jar_hint else ''
        return [], False, 'UNMAPPED' + hint

    # A site-packages/node_modules path with no owner found is always left
    # for a human: these are locations a source above claims to cover,
    # and coming up empty there is a shortfall in that source, not a
    # finding of absence.
    if looks_like_site_packages(path) or '/node_modules/' in path:
        return [], False, 'UNMAPPED'

    # A path shaped like none of the four conventions: the absence really
    # can be the answer, but only once every resource above was actually
    # confirmed read.
    if not resources_confirmed:
        return [], False, 'UNMAPPED' + unavailable_reason
    return [], True, 'unowned'

# --- image extraction (needs docker; not exercised by the unit tests) -------

def extract_python_sites(cid, tmp):
    roots = []
    for i, image_dir in enumerate(PY_SITE_CANDIDATES):
        local_dir = f'{tmp}/py-{i}'
        if sh('docker', 'cp', f'{cid}:{image_dir}', local_dir).returncode == 0:
            roots.append((image_dir, local_dir))
    return roots

def extract_app_dir(cid, tmp):
    local = f'{tmp}/app'
    return local if sh('docker', 'cp', f'{cid}:/app', local).returncode == 0 else None

def extract_os_db(cid, tmp):
    """dpkg/apk, exactly as before this script gained the language
    resolvers above. Returns (owners, versions, available): available is
    False when neither database could even be copied out of the image, in
    which case a path absent from the (empty) owners dict has not really
    been checked against anything and must not be read as "not owned"."""
    dpkg = sh('docker', 'cp', f'{cid}:/var/lib/dpkg', f'{tmp}/dpkg').returncode == 0
    apk = sh('docker', 'cp', f'{cid}:/lib/apk/db/installed', f'{tmp}/apk-installed').returncode == 0

    owners = {}  # path -> set(package)
    versions = {}
    if dpkg:
        for lst in glob.glob(f'{tmp}/dpkg/info/*.list'):
            pkg = os.path.basename(lst)[:-5].split(':')[0]
            for line in open(lst, errors='replace'):
                p = line.rstrip('\n')
                if p: owners.setdefault(p, set()).add(pkg)
        md5s = glob.glob(f'{tmp}/dpkg/status.d/*.md5sums')  # distroless
        for f in md5s:
            pkg = os.path.basename(f)[:-8]
            for line in open(f, errors='replace'):
                parts = line.split(None, 1)
                if len(parts) == 2: owners.setdefault('/' + parts[1].strip(), set()).add(pkg)
        st = f'{tmp}/dpkg/status'
        if not os.path.exists(st) and os.path.isdir(f'{tmp}/dpkg/status.d'):
            for f in glob.glob(f'{tmp}/dpkg/status.d/*'):
                if not f.endswith('.md5sums'):
                    for line in open(f, errors='replace'):
                        if line.startswith('Package:'): cur = line.split(':', 1)[1].strip()
                        if line.startswith('Version:'): versions[cur] = line.split(':', 1)[1].strip()
        else:
            cur = None
            for line in open(st, errors='replace'):
                if line.startswith('Package:'): cur = line.split(':', 1)[1].strip()
                if line.startswith('Version:') and cur: versions[cur] = line.split(':', 1)[1].strip()
    if apk:
        cur = None; d = ''
        for line in open(f'{tmp}/apk-installed', errors='replace'):
            line = line.rstrip('\n')
            if not line: cur = None; d = ''; continue
            k, _, v = line.partition(':')
            if k == 'P': cur = v
            elif k == 'V' and cur: versions[cur] = v
            elif k == 'F': d = '/' + v
            elif k == 'R' and cur: owners.setdefault(f'{d}/{v}', set()).add(cur)
    return owners, versions, (dpkg or apk)

def _read_head(local_path, n=4):
    """The file's own first n bytes, or None when even that could not be
    read (a permission error, say) — which must never be treated as a
    confirmed answer about what the file is."""
    try:
        with open(local_path, 'rb') as f:
            return f.read(n)
    except OSError:
        return None

ELF_MAGIC = b'\x7fELF'

# Substrings `go version -m` is actually observed to print (to stderr) when
# it positively identifies a file as not a Go binary at all, as opposed to
# merely failing to read or parse one — captured from real invocations
# against a non-Go ELF binary and cross-checked against the go command's
# own source wording for the equivalent case.
GO_NOT_EXECUTABLE_MESSAGES = ('not a go executable', 'not an executable')

def classify_go_probe(returncode, stdout, stderr, local_path):
    """Classifies a `go version -m` invocation's outcome without running
    anything itself, so a test can supply a captured or synthetic
    (returncode, stdout, stderr) instead of needing a real Go toolchain or
    a real failure condition (a permission error, say) to provoke.

    Returns ("deps", modules) when it is a Go binary; ("not_go", None)
    only when this can positively confirm it is not one (the tool's own
    "not a Go executable"-shaped message, or — independent of what the
    tool says — the file's own first bytes are not the ELF magic number
    at all); ("unavailable", None) for anything else a nonzero exit or an
    unreadable file could mean — a permission error, a truncated or
    corrupted binary, a read failure — none of which say "this is not a
    Go binary", only "this could not be checked". unowned must never be
    reached by treating the second kind of failure as if it were the
    first."""
    if returncode == 0:
        deps = parse_go_version_m(stdout)
        return ('deps', deps) if deps else ('not_go', None)
    if any(msg in stderr.lower() for msg in GO_NOT_EXECUTABLE_MESSAGES):
        return 'not_go', None
    head = _read_head(local_path)
    if head is not None and head != ELF_MAGIC:
        return 'not_go', None
    return 'unavailable', None

def go_probe_result(go_bin, local_path):
    """Runs `go version -m` on a local file; see classify_go_probe for
    what the result means."""
    r = sh(go_bin, 'version', '-m', local_path)
    return classify_go_probe(r.returncode, r.stdout, r.stderr, local_path)

def make_go_check(go_bin, cid, tmp):
    """Builds the go_check callable resolve_path takes: path ->
    (state, deps). Always returns "unavailable" when go_bin is empty
    (no Go toolchain was found), rather than never being called at all —
    resolve_path needs that distinction to keep from concluding "unowned"
    for a path this run simply had no way to ask the Go toolchain about."""
    probe_count = [0]
    def go_check(path):
        if not go_bin:
            return 'unavailable', None
        local = f'{tmp}/goprobe-{probe_count[0]}'
        probe_count[0] += 1
        if sh('docker', 'cp', f'{cid}:{path}', local).returncode != 0:
            return 'unavailable', None
        return go_probe_result(go_bin, local)
    return go_check

def main():
    run, image, kind = sys.argv[1].rstrip('/'), sys.argv[2], sys.argv[3]
    case = json.load(open(f'{run}/case.json'))

    tmp = tempfile.mkdtemp(prefix='gtbdb-')
    cid = sh('docker', 'create', image).stdout.strip()
    try:
        owners, _versions, os_db_available = extract_os_db(cid, tmp)
        py_roots = extract_python_sites(cid, tmp)
        app_local = extract_app_dir(cid, tmp)
        py_exact, py_prefixes = build_python_index(py_roots)

        # Under sudo, ~ is root's home and PATH is root's; the toolchain lives
        # under the invoking user's home. Try that first, then the usual places.
        candidates = [os.environ.get('GO_BIN', '')]
        for home in (os.path.expanduser('~'), f"/home/{os.environ.get('SUDO_USER', '')}"):
            candidates.append(os.path.join(home, '.local/go/bin/go'))
        candidates += [shutil.which('go') or '', '/usr/local/go/bin/go']
        go_bin = next((c for c in candidates if c and os.path.exists(c)), '')
        # None (not just an always-"unavailable" callable) when the
        # scope names nothing Go-shaped: a case with nothing for the
        # probe to find should never pay for it, nor have it gate any
        # other path's unowned decision.
        go_check = make_go_check(go_bin, cid, tmp) if go_scope_present(case.get('gt_b_scope', [])) else None

        # --- collect the paths to attribute ---------------------------------
        paths = set()
        events = []
        if kind == 'usage_log':
            for line in open(f'{run}/gtb-raw/usage.jsonl'):
                line = line.strip()
                if not line: continue
                ev = json.loads(line); events.append(ev)
                # A stage record is the workload signaling its own progress
                # (e.g. "fired"), not a file it opened; its path is not a
                # real path and has no package to be owned by.
                if ev.get('event') == 'stage': continue
                if ev.get('path'): paths.add(ev['path'])
        else:
            for f in glob.glob(f'{run}/gtb-raw/*.maps.txt'):
                for line in open(f):
                    parts = line.split()
                    if len(parts) >= 6 and parts[5].startswith('/') and not parts[5].startswith(('/[', '/dev/', '/memfd:')):
                        paths.add(parts[5].replace(' (deleted)', ''))
            for f in glob.glob(f'{run}/gtb-raw/*.status.txt'):
                for line in open(f):
                    if line.startswith('exe=/'): paths.add(line[4:].strip())

        rows = []; pp = []; unmapped = []; used = {}
        for p in sorted(paths):
            pk, unowned, via = resolve_path(p, owners, os_db_available, py_exact, py_prefixes, app_local, go_check)
            if unowned:
                rows.append(f'{p}\tunowned\t{via}')
                pp.append({'path': p, 'package': '', 'unowned': True})
            elif pk:
                rows.append(f'{p}\t{",".join(pk)}\t{via}')
                if len(pk) > 1:
                    # A structured "packages" list, not just the first name
                    # with a note about the rest: gtb.go credits every
                    # package a path's "packages" names, and a fat jar's
                    # whole point can be the one that does not happen to
                    # sort first (log4j-core inside a fat.jar that also
                    # carries log4j-api, say).
                    entry = {'path': p, 'packages': [{'package': k} for k in pk],
                             'note': 'multiple: ' + ','.join(pk)}
                else:
                    entry = {'path': p, 'package': pk[0]}
                    if via == 'jar-filename-guess':
                        entry['note'] = 'guessed from the jar file name (no embedded Maven metadata)'
                pp.append(entry)
                for k in pk:
                    used[k] = True
            else:
                rows.append(f'{p}\t-\t{via}')
                unmapped.append(p)
        open(f'{run}/gtb-raw/ownership.txt', 'w').write('\n'.join(rows) + '\n')
    finally:
        sh('docker', 'rm', cid)

    gtb = {'case_id': case['case_id'], 'kind': kind}
    if kind == 'usage_log':
        gtb['usage_log'] = events
        gtb['path_packages'] = pp
    else:
        gtb['resident_packages'] = [{'package': k, 'used': True, 'evidence': 'mapped by a resident process (gtb-raw/*.maps.txt); ownership from the image package DB'} for k in sorted(used)]
    json.dump(gtb, open(f'{run}/gtb.json', 'w'), indent=1)
    print(f'{run}: kind={kind} paths={len(paths)} mapped={len(pp)} unmapped={len(unmapped)} packages={sorted(used)}')
    for u in unmapped: print('  UNMAPPED', u)

if __name__ == '__main__':
    main()
