#!/usr/bin/env python3
"""Unit tests for the pure resolution functions in gtb.py, against small
fixture directories built on the fly — no Docker, no image, and none of the
functions here touch a container. Run with:

  python3 -m unittest discover -s tools -p 'gtb_test.py'
  python3 tools/gtb_test.py
"""
import io, json, os, sys, tempfile, unittest, zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gtb


class PythonRecordTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.site = os.path.join(self.tmp.name, 'site-packages')
        os.makedirs(self.site)

    def tearDown(self):
        self.tmp.cleanup()

    def _write_dist_info(self, dist_dir_name, name, version, record_rows):
        d = os.path.join(self.site, dist_dir_name)
        os.makedirs(d)
        with open(os.path.join(d, 'METADATA'), 'w') as f:
            f.write(f'Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n')
        with open(os.path.join(d, 'RECORD'), 'w', newline='') as f:
            for rel in record_rows:
                f.write(f'{rel},,\n')

    def test_dist_info_record_resolves_package_and_pycache(self):
        # A wheel install: RECORD lists both the source file and the
        # __pycache__ compiled copy directly, as pip itself does when it
        # compiles on install.
        self._write_dist_info('cryptography-41.0.0.dist-info', 'cryptography', '41.0.0', [
            'cryptography/__init__.py',
            'cryptography/__pycache__/__init__.cpython-312.pyc',
            'cryptography/hazmat/bindings/_rust.abi3.so',
        ])
        exact, prefixes = gtb.build_python_index([(self.site, self.site)])
        self.assertEqual([], prefixes)
        got = gtb.python_owner(os.path.join(self.site, 'cryptography/__init__.py'), exact, [])
        self.assertEqual(['cryptography'], got)
        got = gtb.python_owner(os.path.join(self.site, 'cryptography/hazmat/bindings/_rust.abi3.so'), exact, [])
        self.assertEqual(['cryptography'], got)

    def test_pycache_falls_back_to_source_when_record_omits_compiled_copy(self):
        # Some installers never list the .pyc at all; the source is what
        # RECORD really owns, and the compiled path has to reduce to it.
        self._write_dist_info('pkg-1.0.dist-info', 'pkg', '1.0', ['pkg/mod.py'])
        exact, prefixes = gtb.build_python_index([(self.site, self.site)])
        compiled = os.path.join(self.site, 'pkg/__pycache__/mod.cpython-312.pyc')
        self.assertEqual(['pkg'], gtb.python_owner(compiled, exact, prefixes))

    def test_two_distributions_in_one_site_packages_do_not_cross_own(self):
        # A separate dependency (cffi's own C backend, say) must resolve to
        # its own distribution, not to whichever happens to be read first.
        self._write_dist_info('cryptography-41.0.0.dist-info', 'cryptography', '41.0.0',
                               ['cryptography/__init__.py'])
        self._write_dist_info('cffi-2.1.1.dist-info', 'cffi', '2.1.1',
                               ['_cffi_backend.cpython-312-x86_64-linux-gnu.so'])
        exact, _ = gtb.build_python_index([(self.site, self.site)])
        self.assertEqual(['cffi'], gtb.python_owner(
            os.path.join(self.site, '_cffi_backend.cpython-312-x86_64-linux-gnu.so'), exact, []))
        self.assertEqual(['cryptography'], gtb.python_owner(
            os.path.join(self.site, 'cryptography/__init__.py'), exact, []))

    def test_name_normalized_pep503(self):
        self.assertEqual('foo-bar', gtb.normalize_py_name('Foo_Bar'))
        self.assertEqual('foo-bar', gtb.normalize_py_name('foo.bar'))

    def test_egg_info_installed_files_resolved_against_image_path_not_local_copy(self):
        # The local copy of a site-packages directory can (and, in a real
        # run, always does) live at a different path than the directory's
        # own place in the image. installed-files.txt's relative entries
        # are the egg-info directory's neighbors IN THE IMAGE — resolving
        # them against the local copy's path instead produces a path
        # nothing will ever actually observe.
        image_dir = '/usr/lib/python3/dist-packages'
        egg = os.path.join(self.site, 'pycparser-3.0.egg-info')
        os.makedirs(egg)
        with open(os.path.join(egg, 'installed-files.txt'), 'w') as f:
            f.write('../pycparser/__init__.py\n../pycparser/c_parser.py\n')
        exact, _ = gtb.build_python_index([(image_dir, self.site)])
        self.assertEqual(['pycparser'], gtb.python_owner(
            os.path.join(image_dir, 'pycparser/__init__.py'), exact, []))
        # And it must not have been indexed under the unrelated local path.
        bogus = os.path.normpath(os.path.join(self.site, 'pycparser/__init__.py'))
        self.assertNotIn(bogus, exact)

    def test_egg_info_top_level_txt_prefix_fallback(self):
        # No RECORD, no installed-files.txt: only the module name is known,
        # so ownership can only be a prefix match under it.
        egg = os.path.join(self.site, 'widget.egg-info')
        os.makedirs(egg)
        with open(os.path.join(egg, 'top_level.txt'), 'w') as f:
            f.write('widget\n')
        exact, prefixes = gtb.build_python_index([(self.site, self.site)])
        self.assertEqual(['widget'], gtb.python_owner(
            os.path.join(self.site, 'widget/sub.py'), exact, prefixes))

    def test_path_outside_any_copied_site_packages_is_not_found(self):
        exact, prefixes = gtb.build_python_index([(self.site, self.site)])
        self.assertIsNone(gtb.python_owner('/usr/local/bin/python3.12', exact, prefixes))


class NodeModulesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = os.path.join(self.tmp.name, 'app')
        os.makedirs(self.app)

    def tearDown(self):
        self.tmp.cleanup()

    def _write_package_json(self, rel_dir, name, version):
        d = os.path.join(self.app, rel_dir)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, 'package.json'), 'w') as f:
            json.dump({'name': name, 'version': version}, f)

    def test_npm_plain_layout(self):
        self._write_package_json('node_modules/lodash', 'lodash', '4.17.15')
        got = gtb.node_owner('/app/node_modules/lodash/lodash.js', self.app)
        self.assertEqual(['lodash'], got)

    def test_pnpm_content_addressed_layout(self):
        self._write_package_json('node_modules/.pnpm/lodash@4.17.15/node_modules/lodash', 'lodash', '4.17.15')
        got = gtb.node_owner(
            '/app/node_modules/.pnpm/lodash@4.17.15/node_modules/lodash/lodash.js', self.app)
        self.assertEqual(['lodash'], got)

    def test_scoped_package(self):
        self._write_package_json('node_modules/@scope/pkg', '@scope/pkg', '1.0.0')
        got = gtb.node_owner('/app/node_modules/@scope/pkg/index.js', self.app)
        self.assertEqual(['@scope/pkg'], got)

    def test_nearest_enclosing_boundary_wins_over_an_outer_one(self):
        # A dependency that itself vendors a second copy of a package one
        # level deeper: the file belongs to the inner (nearest) one.
        self._write_package_json('node_modules/outer', 'outer', '1.0.0')
        self._write_package_json('node_modules/outer/node_modules/inner', 'inner', '2.0.0')
        got = gtb.node_owner('/app/node_modules/outer/node_modules/inner/index.js', self.app)
        self.assertEqual(['inner'], got)

    def test_missing_package_json_is_not_found(self):
        self.assertIsNone(gtb.node_owner('/app/node_modules/ghost/index.js', self.app))


class JarTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def _pom(self, group, artifact, version):
        return f'groupId={group}\nartifactId={artifact}\nversion={version}\n'

    def _make_jar(self, name, entries):
        """entries: {entry_path: bytes_content}."""
        path = os.path.join(self.tmp.name, name)
        with zipfile.ZipFile(path, 'w') as zf:
            for entry_path, content in entries.items():
                zf.writestr(entry_path, content)
        return path

    def test_single_pom_properties(self):
        jar = self._make_jar('log4j-core-2.14.1.jar', {
            'META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties':
                self._pom('org.apache.logging.log4j', 'log4j-core', '2.14.1'),
        })
        kind, value = gtb.jar_owner_at(jar, '/app/log4j-core-2.14.1.jar')
        self.assertEqual('packages', kind)
        self.assertEqual(['org.apache.logging.log4j:log4j-core'], value)

    def test_fat_jar_multiple_pom_properties_unpacked(self):
        # As this experiment's own nested-archive case packages it: the
        # dependencies' classes and metadata are unpacked directly into
        # the outer jar, not kept as separate nested .jar entries.
        jar = self._make_jar('fat.jar', {
            'META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties':
                self._pom('org.apache.logging.log4j', 'log4j-core', '2.14.1'),
            'META-INF/maven/org.apache.logging.log4j/log4j-api/pom.properties':
                self._pom('org.apache.logging.log4j', 'log4j-api', '2.14.1'),
        })
        kind, value = gtb.jar_owner_at(jar, '/app/fat.jar')
        self.assertEqual('packages', kind)
        self.assertEqual(
            ['org.apache.logging.log4j:log4j-api', 'org.apache.logging.log4j:log4j-core'], value)

    def test_fat_jar_with_real_nested_jar_files(self):
        # The Spring-Boot-style layout: each dependency is kept as an
        # actual nested .jar entry (BOOT-INF/lib/*.jar), not unpacked.
        inner_path = os.path.join(self.tmp.name, 'inner-log4j-core.jar')
        with zipfile.ZipFile(inner_path, 'w') as zf:
            zf.writestr('META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties',
                        self._pom('org.apache.logging.log4j', 'log4j-core', '2.14.1'))
        with open(inner_path, 'rb') as f:
            inner_bytes = f.read()
        jar = self._make_jar('fat.jar', {
            'BOOT-INF/lib/log4j-core-2.14.1.jar': inner_bytes,
        })
        kind, value = gtb.jar_owner_at(jar, '/app/fat.jar')
        self.assertEqual('packages', kind)
        self.assertEqual(['org.apache.logging.log4j:log4j-core'], value)

    def test_no_pom_properties_with_versioned_name_stays_unmapped_not_a_guess(self):
        # No Maven metadata anywhere, but the file name still looks like a
        # released artifact's: a real third party that lost its metadata
        # would look exactly like this too, so the name is not trusted as
        # an answer — the jar is left unmapped, with the guess kept only
        # as a hint for a human.
        jar = self._make_jar('somelib-1.2.3.jar', {})
        kind, value = gtb.jar_owner_at(jar, '/app/somelib-1.2.3.jar')
        self.assertEqual('unmapped', kind)
        self.assertEqual('somelib', value)  # a hint, not a package name

    def test_no_pom_properties_and_unversioned_name_is_unowned(self):
        # The case's own compiled program, packaged with `jar --create` and
        # nothing else built in: no Maven bookkeeping anywhere, and no
        # version in the name either.
        jar = self._make_jar('app.jar', {})
        kind, value = gtb.jar_owner_at(jar, '/app/app.jar')
        self.assertEqual('unowned', kind)
        self.assertIsNone(value)

    def test_unreadable_jar_is_left_for_a_human(self):
        bogus = os.path.join(self.tmp.name, 'broken.jar')
        with open(bogus, 'w') as f:
            f.write('not a zip file')
        kind, value = gtb.jar_owner_at(bogus, '/app/broken.jar')
        self.assertEqual('unmapped', kind)
        self.assertIsNone(value)

    def test_pom_properties_missing_groupid_stays_unmapped_not_unowned(self):
        # A pom.properties file existing at all is proof this is a real
        # Maven-built artifact — nothing else ever writes this file — so
        # a groupId (or artifactId) missing from it is a resolution
        # shortfall, not grounds to conclude the jar carries no package.
        jar = self._make_jar('log4j-core-2.14.1.jar', {
            'META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties':
                'artifactId=log4j-core\nversion=2.14.1\n',  # groupId missing
        })
        kind, value = gtb.jar_owner_at(jar, '/app/log4j-core-2.14.1.jar')
        self.assertEqual('unmapped', kind)

    def test_pom_properties_missing_artifactid_stays_unmapped_not_unowned(self):
        jar = self._make_jar('log4j-core-2.14.1.jar', {
            'META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties':
                'groupId=org.apache.logging.log4j\nversion=2.14.1\n',  # artifactId missing
        })
        kind, value = gtb.jar_owner_at(jar, '/app/log4j-core-2.14.1.jar')
        self.assertEqual('unmapped', kind)

    def test_two_levels_of_nested_versioned_jar_with_no_pom_stays_unmapped(self):
        # outer.jar -> mid.jar (no pom of its own) -> leaf-1.0.jar (no pom,
        # but a versioned name): the innermost jar looks exactly like a
        # real third-party dependency that lost its metadata, two levels
        # down, and that must block the whole chain from being called
        # unowned — not just the level it appears at.
        leaf = os.path.join(self.tmp.name, 'leaf.jar')
        with zipfile.ZipFile(leaf, 'w') as zf:
            zf.writestr('leaf.txt', 'nothing maven-shaped here')
        with open(leaf, 'rb') as f:
            leaf_bytes = f.read()
        mid = os.path.join(self.tmp.name, 'mid.jar')
        with zipfile.ZipFile(mid, 'w') as zf:
            zf.writestr('libs/leaf-1.0.jar', leaf_bytes)
        with open(mid, 'rb') as f:
            mid_bytes = f.read()
        outer = self._make_jar('outer.jar', {'libs/mid.jar': mid_bytes})
        kind, value = gtb.jar_owner_at(outer, '/app/outer.jar')
        self.assertEqual('unmapped', kind)

    def test_corrupted_nested_jar_stays_unmapped_not_unowned(self):
        # A stored entry that looks like a nested jar by name but is not
        # readable as one at all: the outer jar's own scan cannot vouch
        # for what that entry actually carries, so it cannot be unowned.
        outer = self._make_jar('outer.jar', {'libs/broken-inner.jar': b'not actually a zip'})
        kind, value = gtb.jar_owner_at(outer, '/app/outer.jar')
        self.assertEqual('unmapped', kind)

    def _crc_corrupted_jar_bytes(self, entry_name, payload):
        # Builds a zip whose one stored entry has a CRC that does not match
        # its bytes, so reading the member raises rather than returning.
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w', compression=zipfile.ZIP_STORED) as zf:
            zf.writestr(entry_name, payload)
        data = bytearray(buf.getvalue())
        pos = data.find(payload)
        assert pos >= 0
        data[pos] = (data[pos] + 1) % 256  # flip one byte of the stored member
        return bytes(data)

    def test_crc_corrupted_pom_properties_stays_unmapped_not_unowned(self):
        # Maven bookkeeping is present but its bytes cannot be read: the
        # jar is a real artifact whose coordinates this run could not
        # read, never a jar with no bookkeeping.
        payload = b'groupId=org.example\nartifactId=lib\nversion=1.0\n'
        data = self._crc_corrupted_jar_bytes('META-INF/maven/org.example/lib/pom.properties', payload)
        path = os.path.join(self.tmp.name, 'app.jar')
        with open(path, 'wb') as f:
            f.write(data)
        kind, value = gtb.jar_owner_at(path, '/app/app.jar')
        self.assertEqual('unmapped', kind)

    def test_crc_corrupted_nested_jar_stays_unmapped_not_unowned(self):
        # The nested jar itself is a valid zip whose one member is
        # unreadable; the failure must reach the outer jar's verdict.
        payload = b'groupId=org.example\nartifactId=inner\nversion=2.0\n'
        inner = self._crc_corrupted_jar_bytes('META-INF/maven/org.example/inner/pom.properties', payload)
        outer = self._make_jar('outer.jar', {'libs/inner.jar': inner})
        kind, value = gtb.jar_owner_at(outer, '/app/outer.jar')
        self.assertEqual('unmapped', kind)

    def test_nesting_deeper_than_the_limit_stays_unmapped(self):
        # A jar nested more levels deep than this scan is willing to
        # follow must not be silently treated as empty.
        level = None
        for i in range(gtb.NESTED_JAR_MAX_DEPTH + 2, 0, -1):
            path = os.path.join(self.tmp.name, f'level{i}.jar')
            with zipfile.ZipFile(path, 'w') as zf:
                if level is not None:
                    zf.writestr(f'inner{i}.jar', level)
                else:
                    zf.writestr('leaf.txt', 'nothing here')
            with open(path, 'rb') as f:
                level = f.read()
        outermost = os.path.join(self.tmp.name, 'outermost.jar')
        with open(outermost, 'wb') as f:
            f.write(level)
        kind, value = gtb.jar_owner_at(outermost, '/app/outermost.jar')
        self.assertEqual('unmapped', kind)


class GoScopeHeuristicTests(unittest.TestCase):
    def test_go_module_path_detected(self):
        self.assertTrue(gtb.go_scope_present(['golang.org/x/text']))

    def test_npm_and_python_and_maven_scopes_are_not_go_shaped(self):
        self.assertFalse(gtb.go_scope_present(['lodash']))
        self.assertFalse(gtb.go_scope_present(['cryptography']))
        self.assertFalse(gtb.go_scope_present(['org.apache.logging.log4j:log4j-core']))

    def test_empty_scope(self):
        self.assertFalse(gtb.go_scope_present([]))


class GoVersionMParseTests(unittest.TestCase):
    """Fixtures below are `go version -m` output actually captured from
    binaries built inside a golang:1.26 container (host go toolchain
    unavailable for a fresh build in this environment) — not hand-written
    guesses at the format."""

    NO_REPLACE = (
        "/w/main/bin: go1.26.8\n"
        "\tpath\tkestrelynx.example/case22-static-go\n"
        "\tmod\tkestrelynx.example/case22-static-go\t(devel)\t\n"
        "\tdep\tgolang.org/x/text\tv0.3.0\th1:g61tztE5qeGQ89tm6NTjjM9VPIm088od1l6aSorWRWg=\n"
        "\tbuild\t-buildmode=exe\n"
        "\tbuild\tCGO_ENABLED=0\n"
    )

    VERSION_BUMP_REPLACE = (
        "/w/bin: go1.26.8\n"
        "\tpath\texample.com/mainmod2\n"
        "\tmod\texample.com/mainmod2\t(devel)\t\n"
        "\tdep\tgolang.org/x/text\tv0.3.0\n"
        "\t=>\tgolang.org/x/text\tv0.17.0\th1:XtiM5bkSOt+ewxlOE/aE/AKEHibwj/6gvWMl9Rsh0Qc=\n"
        "\tbuild\t-buildmode=exe\n"
        "\tbuild\tCGO_ENABLED=0\n"
    )

    LOCAL_PATH_REPLACE = (
        "/w/main/bin: go1.26.8\n"
        "\tpath\texample.com/mainmod\n"
        "\tmod\texample.com/mainmod\t(devel)\t\n"
        "\tdep\texample.com/replacement\tv0.0.0\n"
        "\t=>\t../replacement\t(devel)\t\n"
        "\tbuild\t-buildmode=exe\n"
        "\tbuild\tCGO_ENABLED=0\n"
    )

    def test_no_replace_reports_the_dependency_itself(self):
        self.assertEqual(['golang.org/x/text'], gtb.parse_go_version_m(self.NO_REPLACE))

    def test_version_bump_replace_reports_the_replacement_version(self):
        # Trivy reads the identical debug.BuildInfo structure and reports
        # the replacement's coordinates whenever one applies — the same
        # module path here, but the point being tested is that the
        # replaced-to version is what gets reported, not v0.3.0.
        self.assertEqual(['golang.org/x/text'], gtb.parse_go_version_m(self.VERSION_BUMP_REPLACE))

    def test_local_path_replace_reports_the_replacement_path_verbatim(self):
        # A filesystem-path replace never appears in a built image (it
        # names a path on the machine that built the binary, not this
        # one), but `go version -m` still reports it verbatim, and this
        # mirrors that rather than special-casing it — matching whatever
        # Trivy's own parse of the same structure does with it.
        self.assertEqual(['../replacement'], gtb.parse_go_version_m(self.LOCAL_PATH_REPLACE))

    def test_multiple_deps_with_one_replaced(self):
        output = (
            "/bin: go1.26.8\n"
            "\tpath\texample.com/mainmod3\n"
            "\tdep\tgolang.org/x/net\tv0.1.0\th1:aaa=\n"
            "\tdep\tgolang.org/x/text\tv0.3.0\n"
            "\t=>\tgolang.org/x/text\tv0.17.0\th1:bbb=\n"
        )
        self.assertEqual(['golang.org/x/net', 'golang.org/x/text'], gtb.parse_go_version_m(output))

    def test_no_dependencies(self):
        self.assertEqual([], gtb.parse_go_version_m("/bin: go1.26.8\n\tpath\texample.com/solo\n"))


class GoProbeClassificationTests(unittest.TestCase):
    """classify_go_probe takes its inputs as plain arguments (see its
    docstring) so these failure modes can be tested without a real Go
    toolchain and without actually provoking a permission error — the
    (returncode, stderr) pairs below are real `go version -m` output,
    captured against /bin/ls (confirmed not-a-Go-executable), a
    nonexistent file, and a permission-denied file."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def _elf_file(self):
        # Real ELF magic bytes followed by arbitrary padding — enough for
        # the ELF-magic check, not a file `go version -m` could actually
        # parse (that distinction is exactly the point: a real go
        # invocation against a file shaped like this is expected to exit
        # non-zero with no recognizable message, which is the case this
        # test exists to cover).
        path = os.path.join(self.tmp.name, 'elfish.bin')
        with open(path, 'wb') as f:
            f.write(b'\x7fELF' + b'\x00' * 60)
        return path

    def _non_elf_file(self):
        path = os.path.join(self.tmp.name, 'plain.txt')
        with open(path, 'w') as f:
            f.write('hello\n')
        return path

    def test_confirmed_not_go_executable_message(self):
        # Captured verbatim from `go version -m /bin/ls`.
        state, value = gtb.classify_go_probe(
            1, '', '/bin/ls: could not read Go build info from /bin/ls: not a Go executable\n',
            self._elf_file())
        self.assertEqual(('not_go', None), (state, value))

    def test_non_elf_file_is_confirmed_not_go_even_with_no_message(self):
        # Captured verbatim from `go version -m` against a plain text
        # file: empty stderr, exit 1. The ELF-magic check is what tells
        # this apart from a real failure, independent of the tool's own
        # (in this case silent) diagnosis.
        state, value = gtb.classify_go_probe(1, '', '', self._non_elf_file())
        self.assertEqual(('not_go', None), (state, value))

    def test_permission_error_equivalent_stays_unavailable_not_unowned(self):
        # Captured verbatim shape from `go version -m` against a
        # permission-denied file: exit 1, stderr is just the bare file
        # name with no "not a Go executable" wording at all. The file
        # itself IS an ELF (ownership just could not be determined some
        # other way in the real case), so nothing here may conclude
        # "confirmed not Go" — it must fall through to "could not check".
        state, value = gtb.classify_go_probe(1, '', '/some/path\n', self._elf_file())
        self.assertEqual(('unavailable', None), (state, value))

    def test_nonexistent_file_read_failure_stays_unavailable(self):
        # Captured verbatim shape from `go version -m` against a path
        # that does not exist: exit 1, a "stat ...: no such file or
        # directory" stderr naming no "not a Go executable" verdict.
        missing = os.path.join(self.tmp.name, 'does-not-exist')
        state, value = gtb.classify_go_probe(
            1, '', 'stat %s: no such file or directory\n' % missing, missing)
        self.assertEqual(('unavailable', None), (state, value))

    def test_successful_run_with_dependencies(self):
        state, value = gtb.classify_go_probe(
            0, "/bin: go1.26.8\n\tdep\tgolang.org/x/text\tv0.3.0\n", '', self._elf_file())
        self.assertEqual(('deps', ['golang.org/x/text']), (state, value))


class ResolvePathCascadeTests(unittest.TestCase):
    """End-to-end checks of resolve_path's ordering and its final
    unowned-vs-UNMAPPED decision, combining fixtures for every source at
    once — the same shape a real run mixes them in."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.site = os.path.join(self.tmp.name, 'site-packages')
        self.app = os.path.join(self.tmp.name, 'app')
        os.makedirs(self.site)
        os.makedirs(self.app)
        self.owners = {'/usr/lib/x86_64-linux-gnu/libc.so.6': {'libc6'}}
        d = os.path.join(self.site, 'cryptography-41.0.0.dist-info')
        os.makedirs(d)
        with open(os.path.join(d, 'METADATA'), 'w') as f:
            f.write('Name: cryptography\nVersion: 41.0.0\n')
        with open(os.path.join(d, 'RECORD'), 'w') as f:
            f.write('cryptography/__init__.py,,\n')
        self.py_exact, self.py_prefixes = gtb.build_python_index([(self.site, self.site)])
        os.makedirs(os.path.join(self.app, 'node_modules/lodash'))
        with open(os.path.join(self.app, 'node_modules/lodash/package.json'), 'w') as f:
            json.dump({'name': 'lodash'}, f)
        # An app.jar-shaped fixture: no Maven bookkeeping, no version in
        # the name — exactly what jar_owner_at reads as "unowned" on its
        # own, so it doubles as the fixture for checking that the shared
        # availability gate still applies to a jar.
        with zipfile.ZipFile(os.path.join(self.app, 'app.jar'), 'w') as zf:
            zf.writestr('App.class', b'\xca\xfe\xba\xbe')

    def tearDown(self):
        self.tmp.cleanup()

    def _resolve(self, path, os_db_available=True, go_check=None):
        return gtb.resolve_path(path, self.owners, os_db_available,
                                   self.py_exact, self.py_prefixes, self.app, go_check)

    def test_os_db_wins_first(self):
        pk, unowned, via = self._resolve('/usr/lib/x86_64-linux-gnu/libc.so.6')
        self.assertEqual((['libc6'], False, 'os-db'), (pk, unowned, via))

    def test_python_record(self):
        pk, unowned, via = self._resolve(os.path.join(self.site, 'cryptography/__init__.py'))
        self.assertEqual((['cryptography'], False, 'python-record'), (pk, unowned, via))

    def test_node_package(self):
        pk, unowned, via = self._resolve('/app/node_modules/lodash/lodash.js')
        self.assertEqual((['lodash'], False, 'node-package'), (pk, unowned, via))

    def test_interpreter_binary_shape_matches_nothing_so_it_is_unowned(self):
        # Not under the copied site-packages, not under node_modules, not a
        # .jar: exactly the shape of a from-source language runtime binary
        # (python3.12, node, java) that the base image never registered
        # with any package manager — and the OS database WAS available and
        # actually checked, so the absence is a real finding.
        pk, unowned, via = self._resolve('/usr/local/bin/python3.12')
        self.assertEqual(([], True, 'unowned'), (pk, unowned, via))

    def test_stdlib_file_next_to_site_packages_is_also_unowned(self):
        stdlib_file = os.path.join(os.path.dirname(self.site), '__future__.py')
        pk, unowned, via = self._resolve(stdlib_file)
        self.assertEqual(([], True, 'unowned'), (pk, unowned, via))

    def test_unresolvable_site_packages_path_stays_unmapped(self):
        # This path's shape says a source above should have been able to
        # answer (it is under the copied site-packages), and none did —
        # the opposite of "confirmed no owner".
        missing = os.path.join(self.site, 'some_other_package/file.py')
        pk, unowned, via = self._resolve(missing)
        self.assertEqual(([], False, 'UNMAPPED'), (pk, unowned, via))

    def test_jar_with_no_local_copy_stays_unmapped(self):
        pk, unowned, via = self._resolve('/app/never-copied.jar')
        self.assertEqual(([], False, 'UNMAPPED'), (pk, unowned, via))

    def test_os_db_unavailable_blocks_unowned_even_when_shape_matches_nothing(self):
        # Item 1's core regression: a path that would otherwise be
        # confirmed unowned must not be, once the one resource that could
        # have contradicted it (the OS database) was never actually read.
        pk, unowned, via = self._resolve('/usr/local/bin/python3.12', os_db_available=False)
        self.assertEqual([], pk)
        self.assertFalse(unowned)
        self.assertTrue(via.startswith('UNMAPPED'))

    def test_go_probe_used_when_supplied_and_wins_over_unowned_fallback(self):
        # A path shaped like nothing resolvable (like the interpreter
        # binary case above) must still be given to the Go probe first:
        # a statically linked binary looks exactly as "unshaped" as one,
        # and this is the only way it is ever told apart from one.
        pk, unowned, via = self._resolve('/server', go_check=lambda p: ('deps', ['golang.org/x/text']))
        self.assertEqual((['golang.org/x/text'], False, 'go-version-m'), (pk, unowned, via))

    def test_go_probe_confirming_not_go_falls_through_to_unowned(self):
        pk, unowned, via = self._resolve('/usr/local/bin/node', go_check=lambda p: ('not_go', None))
        self.assertEqual(([], True, 'unowned'), (pk, unowned, via))

    def test_go_probe_unavailable_blocks_unowned(self):
        # Item 1's other regression: the case's scope wants a Go answer,
        # but this run could not get one at all (no toolchain, or no local
        # copy) — the path must not be guessed at as unowned.
        pk, unowned, via = self._resolve('/server', go_check=lambda p: ('unavailable', None))
        self.assertEqual([], pk)
        self.assertFalse(unowned)
        self.assertTrue(via.startswith('UNMAPPED'))

    def test_jar_unowned_verdict_also_needs_os_db_available(self):
        # Item 2's regression: jar_owner_at saying "unowned" on the jar's
        # own content is not enough by itself — an OS package could in
        # principle own this exact path too, and that was never checked
        # if the database itself was never read.
        pk, unowned, via = self._resolve('/app/app.jar', os_db_available=False)
        self.assertEqual([], pk)
        self.assertFalse(unowned)
        self.assertTrue(via.startswith('UNMAPPED'))

    def test_jar_unowned_verdict_confirmed_when_resources_are_available(self):
        # The positive counterpart: with the OS database actually read
        # (and no Go probe relevant here), the jar's own "unowned"
        # verdict is trusted.
        pk, unowned, via = self._resolve('/app/app.jar')
        self.assertEqual(([], True, 'unowned'), (pk, unowned, via))

    def test_os_and_language_owners_on_the_same_path_are_both_credited(self):
        # Item 5: an operating-system package and the finer-grained
        # language package it happens to distribute must both be kept,
        # not just whichever source answered first.
        path = os.path.join(self.site, 'cryptography/__init__.py')
        self.owners[path] = {'python3-cryptography'}
        pk, unowned, via = self._resolve(path)
        self.assertEqual(['cryptography', 'python3-cryptography'], pk)
        self.assertFalse(unowned)
        self.assertIn('os-db', via)
        self.assertIn('python-record', via)


if __name__ == '__main__':
    unittest.main()
