import io
import json
import unittest
import urllib.error

import publish_runtimes as p


def table(updated="2026-11-16T11:58:54Z", extra=None):
    t = {"schema": 1}
    if updated is not None:
        t["updated"] = updated
    t["runtimes"] = [{"id": "node24"}] + (extra or [])
    return (json.dumps(t, indent=2) + "\n").encode()


def manifest(digest, media=p.MEDIA_TYPE, artifact=p.MEDIA_TYPE, layers=None):
    m = {
        "schemaVersion": 2,
        "mediaType": p.MANIFEST_MEDIA_TYPE,
        "artifactType": artifact,
        "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": "sha256:" + "4" * 64, "size": 2},
        "layers": layers if layers is not None else [{"mediaType": media, "digest": digest, "size": 1}],
    }
    if artifact is None:
        del m["artifactType"]
    return m


class FixedTagTest(unittest.TestCase):
    def test_tag_has_the_schema_and_the_compact_time(self):
        self.assertEqual(p.fixed_tag(table()), "1-20261116T115854Z")

    def test_a_table_without_updated_is_refused(self):
        with self.assertRaises(p.Failure):
            p.fixed_tag(table(updated=None))

    def test_a_time_with_an_offset_is_refused(self):
        with self.assertRaises(p.Failure):
            p.fixed_tag(table(updated="2026-11-16T11:58:54+00:00"))

    def test_a_time_without_seconds_is_refused(self):
        with self.assertRaises(p.Failure):
            p.fixed_tag(table(updated="2026-11-16T11:58Z"))

    def test_an_impossible_date_is_refused(self):
        with self.assertRaises(p.Failure):
            p.fixed_tag(table(updated="2026-13-45T11:58:54Z"))

    def test_another_schema_does_not_use_the_moving_tag(self):
        with self.assertRaises(p.Failure):
            p.fixed_tag(b'{"schema": 2, "updated": "2026-11-16T11:58:54Z", "runtimes": []}')

    def test_input_that_is_not_json_is_refused(self):
        with self.assertRaises(p.Failure):
            p.fixed_tag(b"not json")


class DecideTest(unittest.TestCase):
    def test_the_first_publication_publishes(self):
        self.assertTrue(p.decide(table(), None, None))

    def test_the_same_content_does_not_publish_again(self):
        t = table()
        self.assertFalse(p.decide(t, p.sha256_of(t), t))

    def test_a_changed_table_with_a_later_updated_publishes(self):
        old = table("2026-11-16T11:58:54Z")
        new = table("2026-11-23T03:24:00Z", [{"id": "node26"}])
        self.assertTrue(p.decide(new, p.sha256_of(old), old))

    def test_a_changed_table_with_the_same_updated_fails(self):
        old = table()
        new = table(extra=[{"id": "node26"}])
        with self.assertRaises(p.Failure) as c:
            p.decide(new, p.sha256_of(old), old)
        self.assertIn("needs a later updated", str(c.exception))

    def test_a_changed_table_with_an_earlier_updated_fails(self):
        old = table("2026-11-16T11:58:54Z")
        new = table("2026-11-01T00:00:00Z", [{"id": "node26"}])
        with self.assertRaises(p.Failure):
            p.decide(new, p.sha256_of(old), old)

    def test_the_candidate_must_have_updated_even_on_first_publication(self):
        with self.assertRaises(p.Failure):
            p.decide(table(updated=None), None, None)

    def test_a_published_table_without_updated_is_replaced(self):
        old = table(updated=None)
        self.assertTrue(p.decide(table(), p.sha256_of(old), old))


class ManifestTest(unittest.TestCase):
    D = "sha256:" + "a" * 64

    def test_a_good_manifest_passes(self):
        self.assertEqual(p.check_manifest(manifest(self.D), self.D)["digest"], self.D)

    def test_a_missing_artifact_type_fails(self):
        with self.assertRaises(p.Failure):
            p.check_manifest(manifest(self.D, artifact=None), self.D)

    def test_another_layer_media_type_fails(self):
        with self.assertRaises(p.Failure):
            p.check_manifest(manifest(self.D, media="application/vnd.oci.image.layer.v1.tar+gzip"), self.D)

    def test_two_layers_fail(self):
        layer = {"mediaType": p.MEDIA_TYPE, "digest": self.D, "size": 1}
        with self.assertRaises(p.Failure):
            p.check_manifest(manifest(self.D, layers=[layer, layer]), self.D)

    def test_no_layer_fails(self):
        with self.assertRaises(p.Failure):
            p.check_manifest(manifest(self.D, layers=[]), self.D)

    def test_a_different_digest_fails(self):
        with self.assertRaises(p.Failure):
            p.check_manifest(manifest("sha256:" + "b" * 64), self.D)

    def test_an_image_index_fails(self):
        m = manifest(self.D)
        m["mediaType"] = "application/vnd.oci.image.index.v1+json"
        with self.assertRaises(p.Failure):
            p.check_manifest(m, self.D)

    def test_a_manifest_that_is_not_json_fails(self):
        with self.assertRaises(p.Failure):
            p.parse_manifest(b"<html>")


class VerifyTest(unittest.TestCase):
    REPO = "ghcr.io/kitsunetrail/kestrelynx-runtimes"

    def fetcher(self, data, man=None, deny=None):
        digest = p.sha256_of(data)
        man = man or manifest(digest)

        def fetch(url, accept, token=None):
            if deny:
                raise urllib.error.HTTPError(url, deny, "denied", {}, io.BytesIO(b""))
            if "/token?" in url:
                return b'{"token": "t"}'
            if "/manifests/" in url:
                return json.dumps(man).encode()
            return data
        return fetch

    def test_a_published_table_verifies(self):
        t = table()
        p.verify_anonymously(self.REPO, t, False, self.fetcher(t))

    def test_denied_access_says_to_make_the_package_public(self):
        t = table()
        for code in (401, 403, 404):
            with self.assertRaises(p.Failure) as c:
                p.verify_anonymously(self.REPO, t, False, self.fetcher(t, deny=code))
            self.assertIn("make the package public", str(c.exception))

    def test_a_server_error_is_not_reported_as_denied(self):
        t = table()
        with self.assertRaises(p.Failure) as c:
            p.verify_anonymously(self.REPO, t, False, self.fetcher(t, deny=500))
        self.assertNotIn("public", str(c.exception))

    def test_a_layer_that_differs_from_the_table_fails(self):
        t = table()
        with self.assertRaises(p.Failure):
            p.verify_anonymously(self.REPO, t, False, self.fetcher(table("2026-12-01T00:00:00Z")))

    def test_a_blob_that_does_not_match_its_digest_fails(self):
        t = table()
        fetch = self.fetcher(t)

        def tampered(url, accept, token=None):
            return b"other" if "/blobs/" in url else fetch(url, accept, token)
        with self.assertRaises(p.Failure):
            p.verify_anonymously(self.REPO, t, False, tampered)

    def test_the_wrong_layer_media_type_fails(self):
        t = table()
        bad = manifest(p.sha256_of(t), media="application/octet-stream")
        with self.assertRaises(p.Failure):
            p.verify_anonymously(self.REPO, t, False, self.fetcher(t, man=bad))

    def test_the_repository_needs_a_host_and_a_path(self):
        with self.assertRaises(p.Failure):
            p.split_repository("kestrelynx-runtimes")


if __name__ == "__main__":
    unittest.main()
