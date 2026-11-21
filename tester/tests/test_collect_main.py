"""The command as a whole: identity check, output layout, manifest, exit codes."""

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tester import collect
from tester.aws import Aws
from tester.tests.helpers import ACCOUNT, REPO_ROOT, WHEN, Stubs, fake_session

FAKE_TOKEN = "fake-read-token-" + "1" * 8
VERSION = {"commit": "f" * 40, "uncommitted_changes_in_tester_or_controls": False}


class FakeSessionFactory:
    """Returns a session whose clients are pre-stubbed, so main() can be run offline."""

    def __init__(self, caller_arn):
        self.session = fake_session()
        stub_aws = Aws(self.session)
        self.stubs = Stubs(stub_aws)
        self.stubs("sts").add_response("get_caller_identity", {
            "UserId": "AROAFAKE:session", "Account": ACCOUNT, "Arn": caller_arn}, {})
        clients = stub_aws._clients
        self.session.client = lambda service, region_name=None, config=None: clients[(service, region_name)]

    def __call__(self):
        return self.session


class MainTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.out = Path(self._tmp.name) / "out"

    def tearDown(self):
        self._tmp.cleanup()

    def _main(self, factory, collectors, environ=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.dict(collect.COLLECTORS, collectors), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = collect.main(
                ["--out", str(self.out)], session_factory=factory,
                environ={"HARBORLINE_GH_READ_TOKEN": FAKE_TOKEN} if environ is None else environ,
                now=lambda: WHEN, repo_root=REPO_ROOT, code_version=lambda root: VERSION,
                remote_url="https://github.com/harborline-fake-owner/harborline-fake-repo.git")
        return code, stdout.getvalue(), stderr.getvalue()

    def test_wrong_caller_stops_before_any_output(self):
        factory = FakeSessionFactory(f"arn:aws:sts::{ACCOUNT}:assumed-role/harborline-deployer/s")
        called = []
        code, _, err = self._main(factory, {cid: called.append for cid in collect.CONTROL_IDS})
        self.assertEqual(code, 1)
        self.assertIn("not the harborline-tester role", err)
        self.assertEqual(called, [])
        self.assertFalse(self.out.exists())

    def test_missing_github_token_stops_before_aws(self):
        factory = FakeSessionFactory(f"arn:aws:sts::{ACCOUNT}:assumed-role/harborline-tester/s")
        code, _, err = self._main(factory, {}, environ={})
        self.assertEqual(code, 1)
        self.assertIn("HARBORLINE_GH_READ_TOKEN is not set", err)
        self.assertEqual(len(factory.stubs._stubbers), 1)
        with self.assertRaises(AssertionError):  # get_caller_identity was never called.
            factory.stubs.assert_done()

    def test_manifest_lists_every_file_with_hash_and_prints_its_hash(self):
        factory = FakeSessionFactory(f"arn:aws:sts::{ACCOUNT}:assumed-role/harborline-tester/s")

        def fake_collector(control_id):
            def collector(run):
                run.writer.save(control_id, "fake", {"control": control_id, "at": WHEN}, request={"fake": True})
            return collector

        fakes = {cid: fake_collector(cid) for cid in collect.CONTROL_IDS}
        fakes["C-03"] = lambda run: (_ for _ in ()).throw(RuntimeError("fake failure"))
        code, out, err = self._main(factory, fakes)

        self.assertEqual(code, 2)  # One control did not finish.
        run_dir = self.out / "20261120T120000Z"
        manifest_path = run_dir / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        self.assertEqual(manifest["caller_identity"]["Arn"], f"arn:aws:sts::{ACCOUNT}:assumed-role/harborline-tester/s")
        self.assertNotIn("ResponseMetadata", manifest["caller_identity"])
        self.assertEqual(manifest["tester_code"], VERSION)
        self.assertEqual(manifest["collection_started_at"], "2026-11-20T12:00:00+00:00")
        self.assertEqual([f["control"] for f in manifest["files"]],
                         ["C-01", "C-02", "C-04", "C-05", "C-06", "C-07"])
        for entry in manifest["files"]:
            self.assertEqual(entry["sha256"], hashlib.sha256((run_dir / entry["path"]).read_bytes()).hexdigest())
        self.assertEqual(manifest["control_failures"][0]["control"], "C-03")
        self.assertIn("fake failure", err)

        manifest_sha = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        self.assertIn(f"manifest sha256: {manifest_sha}", out)
        self.assertEqual((self.out / ".gitignore").read_text().splitlines()[-1], "*")
        self.assertNotIn(FAKE_TOKEN, out + err + manifest_path.read_text())


if __name__ == "__main__":
    unittest.main()
