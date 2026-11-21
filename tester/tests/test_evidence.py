import datetime
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from tester.evidence import EvidenceWriter, prepare_output, to_json_bytes
from tester.patterns import matches_credential_pattern

WHEN = datetime.datetime(2026, 11, 20, 12, 30, 5, tzinfo=datetime.timezone.utc)


class JsonTest(unittest.TestCase):
    def test_dates_become_iso_text_and_bytes_become_text(self):
        data = {"When": WHEN, "Day": datetime.date(2026, 11, 20), "Content": b"user,arn\n", "n": 1}
        self.assertEqual(json.loads(to_json_bytes(data)), {
            "When": "2026-11-20T12:30:05+00:00", "Day": "2026-11-20", "Content": "user,arn\n", "n": 1})


class WriterTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_files_and_manifest_hashes_match_contents(self):
        run_dir = prepare_output(self.tmp / "out", WHEN)
        self.assertEqual(run_dir.name, "20261120T123005Z")
        writer = EvidenceWriter(run_dir)
        entry = writer.save("C-01", "s3_ListBuckets", {"Buckets": []}, request={"operation": "ListBuckets"})
        path = run_dir / entry["path"]
        self.assertEqual(entry["path"], "C-01/001_s3_ListBuckets.json")
        self.assertEqual(entry["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())

        manifest_path, manifest_sha = writer.write_manifest({"files": writer.files})
        self.assertEqual(manifest_sha, hashlib.sha256(manifest_path.read_bytes()).hexdigest())

    def test_existing_run_folder_is_not_reused(self):
        prepare_output(self.tmp / "out", WHEN)
        with self.assertRaises(FileExistsError):
            prepare_output(self.tmp / "out", WHEN)

    def test_files_are_never_overwritten(self):
        writer = EvidenceWriter(prepare_output(self.tmp / "out", WHEN))
        writer.save("C-01", "a", {}, request={})
        writer._counters["C-01"] = 0
        with self.assertRaises(FileExistsError):
            writer.save("C-01", "a", {}, request={})

    def test_output_cannot_be_committed_even_inside_a_repository(self):
        repo = self.tmp / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        run_dir = prepare_output(repo / "my-evidence", WHEN)
        EvidenceWriter(run_dir).save("C-01", "x", {"a": 1}, request={})
        status = subprocess.run(["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=all"],
                                capture_output=True, text=True, check=True).stdout
        self.assertEqual(status, "")
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
        staged = subprocess.run(["git", "-C", str(repo), "diff", "--cached", "--name-only"],
                                capture_output=True, text=True, check=True).stdout
        self.assertEqual(staged, "")


class PatternTest(unittest.TestCase):
    def test_credential_formats_match(self):
        # Built at run time from fake parts so no credential-shaped literal is in the source.
        samples = [
            "AKIA" + "FAKE" * 4,
            "sk-ant-" + "api03-" + "x" * 30,
            "ghp_" + "A1b2" * 9,
            "-----BEGIN " + "RSA PRIVATE KEY-----",
        ]
        for sample in samples:
            with self.subTest(sample=sample[:6]):
                self.assertTrue(matches_credential_pattern(sample))

    def test_ordinary_settings_do_not_match(self):
        for value in ["claude-haiku-5-5", "harborline-loan-documents-test",
                      "arn:aws:secretsmanager:us-east-1:x:secret:harborline-ai-feature-api-key-AbCdEf",
                      "risk-assessment-model", "", None, "true"]:
            with self.subTest(value=value):
                self.assertFalse(matches_credential_pattern(value))


if __name__ == "__main__":
    unittest.main()
