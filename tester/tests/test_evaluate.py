"""Offline tests for the evaluator (tester/evaluate.py), using the fake evidence
runs in evaluator_samples.py. No network, AWS, GitHub or AI service is used."""

import contextlib
import datetime
import hashlib
import io
import json
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tester import evaluate
from tester.evaluators import classify_action, denies_insecure_transport, tls_minimum
from tester.integrity import IntegrityError, verify_run
from tester.tests import evaluator_samples as samples

CODE = {"commit": "e" * 40, "uncommitted_changes_in_tester_or_controls": False}
LATER = datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc)  # long after collection


class EvaluatorTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self._tmp.name) / "20261120T120000Z"
        self.run_dir.mkdir()
        self.sample = samples.SampleRun()

    def tearDown(self):
        self._tmp.cleanup()

    def run_evaluator(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = evaluate.main(["--run", str(self.run_dir), *extra], repo_root=samples.REPO_ROOT,
                                 code_version=lambda root: CODE, now=lambda: LATER)
        return code, out.getvalue(), err.getvalue()

    def evaluate(self):
        self.manifest_path, self.manifest_sha = self.sample.write(self.run_dir)
        code, out, err = self.run_evaluator()
        self.assertIn(code, (0, 1), err)
        self.out = out
        self.results = json.loads((self.run_dir / "results.json").read_text())
        return self.results

    def control(self, cid):
        return next(c for c in self.results["controls"] if c["id"] == cid)

    def check(self, check_id):
        control = self.control(check_id[:4])
        return next(c for c in control["checks"] if c["id"] == check_id)

    def assertResult(self, check_id, result):
        check = self.check(check_id)
        self.assertEqual(check["result"], result, json.dumps(check, indent=1))
        return check


class SampleRunTest(EvaluatorTestCase):
    def test_clean_sample_passes_every_control_and_writes_results(self):
        results = self.evaluate()
        for control in results["controls"]:
            for check in control["checks"]:
                self.assertEqual(check["result"], "pass", f"{check['id']}: {check['reason']}")
            self.assertEqual(control["result"], "pass")
        self.assertEqual(results["run"]["manifest_sha256"], self.manifest_sha)
        self.assertEqual(results["run"]["manifest_sha256"],
                         hashlib.sha256(self.manifest_path.read_bytes()).hexdigest())
        self.assertEqual(results["evaluator"]["code"]["commit"], "e" * 40)
        self.assertTrue(results["control_library"]["same_as_collection"])
        self.assertTrue((self.run_dir / "results.md").read_text().startswith("# Control test results"))
        lines = [line for line in self.out.splitlines() if line.startswith("C-0")]
        self.assertEqual([line.split()[0] for line in lines], [f"C-0{n}" for n in range(1, 8)])
        self.assertTrue(all(" PASS " in line for line in lines))

    def test_every_check_records_population_and_hashed_evidence(self):
        results = self.evaluate()
        manifest = json.loads(self.manifest_path.read_text())
        hashes = {f["path"]: f["sha256"] for f in manifest["files"]}
        for control in results["controls"]:
            for check in control["checks"]:
                self.assertTrue(check["population"], check["id"])
                self.assertTrue(check["evidence"], check["id"])
                for ref in check["evidence"]:
                    self.assertEqual(hashes[ref["path"]], ref["sha256"])

    def test_left_out_resources_are_listed_with_reasons(self):
        self.evaluate()
        excluded = {e["item"]: e["reason"] for e in self.check("C-01.1")["excluded"]}
        self.assertIn("purpose=audit-log", excluded[f"bucket {samples.LOG_BUCKET}"])
        self.assertIn("not tagged scope=harborline", excluded[f"bucket {samples.OTHER_BUCKET}"])
        tested = [p["item"] for p in self.check("C-01.1")["population"]]
        self.assertEqual(tested, [f"bucket {samples.LOAN_BUCKET}"])
        c4 = {e["item"]: e["reason"] for e in self.check("C-07.4")["excluded"]}
        self.assertTrue(any("first commit" in r for r in c4.values()))

    def test_second_evaluation_replaces_results_without_tripping_the_integrity_check(self):
        self.evaluate()
        code, _, err = self.run_evaluator()
        self.assertEqual(code, 0, err)

    def test_no_network_is_used(self):
        def refuse(*args, **kwargs):
            raise AssertionError("network access attempted")
        with mock.patch.object(socket.socket, "connect", refuse), mock.patch.object(socket, "create_connection",
                                                                                     refuse):
            self.evaluate()

    def test_evaluator_does_not_load_the_aws_sdk(self):
        code = "import sys, tester.evaluate; print('boto3' in sys.modules or 'botocore' in sys.modules)"
        result = subprocess.run([sys.executable, "-c", code], cwd=samples.REPO_ROOT, capture_output=True,
                                text=True, check=True)
        self.assertEqual(result.stdout.strip(), "False")


class SeededFailureTest(EvaluatorTestCase):
    """One test per control: the seeded_failure in controls.yaml produces a fail."""

    def assertSeededFailureFails(self, cid, check_id):
        self.assertTrue(self.sample.library.controls[cid].get("seeded_failure"))
        self.evaluate()
        self.assertEqual(self.control(cid)["result"], "fail")
        self.assertResult(check_id, "fail")
        self.assertTrue(self.control(cid)["exceptions"])
        other = [c["id"] for c in self.results["controls"] if c["id"] != cid and c["result"] != "pass"]
        self.assertEqual(other, [], "the seeded failure should affect only its own control")

    def test_c01_second_tagged_bucket_on_s3_managed_encryption(self):
        # "A second tagged bucket left on default S3-managed encryption."
        self.sample.buckets["harborline-example-seeded-bucket"] = {
            "tags": dict(samples.SCOPE), "encryption": "AES256", "key": None,
            "policy": samples.bucket_policy("harborline-example-seeded-bucket"),
            "public_access": dict(samples.ALL_BLOCKED)}
        # Record its data events too, otherwise C-03.4 rightly fails for the new in-scope bucket.
        selector = self.sample.event_selectors["AdvancedEventSelectors"][0]["FieldSelectors"][2]
        selector["StartsWith"].append("arn:aws:s3:::harborline-example-seeded-bucket/")
        self.assertSeededFailureFails("C-01", "C-01.1")
        self.assertIn("harborline-example-seeded-bucket", self.check("C-01.1")["reason"])

    def test_c02_tagged_bucket_policy_without_deny_statement(self):
        # "A tagged bucket whose policy lacks the deny statement."
        self.sample.buckets[samples.LOAN_BUCKET]["policy"] = samples.bucket_policy(samples.LOAN_BUCKET, deny=False)
        self.assertSeededFailureFails("C-02", "C-02.1")

    def test_c03_log_file_validation_off(self):
        # "Log file validation turned off on the trail."
        self.sample.trail["LogFileValidationEnabled"] = False
        self.assertSeededFailureFails("C-03", "C-03.2")

    def test_c04_api_key_in_lambda_environment_variable(self):
        # "A dummy value in a recognizable API key format placed in a Lambda environment variable."
        dummy = "sk-ant-" + "FAKEDUMMY0" * 3  # built at run time; matched, then discarded like the collector
        self.sample.functions[0]["env"]["THIRD_PARTY_KEY"] = dummy
        self.assertSeededFailureFails("C-04", "C-04.2")
        self.assertNotIn(dummy, (self.run_dir / "results.json").read_text())

    def test_c05_console_user_without_mfa(self):
        # "A test user with a console password and no MFA device."
        self.sample.users.append({"user": "example-seeded-user", "password_enabled": "true", "mfa_active": "false"})
        self.assertSeededFailureFails("C-05", "C-05.1")

    def test_c06_wildcard_role_not_on_approved_list(self):
        # "A role with a wildcard policy that is not on the approved list."
        self.sample.customer_policies["harborline-example-seeded-wildcard"] = {
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        self.assertSeededFailureFails("C-06", "C-06.1")

    def test_c07_change_merged_by_bypass_without_approval(self):
        # "One change merged through an administrator bypass with no approval."
        self.sample.commits[:0] = [samples.commit("7" * 40, "Merge pull request #3", ["5" * 40, "6" * 40]),
                                   samples.commit("6" * 40, "Seeded bypass change", ["5" * 40])]
        self.sample.commit_pulls.update({"6" * 40: [3], "7" * 40: [3]})
        self.sample.pulls[3] = samples.pull(3, "Seeded bypass change", "harborline-bot", "2026-11-12T10:00:00Z",
                                            "7" * 40)
        self.sample.reviews[3] = []
        self.assertSeededFailureFails("C-07", "C-07.5")
        self.assertResult("C-07.6", "fail")
        self.assertResult("C-07.7", "fail")

    def test_every_seeded_failure_in_the_library_has_a_test(self):
        tested = {name.split("_")[1].upper().replace("C", "C-", 1) for name in dir(self) if name.startswith("test_c0")}
        seeded = {cid for cid, c in self.sample.library.controls.items() if c.get("seeded_failure")}
        self.assertEqual(seeded, tested)


class IntegrityTest(EvaluatorTestCase):
    def setUp(self):
        super().setUp()
        self.sample.write(self.run_dir)
        self.manifest = json.loads((self.run_dir / "manifest.json").read_text())
        self.first = self.run_dir / self.manifest["files"][0]["path"]

    def assertStops(self, text, *extra):
        code, out, err = self.run_evaluator(*extra)
        self.assertEqual(code, 3)
        self.assertIn("INTEGRITY CHECK FAILED", err)
        self.assertIn(text, err)
        self.assertNotIn("C-01", out)
        self.assertFalse((self.run_dir / "results.json").exists())
        self.assertFalse((self.run_dir / "results.md").exists())

    def test_missing_file_stops_evaluation(self):
        self.first.unlink()
        self.assertStops(f"missing: {self.manifest['files'][0]['path']}")

    def test_altered_file_stops_evaluation(self):
        self.first.write_text(self.first.read_text().replace("Buckets", "Buckets "))
        self.assertStops(f"altered: {self.manifest['files'][0]['path']}")

    def test_unlisted_file_stops_evaluation(self):
        (self.run_dir / "C-01" / "999_extra.json").write_text("{}")
        self.assertStops("unlisted: C-01/999_extra.json")

    def test_wrong_expected_manifest_hash_stops_evaluation(self):
        self.assertStops("not the expected", "--manifest-sha256", "0" * 64)

    def test_manifest_path_outside_run_folder_is_refused(self):
        self.manifest["files"][0]["path"] = "../outside.json"
        (self.run_dir / "manifest.json").write_text(json.dumps(self.manifest))
        with self.assertRaises(IntegrityError) as caught:
            verify_run(self.run_dir)
        self.assertTrue(any("outside the evidence files" in p for p in caught.exception.problems))

    def test_matching_expected_manifest_hash_is_accepted(self):
        digest = hashlib.sha256((self.run_dir / "manifest.json").read_bytes()).hexdigest()
        code, _, err = self.run_evaluator("--manifest-sha256", digest)
        self.assertEqual(code, 0, err)


class NotTestedTest(EvaluatorTestCase):
    def test_unreadable_tags_make_scope_unknown_not_pass(self):
        self.sample.tagging_errors[samples.OTHER_BUCKET] = "AccessDenied"
        self.evaluate()
        check = self.assertResult("C-01.1", "not_tested")
        self.assertTrue(any(samples.OTHER_BUCKET in e["item"] for e in check["excluded"]))
        self.assertEqual(self.control("C-01")["result"], "not_tested")

    def test_unfinished_collection_turns_passes_into_not_tested(self):
        self.sample.control_failures = [{"control": "C-05", "error": "RuntimeError", "message": "example",
                                         "where": "collect_c05"}]
        self.evaluate()
        self.assertEqual(self.control("C-05")["result"], "not_tested")
        self.assertTrue(all(c["result"] == "not_tested" for c in self.control("C-05")["checks"]))

    def test_unknown_tls_policy_is_not_tested(self):
        self.sample.api.pop("securityPolicy")
        self.evaluate()
        self.assertResult("C-02.2", "not_tested")


class ThresholdTest(EvaluatorTestCase):
    def test_secret_age_is_measured_from_collection_time(self):
        self.sample.secrets = [{"Name": "harborline/example-89", "created_days_ago": 89}]
        self.evaluate()  # evaluated in 2030; the secret was 89 days old when collected
        self.assertResult("C-04.1", "pass")

    def test_secret_older_than_threshold_fails(self):
        self.sample.secrets.append({"Name": "harborline/example-old", "created_days_ago": 91})
        self.evaluate()
        self.assertIn("harborline/example-old", self.assertResult("C-04.1", "fail")["reason"])

    def test_access_key_older_than_threshold_fails(self):
        self.sample.users[1]["access_key_1_last_rotated"] = samples.days_before_collection(91)
        self.evaluate()
        self.assertResult("C-05.2", "fail")

    def test_short_log_retention_fails(self):
        self.sample.buckets[samples.LOG_BUCKET]["lifecycle"][0]["Expiration"] = {"Days": 30}
        self.evaluate()
        self.assertResult("C-03.6", "fail")


class AuthorizationTest(EvaluatorTestCase):
    def test_unapproved_administrator_fails_and_star_pattern_matches(self):
        self.sample.administrators["PolicyUsers"] = [{"UserName": "example-break-glass"}]
        self.evaluate()
        check = self.assertResult("C-06.2", "fail")
        results = {p["item"]: p["result"] for p in check["population"]}
        self.assertEqual(results["role AWSReservedSSO_AdministratorAccess_0fakefake0"], "pass")
        self.assertEqual(results["user example-break-glass"], "fail")

    def test_tester_role_with_write_action_fails(self):
        self.sample.tester_inline = {"example-extra": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:PutObject", "Resource": "*"}]}}
        self.evaluate()
        self.assertResult("C-06.6", "fail")

    def test_read_only_boundary_caps_a_broad_tester_policy(self):
        self.sample.tester_inline = {"example-extra": {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}}
        self.sample.tester_boundary = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["s3:Get*", "s3:List*", "iam:Get*"], "Resource": "*"}]}
        self.evaluate()
        self.assertResult("C-06.6", "pass")

    def test_tester_role_without_secret_deny_fails(self):
        self.sample.tester_policy["Statement"] = self.sample.tester_policy["Statement"][:1]
        self.evaluate()
        self.assertResult("C-06.7", "fail")

    def test_active_external_access_finding_fails(self):
        self.sample.analyzer_findings = [{"id": "f1", "status": "ACTIVE", "findingType": "ExternalAccess",
                                          "resourceType": "AWS::S3::Bucket", "resource": "arn:aws:s3:::example"}]
        self.evaluate()
        self.assertResult("C-06.5", "fail")


class ChangeManagementTest(EvaluatorTestCase):
    def test_direct_commit_without_pull_request_fails(self):
        self.sample.commits.insert(0, samples.commit("8" * 40, "Direct push", ["5" * 40]))
        self.sample.commit_pulls["8" * 40] = []
        self.evaluate()
        self.assertIn("8" * 12, self.assertResult("C-07.4", "fail")["reason"])

    def test_self_approval_fails(self):
        self.sample.pulls[1]["user"]["login"] = "JakeGrantSec"
        self.evaluate()
        self.assertResult("C-07.5", "pass")
        self.assertResult("C-07.6", "fail")

    def test_approval_after_merge_fails(self):
        self.sample.reviews[1] = [samples.review("JakeGrantSec", "APPROVED", "2026-11-10T11:00:00Z")]
        self.evaluate()
        self.assertResult("C-07.7", "fail")

    def test_approval_from_someone_not_on_the_list_fails(self):
        self.sample.reviews[2] = [samples.review("example-outsider", "APPROVED", "2026-11-11T09:00:00Z")]
        self.evaluate()
        self.assertResult("C-07.5", "fail")

    def test_bypass_actor_fails(self):
        self.sample.ruleset["bypass_actors"] = [{"actor_id": 5, "actor_type": "RepositoryRole",
                                                 "bypass_mode": "always"}]
        self.evaluate()
        self.assertResult("C-07.3", "fail")

    def test_first_commit_is_only_exception(self):
        self.sample.commits.append(samples.commit("9" * 40, "Second root commit", []))
        self.sample.commit_pulls["9" * 40] = []
        self.evaluate()
        self.assertResult("C-07.4", "fail")


class HelperTest(unittest.TestCase):
    def test_secure_transport_deny_must_cover_bucket_and_objects(self):
        policy = samples.bucket_policy("b")
        self.assertTrue(denies_insecure_transport(policy, "b", "aws"))
        policy["Statement"][1]["Resource"] = "arn:aws:s3:::b"
        self.assertFalse(denies_insecure_transport(policy, "b", "aws"))
        conditional = samples.bucket_policy("b")
        conditional["Statement"][1]["Condition"]["StringEquals"] = {"aws:PrincipalAccount": "x"}
        self.assertFalse(denies_insecure_transport(conditional, "b", "aws"))

    def test_tls_policy_minimums(self):
        self.assertEqual(tls_minimum("TLS_1_0"), (1, 0))
        self.assertEqual(tls_minimum("TLS_1_2"), (1, 2))
        self.assertEqual(tls_minimum("SecurityPolicy_TLS13_1_2_2021_06"), (1, 2))
        self.assertEqual(tls_minimum("SecurityPolicy_TLS13_1_3_2025_09"), (1, 3))
        self.assertIsNone(tls_minimum("SomethingNew"))

    def test_action_classification(self):
        self.assertEqual(classify_action("s3:GetObject"), "read")
        self.assertEqual(classify_action("ec2:Describe*"), "read")
        self.assertEqual(classify_action("iam:GenerateCredentialReport"), "read")
        self.assertEqual(classify_action("s3:PutObject"), "write")
        self.assertEqual(classify_action("s3:*"), "write")
        self.assertEqual(classify_action("*"), "write")
        self.assertEqual(classify_action("sts:GetSessionToken"), "write")
        self.assertEqual(classify_action("sts:Get*"), "write")
        self.assertEqual(classify_action("s3:*Object"), "unknown")
        self.assertEqual(classify_action("cloudformation:DetectStackDrift"), "unknown")


if __name__ == "__main__":
    unittest.main()
