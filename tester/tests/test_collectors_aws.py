"""Each AWS collector run against stubbed responses. A Stubber fails the test on
any call that was not queued, so these also check the exact calls made."""

import json
import subprocess
import unittest
from pathlib import Path

from tester import collectors
from tester.tests.helpers import (ACCOUNT, REGION, REPO_ROOT, WHEN, RunTestCase, stub_bucket_inventory,
                                  stub_customer_api)

DOCS = "harborline-loan-documents-test"
AUDIT = "harborline-audit-logs-test"
OTHER = "someone-elses-bucket-test"
SCOPE = {"scope": "harborline"}
AUDIT_TAGS = {"scope": "harborline", "purpose": "audit-log"}
BUCKETS = [(DOCS, SCOPE), (AUDIT, AUDIT_TAGS), (OTHER, None)]


class C01Test(RunTestCase):
    def test_in_scope_stores_and_their_keys(self):
        stub_bucket_inventory(self.stubs, BUCKETS)
        s3 = self.stubs("s3")
        s3.add_response("get_bucket_encryption", {"ServerSideEncryptionConfiguration": {"Rules": [
            {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}, "BucketKeyEnabled": True}]}},
            {"Bucket": DOCS})

        table_arn = f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/harborline-loan-records"
        key_arn = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/fake-key-0001"
        ddb = self.stubs("dynamodb")
        ddb.add_response("list_tables", {"TableNames": ["harborline-loan-records"]}, {})
        ddb.add_response("describe_table", {"Table": {
            "TableName": "harborline-loan-records", "TableArn": table_arn,
            "SSEDescription": {"Status": "ENABLED", "SSEType": "KMS", "KMSMasterKeyArn": key_arn}}},
            {"TableName": "harborline-loan-records"})
        ddb.add_response("list_tags_of_resource", {"Tags": [{"Key": "scope", "Value": "harborline"}]},
                         {"ResourceArn": table_arn})

        kms = self.stubs("kms")
        kms.add_response("describe_key", {"KeyMetadata": {"KeyId": "fake-aws-s3", "KeyManager": "AWS"}},
                         {"KeyId": "alias/aws/s3"})
        kms.add_response("describe_key", {"KeyMetadata": {"KeyId": "fake-key-0001", "KeyManager": "CUSTOMER"}},
                         {"KeyId": key_arn})
        kms.add_response("get_key_rotation_status", {"KeyRotationEnabled": True}, {"KeyId": "fake-key-0001"})

        collectors.collect_c01(self.run)
        self.stubs.assert_done()  # The audit-log and untagged buckets were not checked.

        saved = self.saved("C-01")
        self.assertIn("004_s3_GetBucketTagging_someone-elses-bucket-test_error.json", saved)
        self.assertEqual(saved["004_s3_GetBucketTagging_someone-elses-bucket-test_error.json"]["Error"]["Code"],
                         "NoSuchTagSet")
        self.assertEqual(len(saved), 11)
        self.assertEqual(self.run.api_errors, [{"control": "C-01", "operation": "GetBucketTagging",
                                                 "code": "NoSuchTagSet"}])


class C02Test(RunTestCase):
    def test_bucket_policies_and_customer_api(self):
        stub_bucket_inventory(self.stubs, BUCKETS)
        s3 = self.stubs("s3")
        s3.add_response("get_bucket_policy", {"Policy": "{}"}, {"Bucket": DOCS})
        s3.add_client_error("get_bucket_policy", "NoSuchBucketPolicy", http_status_code=404,
                            expected_params={"Bucket": AUDIT})
        stub_customer_api(self.stubs, with_details=True)
        self.stubs("apigateway").add_response("get_domain_names", {"items": []}, {})

        collectors.collect_c02(self.run)
        self.stubs.assert_done()
        names = list(self.saved("C-02"))
        self.assertIn("006_s3_GetBucketPolicy_harborline-audit-logs-test_error.json", names)
        self.assertTrue(any("GetMethod_fakeapi01_fakeres1_POST" in n for n in names))


class C03Test(RunTestCase):
    def test_trail_calls_go_to_its_home_region(self):
        trail_arn = f"arn:aws:cloudtrail:us-west-2:{ACCOUNT}:trail/harborline-audit-trail"
        self.stubs("cloudtrail").add_response("describe_trails", {"trailList": [{
            "Name": "harborline-audit-trail", "TrailARN": trail_arn, "HomeRegion": "us-west-2",
            "S3BucketName": AUDIT, "IsMultiRegionTrail": True, "LogFileValidationEnabled": True}]},
            {"includeShadowTrails": True})
        home = self.stubs("cloudtrail", "us-west-2")
        home.add_response("get_trail_status", {"IsLogging": True}, {"Name": trail_arn})
        home.add_response("get_event_selectors", {"TrailARN": trail_arn, "EventSelectors": []},
                          {"TrailName": trail_arn})
        stub_bucket_inventory(self.stubs, BUCKETS)
        s3 = self.stubs("s3")
        s3.add_response("get_public_access_block", {"PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True}}, {"Bucket": AUDIT})
        s3.add_response("get_bucket_lifecycle_configuration", {"Rules": [
            {"ID": "harborline-expire", "Status": "Enabled", "Expiration": {"Days": 365}, "Filter": {}}]},
            {"Bucket": AUDIT})

        collectors.collect_c03(self.run)
        self.stubs.assert_done()
        saved = self.saved("C-03")
        status = next(v for k, v in saved.items() if "GetTrailStatus" in k)
        self.assertTrue(status["IsLogging"])


class C04Test(RunTestCase):
    def setUp(self):
        super().setUp()
        # Fake values built at run time; they must never reach disk or stdout.
        self.fake_key = "AKIA" + "FAKE" * 4
        self.plain_value = "plain-setting-" + "value-42"
        self.gitleaks_calls = []
        self.report_findings = [{"RuleID": "github-pat", "Secret": "REDACTED", "Match": "REDACTED",
                                 "Commit": "fake", "File": "a.txt"}]
        self.run.gitleaks_bin = "/fake/bin/gitleaks"
        self.run.runner = self._fake_runner

    def _fake_runner(self, cmd, **kwargs):
        self.gitleaks_calls.append(cmd)
        if cmd[1] == "version":
            return subprocess.CompletedProcess(cmd, 0, stdout="8.30.1\n", stderr="")
        report = next(a.split("=", 1)[1] for a in cmd if a.startswith("--report-path="))
        Path(report).write_text(json.dumps(self.report_findings))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="WRN leaks found: 1\n")

    def _stub_secrets_and_lambda(self):
        secret_arn = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:harborline-ai-feature-api-key-FaKeIt"
        sm = self.stubs("secretsmanager")
        sm.add_response("list_secrets", {"SecretList": [{"ARN": secret_arn, "Name": "harborline-ai-feature-api-key"}]}, {})
        sm.add_response("list_secret_version_ids", {"ARN": secret_arn, "NextToken": "fake-next", "Versions": [
            {"VersionId": "fake-version-" + "2" * 20, "VersionStages": ["AWSCURRENT"], "CreatedDate": WHEN}]}, {"SecretId": secret_arn})
        sm.add_response("list_secret_version_ids", {"ARN": secret_arn, "Versions": [
            {"VersionId": "fake-version-" + "1" * 20, "VersionStages": ["AWSPREVIOUS"], "CreatedDate": WHEN}]},
            {"SecretId": secret_arn, "NextToken": "fake-next"})

        fn_arn = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:harborline-loan-summarizer"
        env = {"Variables": {"MODEL_ID": self.plain_value, "LEAKED": self.fake_key}}
        lam = self.stubs("lambda")
        lam.add_response("list_functions", {"Functions": [
            {"FunctionName": "harborline-loan-summarizer", "FunctionArn": f"{fn_arn}:$LATEST",
             "Version": "$LATEST", "Environment": env},
            {"FunctionName": "harborline-loan-summarizer", "FunctionArn": f"{fn_arn}:1",
             "Version": "1", "Environment": env},
        ]}, {"FunctionVersion": "ALL"})
        lam.add_response("list_tags", {"Tags": {"scope": "harborline"}}, {"Resource": fn_arn})

    def test_secret_metadata_lambda_names_and_gitleaks(self):
        self._stub_secrets_and_lambda()
        collectors.collect_c04(self.run)
        self.stubs.assert_done()

        saved = self.saved("C-04")
        functions = next(v for k, v in saved.items() if "ListFunctions" in k)["Functions"]
        for function in functions:
            self.assertNotIn("Variables", function["Environment"])
            self.assertEqual(function["Environment"]["VariableNames"], [
                {"Name": "LEAKED", "MatchesCredentialPattern": True},
                {"Name": "MODEL_ID", "MatchesCredentialPattern": False},
            ])
        output = self.all_output_text()
        self.assertNotIn(self.fake_key, output)
        self.assertNotIn(self.plain_value, output)

        self.assertEqual(sum("ListSecretVersionIds" in k for k in saved), 2)

        command = self.gitleaks_calls[1]
        self.assertEqual(command[1:3], ["git", str(REPO_ROOT)])
        self.assertIn("--redact=100", command)
        self.assertIn("--log-opts=--all --full-history", command)
        report = next(v for k, v in saved.items() if "gitleaks_report" in k)
        self.assertEqual(report, self.report_findings)
        report_entry = next(e for e in self.writer.files if "gitleaks_report" in e["path"])
        self.assertIn("sha256", report_entry)

    def test_unredacted_gitleaks_report_is_deleted(self):
        self._stub_secrets_and_lambda()
        self.report_findings = [{"RuleID": "x", "Secret": "not-redacted-fake", "Match": "REDACTED"}]
        with self.assertRaises(RuntimeError):
            collectors.collect_c04(self.run)
        self.assertNotIn("not-redacted-fake", self.all_output_text())
        self.assertFalse(any("gitleaks_report" in e["path"] for e in self.writer.files))


class C05Test(RunTestCase):
    def test_credential_report_polling_account_summary_and_methods(self):
        iam = self.stubs("iam")
        iam.add_response("generate_credential_report", {"State": "STARTED"}, {})
        iam.add_response("generate_credential_report", {"State": "COMPLETE"}, {})
        iam.add_response("get_credential_report", {"Content": b"user,arn\n<root_account>,fake\n",
                                                   "ReportFormat": "text/csv", "GeneratedTime": WHEN}, {})
        iam.add_response("get_account_summary", {"SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}}, {})
        stub_customer_api(self.stubs)

        collectors.collect_c05(self.run)
        self.stubs.assert_done()
        self.assertEqual(self.sleeps, [collectors.CREDENTIAL_REPORT_WAIT_SECONDS])
        saved = self.saved("C-05")
        report = next(v for k, v in saved.items() if "GetCredentialReport" in k)
        self.assertEqual(report["Content"], "user,arn\n<root_account>,fake\n")
        self.assertEqual(report["GeneratedTime"], "2026-11-20T12:00:00+00:00")
        method = next(v for k, v in saved.items() if "GetMethod" in k)
        self.assertEqual(method["authorizationType"], "AWS_IAM")


class C06Test(RunTestCase):
    def test_policies_admins_public_access_analyzer_and_tester_role(self):
        iam = self.stubs("iam")
        policy_arn = f"arn:aws:iam::{ACCOUNT}:policy/harborline-fake-policy"
        iam.add_response("list_policies", {"Policies": [
            {"PolicyName": "harborline-fake-policy", "Arn": policy_arn, "DefaultVersionId": "v2"}]}, {"Scope": "Local"})
        iam.add_response("get_policy_version", {"PolicyVersion": {"Document": "{}", "VersionId": "v2"}},
                         {"PolicyArn": policy_arn, "VersionId": "v2"})
        iam.add_response("list_entities_for_policy", {"PolicyRoles": [
            {"RoleName": "AWSReservedSSO_AdministratorAccess_fake"}]},
            {"PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})

        self.stubs("s3control").add_response("get_public_access_block", {"PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True}}, {"AccountId": ACCOUNT})
        stub_bucket_inventory(self.stubs, BUCKETS)
        s3 = self.stubs("s3")
        for bucket in (DOCS, AUDIT):
            s3.add_response("get_public_access_block", {"PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True}}, {"Bucket": bucket})

        analyzer_arn = f"arn:aws:access-analyzer:{REGION}:{ACCOUNT}:analyzer/harborline-access-analyzer"
        aa = self.stubs("accessanalyzer")
        aa.add_response("list_analyzers", {"analyzers": [{"arn": analyzer_arn, "name": "harborline-access-analyzer",
                                                          "type": "ACCOUNT", "createdAt": WHEN, "status": "ACTIVE"}]}, {})
        aa.add_response("list_archive_rules", {"archiveRules": []}, {"analyzerName": "harborline-access-analyzer"})
        aa.add_response("list_findings_v2", {"findings": []},
                        {"analyzerArn": analyzer_arn, "filter": {"status": {"eq": ["ACTIVE"]}}})

        readonly = "arn:aws:iam::aws:policy/ReadOnlyAccess"
        iam.add_response("get_role", {"Role": {"Path": "/", "RoleName": "harborline-tester", "RoleId": "AROAFAKEFAKEFAKEFAKE",
                                               "Arn": f"arn:aws:iam::{ACCOUNT}:role/harborline-tester",
                                               "CreateDate": WHEN}}, {"RoleName": "harborline-tester"})
        iam.add_response("list_attached_role_policies", {"AttachedPolicies": [
            {"PolicyName": "ReadOnlyAccess", "PolicyArn": readonly}]}, {"RoleName": "harborline-tester"})
        iam.add_response("get_policy", {"Policy": {"PolicyName": "ReadOnlyAccess", "Arn": readonly,
                                                   "DefaultVersionId": "v99"}}, {"PolicyArn": readonly})
        iam.add_response("get_policy_version", {"PolicyVersion": {"Document": "{}", "VersionId": "v99"}},
                         {"PolicyArn": readonly, "VersionId": "v99"})
        iam.add_response("list_role_policies", {"PolicyNames": ["harborline-tester-deny-secrets"]},
                         {"RoleName": "harborline-tester"})
        iam.add_response("get_role_policy", {"RoleName": "harborline-tester", "PolicyName": "harborline-tester-deny-secrets",
                                             "PolicyDocument": "{}"},
                         {"RoleName": "harborline-tester", "PolicyName": "harborline-tester-deny-secrets"})

        collectors.collect_c06(self.run)
        self.stubs.assert_done()
        approved = next(v for k, v in self.saved("C-06").items() if "approved_lists" in k)
        self.assertEqual(approved["source"], "controls/approved-lists.yaml")
        self.assertIn("approved_administrators", approved["content"])


if __name__ == "__main__":
    unittest.main()
