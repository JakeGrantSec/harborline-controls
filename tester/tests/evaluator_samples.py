"""Small, obviously fake evidence runs for the evaluator tests.

SampleRun builds a run that passes every control, in the same layout and with
the same manifest entries as tester.collect. Tests change its attributes to
seed failures, then write it to a temporary folder. All names, IDs and keys are
fake; the account number is built at run time so none appears in the source.
"""

import copy
import datetime
import json
from pathlib import Path

from tester.evidence import EvidenceWriter
from tester.library import load_library
from tester.patterns import matches_credential_pattern

REPO_ROOT = Path(__file__).resolve().parents[2]

ACCOUNT = "1" * 12
REGION = "us-east-1"
COLLECTED = datetime.datetime(2026, 11, 20, 12, 0, tzinfo=datetime.timezone.utc)
REPO = "example-owner/example-repo"
GH = f"https://api.github.com/repos/{REPO}"

LOAN_BUCKET = "harborline-example-loan-documents"
LOG_BUCKET = "harborline-example-audit-logs"
OTHER_BUCKET = "example-untagged-bucket"
TABLE = "harborline-example-loan-records"
TABLE_ARN = f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{TABLE}"
CMK_ID = "00000000-0000-0000-0000-000000000001"
CMK_ARN = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/{CMK_ID}"
AWS_S3_KEY_ID = "00000000-0000-0000-0000-000000000002"
TRAIL_ARN = f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/harborline-example-trail"
API_ID = "fakeapi001"
TESTER_POLICY_ARN = f"arn:aws:iam::{ACCOUNT}:policy/harborline-example-tester-read"
SCOPE = {"scope": "harborline"}
ALL_BLOCKED = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True,
               "RestrictPublicBuckets": True}
CREDENTIAL_REPORT_COLUMNS = ["user", "arn", "password_enabled", "mfa_active", "access_key_1_active",
                             "access_key_1_last_rotated", "access_key_2_active", "access_key_2_last_rotated"]


def days_before_collection(days):
    return (COLLECTED - datetime.timedelta(days=days)).isoformat()


def tls_deny_statement(bucket):
    return {"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}}}


def bucket_policy(bucket, deny=True):
    statements = [{"Sid": "ExampleRead", "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                   "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/*"}]
    if deny:
        statements.append(tls_deny_statement(bucket))
    return {"Version": "2012-10-17", "Statement": statements}


def commit(sha, message, parents):
    return {"sha": sha, "commit": {"message": message, "author": {"name": "Example"}},
            "parents": [{"sha": p} for p in parents]}


def pull(number, title, author, merged_at, merge_sha):
    return {"number": number, "title": title, "user": {"login": author}, "state": "closed",
            "merged_at": merged_at, "merge_commit_sha": merge_sha, "base": {"ref": "main"}}


def review(login, state, submitted_at):
    return {"user": {"login": login}, "state": state, "submitted_at": submitted_at}


class SampleRun:
    def __init__(self):
        self.library = load_library(REPO_ROOT)
        self.buckets = {
            LOAN_BUCKET: {"tags": dict(SCOPE), "encryption": "aws:kms", "key": CMK_ARN,
                          "policy": bucket_policy(LOAN_BUCKET), "public_access": dict(ALL_BLOCKED)},
            LOG_BUCKET: {"tags": dict(SCOPE, purpose="audit-log"), "encryption": "aws:kms", "key": None,
                         "policy": bucket_policy(LOG_BUCKET), "public_access": dict(ALL_BLOCKED),
                         "lifecycle": [{"ID": "expire-after-365-days", "Status": "Enabled", "Filter": {},
                                        "Expiration": {"Days": 365},
                                        "NoncurrentVersionExpiration": {"NoncurrentDays": 365}}]},
            OTHER_BUCKET: {"tags": None, "encryption": "AES256", "key": None},
        }
        self.tagging_errors = {}  # bucket -> error code for GetBucketTagging
        self.table_sse = {"Status": "ENABLED", "SSEType": "KMS", "KMSMasterKeyArn": CMK_ARN}
        self.keys = {
            CMK_ARN: {"KeyId": CMK_ID, "KeyManager": "CUSTOMER", "KeyState": "Enabled", "rotation": True},
            "alias/aws/s3": {"KeyId": AWS_S3_KEY_ID, "KeyManager": "AWS", "KeyState": "Enabled"},
        }
        self.api = {"id": API_ID, "name": "harborline-example-api", "tags": dict(SCOPE),
                    "securityPolicy": "SecurityPolicy_TLS13_1_2_2021_06",
                    "endpointConfiguration": {"types": ["REGIONAL"]}}
        self.methods = [{"resource": "res001", "path": "/summaries", "httpMethod": "POST",
                         "authorizationType": "AWS_IAM",
                         "methodIntegration": {"type": "AWS_PROXY", "uri": "arn:aws:apigateway:example"}}]
        self.domains = []
        self.trail = {"Name": "harborline-example-trail", "TrailARN": TRAIL_ARN, "HomeRegion": REGION,
                      "IsMultiRegionTrail": True, "LogFileValidationEnabled": True, "S3BucketName": LOG_BUCKET}
        self.trail_logging = True
        self.event_selectors = {"AdvancedEventSelectors": [{"Name": "loan document object events", "FieldSelectors": [
            {"Field": "eventCategory", "Equals": ["Data"]},
            {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
            {"Field": "resources.ARN", "StartsWith": [f"arn:aws:s3:::{LOAN_BUCKET}/"]}]}]}
        self.secrets = [{"Name": "harborline/example-api-key", "created_days_ago": 30}]
        self.functions = [{"FunctionName": "harborline-example-summarizer", "tags": dict(SCOPE),
                           "env": {"MODEL_NAME": "example-model", "SECRET_ARN": "arn:aws:secretsmanager:example"}}]
        self.gitleaks_findings = []
        self.users = [
            {"user": "<root_account>", "password_enabled": "not_supported", "mfa_active": "true"},
            {"user": "example-person", "password_enabled": "true", "mfa_active": "true",
             "access_key_1_active": "true", "access_key_1_last_rotated": days_before_collection(10)},
            {"user": "example-service", "password_enabled": "false", "mfa_active": "false"},
        ]
        self.account_summary = {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}
        self.customer_policies = {
            "harborline-example-deployer": {"Version": "2012-10-17", "Statement": [
                {"Effect": "Allow", "Action": ["s3:*", "dynamodb:*"], "Resource": "arn:aws:s3:::harborline-*"}]},
        }
        self.administrators = {"PolicyRoles": [{"RoleName": "AWSReservedSSO_AdministratorAccess_0fakefake0"}],
                               "PolicyUsers": [], "PolicyGroups": []}
        self.account_public_access = dict(ALL_BLOCKED)
        self.analyzer_findings = []
        self.tester_policy = {"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": ["s3:Get*", "s3:List*", "dynamodb:Describe*", "dynamodb:List*",
                                           "kms:DescribeKey", "kms:GetKeyRotationStatus",
                                           "iam:GenerateCredentialReport", "iam:Get*", "iam:List*"],
             "Resource": "*"},
            {"Effect": "Deny", "Action": ["secretsmanager:GetSecretValue", "secretsmanager:BatchGetSecretValue"],
             "Resource": "*"}]}
        self.tester_inline = {}
        self.tester_boundary = None
        self.ruleset = {"id": 7, "name": "protect-main", "enforcement": "active", "bypass_actors": [],
                        "rules": [{"type": "pull_request", "parameters": {
                            "required_approving_review_count": 1, "dismiss_stale_reviews_on_push": True}}]}
        self.commits = [
            commit("5" * 40, "Merge pull request #2", ["3" * 40, "4" * 40]),
            commit("4" * 40, "Add example change two", ["3" * 40]),
            commit("3" * 40, "Merge pull request #1", ["1" * 40, "2" * 40]),
            commit("2" * 40, "Add example change one", ["1" * 40]),
            commit("1" * 40, "Initial commit", []),
        ]
        self.commit_pulls = {"2" * 40: [1], "3" * 40: [1], "4" * 40: [2], "5" * 40: []}
        self.pulls = {
            1: pull(1, "Example change one", "harborline-bot", "2026-11-10T10:00:00Z", "3" * 40),
            2: pull(2, "Example change two", "harborline-bot", "2026-11-11T10:00:00Z", "5" * 40),
        }
        self.reviews = {
            1: [review("JakeGrantSec", "APPROVED", "2026-11-10T09:00:00Z")],
            2: [review("JakeGrantSec", "APPROVED", "2026-11-11T09:00:00Z")],
        }
        self.control_failures = []

    # --- writing ------------------------------------------------------------

    def write(self, run_dir):
        self.run_dir = run_dir
        self.writer = EvidenceWriter(run_dir)
        for control in ("C-01", "C-02", "C-03", "C-04", "C-05", "C-06", "C-07"):
            getattr(self, "_write_" + control.replace("-", "").lower())(control)
        manifest = {
            "collection_started_at": COLLECTED.isoformat(),
            "collection_finished_at": (COLLECTED + datetime.timedelta(minutes=2)).isoformat(),
            "caller_identity": {"Account": ACCOUNT,
                                "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/harborline-tester/example-session"},
            "aws_profile": "harborline-tester",
            "aws_region": REGION,
            "tester_code": {"commit": "f" * 40, "uncommitted_changes_in_tester_or_controls": False},
            "control_library": {"version": self.library.version,
                                "controls_yaml_sha256": self.library.controls_sha256,
                                "approved_lists_yaml_sha256": self.library.approved_lists_sha256},
            "github_repository": REPO,
            "files": self.writer.files,
            "api_errors": [],
            "control_failures": copy.deepcopy(self.control_failures),
        }
        return self.writer.write_manifest(manifest)

    def aws(self, control, service, operation, name, data, error=None, region=REGION, **params):
        request = {"service": service, "operation": operation, "region": region, "params": params}
        if error:
            data = {"Error": {"Code": error, "Message": "example error"}}
        return self.writer.save(control, f"{service}_{operation}_{name}", data, request=request, error=error)

    def github(self, control, name, url, body, status=200):
        request = {"method": "GET", "url": url, "status": status}
        error = None if 200 <= status < 300 else f"HTTP {status}"
        return self.writer.save(control, name, body, request=request, error=error)

    def _bucket_inventory(self, c):
        self.aws(c, "s3", "ListBuckets", "page001",
                 {"Buckets": [{"Name": n, "BucketRegion": REGION} for n in self.buckets]})
        for name, bucket in self.buckets.items():
            error = self.tagging_errors.get(name) or (None if bucket["tags"] else "NoSuchTagSet")
            self.aws(c, "s3", "GetBucketTagging", name,
                     {"TagSet": [{"Key": k, "Value": v} for k, v in (bucket["tags"] or {}).items()]},
                     error=error, Bucket=name)

    def _in_scope(self, exclude_audit):
        for name, bucket in self.buckets.items():
            tags = bucket["tags"] or {}
            if name in self.tagging_errors or tags.get("scope") != "harborline":
                continue
            if exclude_audit and tags.get("purpose") == "audit-log":
                continue
            yield name, bucket

    def _write_c01(self, c):
        self._bucket_inventory(c)
        used = []
        for name, bucket in self._in_scope(True):
            default = {"SSEAlgorithm": bucket["encryption"]}
            if bucket.get("key"):
                default["KMSMasterKeyID"] = bucket["key"]
            self.aws(c, "s3", "GetBucketEncryption", name, {"ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": default}]}}, Bucket=name)
            if bucket["encryption"].startswith("aws:kms"):
                used.append(bucket.get("key") or "alias/aws/s3")
        self.aws(c, "dynamodb", "ListTables", "page001", {"TableNames": [TABLE]})
        table = {"TableName": TABLE, "TableArn": TABLE_ARN}
        if self.table_sse:
            table["SSEDescription"] = self.table_sse
            if self.table_sse.get("KMSMasterKeyArn"):
                used.append(self.table_sse["KMSMasterKeyArn"])
        self.aws(c, "dynamodb", "DescribeTable", TABLE, {"Table": table}, TableName=TABLE)
        self.aws(c, "dynamodb", "ListTagsOfResource", TABLE + "_page001",
                 {"Tags": [{"Key": "scope", "Value": "harborline"}]}, ResourceArn=TABLE_ARN)
        for key in dict.fromkeys(used):
            meta = self.keys[key]
            self.aws(c, "kms", "DescribeKey", key, {"KeyMetadata": {
                "KeyId": meta["KeyId"], "KeyManager": meta["KeyManager"], "KeyState": meta["KeyState"]}}, KeyId=key)
            if meta["KeyManager"] == "CUSTOMER":
                self.aws(c, "kms", "GetKeyRotationStatus", meta["KeyId"],
                         {"KeyRotationEnabled": meta["rotation"]}, KeyId=meta["KeyId"])

    def _api_inventory(self, c):
        self.aws(c, "apigateway", "GetRestApis", "page001", {"items": [
            {"id": self.api["id"], "name": self.api["name"], "tags": self.api["tags"]}]})

    def _api_methods(self, c):
        resources = {}
        for m in self.methods:
            resources.setdefault((m["resource"], m["path"]), {})[m["httpMethod"]] = {}
        self.aws(c, "apigateway", "GetResources", API_ID + "_page001", {"items": [
            {"id": rid, "path": path, "resourceMethods": methods} for (rid, path), methods in resources.items()]},
            restApiId=API_ID, embed=["methods"])
        for m in self.methods:
            data = {"httpMethod": m["httpMethod"], "authorizationType": m["authorizationType"],
                    "methodIntegration": m["methodIntegration"]}
            self.aws(c, "apigateway", "GetMethod", f"{API_ID}_{m['resource']}_{m['httpMethod']}", data,
                     restApiId=API_ID, resourceId=m["resource"], httpMethod=m["httpMethod"])

    def _write_c02(self, c):
        self._bucket_inventory(c)
        for name, bucket in self._in_scope(False):
            if bucket.get("policy") is None:
                self.aws(c, "s3", "GetBucketPolicy", name, None, error="NoSuchBucketPolicy", Bucket=name)
            else:
                self.aws(c, "s3", "GetBucketPolicy", name, {"Policy": json.dumps(bucket["policy"])}, Bucket=name)
        self._api_inventory(c)
        self.aws(c, "apigateway", "GetRestApi", API_ID, self.api, restApiId=API_ID)
        self.aws(c, "apigateway", "GetStages", API_ID, {"item": [{"stageName": "prod"}]}, restApiId=API_ID)
        self._api_methods(c)
        self.aws(c, "apigateway", "GetDomainNames", "page001", {"items": self.domains})

    def _write_c03(self, c):
        self.aws(c, "cloudtrail", "DescribeTrails", "", {"trailList": [self.trail]}, includeShadowTrails=True)
        self.aws(c, "cloudtrail", "GetTrailStatus", self.trail["Name"], {"IsLogging": self.trail_logging},
                 Name=TRAIL_ARN)
        self.aws(c, "cloudtrail", "GetEventSelectors", self.trail["Name"],
                 dict(self.event_selectors, TrailARN=TRAIL_ARN), TrailName=TRAIL_ARN)
        self._bucket_inventory(c)
        log = self.buckets[LOG_BUCKET]
        self.aws(c, "s3", "GetPublicAccessBlock", LOG_BUCKET,
                 {"PublicAccessBlockConfiguration": log["public_access"]}, Bucket=LOG_BUCKET)
        self.aws(c, "s3", "GetBucketLifecycleConfiguration", LOG_BUCKET, {"Rules": log["lifecycle"]},
                 Bucket=LOG_BUCKET)

    def _write_c04(self, c):
        listed = []
        for s in self.secrets:
            arn = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:{s['Name']}-AbCdEf"
            listed.append({"Name": s["Name"], "ARN": arn})
        self.aws(c, "secretsmanager", "ListSecrets", "page001", {"SecretList": listed})
        for s, entry in zip(self.secrets, listed):
            self.aws(c, "secretsmanager", "ListSecretVersionIds", s["Name"] + "_page001", {"Versions": [
                {"VersionId": "v-current", "VersionStages": ["AWSCURRENT"],
                 "CreatedDate": days_before_collection(s["created_days_ago"])},
                {"VersionId": "v-old", "VersionStages": ["AWSPREVIOUS"],
                 "CreatedDate": days_before_collection(400)}]}, SecretId=entry["ARN"])
        functions = []
        for f in self.functions:
            arn = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{f['FunctionName']}"
            # The collector saves only names and match results; values are discarded.
            names = [{"Name": k, "MatchesCredentialPattern": matches_credential_pattern(v)}
                     for k, v in sorted(f["env"].items())]
            functions.append({"FunctionName": f["FunctionName"], "FunctionArn": arn + ":$LATEST",
                              "Version": "$LATEST", "Environment": {"VariableNames": names}})
        self.aws(c, "lambda", "ListFunctions", "page001", {"Functions": functions}, FunctionVersion="ALL")
        for f in self.functions:
            arn = f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{f['FunctionName']}"
            self.aws(c, "lambda", "ListTags", f["FunctionName"], {"Tags": f["tags"]}, Resource=arn)
        report = self.writer.reserve(c, "gitleaks_report")
        report.write_text(json.dumps(self.gitleaks_findings))
        command = ["gitleaks", "git", "repo", "--log-opts=--all --full-history", "--redact=100"]
        request = {"command": "gitleaks git", "args": command[2:]}
        self.writer.register(c, report, request=request, note="gitleaks JSON report, written by gitleaks")
        self.writer.save(c, "gitleaks_run", {"gitleaks_version": "8.0.0-example", "command": command,
                                             "exit_code": 0, "stderr": ""}, request=request)

    def _write_c05(self, c):
        self.aws(c, "iam", "GenerateCredentialReport", "attempt01", {"State": "COMPLETE"})
        lines = [",".join(CREDENTIAL_REPORT_COLUMNS)]
        for u in self.users:
            row = {k: "false" for k in CREDENTIAL_REPORT_COLUMNS}
            row.update(arn=f"arn:aws:iam::{ACCOUNT}:user/x", access_key_1_last_rotated="N/A",
                       access_key_2_last_rotated="N/A")
            row.update(u)
            lines.append(",".join(row[k] for k in CREDENTIAL_REPORT_COLUMNS))
        self.aws(c, "iam", "GetCredentialReport", "", {"Content": "\n".join(lines) + "\n", "ReportFormat": "text/csv",
                                                       "GeneratedTime": COLLECTED.isoformat()})
        self.aws(c, "iam", "GetAccountSummary", "", {"SummaryMap": self.account_summary})
        self._api_inventory(c)
        self._api_methods(c)

    def _write_c06(self, c):
        policies = dict(self.customer_policies, **{"harborline-example-tester-read": self.tester_policy})
        listed = [{"PolicyName": n, "Arn": f"arn:aws:iam::{ACCOUNT}:policy/{n}", "DefaultVersionId": "v1",
                   "AttachmentCount": 1} for n in policies]
        self.aws(c, "iam", "ListPolicies", "page001", {"Policies": listed}, Scope="Local")
        for entry in listed:
            self.aws(c, "iam", "GetPolicyVersion", entry["PolicyName"],
                     {"PolicyVersion": {"Document": policies[entry["PolicyName"]], "VersionId": "v1"}},
                     PolicyArn=entry["Arn"], VersionId="v1")
        admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
        self.aws(c, "iam", "ListEntitiesForPolicy", "AdministratorAccess_page001", self.administrators,
                 PolicyArn=admin_arn)
        self.writer.save(c, "approved_lists", {"source": "controls/approved-lists.yaml",
                                               "sha256": self.library.approved_lists_sha256,
                                               "content": self.library.approved_lists},
                         request={"file": "controls/approved-lists.yaml"})
        self.aws(c, "s3control", "GetPublicAccessBlock", "account",
                 {"PublicAccessBlockConfiguration": self.account_public_access}, AccountId=ACCOUNT)
        self._bucket_inventory(c)
        for name, bucket in self._in_scope(False):
            self.aws(c, "s3", "GetPublicAccessBlock", name,
                     {"PublicAccessBlockConfiguration": bucket["public_access"]}, Bucket=name)
        analyzer_arn = f"arn:aws:access-analyzer:{REGION}:{ACCOUNT}:analyzer/harborline-example-analyzer"
        self.aws(c, "accessanalyzer", "ListAnalyzers", "page001", {"analyzers": [
            {"name": "harborline-example-analyzer", "arn": analyzer_arn, "type": "ACCOUNT", "status": "ACTIVE"}]})
        self.aws(c, "accessanalyzer", "ListArchiveRules", "harborline-example-analyzer_page001",
                 {"archiveRules": []}, analyzerName="harborline-example-analyzer")
        self.aws(c, "accessanalyzer", "ListFindingsV2", "harborline-example-analyzer_page001",
                 {"findings": self.analyzer_findings}, analyzerArn=analyzer_arn,
                 filter={"status": {"eq": ["ACTIVE"]}})
        role = {"RoleName": "harborline-tester", "Arn": f"arn:aws:iam::{ACCOUNT}:role/harborline-tester"}
        boundary_arn = f"arn:aws:iam::{ACCOUNT}:policy/harborline-example-boundary"
        if self.tester_boundary is not None:
            role["PermissionsBoundary"] = {"PermissionsBoundaryArn": boundary_arn}
        self.aws(c, "iam", "GetRole", "harborline-tester", {"Role": role}, RoleName="harborline-tester")
        self.aws(c, "iam", "ListAttachedRolePolicies", "harborline-tester_page001", {"AttachedPolicies": [
            {"PolicyName": "harborline-example-tester-read", "PolicyArn": TESTER_POLICY_ARN}]},
            RoleName="harborline-tester")
        for arn, document in ((TESTER_POLICY_ARN, self.tester_policy), (boundary_arn, self.tester_boundary)):
            if document is None:
                continue
            name = arn.rsplit("/", 1)[-1]
            self.aws(c, "iam", "GetPolicy", name, {"Policy": {"Arn": arn, "DefaultVersionId": "v1"}}, PolicyArn=arn)
            self.aws(c, "iam", "GetPolicyVersion", name, {"PolicyVersion": {"Document": document, "VersionId": "v1"}},
                     PolicyArn=arn, VersionId="v1")
        self.aws(c, "iam", "ListRolePolicies", "harborline-tester_page001",
                 {"PolicyNames": list(self.tester_inline)}, RoleName="harborline-tester")
        for name, document in self.tester_inline.items():
            self.aws(c, "iam", "GetRolePolicy", name, {"PolicyName": name, "PolicyDocument": document},
                     RoleName="harborline-tester", PolicyName=name)

    def _write_c07(self, c):
        rule = dict(self.ruleset["rules"][0], ruleset_id=self.ruleset["id"], ruleset_source_type="Repository")
        self.github(c, "github_rules_branch_main", f"{GH}/rules/branches/main", [rule])
        self.github(c, "github_rulesets_page001", f"{GH}/rulesets?includes_parents=true&per_page=100",
                    [{"id": self.ruleset["id"], "name": self.ruleset["name"]}])
        self.github(c, f"github_ruleset_{self.ruleset['id']}", f"{GH}/rulesets/{self.ruleset['id']}", self.ruleset)
        self.github(c, "github_commits_main_page001", f"{GH}/commits?sha=main&per_page=100", self.commits)
        numbers = []
        for cm in self.commits:
            found = [self.pulls[n] for n in self.commit_pulls.get(cm["sha"], [])]
            numbers.extend(p["number"] for p in found if p["number"] not in numbers)
            self.github(c, f"github_commit_{cm['sha'][:12]}_pulls_page001",
                        f"{GH}/commits/{cm['sha']}/pulls?per_page=100", found)
        for number in numbers:
            self.github(c, f"github_pull_{number}", f"{GH}/pulls/{number}", self.pulls[number])
            self.github(c, f"github_pull_{number}_reviews_page001", f"{GH}/pulls/{number}/reviews?per_page=100",
                        self.reviews.get(number, []))
