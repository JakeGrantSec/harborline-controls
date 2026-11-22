"""Evidence collectors for C-01 to C-07, following each control's test procedure
in controls/controls.yaml. Collection only: nothing here decides pass or fail.

Selecting the in-scope population (by the tags defined in controls.yaml) is the
only filtering done. Every call goes through Run, which saves each raw response.
"""

import copy
import json
import shutil

from .aws import ROLE_NAME, region_from_arn
from .patterns import matches_credential_pattern

GITHUB_BRANCH = "main"
LAMBDA_ENV_NOTE = (
    "Environment variable values removed before saving. Each variable is saved as "
    "its name and whether its value matches a credential pattern (tester/patterns.py)."
)


# --- Inventory helpers ---------------------------------------------------------


def _tag_list(tags):
    return {t["Key"]: t["Value"] for t in tags or []}


def bucket_inventory(run, control):
    """All buckets in the account with their tags: {name: (region, tags)}."""
    s3 = run.aws.client("s3")
    buckets = {}
    for page in run.paginate(control, s3, "list_buckets"):
        for bucket in page.get("Buckets", []):
            buckets[bucket["Name"]] = bucket.get("BucketRegion") or run.aws.region
    inventory = {}
    for name, region in buckets.items():
        response = run.call(control, run.aws.client("s3", region), "get_bucket_tagging", name, Bucket=name)
        inventory[name] = (region, _tag_list(response.get("TagSet")) if response else {})
    return inventory


def table_inventory(run, control):
    """All DynamoDB tables with their describe-table output and tags."""
    dynamodb = run.aws.client("dynamodb")
    names = []
    for page in run.paginate(control, dynamodb, "list_tables"):
        names.extend(page.get("TableNames", []))
    inventory = {}
    for name in names:
        described = run.call(control, dynamodb, "describe_table", name, TableName=name)
        if not described:
            continue
        arn = described["Table"]["TableArn"]
        tags = {}
        for page in run.token_pages(control, dynamodb, "list_tags_of_resource", name, ResourceArn=arn):
            tags.update(_tag_list(page.get("Tags")))
        inventory[name] = (described, tags)
    return inventory


def customer_apis(run, control):
    """In-scope REST APIs (tagged with the scope tag)."""
    apigateway = run.aws.client("apigateway")
    apis = []
    for page in run.paginate(control, apigateway, "get_rest_apis"):
        apis.extend(page.get("items", []))
    return [api for api in apis if run.library.scope_tag.matches(api.get("tags") or {})]


def api_methods(run, control, api_id):
    """Every resource of one API, and get-method for every method on it."""
    apigateway = run.aws.client("apigateway")
    for page in run.paginate(control, apigateway, "get_resources", api_id, restApiId=api_id, embed=["methods"]):
        for resource in page.get("items", []):
            for http_method in sorted(resource.get("resourceMethods") or {}):
                run.call(control, apigateway, "get_method", f"{api_id}_{resource['id']}_{http_method}",
                         restApiId=api_id, resourceId=resource["id"], httpMethod=http_method)


# --- C-01 Encryption at rest -----------------------------------------------------


def collect_c01(run):
    c = "C-01"
    scope, audit = run.library.scope_tag, run.library.audit_log_tag
    keys = []  # (key id, region), in the order found

    for name, (region, tags) in bucket_inventory(run, c).items():
        if not scope.matches(tags) or audit.matches(tags):
            continue
        response = run.call(c, run.aws.client("s3", region), "get_bucket_encryption", name, Bucket=name)
        for rule in (response or {}).get("ServerSideEncryptionConfiguration", {}).get("Rules", []):
            default = rule.get("ApplyServerSideEncryptionByDefault") or {}
            if default.get("SSEAlgorithm", "").startswith("aws:kms"):
                # No key ID means the AWS managed key for S3.
                keys.append((default.get("KMSMasterKeyID") or "alias/aws/s3", region))

    for name, (described, tags) in table_inventory(run, c).items():
        if not scope.matches(tags) or audit.matches(tags):
            continue
        key_arn = (described["Table"].get("SSEDescription") or {}).get("KMSMasterKeyArn")
        if key_arn:
            keys.append((key_arn, region_from_arn(key_arn, run.aws.region)))

    seen = set()
    for key_id, region in keys:
        if (key_id, region) in seen:
            continue
        seen.add((key_id, region))
        kms = run.aws.client("kms", region_from_arn(key_id, region))
        described = run.call(c, kms, "describe_key", key_id, KeyId=key_id)
        metadata = (described or {}).get("KeyMetadata") or {}
        if metadata.get("KeyManager") == "CUSTOMER":
            run.call(c, kms, "get_key_rotation_status", metadata["KeyId"], KeyId=metadata["KeyId"])


# --- C-02 Encryption in transit --------------------------------------------------


def collect_c02(run):
    c = "C-02"
    for name, (region, tags) in bucket_inventory(run, c).items():
        if run.library.scope_tag.matches(tags):
            run.call(c, run.aws.client("s3", region), "get_bucket_policy", name, Bucket=name)

    apigateway = run.aws.client("apigateway")
    for api in customer_apis(run, c):
        run.call(c, apigateway, "get_rest_api", api["id"], restApiId=api["id"])
        run.call(c, apigateway, "get_stages", api["id"], restApiId=api["id"])
        api_methods(run, c, api["id"])
    run.paginate(c, apigateway, "get_domain_names")


# --- C-03 Audit logging ----------------------------------------------------------


def collect_c03(run):
    c = "C-03"
    trails = run.call(c, run.aws.client("cloudtrail"), "describe_trails", includeShadowTrails=True)
    log_buckets = set()
    seen = set()
    for trail in (trails or {}).get("trailList", []):
        arn = trail["TrailARN"]
        if arn in seen:
            continue
        seen.add(arn)
        if trail.get("S3BucketName"):
            log_buckets.add(trail["S3BucketName"])
        home = run.aws.client("cloudtrail", trail.get("HomeRegion"))
        run.call(c, home, "get_trail_status", trail["Name"], Name=arn)
        run.call(c, home, "get_event_selectors", trail["Name"], TrailName=arn)

    scope, audit = run.library.scope_tag, run.library.audit_log_tag
    inventory = bucket_inventory(run, c)
    for name, (region, tags) in inventory.items():
        if scope.matches(tags) and audit.matches(tags):
            log_buckets.add(name)
    for name in sorted(log_buckets):
        s3 = run.aws.client("s3", inventory.get(name, (None,))[0])
        run.call(c, s3, "get_public_access_block", name, Bucket=name)
        run.call(c, s3, "get_bucket_lifecycle_configuration", name, Bucket=name)


# --- C-04 Secrets storage --------------------------------------------------------


def redact_lambda_page(page):
    """Replace environment variable values with credential-pattern results."""
    page = copy.deepcopy(page)
    for function in page.get("Functions", []):
        environment = function.get("Environment")
        if isinstance(environment, dict) and "Variables" in environment:
            variables = environment.pop("Variables") or {}
            environment["VariableNames"] = [
                {"Name": name, "MatchesCredentialPattern": matches_credential_pattern(value)}
                for name, value in sorted(variables.items())
            ]
    return page


def collect_c04(run):
    c = "C-04"
    secrets = run.aws.client("secretsmanager")
    # Metadata only. GetSecretValue is never called (and is refused by the guard).
    for page in run.paginate(c, secrets, "list_secrets"):
        for secret in page.get("SecretList", []):
            run.token_pages(c, secrets, "list_secret_version_ids", secret["Name"], SecretId=secret["ARN"])

    lambda_client = run.aws.client("lambda")
    functions = []
    pages = run.paginate(c, lambda_client, "list_functions", transform=redact_lambda_page,
                         note=LAMBDA_ENV_NOTE, FunctionVersion="ALL")
    for page in pages:
        functions.extend(f for f in page.get("Functions", []) if f.get("Version") == "$LATEST")
    for function in functions:
        arn = function["FunctionArn"].removesuffix(":$LATEST")
        run.call(c, lambda_client, "list_tags", function["FunctionName"], Resource=arn)

    run_gitleaks(run, c)


def run_gitleaks(run, control):
    binary = run.gitleaks_bin or shutil.which("gitleaks")
    if not binary:
        raise RuntimeError("gitleaks is not installed or not on PATH")
    version = run.runner([binary, "version"], capture_output=True, text=True, timeout=60)
    report = run.writer.reserve(control, "gitleaks_report")
    command = [
        binary, "git", str(run.repo_root),
        "--log-opts=--all --full-history",  # Full history, every branch.
        "--redact=100",
        "--report-format=json",
        f"--report-path={report}",
        "--exit-code=0",  # Findings are evidence, not a failure of the run.
        "--no-banner", "--no-color", "--log-level=warn",
    ]
    result = run.runner(command, capture_output=True, text=True, timeout=900)
    info = {
        "gitleaks_version": version.stdout.strip(),
        "command": command,
        "exit_code": result.returncode,
        "stderr": result.stderr,
    }
    request = {"command": "gitleaks git", "args": command[2:]}

    if result.returncode != 0 or not report.exists():
        run.writer.discard(report)
        run.writer.save(control, "gitleaks_run", info, request=request, error="gitleaks_failed")
        run.api_errors.append({"control": control, "operation": "gitleaks git", "code": "gitleaks_failed"})
        return

    findings = json.loads(report.read_text(encoding="utf-8") or "[]")
    if any(f.get("Secret") != "REDACTED" or f.get("Match") != "REDACTED" for f in findings):
        run.writer.discard(report)
        raise RuntimeError("gitleaks report was not fully redacted; it was deleted and not saved")
    run.writer.register(control, report, request=request, note="gitleaks JSON report, written by gitleaks")
    run.writer.save(control, "gitleaks_run", info, request=request)


# --- C-05 Authentication ---------------------------------------------------------

CREDENTIAL_REPORT_ATTEMPTS = 20
CREDENTIAL_REPORT_WAIT_SECONDS = 3


def collect_c05(run):
    c = "C-05"
    iam = run.aws.client("iam")
    for attempt in range(1, CREDENTIAL_REPORT_ATTEMPTS + 1):
        state = run.call(c, iam, "generate_credential_report", f"attempt{attempt:02d}")
        if state is None or state.get("State") == "COMPLETE":
            break
        run.sleep(CREDENTIAL_REPORT_WAIT_SECONDS)
    run.call(c, iam, "get_credential_report")
    run.call(c, iam, "get_account_summary")

    for api in customer_apis(run, c):
        api_methods(run, c, api["id"])


# --- C-06 Authorization ----------------------------------------------------------


def _policy_and_default_version(run, control, iam, policy_arn):
    policy = run.call(control, iam, "get_policy", policy_arn.rsplit("/", 1)[-1], PolicyArn=policy_arn)
    version = ((policy or {}).get("Policy") or {}).get("DefaultVersionId")
    if version:
        run.call(control, iam, "get_policy_version", policy_arn.rsplit("/", 1)[-1],
                 PolicyArn=policy_arn, VersionId=version)


def collect_c06(run):
    c = "C-06"
    iam = run.aws.client("iam")

    # Customer managed policies and their current documents.
    for page in run.paginate(c, iam, "list_policies", Scope="Local"):
        for policy in page.get("Policies", []):
            run.call(c, iam, "get_policy_version", policy["PolicyName"],
                     PolicyArn=policy["Arn"], VersionId=policy["DefaultVersionId"])

    # Every inline policy on every IAM user, group and role (read-only, paginated).
    run.paginate(c, iam, "get_account_authorization_details", "inline_policies",
                 Filter=["User", "Group", "Role"])

    # Identities holding the administrator policy, saved with the approved list.
    admin_arn = f"arn:{run.partition}:iam::aws:policy/AdministratorAccess"
    run.paginate(c, iam, "list_entities_for_policy", "AdministratorAccess", PolicyArn=admin_arn)
    run.writer.save(c, "approved_lists", {
        "source": "controls/approved-lists.yaml",
        "sha256": run.library.approved_lists_sha256,
        "content": run.library.approved_lists,
    }, request={"file": "controls/approved-lists.yaml"})

    # Public access blocks: account level and each in-scope bucket.
    run.call(c, run.aws.client("s3control"), "get_public_access_block", "account", AccountId=run.account_id)
    for name, (region, tags) in bucket_inventory(run, c).items():
        if run.library.scope_tag.matches(tags):
            run.call(c, run.aws.client("s3", region), "get_public_access_block", name, Bucket=name)

    # Access analyzers, their archive rules, and active findings.
    analyzer = run.aws.client("accessanalyzer")
    for page in run.paginate(c, analyzer, "list_analyzers"):
        for item in page.get("analyzers", []):
            run.paginate(c, analyzer, "list_archive_rules", item["name"], analyzerName=item["name"])
            run.paginate(c, analyzer, "list_findings_v2", item["name"], analyzerArn=item["arn"],
                         filter={"status": {"eq": ["ACTIVE"]}})

    # The tester role and every policy that applies to it.
    role = run.call(c, iam, "get_role", ROLE_NAME, RoleName=ROLE_NAME)
    boundary = (((role or {}).get("Role") or {}).get("PermissionsBoundary") or {}).get("PermissionsBoundaryArn")
    for page in run.paginate(c, iam, "list_attached_role_policies", ROLE_NAME, RoleName=ROLE_NAME):
        for attached in page.get("AttachedPolicies", []):
            _policy_and_default_version(run, c, iam, attached["PolicyArn"])
    if boundary:
        _policy_and_default_version(run, c, iam, boundary)
    for page in run.paginate(c, iam, "list_role_policies", ROLE_NAME, RoleName=ROLE_NAME):
        for policy_name in page.get("PolicyNames", []):
            run.call(c, iam, "get_role_policy", policy_name, RoleName=ROLE_NAME, PolicyName=policy_name)


# --- C-07 Change management ------------------------------------------------------


def collect_c07(run):
    c = "C-07"
    gh = run.github
    owner, repo = run.github_repo
    base = f"/repos/{owner}/{repo}"

    run.save_github(c, "github_rules_branch_main", gh.get(gh.url(f"{base}/rules/branches/{GITHUB_BRANCH}")))

    ruleset_ids = []
    for n, page in enumerate(gh.paginate(gh.url(f"{base}/rulesets", {"includes_parents": "true", "per_page": 100})), 1):
        run.save_github(c, f"github_rulesets_page{n:03d}", page)
        if page.ok:
            ruleset_ids.extend(r["id"] for r in page.body or [])
    for ruleset_id in ruleset_ids:
        run.save_github(c, f"github_ruleset_{ruleset_id}", gh.get(gh.url(f"{base}/rulesets/{ruleset_id}")))

    shas = []
    for n, page in enumerate(gh.paginate(gh.url(f"{base}/commits", {"sha": GITHUB_BRANCH, "per_page": 100})), 1):
        run.save_github(c, f"github_commits_main_page{n:03d}", page)
        if page.ok:
            shas.extend(commit["sha"] for commit in page.body or [])

    pull_numbers = []
    for sha in shas:
        for n, page in enumerate(gh.paginate(gh.url(f"{base}/commits/{sha}/pulls", {"per_page": 100})), 1):
            run.save_github(c, f"github_commit_{sha[:12]}_pulls_page{n:03d}", page)
            if page.ok:
                for pull in page.body or []:
                    if pull["number"] not in pull_numbers:
                        pull_numbers.append(pull["number"])

    for number in pull_numbers:
        run.save_github(c, f"github_pull_{number}", gh.get(gh.url(f"{base}/pulls/{number}")))
        for n, page in enumerate(gh.paginate(gh.url(f"{base}/pulls/{number}/reviews", {"per_page": 100})), 1):
            run.save_github(c, f"github_pull_{number}_reviews_page{n:03d}", page)


COLLECTORS = {
    "C-01": collect_c01,
    "C-02": collect_c02,
    "C-03": collect_c03,
    "C-04": collect_c04,
    "C-05": collect_c05,
    "C-06": collect_c06,
    "C-07": collect_c07,
}
