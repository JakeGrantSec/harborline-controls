"""AWS session, caller check and the read-only call guard.

The session always uses the harborline-tester profile. Credentials, profile
names and endpoint overrides set in the environment are removed first, so they
are never used. Every client gets a guard that refuses any operation not on
ALLOWED_OPERATIONS, before the request is signed or sent.
"""

import os
import re

import boto3
from botocore.config import Config

PROFILE = "harborline-tester"
ROLE_NAME = "harborline-tester"

# Removed from the environment before the session is created.
IGNORED_ENV_VARS = (
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_CREDENTIAL_EXPIRATION",
    "AWS_ENDPOINT_URL",
)
IGNORED_ENV_PREFIXES = ("AWS_ENDPOINT_URL_",)

# Every AWS operation the collector may call. Read operations only, plus
# iam:GenerateCredentialReport, which C-05 requires.
ALLOWED_OPERATIONS = frozenset({
    ("sts", "GetCallerIdentity"),
    ("s3", "ListBuckets"),
    ("s3", "GetBucketTagging"),
    ("s3", "GetBucketEncryption"),
    ("s3", "GetBucketPolicy"),
    ("s3", "GetPublicAccessBlock"),
    ("s3", "GetBucketLifecycleConfiguration"),
    # Not called by the collector: botocore calls HeadBucket itself to find a
    # bucket's region when a request is redirected. It reads no objects.
    ("s3", "HeadBucket"),
    ("s3control", "GetPublicAccessBlock"),
    ("dynamodb", "ListTables"),
    ("dynamodb", "DescribeTable"),
    ("dynamodb", "ListTagsOfResource"),
    ("kms", "DescribeKey"),
    ("kms", "GetKeyRotationStatus"),
    ("apigateway", "GetRestApis"),
    ("apigateway", "GetRestApi"),
    ("apigateway", "GetStages"),
    ("apigateway", "GetResources"),
    ("apigateway", "GetMethod"),
    ("apigateway", "GetDomainNames"),
    ("cloudtrail", "DescribeTrails"),
    ("cloudtrail", "GetTrailStatus"),
    ("cloudtrail", "GetEventSelectors"),
    ("secretsmanager", "ListSecrets"),
    ("secretsmanager", "ListSecretVersionIds"),
    ("lambda", "ListFunctions"),
    ("lambda", "ListTags"),
    ("iam", "GenerateCredentialReport"),
    ("iam", "GetCredentialReport"),
    ("iam", "GetAccountSummary"),
    ("iam", "ListPolicies"),
    ("iam", "GetPolicy"),
    ("iam", "GetPolicyVersion"),
    ("iam", "ListEntitiesForPolicy"),
    ("iam", "GetRole"),
    ("iam", "ListAttachedRolePolicies"),
    ("iam", "ListRolePolicies"),
    ("iam", "GetRolePolicy"),
    ("accessanalyzer", "ListAnalyzers"),
    ("accessanalyzer", "ListArchiveRules"),
    ("accessanalyzer", "ListFindingsV2"),
})

# Never allowed, whatever is added above. Checked by the unit tests too.
FORBIDDEN_OPERATIONS = frozenset({
    ("secretsmanager", "GetSecretValue"),
    ("secretsmanager", "BatchGetSecretValue"),
    ("s3", "GetObject"),
    ("s3", "GetObjectAttributes"),
    ("s3", "SelectObjectContent"),
    ("dynamodb", "GetItem"),
    ("dynamodb", "BatchGetItem"),
    ("dynamodb", "Query"),
    ("dynamodb", "Scan"),
    ("dynamodb", "ExecuteStatement"),
    ("dynamodb", "BatchExecuteStatement"),
})

BOTO_CONFIG = Config(
    retries={"max_attempts": 5, "mode": "standard"},
    connect_timeout=5,
    read_timeout=30,
)

_ROLE_ARN = re.compile(
    r"^arn:(?P<partition>aws[a-z-]*):sts::(?P<account>\d{12}):assumed-role/"
    + re.escape(ROLE_NAME)
    + r"/[\w+=,.@-]+$"
)


class ForbiddenOperation(Exception):
    pass


class IdentityError(Exception):
    pass


def read_only_guard(model, **kwargs):
    """botocore event handler: refuse anything not on the allow list."""
    key = (model.service_model.service_name, model.name)
    if key in FORBIDDEN_OPERATIONS or key not in ALLOWED_OPERATIONS:
        raise ForbiddenOperation(f"{key[0]}:{key[1]} is not an allowed read operation")


def clean_environment(environ=os.environ):
    for name in list(environ):
        if name in IGNORED_ENV_VARS or name.startswith(IGNORED_ENV_PREFIXES):
            del environ[name]


def build_session():
    clean_environment()
    return boto3.Session(profile_name=PROFILE)


class Aws:
    """Creates guarded clients, one per service and region."""

    def __init__(self, session):
        self.session = session
        self.region = session.region_name
        self._clients = {}

    def client(self, service, region=None):
        key = (service, region or self.region)
        if key not in self._clients:
            client = self.session.client(service, region_name=key[1], config=BOTO_CONFIG)
            # before-parameter-build is the first event of every API call, before
            # the request is built, signed or sent. The ".*.*" form is needed:
            # botocore runs handlers for more specific event names first.
            client.meta.events.register_first("before-parameter-build.*.*", read_only_guard)
            self._clients[key] = client
        return self._clients[key]


def verify_identity(sts_client):
    """Return the caller identity, or stop unless it is the tester role."""
    response = sts_client.get_caller_identity()
    arn = response.get("Arn", "")
    match = _ROLE_ARN.match(arn)
    if not match or match.group("account") != response.get("Account"):
        shown = re.sub(r"\d{12}", "<account>", arn)
        raise IdentityError(f"caller is not the {ROLE_NAME} role: {shown or '<no ARN>'}")
    return response, match.group("partition"), match.group("account")


def region_from_arn(arn, default):
    parts = arn.split(":") if isinstance(arn, str) and arn.startswith("arn:") else []
    return parts[3] if len(parts) > 3 and parts[3] else default
