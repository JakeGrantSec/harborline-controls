"""Offline test helpers: fake AWS sessions with botocore Stubbers, and a fake
GitHub transport. No network calls are made and no real credentials are used.

All identifiers are obviously fake. The account number is built at run time so
no 12-digit number appears in the source.
"""

import datetime
import io
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path

import boto3
from botocore.stub import Stubber

from tester.aws import Aws
from tester.evidence import EvidenceWriter
from tester.library import load_library
from tester.run import Run

REPO_ROOT = Path(__file__).resolve().parents[2]
REGION = "us-east-1"
ACCOUNT = "1" * 12
WHEN = datetime.datetime(2026, 11, 20, 12, 0, tzinfo=datetime.timezone.utc)


def fake_session():
    return boto3.Session(
        aws_access_key_id="fake-test-access-key-id",
        aws_secret_access_key="fake-test-secret",
        region_name=REGION,
    )


class Stubs:
    """One activated Stubber per (service, region) client of an Aws object."""

    def __init__(self, aws):
        self.aws = aws
        self._stubbers = {}

    def __call__(self, service, region=None):
        client = self.aws.client(service, region)
        key = id(client)
        if key not in self._stubbers:
            stubber = Stubber(client)
            stubber.activate()
            self._stubbers[key] = stubber
        return self._stubbers[key]

    def assert_done(self):
        for stubber in self._stubbers.values():
            stubber.assert_no_pending_responses()


class RunTestCase(unittest.TestCase):
    """Builds a Run with a fake session, stubbed clients and a temp output folder."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self._tmp.name) / "run"
        self.run_dir.mkdir()
        self.aws = Aws(fake_session())
        self.stubs = Stubs(self.aws)
        self.writer = EvidenceWriter(self.run_dir)
        self.sleeps = []
        self.run = Run(aws=self.aws, writer=self.writer, library=load_library(REPO_ROOT),
                       partition="aws", account_id=ACCOUNT, repo_root=REPO_ROOT,
                       sleep=self.sleeps.append)

    def tearDown(self):
        self._tmp.cleanup()

    def saved(self, control):
        """{file name: parsed JSON} for one control folder."""
        folder = self.run_dir / control
        return {p.name: json.loads(p.read_text()) for p in sorted(folder.glob("*.json"))}

    def all_output_text(self):
        return "".join(p.read_text(errors="replace") for p in self.run_dir.rglob("*") if p.is_file())


# --- Stubbed responses used by several tests ------------------------------------


def stub_bucket_inventory(stubs, buckets):
    """buckets: list of (name, tags or None). None means the bucket has no tags."""
    s3 = stubs("s3")
    s3.add_response("list_buckets", {"Buckets": [{"Name": n, "BucketRegion": REGION} for n, _ in buckets]}, {})
    for name, tags in buckets:
        if tags is None:
            s3.add_client_error("get_bucket_tagging", "NoSuchTagSet", http_status_code=404,
                                expected_params={"Bucket": name})
        else:
            s3.add_response("get_bucket_tagging",
                            {"TagSet": [{"Key": k, "Value": v} for k, v in tags.items()]},
                            {"Bucket": name})


def stub_customer_api(stubs, with_details=False):
    apigw = stubs("apigateway")
    apigw.add_response("get_rest_apis", {"items": [
        {"id": "fakeapi01", "name": "harborline-customer-api", "tags": {"scope": "harborline"}},
        {"id": "fakeapi99", "name": "someone-else", "tags": {}},
    ]}, {})
    if with_details:
        apigw.add_response("get_rest_api", {"id": "fakeapi01", "securityPolicy": "SecurityPolicy_TLS13_1_2_2021_06"},
                           {"restApiId": "fakeapi01"})
        apigw.add_response("get_stages", {"item": [{"stageName": "prod"}]}, {"restApiId": "fakeapi01"})
    apigw.add_response("get_resources", {"items": [
        {"id": "fakeroot", "path": "/"},
        {"id": "fakeres1", "path": "/summarize", "resourceMethods": {"POST": {}}},
    ]}, {"restApiId": "fakeapi01", "embed": ["methods"]})
    apigw.add_response("get_method", {"httpMethod": "POST", "authorizationType": "AWS_IAM"},
                       {"restApiId": "fakeapi01", "resourceId": "fakeres1", "httpMethod": "POST"})


# --- Fake GitHub transport -------------------------------------------------------


class FakeHTTPResponse:
    def __init__(self, status, body, link=None):
        self.status = status
        self._raw = json.dumps(body).encode()
        self.headers = {"Link": link} if link else {}

    def read(self):
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeGitHubOpener:
    """Maps full URLs to (status, body, link). Records every request."""

    def __init__(self, routes):
        self.routes = routes
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append(request)
        if request.full_url not in self.routes:
            raise AssertionError(f"unexpected GitHub request: {request.full_url}")
        status, body, link = self.routes[request.full_url]
        if status >= 400:
            raise urllib.error.HTTPError(request.full_url, status, "error", {}, io.BytesIO(json.dumps(body).encode()))
        return FakeHTTPResponse(status, body, link)
