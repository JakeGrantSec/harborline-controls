import unittest
from unittest import mock

import botocore.session

from tester import aws as aws_module
from tester.aws import (ALLOWED_OPERATIONS, FORBIDDEN_OPERATIONS, Aws, ForbiddenOperation,
                        IdentityError, clean_environment, verify_identity)
from tester.tests.helpers import ACCOUNT, Stubs, fake_session


class ReadOnlyGuardTest(unittest.TestCase):
    def setUp(self):
        self.aws = Aws(fake_session())
        self.stubs = Stubs(self.aws)

    def test_forbidden_calls_are_refused_before_sending(self):
        cases = [
            ("secretsmanager", "get_secret_value", {"SecretId": "harborline-fake"}, {"Name": "x"}),
            ("s3", "get_object", {"Bucket": "harborline-fake", "Key": "k"}, {}),
            ("dynamodb", "scan", {"TableName": "harborline-fake"}, {}),
            ("dynamodb", "get_item", {"TableName": "harborline-fake", "Key": {"id": {"S": "1"}}}, {}),
            ("iam", "create_user", {"UserName": "harborline-fake"}, {"User": {
                "Path": "/", "UserName": "harborline-fake", "UserId": "AIDAFAKEFAKEFAKEFAKE1",
                "Arn": "arn:aws:iam::x:user/harborline-fake", "CreateDate": "2026-01-01T00:00:00Z"}}),
            ("s3", "put_object", {"Bucket": "harborline-fake", "Key": "k"}, {}),
        ]
        for service, method, params, response in cases:
            with self.subTest(method=method):
                # Even with a response queued, the guard stops the call first.
                self.stubs(service).add_response(method, response, params)
                with self.assertRaises(ForbiddenOperation):
                    getattr(self.aws.client(service), method)(**params)

    def test_forbidden_call_without_stubber_is_refused_before_any_request(self):
        client = self.aws.client("secretsmanager")
        sent = []
        client.meta.events.register("before-send", lambda request, **kw: sent.append(request))
        with self.assertRaises(ForbiddenOperation):
            client.get_secret_value(SecretId="harborline-fake")
        self.assertEqual(sent, [])

    def test_allowed_call_goes_through(self):
        self.stubs("s3").add_response("list_buckets", {"Buckets": []}, {})
        self.assertEqual(self.aws.client("s3").list_buckets()["Buckets"], [])


class AllowListTest(unittest.TestCase):
    def test_allow_list_is_read_only(self):
        for service, operation in ALLOWED_OPERATIONS:
            with self.subTest(operation=f"{service}:{operation}"):
                read = operation.startswith(("Get", "List", "Describe", "Head"))
                self.assertTrue(read or (service, operation) == ("iam", "GenerateCredentialReport"))

    def test_allow_list_has_no_forbidden_operation(self):
        self.assertFalse(ALLOWED_OPERATIONS & FORBIDDEN_OPERATIONS)

    def test_allow_list_names_exist_in_botocore(self):
        session = botocore.session.get_session()
        for service, operation in ALLOWED_OPERATIONS:
            with self.subTest(operation=f"{service}:{operation}"):
                self.assertIn(operation, session.get_service_model(service).operation_names)


class EnvironmentTest(unittest.TestCase):
    def test_credentials_and_profile_in_environment_are_removed(self):
        environ = {
            "AWS_PROFILE": "someone-else",
            "AWS_DEFAULT_PROFILE": "someone-else",
            "AWS_ACCESS_KEY_ID": "fake",
            "AWS_SECRET_ACCESS_KEY": "fake",
            "AWS_SESSION_TOKEN": "fake",
            "AWS_ENDPOINT_URL": "https://example.invalid",
            "AWS_ENDPOINT_URL_S3": "https://example.invalid",
            "AWS_CONFIG_FILE": "/fake/config",
            "HOME": "/fake/home",
        }
        clean_environment(environ)
        self.assertEqual(environ, {"AWS_CONFIG_FILE": "/fake/config", "HOME": "/fake/home"})

    def test_session_uses_tester_profile_explicitly(self):
        with mock.patch.dict("os.environ", {"AWS_PROFILE": "someone-else", "AWS_ACCESS_KEY_ID": "fake"}), \
                mock.patch.object(aws_module.boto3, "Session") as session:
            aws_module.build_session()
            import os
            self.assertNotIn("AWS_PROFILE", os.environ)
            self.assertNotIn("AWS_ACCESS_KEY_ID", os.environ)
        session.assert_called_once_with(profile_name="harborline-tester")


class IdentityTest(unittest.TestCase):
    def _identity(self, arn, account=ACCOUNT):
        aws = Aws(fake_session())
        stubs = Stubs(aws)
        stubs("sts").add_response("get_caller_identity", {"UserId": "AROAFAKE:s", "Account": account, "Arn": arn}, {})
        return verify_identity(aws.client("sts"))

    def test_tester_role_is_accepted(self):
        _, partition, account = self._identity(f"arn:aws:sts::{ACCOUNT}:assumed-role/harborline-tester/session-1")
        self.assertEqual((partition, account), ("aws", ACCOUNT))

    def test_other_callers_are_rejected(self):
        for arn in [
            f"arn:aws:sts::{ACCOUNT}:assumed-role/harborline-deployer/session-1",
            f"arn:aws:sts::{ACCOUNT}:assumed-role/harborline-tester-extra/session-1",
            f"arn:aws:sts::{ACCOUNT}:assumed-role/AWSReservedSSO_AdministratorAccess_fake/me",
            f"arn:aws:iam::{ACCOUNT}:user/harborline-tester",
            f"arn:aws:iam::{ACCOUNT}:root",
        ]:
            with self.subTest(arn=arn), self.assertRaises(IdentityError) as ctx:
                self._identity(arn)
            self.assertNotIn(ACCOUNT, str(ctx.exception))

    def test_account_mismatch_is_rejected(self):
        with self.assertRaises(IdentityError):
            self._identity(f"arn:aws:sts::{ACCOUNT}:assumed-role/harborline-tester/s", account="2" * 12)


if __name__ == "__main__":
    unittest.main()
