import contextlib
import io
import unittest

from tester import collectors
from tester.github import API_ROOT, GitHub, GitHubError, _NoRedirect, parse_github_remote
from tester.tests.helpers import FakeGitHubOpener, RunTestCase

# Built at run time; obviously fake.
FAKE_TOKEN = "fake-read-token-" + "0" * 8
BASE = f"{API_ROOT}/repos/harborline-fake-owner/harborline-fake-repo"
SHA1, SHA2 = "a" * 40, "b" * 40


def routes():
    return {
        f"{BASE}/rules/branches/main": (200, [{"type": "pull_request", "ruleset_id": 7}], None),
        f"{BASE}/rulesets?includes_parents=true&per_page=100": (200, [{"id": 7, "name": "main"}], None),
        f"{BASE}/rulesets/7": (200, {"id": 7, "enforcement": "active", "bypass_actors": []}, None),
        f"{BASE}/commits?sha=main&per_page=100": (
            200, [{"sha": SHA1}], f'<{BASE}/commits?sha=main&per_page=100&page=2>; rel="next"'),
        f"{BASE}/commits?sha=main&per_page=100&page=2": (200, [{"sha": SHA2}], None),
        f"{BASE}/commits/{SHA1}/pulls?per_page=100": (200, [{"number": 5}], None),
        f"{BASE}/commits/{SHA2}/pulls?per_page=100": (200, [{"number": 5}], None),
        f"{BASE}/pulls/5": (200, {"number": 5, "merged_at": "2026-11-20T10:00:00Z"}, None),
        f"{BASE}/pulls/5/reviews?per_page=100": (200, [{"state": "APPROVED", "user": {"login": "fake-approver"}}], None),
    }


class C07Test(RunTestCase):
    def test_ruleset_commits_pulls_and_reviews(self):
        opener = FakeGitHubOpener(routes())
        self.run.github = GitHub(FAKE_TOKEN, opener=opener)
        self.run.github_repo = ("harborline-fake-owner", "harborline-fake-repo")

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            collectors.collect_c07(self.run)

        self.assertEqual(len(opener.requests), len(routes()))  # Each URL once; PR 5 collected once.
        for request in opener.requests:
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(request.get_header("Authorization"), f"Bearer {FAKE_TOKEN}")
        saved = self.saved("C-07")
        self.assertEqual(len(saved), len(routes()))
        self.assertEqual(saved["006_github_commit_aaaaaaaaaaaa_pulls_page001.json"], [{"number": 5}])
        self.assertNotIn(FAKE_TOKEN, self.all_output_text())
        self.assertNotIn(FAKE_TOKEN, stdout.getvalue())
        entry = self.writer.files[0]
        self.assertEqual(entry["request"], {"method": "GET", "url": f"{BASE}/rules/branches/main", "status": 200})

    def test_error_responses_are_saved_and_recorded(self):
        r = routes()
        r[f"{BASE}/rulesets?includes_parents=true&per_page=100"] = (403, {"message": "Resource not accessible"}, None)
        self.run.github = GitHub(FAKE_TOKEN, opener=FakeGitHubOpener(r))
        self.run.github_repo = ("harborline-fake-owner", "harborline-fake-repo")
        collectors.collect_c07(self.run)
        self.assertIn({"control": "C-07", "operation": f"GET {BASE}/rulesets?includes_parents=true&per_page=100",
                       "code": "HTTP 403"}, self.run.api_errors)


class ClientTest(unittest.TestCase):
    def test_token_required_and_hidden(self):
        with self.assertRaises(GitHubError):
            GitHub("")
        self.assertNotIn(FAKE_TOKEN, repr(GitHub(FAKE_TOKEN)))

    def test_only_github_api_urls(self):
        with self.assertRaises(GitHubError):
            GitHub(FAKE_TOKEN, opener=FakeGitHubOpener({})).get("https://example.invalid/x")

    def test_next_link_to_another_host_is_not_followed(self):
        url = f"{BASE}/commits"
        gh = GitHub(FAKE_TOKEN, opener=FakeGitHubOpener({url: (200, [], '<https://example.invalid/x>; rel="next"')}))
        self.assertEqual(len(list(gh.paginate(url))), 1)

    def test_redirects_are_not_followed(self):
        self.assertIsNone(_NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://example.invalid"))

    def test_parse_remote(self):
        for remote in ["https://github.com/fake-owner/fake-repo.git", "git@github.com:fake-owner/fake-repo.git",
                       "https://github.com/fake-owner/fake-repo"]:
            self.assertEqual(parse_github_remote(remote), ("fake-owner", "fake-repo"))
        with self.assertRaises(GitHubError):
            parse_github_remote("https://example.invalid/fake-owner/fake-repo.git")


if __name__ == "__main__":
    unittest.main()
