"""Minimal read-only GitHub REST client (C-07).

GET requests only, to https://api.github.com only. Redirects are not followed,
so the token is never sent to another host. The token is held privately and
never printed, logged or saved.
"""

import json
import re
import urllib.error
import urllib.parse
import urllib.request

API_ROOT = "https://api.github.com"
TOKEN_ENV = "HARBORLINE_GH_READ_TOKEN"

_NEXT_LINK = re.compile(r'<([^>]+)>;\s*rel="next"')


class GitHubError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # urllib then raises HTTPError with the 3xx status.


class GitHubResponse:
    def __init__(self, url, status, body, next_url):
        self.url = url
        self.status = status
        self.body = body
        self.next_url = next_url

    @property
    def ok(self):
        return 200 <= self.status < 300


class GitHub:
    def __init__(self, token, opener=None):
        if not token:
            raise GitHubError(f"{TOKEN_ENV} is not set")
        self.__token = token
        self._opener = opener or urllib.request.build_opener(_NoRedirect())

    def __repr__(self):
        return "GitHub(token=<hidden>)"

    def url(self, path, params=None):
        query = f"?{urllib.parse.urlencode(params)}" if params else ""
        return f"{API_ROOT}{path}{query}"

    def get(self, url):
        if not url.startswith(API_ROOT + "/"):
            raise GitHubError("refusing a request outside https://api.github.com")
        request = urllib.request.Request(
            url,
            method="GET",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.__token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "harborline-tester",
            },
        )
        try:
            with self._opener.open(request, timeout=30) as resp:
                status, raw, link = resp.status, resp.read(), resp.headers.get("Link")
        except urllib.error.HTTPError as exc:
            with exc:
                status, raw, link = exc.code, exc.read(), None
        except urllib.error.URLError as exc:
            raise GitHubError(f"GitHub request failed: {type(exc.reason).__name__}") from None
        try:
            body = json.loads(raw) if raw else None
        except ValueError:
            body = {"non_json_response_bytes": len(raw)}
        next_url = None
        if link:
            match = _NEXT_LINK.search(link)
            if match and match.group(1).startswith(API_ROOT + "/"):
                next_url = match.group(1)
        return GitHubResponse(url, status, body, next_url)

    def paginate(self, url):
        while url:
            response = self.get(url)
            yield response
            url = response.next_url if response.ok else None


def parse_github_remote(remote_url):
    """Return (owner, repo) from a GitHub https or ssh remote URL."""
    match = re.match(
        r"^(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)"
        r"(?P<owner>[A-Za-z0-9-]+)/(?P<repo>[A-Za-z0-9._-]+?)(?:\.git)?/?$",
        remote_url.strip(),
    )
    if not match:
        raise GitHubError("origin is not a github.com repository")
    return match.group("owner"), match.group("repo")
