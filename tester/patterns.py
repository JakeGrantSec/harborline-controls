"""Credential formats checked in Lambda environment variable values (C-04).

Only the result (True or False) is ever saved. The values themselves are never
written to disk or printed.
"""

import re

CREDENTIAL_PATTERNS = {
    "aws_access_key_id": re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA|A3T[A-Z0-9])[A-Z2-7]{16}(?![A-Z0-9])"),
    "anthropic_api_key": re.compile(r"(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_-]{20,}"),
    "openai_style_api_key": re.compile(r"(?<![A-Za-z0-9-])sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    "github_token": re.compile(r"(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"),
    "slack_token": re.compile(r"(?<![A-Za-z0-9])xox[abprs]-[A-Za-z0-9-]{10,}"),
    "google_api_key": re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_-]{35}"),
    "stripe_secret_key": re.compile(r"(?<![A-Za-z0-9])[rs]k_live_[0-9A-Za-z]{20,}"),
    "private_key_block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "jwt": re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
}


def matches_credential_pattern(value):
    if not isinstance(value, str):
        return False
    return any(p.search(value) for p in CREDENTIAL_PATTERNS.values())
