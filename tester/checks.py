"""Building blocks for the evaluator: an index over verified evidence, and the
Check record that holds one pass criterion's result, population and evidence.

Results are pass, fail or not_tested. A check fails if any tested item fails,
is not_tested if the evidence cannot prove every item, and passes only when
every item in a population known to be complete passes.
"""

import datetime
import json
import urllib.parse
from dataclasses import dataclass

PASS, FAIL, NOT_TESTED = "pass", "fail", "not_tested"
RESULTS = (PASS, FAIL, NOT_TESTED)


# --- Evidence -------------------------------------------------------------------


@dataclass(frozen=True)
class Item:
    """One verified evidence file and its manifest entry."""
    path: str
    sha256: str
    control: str
    request: dict
    error: str
    note: str
    raw: bytes

    @property
    def ref(self):
        return {"path": self.path, "sha256": self.sha256}

    @property
    def params(self):
        return (self.request or {}).get("params") or {}

    def data(self):
        """Parsed JSON, or None if the file is not JSON."""
        try:
            return json.loads(self.raw)
        except ValueError:
            return None

    # GitHub responses (C-07) record the URL instead of an AWS operation.
    @property
    def url_path(self):
        url = (self.request or {}).get("url") or ""
        return urllib.parse.urlsplit(url).path

    @property
    def url_query(self):
        url = (self.request or {}).get("url") or ""
        return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))


class Evidence:
    def __init__(self, verified):
        self.items = []
        for entry in verified.manifest.get("files", []):
            self.items.append(Item(
                path=entry["path"],
                sha256=entry["sha256"].lower(),
                control=entry.get("control") or "",
                request=entry.get("request") if isinstance(entry.get("request"), dict) else {},
                error=entry.get("error") or "",
                note=entry.get("note") or "",
                raw=verified.contents[entry["path"]],
            ))

    def find(self, control, service=None, operation=None, **params):
        """AWS responses for one control, by service, operation and request parameters."""
        found = []
        for item in self.items:
            if item.control != control:
                continue
            if service and item.request.get("service") != service:
                continue
            if operation and item.request.get("operation") != operation:
                continue
            if any(item.params.get(k) != v for k, v in params.items()):
                continue
            found.append(item)
        return found

    def github(self, control, predicate):
        return [i for i in self.items if i.control == control and "url" in i.request and predicate(i)]


# --- Checks ---------------------------------------------------------------------


class Check:
    def __init__(self, check_id, criterion):
        self.id = check_id
        self.criterion = criterion
        self.population = []   # {"item", "result", "detail"}
        self.excluded = []     # {"item", "reason"}
        self.gaps = []         # reasons the population may be incomplete
        self.evidence = {}     # path -> sha256
        self.empty_reason = None
        self.result = None
        self.reason = None

    def use(self, *items):
        for item in items:
            if item is not None:
                self.evidence[item.path] = item.sha256
        return self

    def add(self, name, result, detail, evidence=()):
        assert result in RESULTS
        self.population.append({"item": name, "result": result, "detail": detail})
        self.use(*evidence)

    def exclude(self, name, reason, evidence=()):
        self.excluded.append({"item": name, "reason": reason})
        self.use(*evidence)

    def gap(self, reason, evidence=()):
        if reason not in self.gaps:
            self.gaps.append(reason)
        self.use(*evidence)

    def allow_empty(self, reason):
        """An empty population passes, because the evidence shows it is complete and empty."""
        self.empty_reason = reason

    def decide(self, result, reason):
        """Set the result directly (used where the rule is not per item)."""
        assert result in RESULTS
        self.result, self.reason = result, reason

    def finalize(self):
        if self.result is not None:
            return self
        failed = [p for p in self.population if p["result"] == FAIL]
        untested = [p for p in self.population if p["result"] == NOT_TESTED]
        if failed:
            self.result = FAIL
            self.reason = "Failed for " + "; ".join(f"{p['item']}: {p['detail']}" for p in failed)
            if self.gaps:
                self.reason += ". Also not fully tested: " + "; ".join(self.gaps)
        elif untested or self.gaps:
            self.result = NOT_TESTED
            parts = [f"{p['item']}: {p['detail']}" for p in untested] + self.gaps
            self.reason = "The evidence cannot prove this criterion: " + "; ".join(parts)
        elif not self.population:
            if self.empty_reason:
                self.result, self.reason = PASS, self.empty_reason
            else:
                self.result = NOT_TESTED
                self.reason = "No items to test were found in the evidence, so the criterion cannot be proven."
        else:
            self.result = PASS
            n = len(self.population)
            self.reason = "The 1 tested item passes." if n == 1 else f"All {n} tested items pass."
        return self

    def to_dict(self):
        self.finalize()
        return {
            "id": self.id,
            "criterion": self.criterion,
            "result": self.result,
            "reason": self.reason,
            "population": self.population,
            "excluded": self.excluded,
            "gaps": self.gaps,
            "evidence": [{"path": p, "sha256": s} for p, s in sorted(self.evidence.items())],
        }


def control_result(checks):
    results = [c.finalize().result for c in checks]
    if results and all(r == PASS for r in results):
        return PASS
    if FAIL in results:
        return FAIL
    return NOT_TESTED


# --- Small helpers ----------------------------------------------------------------


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def parse_time(value):
    """ISO 8601 text to an aware datetime (UTC if no zone), or None."""
    if not isinstance(value, str) or not value or value in ("N/A", "not_supported", "no_information"):
        return None
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed


def age_days(then, now):
    return (now - then).total_seconds() / 86400


def policy_document(value):
    """IAM policy document as a dict (boto3 decodes it; accept URL-encoded text too)."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        for text in (value, urllib.parse.unquote(value)):
            try:
                parsed = json.loads(text)
            except ValueError:
                continue
            if isinstance(parsed, dict):
                return parsed
    return None


def statements(document):
    return [s for s in as_list((document or {}).get("Statement")) if isinstance(s, dict)]


def items_text(names, limit=10):
    names = list(names)
    shown = ", ".join(names[:limit])
    return shown + (f" and {len(names) - limit} more" if len(names) > limit else "")
