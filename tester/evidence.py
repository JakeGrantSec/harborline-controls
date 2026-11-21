"""Writes raw evidence files and the manifest.

Each response is written once, as JSON, unchanged except that dates become ISO
8601 text and byte strings (the IAM credential report) become UTF-8 text. The
SHA-256 hash of each file is recorded when it is written, before anything reads
or interprets it.
"""

import datetime
import hashlib
import json
import re
from pathlib import Path

# Written to the output folder so nothing under it can be added to git
# (the pattern also matches this .gitignore file itself).
OUTPUT_GITIGNORE = "# Evidence output: never commit.\n*\n"

_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def _json_default(value):
    if isinstance(value, (datetime.datetime, datetime.date)):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8")
    raise TypeError(f"cannot serialize {type(value).__name__}")


def to_json_bytes(data):
    return (json.dumps(data, default=_json_default, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def safe_name(text):
    return _SAFE_NAME.sub("_", text).strip("_")[:150] or "item"


def utc_timestamp(now):
    return now.strftime("%Y%m%dT%H%M%SZ")


def prepare_output(out_dir, now):
    """Create <out>/<UTC timestamp>/ and make <out> uncommittable."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    gitignore = out / ".gitignore"
    if not gitignore.exists() or "*" not in gitignore.read_text(encoding="utf-8").splitlines():
        gitignore.write_text(OUTPUT_GITIGNORE, encoding="utf-8")
    run_dir = out / utc_timestamp(now)
    run_dir.mkdir()  # Fails if this run folder already exists.
    return run_dir


class EvidenceWriter:
    def __init__(self, run_dir):
        self.run_dir = Path(run_dir)
        self.files = []
        self._counters = {}

    def _next_path(self, control_id, name, suffix=".json"):
        folder = self.run_dir / control_id
        folder.mkdir(exist_ok=True)
        n = self._counters.get(control_id, 0) + 1
        self._counters[control_id] = n
        return folder / f"{n:03d}_{safe_name(name)}{suffix}"

    def _record(self, path, body, control_id, request, error, note):
        entry = {
            "path": path.relative_to(self.run_dir).as_posix(),
            "sha256": sha256_hex(body),
            "control": control_id,
            "request": request,
        }
        if error:
            entry["error"] = error
        if note:
            entry["note"] = note
        self.files.append(entry)
        return entry

    def save(self, control_id, name, data, *, request, error=None, note=None):
        """Write one response as JSON. Returns the manifest entry."""
        body = to_json_bytes(data)
        path = self._next_path(control_id, name)
        with open(path, "xb") as f:
            f.write(body)
        return self._record(path, body, control_id, request, error, note)

    def reserve(self, control_id, name, suffix=".json"):
        """A path for a file another program writes (the gitleaks report)."""
        return self._next_path(control_id, name, suffix)

    def register(self, control_id, path, *, request, note=None):
        """Record the hash of a file written by another program."""
        body = Path(path).read_bytes()
        return self._record(Path(path), body, control_id, request, None, note)

    def discard(self, path):
        Path(path).unlink(missing_ok=True)

    def write_manifest(self, manifest):
        body = to_json_bytes(manifest)
        path = self.run_dir / "manifest.json"
        with open(path, "xb") as f:
            f.write(body)
        return path, sha256_hex(body)
