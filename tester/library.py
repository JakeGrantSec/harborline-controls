"""Loads the control library and approved lists from controls/ (the source of truth)."""

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .evidence import sha256_hex

CONTROLS_FILE = Path("controls/controls.yaml")
APPROVED_LISTS_FILE = Path("controls/approved-lists.yaml")
CONTROL_IDS = ("C-01", "C-02", "C-03", "C-04", "C-05", "C-06", "C-07")


class LibraryError(Exception):
    pass


@dataclass(frozen=True)
class Tag:
    key: str
    value: str

    def matches(self, tags):
        return tags.get(self.key) == self.value


@dataclass(frozen=True)
class Library:
    controls: dict
    approved_lists: dict
    scope_tag: Tag
    audit_log_tag: Tag
    version: str
    controls_sha256: str
    approved_lists_sha256: str
    thresholds: dict = field(default_factory=dict)


def _tag(scope, name):
    tag = scope.get(name)
    if not isinstance(tag, dict) or not isinstance(tag.get("key"), str) or not isinstance(tag.get("value"), str):
        raise LibraryError(f"scope.{name} must have a string key and value")
    return Tag(tag["key"], tag["value"])


def load_library(repo_root):
    root = Path(repo_root)
    controls_raw = (root / CONTROLS_FILE).read_bytes()
    lists_raw = (root / APPROVED_LISTS_FILE).read_bytes()
    data = yaml.safe_load(controls_raw)
    lists = yaml.safe_load(lists_raw)
    if not isinstance(data, dict) or not isinstance(lists, dict):
        raise LibraryError("control library files must contain YAML mappings")

    controls = {c.get("id"): c for c in data.get("controls") or [] if isinstance(c, dict)}
    missing = [cid for cid in CONTROL_IDS if cid not in controls]
    if missing:
        raise LibraryError(f"controls.yaml has no definition for {', '.join(missing)}")

    scope = data.get("scope") or {}
    return Library(
        controls=controls,
        approved_lists=lists,
        scope_tag=_tag(scope, "in_scope_tag"),
        audit_log_tag=_tag(scope, "audit_log_tag"),
        version=str((data.get("library") or {}).get("version", "")),
        controls_sha256=sha256_hex(controls_raw),
        approved_lists_sha256=sha256_hex(lists_raw),
        thresholds=dict(scope.get("thresholds") or {}),
    )
