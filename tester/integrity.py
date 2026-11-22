"""Verifies a collected evidence run before anything in it is evaluated.

Every file listed in manifest.json is read once, its SHA-256 recomputed and
compared with the manifest. Any missing, altered or unlisted file stops the
evaluation. The verified bytes are kept in memory and are the only copy the
evaluator reads, so a file cannot change between being checked and being used.
"""

import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .evidence import sha256_hex

MANIFEST = "manifest.json"
# Written into the run folder by the evaluator itself (tester/evaluate.py), so
# they are expected there on a second evaluation and are not evidence.
EVALUATOR_OUTPUTS = ("results.json", "results.md")


class IntegrityError(Exception):
    def __init__(self, problems):
        super().__init__("; ".join(problems))
        self.problems = list(problems)


@dataclass(frozen=True)
class VerifiedRun:
    run_dir: Path
    manifest: dict
    manifest_sha256: str
    contents: dict  # manifest path -> verified bytes


def _inside(run_dir, rel):
    """True if rel names a regular file reached without following any symlink."""
    path = run_dir
    for part in rel.parts:
        path = path / part
        if path.is_symlink():
            return False
    return True


def verify_run(run_dir, expected_manifest_sha256=None):
    run_dir = Path(run_dir)
    if not run_dir.is_dir() or run_dir.is_symlink():
        raise IntegrityError([f"run folder not found: {run_dir}"])

    manifest_path = run_dir / MANIFEST
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise IntegrityError(["manifest.json is missing from the run folder"])
    raw = manifest_path.read_bytes()
    manifest_sha = sha256_hex(raw)
    if expected_manifest_sha256 and manifest_sha != expected_manifest_sha256.strip().lower():
        raise IntegrityError([f"manifest.json has SHA-256 {manifest_sha}, not the expected "
                              f"{expected_manifest_sha256.strip().lower()}"])
    try:
        manifest = json.loads(raw)
    except ValueError:
        raise IntegrityError(["manifest.json is not valid JSON"]) from None
    entries = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(entries, list):
        raise IntegrityError(["manifest.json has no list of files"])

    problems = []
    contents = {}
    listed = set()
    for n, entry in enumerate(entries, start=1):
        path = entry.get("path") if isinstance(entry, dict) else None
        expected = entry.get("sha256") if isinstance(entry, dict) else None
        if not isinstance(path, str) or not path or not isinstance(expected, str):
            problems.append(f"manifest entry {n} has no path or no sha256")
            continue
        rel = PurePosixPath(path)
        if (rel.is_absolute() or ".." in rel.parts or "\\" in path
                or path in (MANIFEST, *EVALUATOR_OUTPUTS)):
            problems.append(f"manifest entry {n} names a path outside the evidence files: {path}")
            continue
        if path in listed:
            problems.append(f"listed twice in the manifest: {path}")
            continue
        listed.add(path)
        full = run_dir.joinpath(*rel.parts)
        if not _inside(run_dir, rel):
            problems.append(f"is a symbolic link, not a file in the run folder: {path}")
            continue
        if not full.is_file():
            problems.append(f"missing: {path}")
            continue
        data = full.read_bytes()
        actual = sha256_hex(data)
        if actual != expected.lower():
            problems.append(f"altered: {path} (manifest {expected.lower()}, file {actual})")
            continue
        contents[path] = data

    for item in sorted(run_dir.rglob("*")):
        rel = item.relative_to(run_dir).as_posix()
        if item.is_dir() and not item.is_symlink():
            continue
        if rel in (MANIFEST, *EVALUATOR_OUTPUTS) and not item.is_symlink():
            continue
        if rel not in listed:
            problems.append(f"unlisted: {rel}")

    if problems:
        raise IntegrityError(problems)
    return VerifiedRun(run_dir=run_dir, manifest=manifest, manifest_sha256=manifest_sha, contents=contents)
