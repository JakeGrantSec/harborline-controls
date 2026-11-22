"""Evaluate one collected evidence run against the pass criteria in controls/controls.yaml.

    python -m tester.evaluate --run <run folder> [--manifest-sha256 <hash>]

First recomputes the SHA-256 of every file in the run's manifest.json and stops,
evaluating nothing, if any file is missing, altered or unlisted. Then judges
each control's checks as pass, fail or not_tested and writes results.json and
results.md into the run folder. Reads only the run folder and the two control
library files: no AWS, GitHub or other network calls, and no AI service.

Exit codes: 0 every control passed; 1 a control failed or was not fully tested;
2 the run or the control library could not be read; 3 the integrity check failed.
"""

import argparse
import datetime
import subprocess
import sys
from pathlib import Path

from .checks import FAIL, NOT_TESTED, PASS, Evidence, control_result, parse_time
from .evaluators import EVALUATORS, Context
from .integrity import IntegrityError, verify_run
from .library import CONTROL_IDS, LibraryError, load_library
from .report import LABELS, write_results

REPO_ROOT = Path(__file__).resolve().parents[1]


def _git(repo_root, *args):
    return subprocess.run(["git", "-C", str(repo_root), *args], capture_output=True, text=True,
                          check=True, timeout=30).stdout.strip()


def evaluator_code_version(repo_root):
    try:
        return {
            "commit": _git(repo_root, "rev-parse", "HEAD"),
            "uncommitted_changes_in_tester_or_controls": bool(
                _git(repo_root, "status", "--porcelain", "--", "tester", "controls")),
        }
    except (OSError, subprocess.SubprocessError) as exc:
        return {"commit": None, "error": f"could not read the git commit: {type(exc).__name__}"}


def evaluate(verified, library):
    """The list of evaluated controls, in control ID order."""
    ctx = Context(Evidence(verified), library, verified.manifest)
    failures = {}
    for failure in verified.manifest.get("control_failures") or []:
        if isinstance(failure, dict):
            failures.setdefault(failure.get("control"), []).append(failure)

    controls = []
    for cid in CONTROL_IDS:
        definition = library.controls[cid]
        checks = EVALUATORS[cid](ctx)
        for failure in failures.get(cid, []):
            for check in checks:
                check.gap(f"collection of {cid} did not finish ({failure.get('error')}: {failure.get('message')}), "
                          "so its evidence may be incomplete")
        result = control_result(checks)
        checks = [check.to_dict() for check in checks]
        controls.append({
            "id": cid,
            "name": definition.get("name"),
            "result": result,
            "pass_criteria": " ".join(str(definition.get("pass_criteria", "")).split()),
            "seeded_failure": definition.get("seeded_failure"),
            "checks": checks,
            "exceptions": [{"check": check["id"], "item": item["item"], "detail": item["detail"]}
                           for check in checks for item in check["population"] if item["result"] == FAIL],
        })
    return controls


def build_results(verified, library, controls, code_version, evaluated_at):
    manifest = verified.manifest
    at_collection = manifest.get("control_library") or {}
    return {
        "evaluator": {"module": "tester.evaluate", "code": code_version},
        "evaluated_at": evaluated_at.isoformat(),
        "run": {
            "folder": verified.run_dir.name,
            "manifest_sha256": verified.manifest_sha256,
            "files_verified": len(verified.contents),
            "collection_started_at": manifest.get("collection_started_at"),
            "collection_finished_at": manifest.get("collection_finished_at"),
            "age_reference_time": manifest.get("collection_started_at"),
            "caller_identity_arn": (manifest.get("caller_identity") or {}).get("Arn"),
            "collector_code": manifest.get("tester_code"),
            "api_errors": manifest.get("api_errors") or [],
            "control_failures": manifest.get("control_failures") or [],
        },
        "control_library": {
            "version": library.version,
            "controls_yaml_sha256": library.controls_sha256,
            "approved_lists_yaml_sha256": library.approved_lists_sha256,
            "at_collection": at_collection,
            "same_as_collection": (at_collection.get("controls_yaml_sha256") == library.controls_sha256
                                   and at_collection.get("approved_lists_yaml_sha256") == library.approved_lists_sha256),
        },
        "summary": {c["id"]: c["result"] for c in controls},
        "controls": controls,
    }


def parse_args(argv):
    parser = argparse.ArgumentParser(prog="python -m tester.evaluate", description=__doc__.splitlines()[0])
    parser.add_argument("--run", required=True, help="one run folder written by tester.collect")
    parser.add_argument("--manifest-sha256", help="optional: the manifest hash printed by the collector; "
                                                  "the evaluation stops if it differs")
    return parser.parse_args(argv)


def main(argv=None, *, repo_root=REPO_ROOT, code_version=evaluator_code_version, now=None):
    args = parse_args(argv)
    try:
        library = load_library(repo_root)
    except (LibraryError, OSError) as exc:
        print(f"error: control library: {exc}", file=sys.stderr)
        return 2

    try:
        verified = verify_run(args.run, args.manifest_sha256)
    except IntegrityError as exc:
        print(f"INTEGRITY CHECK FAILED for {args.run}; nothing was evaluated:", file=sys.stderr)
        for problem in exc.problems:
            print(f"  {problem}", file=sys.stderr)
        return 3

    if parse_time(verified.manifest.get("collection_started_at")) is None:
        print("error: manifest.json has no readable collection_started_at; nothing was evaluated", file=sys.stderr)
        return 2
    try:
        controls = evaluate(verified, library)
    except KeyError as exc:
        print(f"error: control library: {exc.args[0]}", file=sys.stderr)
        return 2

    evaluated_at = (now or (lambda: datetime.datetime.now(datetime.timezone.utc)))()
    results = build_results(verified, library, controls, code_version(repo_root), evaluated_at)
    json_path, md_path = write_results(verified.run_dir, results)

    print(f"manifest sha256: {verified.manifest_sha256} ({len(verified.contents)} files verified)")
    if not results["control_library"]["same_as_collection"]:
        print("warning: the control library differs from the one recorded at collection; the current one was used")
    for control in controls:
        counts = {r: sum(1 for c in control["checks"] if c["result"] == r) for r in (PASS, FAIL, NOT_TESTED)}
        print(f"{control['id']} {LABELS[control['result']]:<10} {control['name']} "
              f"(checks: {counts[PASS]} pass, {counts[FAIL]} fail, {counts[NOT_TESTED]} not tested)")
    print(f"results: {json_path}")
    print(f"results: {md_path}")
    return 0 if all(c["result"] == PASS for c in controls) else 1


if __name__ == "__main__":
    sys.exit(main())
