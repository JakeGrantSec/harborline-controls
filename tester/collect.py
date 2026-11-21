"""Collect raw evidence for C-01 to C-07.

    python -m tester.collect --out <folder>

Uses the harborline-tester AWS profile only, and stops unless the caller is the
harborline-tester role. Read calls only (plus generating the IAM credential
report). Writes <out>/<UTC timestamp>/<control ID>/*.json and a manifest.json,
then prints the manifest's SHA-256 hash. Collection only: no pass or fail
evaluation, and no AI service is called.
"""

import argparse
import datetime
import os
import subprocess
import sys
import traceback
from pathlib import Path

from . import aws as aws_module
from .collectors import COLLECTORS
from .evidence import EvidenceWriter, prepare_output
from .github import TOKEN_ENV, GitHub, GitHubError, parse_github_remote
from .library import CONTROL_IDS, LibraryError, load_library
from .run import Run

REPO_ROOT = Path(__file__).resolve().parents[1]


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def _git(repo_root, *args):
    return subprocess.run(["git", "-C", str(repo_root), *args], capture_output=True, text=True,
                          check=True, timeout=30).stdout.strip()


def tester_code_version(repo_root):
    return {
        "commit": _git(repo_root, "rev-parse", "HEAD"),
        "uncommitted_changes_in_tester_or_controls": bool(
            _git(repo_root, "status", "--porcelain", "--", "tester", "controls")),
    }


def parse_args(argv):
    parser = argparse.ArgumentParser(prog="python -m tester.collect", description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, help="output folder; a UTC timestamp folder is created in it")
    return parser.parse_args(argv)


def main(argv=None, *, session_factory=aws_module.build_session, github_opener=None,
         environ=os.environ, now=_utcnow, repo_root=REPO_ROOT, code_version=tester_code_version,
         remote_url=None, gitleaks_bin=None, runner=subprocess.run, sleep=None):
    args = parse_args(argv)

    try:
        library = load_library(repo_root)
        github = GitHub(environ.get(TOKEN_ENV), opener=github_opener)
        owner_repo = parse_github_remote(remote_url or _git(repo_root, "remote", "get-url", "origin"))
        version = code_version(repo_root)
    except (LibraryError, GitHubError, OSError, subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    aws = aws_module.Aws(session_factory())
    if not aws.region:
        print(f"error: profile {aws_module.PROFILE} has no region configured", file=sys.stderr)
        return 1
    try:
        identity, partition, account_id = aws_module.verify_identity(aws.client("sts"))
    except aws_module.IdentityError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    started = now()
    run_dir = prepare_output(args.out, started)
    writer = EvidenceWriter(run_dir)

    run_kwargs = dict(aws=aws, writer=writer, library=library, partition=partition,
                      account_id=account_id, repo_root=repo_root, github=github,
                      github_repo=owner_repo, gitleaks_bin=gitleaks_bin, runner=runner)
    if sleep is not None:
        run_kwargs["sleep"] = sleep
    run = Run(**run_kwargs)

    failures = []
    for control_id in CONTROL_IDS:
        print(f"collecting {control_id} ...", flush=True)
        try:
            COLLECTORS[control_id](run)
        except Exception as exc:  # Record and continue with the next control.
            failures.append({
                "control": control_id,
                "error": type(exc).__name__,
                "message": str(exc),
                "where": traceback.extract_tb(exc.__traceback__)[-1].name,
            })

    identity = {k: v for k, v in identity.items() if k != "ResponseMetadata"}
    manifest = {
        "collection_started_at": started.isoformat(),
        "collection_finished_at": now().isoformat(),
        "caller_identity": identity,
        "aws_profile": aws_module.PROFILE,
        "aws_region": aws.region,
        "tester_code": version,
        "control_library": {
            "version": library.version,
            "controls_yaml_sha256": library.controls_sha256,
            "approved_lists_yaml_sha256": library.approved_lists_sha256,
        },
        "github_repository": "/".join(owner_repo),
        "files": writer.files,
        "api_errors": run.api_errors,
        "control_failures": failures,
    }
    manifest_path, manifest_sha = writer.write_manifest(manifest)

    print(f"files written: {len(writer.files)}; API error responses saved: {len(run.api_errors)}; "
          f"controls that did not finish: {len(failures)}")
    for failure in failures:
        print(f"  {failure['control']}: {failure['error']}: {failure['message']}", file=sys.stderr)
    print(f"manifest: {manifest_path}")
    print(f"manifest sha256: {manifest_sha}")
    return 2 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
