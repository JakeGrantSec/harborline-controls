"""Writes results.json and results.md into the evaluated run folder."""

import json
from pathlib import Path

LABELS = {"pass": "PASS", "fail": "FAIL", "not_tested": "NOT TESTED"}


def _md(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(results):
    run = results["run"]
    lib = results["control_library"]
    code = results["evaluator"]["code"]
    lines = [
        f"# Control test results: {run['folder']}",
        "",
        f"- Evidence collected: {run['collection_started_at']} to {run['collection_finished_at']}",
        f"- Manifest SHA-256: `{run['manifest_sha256']}` ({run['files_verified']} evidence files verified)",
        f"- Collected as: `{run['caller_identity_arn']}`",
        f"- Evaluator commit: `{code.get('commit')}`"
        + (" (with uncommitted changes in tester/ or controls/)" if code.get("uncommitted_changes_in_tester_or_controls")
           else ""),
        f"- Control library version {lib['version']}: controls.yaml `{lib['controls_yaml_sha256']}`, "
        f"approved-lists.yaml `{lib['approved_lists_yaml_sha256']}`"
        + ("" if lib["same_as_collection"] else " (**differs from the library used at collection**)"),
        f"- Ages are measured from the collection start time, not the evaluation time ({results['evaluated_at']}).",
        "",
        "| Control | Name | Result | Checks passed |",
        "|---|---|---|---|",
    ]
    for control in results["controls"]:
        passed = sum(1 for c in control["checks"] if c["result"] == "pass")
        lines.append(f"| {control['id']} | {_md(control['name'])} | {LABELS[control['result']]} | "
                     f"{passed} of {len(control['checks'])} |")
    for control in results["controls"]:
        lines += ["", f"## {control['id']} {control['name']}: {LABELS[control['result']]}", "",
                  f"Pass criteria: {_md(control['pass_criteria'])}", ""]
        if control["exceptions"]:
            lines.append("Exceptions:")
            lines += [f"- {e['check']} {_md(e['item'])}: {_md(e['detail'])}" for e in control["exceptions"]]
            lines.append("")
        for check in control["checks"]:
            lines += [f"### {check['id']} {LABELS[check['result']]}", "", _md(check["criterion"]), "",
                      f"Result: {_md(check['reason'])}", ""]
            if check["population"]:
                lines += ["| Tested | Result | Detail |", "|---|---|---|"]
                lines += [f"| {_md(p['item'])} | {LABELS.get(p['result'], p['result'])} | {_md(p['detail'])} |"
                          for p in check["population"]]
                lines.append("")
            if "approved_exceptions" in check:
                lines.append("Approved exceptions (controls/approved-lists.yaml, matched exactly as written):")
                lines += [f"- `{_md(e['action'])}`: {_md(e['reason'])} Approved by {_md(e['approved_by'])} on "
                          f"{_md(e['approved_on'])}. Used by: {_md(', '.join(e['used_by']) or 'no policy')}."
                          for e in check["approved_exceptions"]] or ["- none"]
                lines.append("")
            if check["excluded"]:
                lines.append("Left out:")
                lines += [f"- {_md(e['item'])}: {_md(e['reason'])}" for e in check["excluded"]]
                lines.append("")
            if check["gaps"]:
                lines.append("Gaps in the evidence:")
                lines += [f"- {_md(g)}" for g in check["gaps"]]
                lines.append("")
            if check["evidence"]:
                lines.append("<details><summary>Evidence files</summary>\n")
                lines += [f"- `{e['path']}` `{e['sha256']}`" for e in check["evidence"]]
                lines += ["", "</details>", ""]
    return "\n".join(lines).rstrip() + "\n"


def _write_new(path, text):
    path = Path(path)
    if path.is_symlink() or path.exists():
        path.unlink()  # Replace an earlier result; never write through a link.
    with open(path, "x", encoding="utf-8") as f:
        f.write(text)


def write_results(run_dir, results):
    run_dir = Path(run_dir)
    json_path, md_path = run_dir / "results.json", run_dir / "results.md"
    _write_new(json_path, json.dumps(results, indent=2, ensure_ascii=False) + "\n")
    _write_new(md_path, render_markdown(results))
    return json_path, md_path
