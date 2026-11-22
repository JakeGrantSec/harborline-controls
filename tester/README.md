# Evidence collector

Collects raw evidence for controls C-01 to C-07, following the test procedures in
`controls/controls.yaml`. It collects only: it does not decide pass or fail, and
it calls no AI service.

```sh
pip install -r tester/requirements.txt
export HARBORLINE_GH_READ_TOKEN=...   # read-only GitHub token; never printed or saved
python -m tester.collect --out evidence
```

- **AWS identity:** uses the `harborline-tester` AWS profile only. Credentials and profile names already set in the environment are ignored. The collector stops unless the caller is the `harborline-tester` role.
- **Read-only:** every AWS client refuses any operation not on `ALLOWED_OPERATIONS` in `tester/aws.py`, before the request is built. The one non-read call is `iam:GenerateCredentialReport`, which C-05 requires.
- **Output:** written to `<out>/<UTC timestamp>/<control ID>/`, one JSON file per response, plus `manifest.json` (every file with its SHA-256, the collection time, the caller identity and the tester's git commit). The manifest's own hash is printed at the end.
- **Never committed:** the collector writes a `.gitignore` containing `*` into the `--out` folder, so output cannot be committed from any path. `/evidence/` is also in the repository `.gitignore`.
- **Requires** `gitleaks` on `PATH` (C-04) and a GitHub `origin` remote (C-07).

# Evaluator

Judges one collected run against the pass criteria in `controls/controls.yaml`,
using `controls/approved-lists.yaml`:

```sh
python -m tester.evaluate --run evidence/<UTC timestamp> [--manifest-sha256 <hash printed by the collector>]
```

- **Integrity first:** recomputes the SHA-256 of every file in the run's `manifest.json`. If any file is missing,
  altered or unlisted (or the manifest hash differs from `--manifest-sha256`), it stops and evaluates nothing
  (exit code 3). `results.json` and `results.md` from an earlier evaluation are the only files allowed besides
  the manifest; they are replaced.
- **Offline:** reads only the run folder and the two control files. No AWS, GitHub or other network calls, no AI
  service, and the AWS SDK is not loaded. It runs `git rev-parse HEAD` to record its own commit.
- **Checks:** each control's pass criteria are split into checks with a result of `pass`, `fail` or `not_tested`
  and a reason. Anything the evidence cannot prove is `not_tested`, never passed. A control passes only if every
  check passes. Each check lists the population tested, resources left out and why, gaps in the evidence, and
  the evidence files used with their hashes.
- **Reproducible:** thresholds come from `controls.yaml`; ages (secrets, access keys) are measured from
  `collection_started_at` in the manifest, not the current time.
- **Output:** `results.json` and `results.md` in the run folder (never the repository), with the manifest hash and
  the evaluator's git commit, and one line per control on the console. Exit code 0 if every control passes,
  1 otherwise, 2 if the run or control library cannot be read.

# Tests

Unit tests run offline, with stubbed AWS and GitHub responses and small fake evidence runs
(`tester/tests/evaluator_samples.py`):

```sh
python -m unittest discover -s tester/tests -t .
```
