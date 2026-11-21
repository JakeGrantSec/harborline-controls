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

Unit tests run offline, with stubbed AWS and GitHub responses:

```sh
python -m unittest discover -s tester/tests -t .
```
