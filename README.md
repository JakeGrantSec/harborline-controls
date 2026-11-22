# Harborline Controls

Security controls for a small cloud environment that was built by an AI coding agent working under human
governance, with automated tests that check whether the controls hold.

> **Disclaimer.** This is a personal learning and portfolio project. Harborline Financial Technologies is a
> fictional company, and all data here is synthetic. The infrastructure is a sandbox. It is not hardened for
> production and should not be reused in a production environment without independent review.

## What this project demonstrates

How to govern an AI coding agent that builds cloud infrastructure:

- **The agent builds.** An AI coding agent writes the Terraform, the tester code and the pull requests.
- **A human sets the rules.** A human designed and approved the seven security controls, and the agent must
  follow the project rules in [CLAUDE.md](CLAUDE.md).
- **Controls are tested, not assumed.** A tester gathers evidence through a read-only AWS role and judges it
  against the control definitions.

## How changes flow

1. The agent authors every change as the machine account `harborline-bot`, on its own branch.
2. It opens a pull request. A human reviews and approves every pull request. The agent can't approve its own
   work, and it's never allowed to merge.
3. Branch rules on `main` block direct changes, so the only way in is an approved pull request.
4. A human deploys to AWS from `main`. The agent never runs `terraform apply` or any AWS command that changes
   resources.

Control C-07 tests this flow: every change must have a prior approval from someone other than its author.

## The seven controls

Full definitions, test procedures, pass criteria and framework mappings are in
[controls/controls.yaml](controls/controls.yaml). Approved administrators and approvers are in
[controls/approved-lists.yaml](controls/approved-lists.yaml).

| ID | Control | Purpose |
|---|---|---|
| C-01 | Encryption at rest | Stores holding customer data are encrypted with an AWS KMS key. |
| C-02 | Encryption in transit | Buckets and the customer API reject unencrypted connections and require TLS 1.2 or higher. |
| C-03 | Audit logging | API activity and data access are logged to a tamper-evident, restricted store and kept for 365 days. |
| C-04 | Secrets storage | Secrets live only in Secrets Manager, are rotated every 90 days and never appear in code or settings. |
| C-05 | Authentication | Humans use MFA, root is locked down, access keys are at most 90 days old, and the API requires authentication. |
| C-06 | Authorization | Least privilege, an approved list of administrators, no public access, and a read-only tester role. |
| C-07 | Change management | Every change goes through a pull request approved by someone other than its author. |

## How evidence works

- **Collect.** The collector (`python -m tester.collect`) runs as the read-only `harborline-tester` role. It
  saves each raw API response as a file and records every file's SHA-256 hash in a `manifest.json` before
  anything interprets it.
- **Evaluate.** The evaluator (`python -m tester.evaluate`) first re-checks every hash and stops if any file is
  missing, altered or unlisted. It then splits each control's pass criteria into separate checks and marks
  each one pass, fail or not tested. Anything the evidence can't prove is marked not tested, never passed. It
  works offline and calls no AI service.
- **Keep evidence private.** Raw evidence never goes into this repository. The collector makes its output
  folder impossible to commit, and the evidence folder is also excluded in `.gitignore`.

## Repository layout

| Path | What's in it |
|---|---|
| [infra/](infra/) | Terraform for the sandbox: loan document bucket, loan records table, audit trail, AI summarizer, customer API. |
| [controls/](controls/) | The approved control library and approved lists, the source of truth for all testing. |
| [tester/](tester/) | The evidence collector, the evaluator and their offline unit tests. See [tester/README.md](tester/README.md). |
| [CLAUDE.md](CLAUDE.md) | The rules the AI coding agent must follow in this repository. |

## Status

**Built**

- Sandbox infrastructure in Terraform: an encrypted loan document bucket and loan records table, a
  multi-region CloudTrail trail with an audit log bucket, a Lambda function that summarizes synthetic loan
  documents with the Claude API, a customer API that requires IAM authorization, IAM Access Analyzer and
  account-level S3 Block Public Access.
- The approved control library (C-01 to C-07) and approved lists.
- The evidence collector, with offline unit tests. It has not yet been run against AWS or GitHub.
- The evaluator, which is in review (pull request #11), with offline unit tests that show each control's
  seeded failure is caught. It has not yet been run against real evidence.

**Planned**

- An AI agent that writes evidence narratives from the evaluator's results.
- Planted failures: deliberately applying each control's `seeded_failure` in the sandbox to show the
  tests catch it in a live environment.
- A write-up on AI governance: what worked, what didn't, and what the controls do and don't cover.

## Known limitations

These are recorded in `controls/controls.yaml` and in earlier pull requests.

**Gaps between what the controls state and what they test**

- **C-03:** reads of the audit log bucket itself aren't recorded. This is accepted for the sandbox.
- **C-05:** MFA is checked only for IAM users. Users who sign in through IAM Identity Center, including the
  approved administrator, aren't covered by the credential report.
- **C-02:** the loan records table is covered by the control statement but not by its test procedure.
- **C-06:** only customer-managed policies are checked for wildcards, not inline policies. The evaluator
  decides the tester role is read-only by matching action names, not by AWS's own access-level reference.
- **C-07:** the repository's first commit predates the branch rules. The deployer and tester roles and the
  Terraform state bucket were created by hand as a bootstrap exception.
- **Framework references** in the control library have not yet been checked against the published standards.

**Tests not yet run live**

- The collector and evaluator have only been tested offline with stubbed or fake data. Real response shapes,
  IAM permissions and pagination haven't been exercised against AWS or GitHub.
- The collector covers regional services only in its configured region.

**Infrastructure limitations**

- The summarizer Lambda has no per-function cost cap, no code signing and no X-Ray tracing.
- Its API key is rotated by hand.
- It sends synthetic document text to the Claude API, outside AWS. Real data would need a data-handling review.
- The customer API has no WAF and no request-body validation.
- Function errors are returned with HTTP status 200.
- The API Gateway logging role is set for the whole account and region.

## Authorship

The code, Terraform and documentation in this repository were written by an AI coding agent (Claude Code)
under human direction. Every change was reviewed and approved by the repository owner before it merged.
