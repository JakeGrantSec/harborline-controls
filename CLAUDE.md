# CLAUDE.md

## Project

This is the Harborline controls project for a fictional company; all data is synthetic.

## Rules

- Never commit or push to `main`; make each change on a new branch and open a pull request.
- Never approve or merge a pull request.
- Never put secrets, tokens or keys in any file, commit or command.
- Do not read or change anything outside this repository folder.
- Do not run `terraform apply` or any AWS command that changes resources.
- Ask before installing anything.

## Infrastructure rules

These apply to every change under `infra/`.

- Every AWS resource name starts with `harborline-`.
- No secrets and no AWS account numbers in any file. Read the account ID from a data source (`aws_caller_identity`) instead of hardcoding it.
- Do not set a region in the provider; the state bucket and region are supplied at `terraform init`.
- Keep the provider default tags `scope = harborline` and `project = harborline-controls`.
- Before committing, run `terraform fmt`, `terraform init -backend=false`, `terraform validate` and `checkov` on the folder.
- Fix every checkov finding, or skip it inline with `#checkov:skip=<ID>:<written reason>`. Never skip without a reason, and list every skip in the pull request description.
- Do not run `terraform plan` or `terraform apply`, and do not run any `aws` command.
- Sample data must be small and obviously fake.
