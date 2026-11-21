"""Shared state for one collection run, and helpers that call and save."""

import subprocess
import time

from botocore.exceptions import ClientError


class Run:
    def __init__(self, *, aws, writer, library, partition, account_id, repo_root,
                 github=None, github_repo=None, gitleaks_bin=None,
                 runner=subprocess.run, sleep=time.sleep):
        self.aws = aws
        self.writer = writer
        self.library = library
        self.partition = partition
        self.account_id = account_id
        self.repo_root = repo_root
        self.github = github
        self.github_repo = github_repo
        self.gitleaks_bin = gitleaks_bin
        self.runner = runner
        self.sleep = sleep
        self.api_errors = []

    # --- AWS ------------------------------------------------------------------

    @staticmethod
    def _request(client, method, params):
        return {
            "service": client.meta.service_model.service_name,
            "operation": client.meta.method_to_api_mapping[method],
            "region": client.meta.region_name,
            "params": params,
        }

    def _name(self, request, label):
        return f"{request['service']}_{request['operation']}" + (f"_{label}" if label else "")

    def _save_error(self, control, request, label, exc):
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        self.writer.save(control, self._name(request, label) + "_error", exc.response,
                         request=request, error=code)
        self.api_errors.append({"control": control, "operation": request["operation"], "code": code})

    def call(self, control, client, method, label="", **params):
        """One call. Saves the response, or the error response, and returns the
        response (None on an AWS error)."""
        request = self._request(client, method, params)
        try:
            response = getattr(client, method)(**params)
        except ClientError as exc:
            self._save_error(control, request, label, exc)
            return None
        self.writer.save(control, self._name(request, label), response, request=request)
        return response

    def paginate(self, control, client, method, label="", transform=None, note=None, **params):
        """All pages of a paginated call, each saved as its own file. If transform
        is given, only the transformed page is saved and returned."""
        request = self._request(client, method, params)
        pages = []
        try:
            for n, page in enumerate(client.get_paginator(method).paginate(**params), start=1):
                if transform is not None:
                    page = transform(page)
                name = self._name(request, label) + f"_page{n:03d}"
                self.writer.save(control, name, page, request=dict(request, page=n), note=note)
                pages.append(page)
        except ClientError as exc:
            self._save_error(control, dict(request, page=len(pages) + 1), label, exc)
        return pages

    def token_pages(self, control, client, method, label="", **params):
        """Pages of a call that uses NextToken but has no boto3 paginator."""
        pages = []
        token = None
        while True:
            call_params = dict(params, NextToken=token) if token else params
            page_label = f"page{len(pages) + 1:03d}"
            page = self.call(control, client, method, f"{label}_{page_label}" if label else page_label,
                             **call_params)
            if page is None:
                break
            pages.append(page)
            token = page.get("NextToken")
            if not token:
                break
        return pages

    # --- GitHub ---------------------------------------------------------------

    def save_github(self, control, name, response):
        request = {"method": "GET", "url": response.url, "status": response.status}
        error = None if response.ok else f"HTTP {response.status}"
        self.writer.save(control, name, response.body, request=request, error=error)
        if error:
            self.api_errors.append({"control": control, "operation": f"GET {response.url}", "code": error})
