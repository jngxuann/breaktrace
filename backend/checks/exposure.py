"""Deterministic check: basic accidental exposure (Milestone 9, Layer 2).

Only a SMALL, fixed allowlist of common accidental exposure paths is tested:

    /.env
    /.git/config

GET only, sandbox-local target only, no directory brute forcing, no wordlists,
no recursive crawling, no external targets.

A positive HTTP status alone does NOT prove exposure: the response body must
match the expected content characteristics before a finding is marked
verified.
"""

import json
import re

from checks.base import SecurityCheck
from models import SecurityFinding

# The entire exposure surface. Fixed allowlist - adding paths is a code change.
EXPOSURE_ALLOWLIST = ("/.env", "/.git/config")

_ENV_KEY_RE = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_]*=", re.MULTILINE)
_ENV_INTERESTING_KEYS = (
    "SECRET",
    "KEY",
    "TOKEN",
    "PASSWORD",
    "PASS",
    "DB_",
    "MONGO",
    "PORT",
    "API_",
    "URL",
    "USER",
    "HOST",
)


class ExposureSecurityCheck(SecurityCheck):
    id = "exposure-001"
    title = "Accidental sensitive file exposure"
    category = "exposure"
    severity = "high"

    def _body_text(self, body) -> str:
        if body is None:
            return ""
        if isinstance(body, str):
            return body
        try:
            return json.dumps(body)
        except (TypeError, ValueError):
            return str(body)

    def _looks_like_env(self, body) -> bool:
        text = self._body_text(body)
        if not _ENV_KEY_RE.search(text):
            return False
        upper = text.upper()
        return any(key in upper for key in _ENV_INTERESTING_KEYS)

    def _looks_like_git_config(self, body) -> bool:
        text = self._body_text(body)
        return (
            "[core]" in text
            or "repositoryformatversion" in text
            or "[remote" in text
            or "[http" in text
        )

    def _match_reason(self, path: str, body) -> str:
        if path == "/.env":
            return "response body matches environment-variable content"
        return "response body matches a git config structure"

    def run(self, runtime: "TwinRuntime") -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        for path in EXPOSURE_ALLOWLIST:
            response = runtime.http_get(path)
            status = response.get("status")
            body = response.get("body")
            if status != 200:
                continue  # not exposed
            exposed = (
                self._looks_like_env(body)
                if path == "/.env"
                else self._looks_like_git_config(body)
            )
            if not exposed:
                continue  # 200 alone does not prove sensitive exposure
            findings.append(
                self.finding(
                    title=f"Sensitive file exposed: {path}",
                    description=(
                        f"The sandbox-local application returns HTTP 200 for "
                        f"{path} and the response body matches sensitive "
                        f"content ({self._match_reason(path, body)})."
                    ),
                    severity="high",
                    evidence={
                        "path": path,
                        "status": status,
                        "validation": self._match_reason(path, body),
                        "body_preview": self._body_text(body)[:200],
                    },
                    remediation=(
                        "Remove the file from the served web root and block "
                        "requests to dot-paths / debug metadata endpoints."
                    ),
                    test_definition={
                        "kind": "exposure_check",
                        "method": "GET",
                        "path": path,
                    },
                )
            )
        return findings
