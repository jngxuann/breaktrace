"""Deterministic check interface (Milestone 9, Layer 2).

A SecurityCheck inspects the sandbox-local application instance through a
TwinRuntime and returns zero or more SecurityFindings. Checks contain NO
orchestration logic - the orchestrator iterates the registry generically.

Severity policy: missing headers/cookie attributes are NEVER automatically
critical. Conservative severities (low/medium) are used; only a positively
validated sensitive-file exposure may reach high.
"""

import uuid
from abc import ABC, abstractmethod

from models import SecurityFinding


def redact_value(value: str) -> str:
    """Redact a sensitive value (e.g. cookie value) before storing evidence."""
    if not value:
        return ""
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def header_value(headers: dict, name: str):
    """First value of a (case-insensitive) response header, or None.

    The sandbox client returns headers as a lower-cased key -> value map,
    where multi-valued headers (e.g. Set-Cookie) are lists.
    """
    if not headers:
        return None
    value = headers.get(name.lower())
    if isinstance(value, list):
        return value[0] if value else None
    return value


def header_present(headers: dict, name: str) -> bool:
    """True when the (case-insensitive) response header exists."""
    return header_value(headers, name) is not None


class SecurityCheck(ABC):
    """Base class for one bounded deterministic security check."""

    id: str = ""
    title: str = ""
    category: str = ""
    severity: str = "low"

    @abstractmethod
    def run(self, runtime: "TwinRuntime") -> list[SecurityFinding]:
        """Execute the check against the sandbox-local instance.

        Returns the ISSUES found (empty list = check passed). The orchestrator
        wraps the result with target/assessment metadata.
        """

    def finding(
        self,
        *,
        title: str,
        description: str,
        severity: str | None = None,
        evidence: dict | None = None,
        remediation: str = "",
        test_definition: dict | None = None,
    ) -> SecurityFinding:
        """Build an issue finding for this check."""
        return SecurityFinding(
            id=f"{self.id}-{uuid.uuid4().hex[:8]}",
            target_id="",
            source="deterministic",
            category=self.category,
            title=title,
            severity=severity or self.severity,
            status="verified",
            description=description,
            evidence=evidence or {},
            remediation=remediation,
            test_definition=test_definition,
        )


class TwinRuntime:
    """Bounded HTTP access to the sandbox-local Security Twin instance.

    All requests go through the trusted in-sandbox client uploaded during
    target preparation. Only the adapter's local origin is ever contacted -
    there is no code path to an external host.
    """

    def __init__(self, sandbox, adapter, origin: str, client_path: str):
        self.sandbox = sandbox
        self.adapter = adapter
        self.origin = origin
        self.client_path = client_path

    def _call(self, method: str, path: str, headers: dict | None = None) -> dict:
        import json as _json
        import shlex

        from discovery import exec_in_sandbox

        env = {"BREAKTRACE_TARGET_ORIGIN": self.origin}
        if headers:
            env["BREAKTRACE_TARGET_HEADERS"] = "\n".join(
                f"{key}: {value}" for key, value in headers.items()
            )
        output = exec_in_sandbox(
            self.sandbox,
            f"python {self.client_path} --headers {method} "
            f"{shlex.quote(path)}",
            timeout=60,
            env=env,
        )
        try:
            parsed = _json.loads(output)
        except (ValueError, TypeError) as exc:
            raise RuntimeError(
                f"Malformed check output from sandbox: {output or '(empty)'}"
            ) from exc
        return parsed

    def http_get(self, path: str, headers: dict | None = None) -> dict:
        """GET a sandbox-local path; returns {\"status\", \"headers\", \"body\"}."""
        return self._call("GET", path, headers)

    def http_request(self, method: str, path: str, headers: dict | None = None) -> dict:
        """Bounded non-GET request (OPTIONS preflight only) to a sandbox-local path."""
        return self._call(method, path, headers)
