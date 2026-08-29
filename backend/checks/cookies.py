"""Deterministic check: cookie security attributes (Milestone 9, Layer 2).

If (and only if) Set-Cookie headers are observed on the sandbox-local
application's responses, each cookie is checked for the Secure, HttpOnly and
SameSite attributes. When no cookie exists, no finding is reported.

Cookie VALUES are never stored - evidence identifies the cookie by name and
records only which attributes are missing.
"""

from checks.base import SecurityCheck, redact_value
from models import SecurityFinding


class CookieSecurityCheck(SecurityCheck):
    id = "cookies-001"
    title = "Cookie security attributes"
    category = "cookie_security"
    severity = "medium"

    PROBE_PATH = "/"

    def run(self, runtime: "TwinRuntime") -> list[SecurityFinding]:
        response = runtime.http_get(self.PROBE_PATH)
        headers = response.get("headers") or {}
        set_cookie = headers.get("set-cookie")
        if not set_cookie:
            # No cookie observed - nothing to report.
            return []

        raw_values = set_cookie if isinstance(set_cookie, list) else [set_cookie]
        findings: list[SecurityFinding] = []
        for raw in raw_values:
            if not isinstance(raw, str):
                continue
            name = raw.split("=", 1)[0].strip() or "(unnamed)"
            lowered = raw.lower()
            missing = []
            if "secure" not in lowered:
                missing.append("Secure")
            if "httponly" not in lowered:
                missing.append("HttpOnly")
            if "samesite" not in lowered:
                missing.append("SameSite")
            if missing:
                findings.append(
                    self.finding(
                        title=f"Cookie missing security attributes: {name}",
                        description=(
                            f"The cookie {name!r} is set without "
                            f"{', '.join(missing)}."
                        ),
                        severity="medium",
                        evidence={
                            "cookie_name": name,
                            "cookie_value": redact_value(raw),
                            "missing_attributes": missing,
                        },
                        remediation=(
                            "Set the missing attributes where appropriate: "
                            "Secure (HTTPS only), HttpOnly (no script "
                            "access), SameSite (CSRF protection)."
                        ),
                        test_definition={
                            "kind": "cookie_check",
                            "path": self.PROBE_PATH,
                        },
                    )
                )
        return findings
