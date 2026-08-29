"""Deterministic check: security response headers (Milestone 9, Layer 2).

Inspects real response headers from the sandbox-local application for a small
set of well-known security headers. Missing headers are reported with
CONSERVATIVE severity (low/medium) - never automatically critical.

Checks performed:
- Content-Security-Policy presence
- X-Content-Type-Options presence
- Referrer-Policy presence
- Frame protection: X-Frame-Options OR CSP frame-ancestors
"""

from checks.base import SecurityCheck, header_present, header_value
from models import SecurityFinding


class HeaderSecurityCheck(SecurityCheck):
    id = "headers-001"
    title = "Security response headers"
    category = "security_headers"
    severity = "low"

    PROBE_PATH = "/"

    def run(self, runtime: "TwinRuntime") -> list[SecurityFinding]:
        response = runtime.http_get(self.PROBE_PATH)
        headers = response.get("headers") or {}
        findings: list[SecurityFinding] = []

        def _missing(name: str, title: str, description: str, remediation: str, severity: str) -> None:
            findings.append(
                self.finding(
                    title=title,
                    description=description,
                    severity=severity,
                    evidence={
                        "path": self.PROBE_PATH,
                        "missing_header": name,
                        "observed_headers": headers,
                    },
                    remediation=remediation,
                    test_definition={"kind": "header_check", "path": self.PROBE_PATH},
                )
            )

        if not header_present(headers, "Content-Security-Policy"):
            _missing(
                "Content-Security-Policy",
                "Missing Content-Security-Policy header",
                "The response does not include a Content-Security-Policy "
                "header, which browsers use to restrict the sources of "
                "scripts, styles and other resources.",
                "Set a Content-Security-Policy header appropriate for the "
                "application (start restrictive, allowlist your own origins).",
                "low",
            )

        if not header_present(headers, "X-Content-Type-Options"):
            _missing(
                "X-Content-Type-Options",
                "Missing X-Content-Type-Options header",
                "The response does not include X-Content-Type-Options: "
                "nosniff, so browsers may MIME-sniff responses.",
                "Send X-Content-Type-Options: nosniff on all responses.",
                "low",
            )

        if not header_present(headers, "Referrer-Policy"):
            _missing(
                "Referrer-Policy",
                "Missing Referrer-Policy header",
                "The response does not define a Referrer-Policy, so the "
                "browser default controls what referrer information leaks "
                "to other origins.",
                "Set Referrer-Policy (e.g. strict-origin-when-cross-origin).",
                "low",
            )

        csp = header_value(headers, "Content-Security-Policy") or ""
        if not header_present(headers, "X-Frame-Options") and "frame-ancestors" not in csp:
            _missing(
                "X-Frame-Options / CSP frame-ancestors",
                "Missing frame protection",
                "The response does not declare X-Frame-Options and the "
                "Content-Security-Policy does not restrict frame-ancestors, "
                "so the page may be embeddable in third-party frames "
                "(clickjacking risk).",
                "Send X-Frame-Options: DENY (or SAMEORIGIN) or add "
                "frame-ancestors to the Content-Security-Policy.",
                "medium",
            )

        return findings
