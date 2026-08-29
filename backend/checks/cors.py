"""Deterministic check: bounded CORS configuration (Milestone 9, Layer 2).

Detects obviously risky CORS configurations on the sandbox-local instance:

- Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials
- unconditional reflection of any Origin header (with credentials)

BOUNDED: only GET + a single OPTIONS preflight, only against the adapter's
sandbox-local origin, only the fixed test origin below, no broad CORS
exploitation. Observed headers are returned as evidence either way.
"""

from checks.base import SecurityCheck, header_value
from models import SecurityFinding

# Fixed, documented test origin - never user or AI controlled.
TEST_ORIGIN = "https://evil-breaktrace.example"

ALLOWED_CORS_METHODS = ("GET", "DELETE", "OPTIONS")


class CorsSecurityCheck(SecurityCheck):
    id = "cors-001"
    title = "CORS configuration"
    category = "cors"
    severity = "medium"

    PROBE_PATH = "/"

    def run(self, runtime: "TwinRuntime") -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []

        def _check(response: dict, label: str) -> None:
            headers = response.get("headers") or {}
            allow_origin = header_value(headers, "Access-Control-Allow-Origin")
            allow_credentials = header_value(headers, "Access-Control-Allow-Credentials")
            credentials_true = (
                allow_credentials is not None
                and str(allow_credentials).strip().lower() == "true"
            )
            if not allow_origin:
                return  # no CORS policy observed on this response

            if allow_origin.strip() == "*" and credentials_true:
                findings.append(
                    self.finding(
                        title="CORS wildcard origin with credentials",
                        description=(
                            f"{label}: the application returns "
                            "Access-Control-Allow-Origin: * together with "
                            "Access-Control-Allow-Credentials: true, which "
                            "lets any origin read credentialed responses."
                        ),
                        severity="medium",
                        evidence={
                            "probe": label,
                            "observed_headers": headers,
                        },
                        remediation=(
                            "Never combine a wildcard origin with "
                            "credentials; allowlist specific trusted origins."
                        ),
                        test_definition={
                            "kind": "cors_check",
                            "path": self.PROBE_PATH,
                        },
                    )
                )
            elif allow_origin.strip() == TEST_ORIGIN and credentials_true:
                findings.append(
                    self.finding(
                        title="CORS origin reflection with credentials",
                        description=(
                            f"{label}: the application reflects the arbitrary "
                            f"origin {TEST_ORIGIN!r} with credentials enabled, "
                            "allowing any site to issue credentialed "
                            "cross-origin reads."
                        ),
                        severity="medium",
                        evidence={
                            "probe": label,
                            "test_origin": TEST_ORIGIN,
                            "observed_headers": headers,
                        },
                        remediation=(
                            "Allowlist only the application's own trusted "
                            "origins instead of reflecting arbitrary Origins."
                        ),
                        test_definition={
                            "kind": "cors_check",
                            "path": self.PROBE_PATH,
                        },
                    )
                )

        # Simple request with a foreign Origin.
        simple = runtime.http_get(
            self.PROBE_PATH, headers={"Origin": TEST_ORIGIN}
        )
        _check(simple, "GET with Origin header")

        # OPTIONS preflight.
        preflight = runtime.http_request(
            "OPTIONS",
            self.PROBE_PATH,
            headers={
                "Origin": TEST_ORIGIN,
                "Access-Control-Request-Method": "GET",
            },
        )
        _check(preflight, "OPTIONS preflight")

        return findings
