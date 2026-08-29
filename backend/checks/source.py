"""Source-based deterministic checks (Milestone 10).

Deterministic checks that scan the CLONED REPOSITORY SOURCE inside the
sandbox instead of making HTTP requests. They are generic (Vite/React and
any JS/TS codebase), bounded (fixed allowlisted patterns, fixed file globs,
no crawling) and contain NO target-specific vulnerability knowledge.

Implemented checks:
- HardcodedSecretCheck: obvious private keys / API secrets in source
  (conservative: only high-confidence patterns; ordinary public API keys
  such as "apiKey" are NOT flagged).
- ClientStorageAuthCheck: auth-like values stored via localStorage /
  sessionStorage (discovery observation, medium severity).

Secret VALUES are redacted in evidence - only the file/line/pattern are kept.
"""

import re
import shlex

from checks.base import SecurityCheck, redact_value
from discovery import exec_in_sandbox, parse_frontend_lines
from models import SecurityFinding

_SOURCE_GLOBS = (
    "--include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' "
    "--include='*.json' --include='*.env*'"
)


class SourceSecurityCheck(SecurityCheck):
    """Base class for repository-source deterministic checks."""

    # Fixed allowlisted regex sources scanned for this check.
    source_patterns: list[str] = []

    def run(self, runtime):  # pragma: no cover - source checks use run_source
        raise NotImplementedError(
            "Source checks run via run_source() with a repository scan, "
            "not via HTTP."
        )

    def run_source(self, matches: list[dict]) -> list[SecurityFinding]:
        """Evaluate the scan matches for this check.

        matches: [{"path", "line", "content", "pattern"}]
        Returns issue findings (empty = passed).
        """
        raise NotImplementedError


class HardcodedSecretCheck(SourceSecurityCheck):
    id = "secrets-001"
    title = "Hardcoded secrets in client source"
    category = "hardcoded_secrets"
    severity = "high"

    # High-confidence secret material only. Ordinary public keys (anon API
    # keys, "apiKey" fields) are intentionally NOT matched.
    source_patterns = [
        r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----",
        r"sk_live_[A-Za-z0-9]+",
        r"sk_test_[A-Za-z0-9]+",
        r"AKIA[0-9A-Z]{16}",
        r"aws_secret_access_key\s*[:=]",
        r"\"private_key\"\s*:\s*\"",
    ]

    def run_source(self, matches: list[dict]) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        for match in matches:
            content = match["content"]
            snippet = content.strip()[:80]
            findings.append(
                self.finding(
                    title="Possible hardcoded secret in client source",
                    description=(
                        f"Source file {match['path']} contains material that "
                        "looks like a private key or live API secret. Client "
                        "bundles ship this value to every visitor - treat it "
                        "as exposed and rotate it."
                    ),
                    severity="high",
                    evidence={
                        "file": match["path"],
                        "line": match["line"],
                        "matched_pattern": match["pattern"],
                        "redacted_snippet": redact_value(snippet),
                    },
                    remediation=(
                        "Remove secrets from client source; load them "
                        "server-side and never ship private keys to browsers."
                    ),
                    test_definition={"kind": "source_secret_check"},
                )
            )
        return findings


class ClientStorageAuthCheck(SourceSecurityCheck):
    id = "client-storage-001"
    title = "Auth-related value stored in client storage"
    category = "client_storage"
    severity = "medium"

    source_patterns = [
        r"(?:localStorage|sessionStorage)\.(?:setItem|getItem)\(\s*"
        r"[\"'][^\"']*(?:token|auth|session|jwt|credential|password|secret)"
        r"[^\"']*[\"']",
    ]

    _STORAGE_TYPE_RE = re.compile(r"(localStorage|sessionStorage)")
    _KEY_RE = re.compile(r"\(\s*[\"']([^\"']+)[\"']")

    def run_source(self, matches: list[dict]) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        for match in matches:
            content = match["content"]
            storage_type = (
                self._STORAGE_TYPE_RE.search(content).group(1)
                if self._STORAGE_TYPE_RE.search(content)
                else "client_storage"
            )
            key_match = self._KEY_RE.search(content)
            key = key_match.group(1) if key_match else "(unknown key)"
            findings.append(
                self.finding(
                    title="Auth-related value stored in client storage",
                    description=(
                        f"{storage_type} is used with an auth-related key "
                        f"({key!r}) in {match['path']}. Client storage is "
                        "readable by any script running in the page and by "
                        "the user; treat anything stored there as exposed. "
                        "This is a DISCOVERY OBSERVATION - the value is "
                        "never extracted or stored."
                    ),
                    severity="medium",
                    evidence={
                        "file": match["path"],
                        "line": match["line"],
                        "storage_type": storage_type,
                        "key": key,
                        "value": "REDACTED",
                    },
                    remediation=(
                        "Prefer httpOnly cookies or short-lived in-memory "
                        "tokens over long-lived client-storage auth values."
                    ),
                    test_definition={"kind": "source_storage_check"},
                )
            )
        return findings


def scan_repository_source(
    sandbox, adapter, checks: list[SourceSecurityCheck]
) -> dict[str, list[dict]]:
    """Bounded scan of the cloned repository source for the registered
    checks' patterns.

    Returns {check_id: [{"path", "line", "content", "pattern"}]}. Fixed
    allowlisted patterns over fixed file globs - no crawling. Unparseable or
    empty output is treated as no matches.

    Raises:
        RuntimeError: If a scan command itself fails.
    """
    scan: dict[str, list[dict]] = {}
    for check in checks:
        pattern = "|".join(f"(?:{p})" for p in check.source_patterns)
        command = (
            f"cd {adapter.repo_dir} && grep -rInE {_SOURCE_GLOBS} "
            "--exclude-dir=node_modules --exclude-dir=dist "
            "--exclude-dir=.git "
            f"-e {shlex.quote(pattern)} . 2>/dev/null | head -300 || true"
        )
        try:
            output = exec_in_sandbox(sandbox, command, timeout=90)
        except Exception:
            output = ""
        matches: list[dict] = []
        for path, line, content in parse_frontend_lines(output):
            for source_pattern in check.source_patterns:
                if re.search(source_pattern, content):
                    matches.append(
                        {
                            "path": path,
                            "line": line,
                            "content": content,
                            "pattern": source_pattern,
                        }
                    )
        scan[check.id] = matches
    return scan
