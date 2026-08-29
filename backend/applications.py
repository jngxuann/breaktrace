"""BreakTrace application registry (Milestone 7).

Application identity is the normalized URL origin of the application under
test. A deterministic SHA-256 target_id is derived from that origin, and a
local JSON file (backend/data/applications.json) keeps the registry across
backend restarts.

IMPORTANT: this milestone is APPLICATION IDENTITY only. Entering a URL NEVER
causes BreakTrace to scan or attack that external URL - the security
execution always runs against the controlled Daytona demo application. The
URL only selects which application's history/library is shown.

Design decisions:
- normalize_target_url: scheme + lowercase hostname + non-default port only.
- target_id = sha256(normalized_origin).hexdigest() - raw URLs are never
  used as filenames.
- Atomic writes (temp file + os.replace): a failed write never destroys the
  existing registry, and a missing file initializes an empty registry.
- resolve is idempotent: re-resolving the same origin returns the existing
  record, never creates duplicates, and never touches assessment_count.
- Legacy M6 library entries (no target_id) are deterministically migrated to
  the FIRST application ever created, so existing demo history survives.
"""

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from library import list_entries, migrate_unassigned_entries
from models import ApplicationRecord, ApplicationSummary

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
APPLICATIONS_PATH = os.path.join(DATA_DIR, "applications.json")

# Hostname validation: letters, digits, hyphens, dots (and colons so IPv6
# literals like [::1] are accepted). At least one alphanumeric character.
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.:-]*[A-Za-z0-9])?$")

_DEFAULT_PORTS = {"http": 80, "https": 443}


class ApplicationError(RuntimeError):
    """The application URL could not be normalized or the registry failed."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# URL normalization + target_id
# ---------------------------------------------------------------------------


def normalize_target_url(url: str) -> str:
    """Normalize an application URL to its canonical ORIGIN.

    Identity = scheme + hostname + non-default port. Everything else (path,
    query, fragment, trailing slash, default port, case) is dropped.

    Examples:
        https://Example.com/login  -> https://example.com
        https://example.com?x=1    -> https://example.com
        https://example.com/#a     -> https://example.com
        http://example.com:80      -> http://example.com
        https://example.com:8443   -> https://example.com:8443

    Rules: only http/https schemes, lowercase hostname, default ports (80 for
    http, 443 for https) removed, non-default ports preserved, valid hostname
    required. Schemes like javascript:, file:, data: are rejected. A bare
    hostname without a scheme defaults to https:// for convenience.

    Raises:
        ApplicationError: If the URL is missing, unsupported, or invalid.
    """
    raw = (url or "").strip()
    if not raw:
        raise ApplicationError("Application URL is required.")

    if "://" in raw:
        # Explicit scheme - only http/https are ever accepted.
        scheme_prefix = raw.split("://", 1)[0].lower()
        if scheme_prefix not in ("http", "https"):
            raise ApplicationError(
                f"Unsupported URL scheme {scheme_prefix!r}. Only http and "
                "https are allowed."
            )
    else:
        # No "://". Reject scheme-like prefixes (javascript:..., data:...,
        # mailto:...) before applying the bare-hostname convenience default.
        head, sep, tail = raw.partition(":")
        if sep and tail and not tail.replace(".", "").isdigit():
            if head.lower() not in ("http", "https"):
                raise ApplicationError(
                    f"Unsupported URL scheme {head!r}. Only http and https "
                    "are allowed."
                )
            raw = f"{head.lower()}://{tail.lstrip('/')}"
        else:
            # Bare hostname (optionally with a port) defaults to https.
            raw = "https://" + raw

    try:
        parsed = urlparse(raw)
        scheme = parsed.scheme.lower()
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ApplicationError(f"Invalid application URL: {raw!r}") from exc

    if scheme not in ("http", "https"):
        raise ApplicationError(
            f"Unsupported URL scheme {scheme!r}. Only http and https are "
            "allowed."
        )
    if not hostname:
        raise ApplicationError(f"Application URL has no hostname: {raw!r}")
    hostname = hostname.lower()
    if len(hostname) > 253 or not _HOSTNAME_RE.match(hostname):
        raise ApplicationError(f"Invalid hostname in application URL: {raw!r}")

    port_str = ""
    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        port_str = f":{port}"
    return f"{scheme}://{hostname}{port_str}"


def target_id_for(origin: str) -> str:
    """Deterministic SHA-256 of the normalized origin.

    Same origin variants always map to the same target_id; raw URLs are never
    used as filenames.
    """
    return hashlib.sha256(origin.encode("utf-8")).hexdigest()


def display_name_for(origin: str) -> str:
    """Human-friendly label: hostname, plus non-default port when present."""
    parsed = urlparse(origin)
    host = parsed.hostname or ""
    port = parsed.port
    if port is not None and port != _DEFAULT_PORTS.get(parsed.scheme):
        return f"{host}:{port}"
    return host


# ---------------------------------------------------------------------------
# Registry persistence (atomic writes)
# ---------------------------------------------------------------------------


def load_applications() -> dict[str, ApplicationRecord]:
    """Load all application records keyed by target_id.

    A missing file simply means an empty registry (created on first save). A
    corrupted file raises ApplicationError so nothing is silently destroyed.

    Raises:
        ApplicationError: If the registry file exists but cannot be parsed.
    """
    if not os.path.exists(APPLICATIONS_PATH):
        return {}
    try:
        with open(APPLICATIONS_PATH, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (ValueError, OSError) as exc:
        raise ApplicationError(
            "Application registry is corrupted and could not be read."
        ) from exc
    if not isinstance(raw, dict):
        raise ApplicationError(
            "Application registry has an unexpected structure."
        )
    records: dict[str, ApplicationRecord] = {}
    for item in raw.get("applications") or []:
        try:
            record = ApplicationRecord.model_validate(item)
        except Exception as exc:  # one bad record must not kill the registry
            raise ApplicationError(
                f"Application registry contains an invalid record: {exc}"
            ) from exc
        records[record.target_id] = record
    return records


def save_applications(records: dict[str, ApplicationRecord]) -> None:
    """Atomically persist the registry. A failed write never destroys the
    existing registry.

    Raises:
        ApplicationError: If the file cannot be written.
    """
    os.makedirs(DATA_DIR, exist_ok=True)
    payload = {
        "version": 1,
        "applications": [
            r.model_dump(mode="json") for r in records.values()
        ],
    }
    tmp_path = APPLICATIONS_PATH + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        os.replace(tmp_path, APPLICATIONS_PATH)
    except OSError as exc:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass
        raise ApplicationError(
            f"Could not write application registry: {exc}"
        ) from exc


def get_application(target_id: str) -> ApplicationRecord | None:
    """Return one application record by target_id, or None."""
    return load_applications().get(target_id)


# ---------------------------------------------------------------------------
# Resolve + lifecycle
# ---------------------------------------------------------------------------


def resolve_application(url: str) -> tuple[bool, ApplicationRecord]:
    """Resolve a URL to an application record, creating it if unknown.

    Idempotent: re-resolving the same normalized origin returns the existing
    record and never creates duplicates. assessment_count is NEVER touched by
    resolve - only record_assessment_completed increments it.

    Legacy migration: the FIRST application ever created adopts any existing
    M6 library entries that have no target_id, so demo history is preserved
    and stays visible in the scoped library.

    Returns:
        (created, record) where created is True only when a new record was
        written.

    Raises:
        ApplicationError: If the URL cannot be normalized or saved.
    """
    origin = normalize_target_url(url)
    target_id = target_id_for(origin)
    records = load_applications()

    existing = records.get(target_id)
    if existing is not None:
        return False, existing

    record = ApplicationRecord(
        target_id=target_id,
        origin=origin,
        display_name=display_name_for(origin),
        created_at=_now_iso(),
        last_assessed_at=None,
        assessment_count=0,
    )
    if not records:
        # Deterministic migration: the first application adopts legacy
        # (unassigned) M6 library entries.
        migrate_unassigned_entries(target_id, origin)

    records[target_id] = record
    save_applications(records)
    return True, record


def record_assessment_completed(target_id: str) -> ApplicationRecord:
    """Update an application after a completed assessment run.

    Sets last_assessed_at and increments assessment_count. ONLY actual
    assessments call this - resolve never does.

    Raises:
        ApplicationError: If the application is unknown.
    """
    records = load_applications()
    record = records.get(target_id)
    if record is None:
        raise ApplicationError(f"Unknown application target_id {target_id!r}.")
    record.last_assessed_at = _now_iso()
    record.assessment_count += 1
    save_applications(records)
    return record


# ---------------------------------------------------------------------------
# Application-scoped summary
# ---------------------------------------------------------------------------


def build_application_summary(record: ApplicationRecord) -> ApplicationSummary:
    """Derive the application-scoped summary from registry + library data.

    verified_vulnerabilities counts stored regression BreakTraces for THIS
    application only (each verified vulnerability becomes one regression
    test). regression_score is None ("Not enough data") until at least one
    regression test has been replayed.
    """
    response = list_entries(record.target_id)
    regression = [e for e in response.entries if e.kind == "regression"]
    replayed = [e for e in regression if e.current_status is not None]
    failed = [e for e in replayed if e.current_status == "failed"]
    passed = len(replayed) - len(failed)
    regression_score = (
        round(passed / len(replayed) * 100) if replayed else None
    )
    return ApplicationSummary(
        application=record,
        verified_vulnerabilities=len(regression),
        regression_tests=len(regression),
        current_regressions=len(failed),
        regression_score=regression_score,
        last_assessed_at=record.last_assessed_at,
    )
