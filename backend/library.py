"""BreakTrace regression library (Milestone 6).

Local JSON-file persistence for verified security regression tests. A
"break becomes a permanent test": every verified vulnerability from an
assessment can be saved here as a regression test, deduplicated by a stable
test fingerprint, and replayed against the fixed controlled application.

Design decisions:
- Local JSON file (backend/data/breaktraces.json). No database.
- Atomic writes: write a temp file, then os.replace. A failed write never
  destroys the existing library.
- Fingerprint = deterministic hash of (actor.user_id, method, path,
  expected.status, category, invariant). Rediscovering the same test updates
  the existing entry; original evidence + first_seen are preserved.
- Original status/evidence and current status are tracked separately:
  original_observed is never overwritten by replays.
"""

import hashlib
import json
import os
import re
from datetime import datetime, timezone

from models import (
    AssessmentRunResult,
    BreakTraceActor,
    BreakTraceExpected,
    BreakTraceRequest,
    DashboardMetrics,
    LibraryEntry,
    LibraryListResponse,
    LibraryReplayResult,
    ReplayItem,
)

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
LIBRARY_PATH = os.path.join(DATA_DIR, "breaktraces.json")


class LibraryError(RuntimeError):
    """The library file could not be read or written."""


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fingerprint_for(
    user_id: int, method: str, path: str, expected_status: int,
    category: str, invariant: str, headers: dict | None = None,
) -> str:
    """Stable, deterministic fingerprint for one regression test.

    The test's stable identity is (principal, method, path, expected status,
    category, invariant). The principal is captured both from the actor
    user_id and, when present, from the request's safe/allowlisted identity
    headers (sorted by name so ordering never matters). Requests without
    headers keep the exact original formula, so legacy entries remain
    deduplicable.
    """
    parts = [
        str(user_id),
        method,
        path,
        str(expected_status),
        category,
        invariant,
    ]
    if headers:
        for name in sorted(headers):
            parts.append(f"{name}={headers[name]}")
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def fingerprint_for_result(result) -> str:
    """Fingerprint a BreakTraceResult."""
    return _fingerprint_for(
        result.actor.user_id,
        result.request.method,
        result.request.path,
        result.expected.status,
        result.category,
        result.invariant,
        getattr(result.request, "headers", None) or None,
    )


def is_verified_principal_test(result) -> bool:
    """Generic quality gate: should this verified failure become a permanent
    Security Memory regression test?

    A permanent regression test must represent a verified failure of an
    ACTOR-attributable request: either the actor carries a real principal id
    or the request carries at least one non-empty request header (the safe
    identity header the application reads, e.g. X-Demo-User). Baseline
    checks with no principal at all - e.g. "an unauthenticated request must
    be denied" - are observation/deterministic-level and do NOT become
    Security Memory entries.

    The gate is structural (source/status/request/test_definition), never
    title-based, so it applies identically to any target.
    """
    if not (
        result.test_executed
        and result.invariant_violated
        and result.status == "vulnerable"
    ):
        return False
    if not (result.request.method and result.request.path):
        return False
    headers = getattr(result.request, "headers", None) or {}
    has_identity_value = any(str(v).strip() for v in headers.values())
    has_principal = (result.actor.user_id or 0) != 0
    return has_identity_value or has_principal


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def load_library() -> dict[str, LibraryEntry]:
    """Load all library entries keyed by fingerprint.

    A missing file simply means an empty library (created on first save). A
    corrupted file raises LibraryError so nothing is silently destroyed.

    Raises:
        LibraryError: If the library file exists but cannot be parsed.
    """
    if not os.path.exists(LIBRARY_PATH):
        return {}
    try:
        with open(LIBRARY_PATH, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (ValueError, OSError) as exc:
        raise LibraryError(
            "Library file is corrupted and could not be read."
        ) from exc
    if not isinstance(raw, dict):
        raise LibraryError("Library file has an unexpected structure.")
    entries: dict[str, LibraryEntry] = {}
    for item in raw.get("entries") or []:
        try:
            entry = LibraryEntry.model_validate(item)
        except Exception as exc:  # one bad entry must not kill the library
            raise LibraryError(
                f"Library file contains an invalid entry: {exc}"
            ) from exc
        entries[entry.fingerprint] = entry
    return entries


def save_library(entries: dict[str, LibraryEntry]) -> None:
    """Atomically persist the library. A failed write never destroys the
    existing library.

    Raises:
        LibraryError: If the file cannot be written.
    """
    os.makedirs(DATA_DIR, exist_ok=True)
    payload = {
        "version": 1,
        "entries": [e.model_dump(mode="json") for e in entries.values()],
    }
    tmp_path = LIBRARY_PATH + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        os.replace(tmp_path, LIBRARY_PATH)
    except OSError as exc:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass
        raise LibraryError(f"Could not write library: {exc}") from exc


# ---------------------------------------------------------------------------
# Saving verified BreakTraces
# ---------------------------------------------------------------------------


def _test_definition_for(result) -> dict:
    """Stored experiment definition so replay never needs the AI again."""
    req = {
        "method": result.request.method,
        "path": result.request.path,
    }
    headers = getattr(result.request, "headers", None)
    if headers:
        req["headers"] = headers
    return {
        "kind": "http_experiment",
        **req,
        "expected_status": result.expected.status,
        "invariant": result.invariant,
        "category": result.category,
        "actor": {
            "name": result.actor.name,
            "user_id": result.actor.user_id,
        },
    }


def _next_entry_id(entries: dict, target_id: str) -> str:
    """Smallest unused human-readable BT-NNN id for ONE application.

    Scans every entry already assigned to this application and returns the
    first free BT-NNN number. This guarantees unique, stable, human-readable
    ids per application library, restarts cleanly at BT-001 after a reset,
    and can never produce a duplicate BT id no matter how many runs happen.
    """
    used = set()
    for entry in entries.values():
        if entry.target_id != target_id:
            continue
        match = re.fullmatch(r"BT-(\d+)", entry.id or "")
        if match:
            used.add(int(match.group(1)))
    n = 1
    while n in used:
        n += 1
    return f"BT-{n:03d}"


def add_from_results(
    run_result: AssessmentRunResult,
    source: str,
    target_id: str = "",
    origin: str = "",
    assessment_id: str = "",
    application_version: dict | None = None,
    origin_source: str = "ai",
    quality_filter=None,
) -> dict:
    """Save all verified VULNERABLE results from an assessment run into the
    library, associated with ONE application (target_id + origin).

    Only results where test_executed=True, invariant_violated=True and
    status=="vulnerable" become regression tests. Safe controls are not
    saved. Duplicate fingerprints update nothing (existing entry wins) so the
    original evidence is preserved.

    quality_filter (optional): a generic callable(BreakTraceResult) -> bool
    applied BEFORE saving, so callers can opt into a stricter finding-quality
    gate (e.g. is_verified_principal_test) for specific flows without
    changing the default behaviour for normal applications.

    Entry ids are assigned per application (BT-001, BT-002, ...) from the
    first unused number - never taken from the per-run result id - so ids
    stay unique and stable across repeated assessment runs.

    Since Milestone 7 an assessment result may NOT be saved without a
    target/application association - a missing target_id raises LibraryError.

    Args:
        run_result: The executed AssessmentRunResult.
        source: Provider source label (e.g. "groq_ai", "nosana_ai").
        target_id: The application's deterministic target_id (required).
        origin: The application's normalized origin (required).
        quality_filter: Optional generic finding-quality gate.

    Returns:
        {"saved": int, "new": int, "already_in_library": int,
         "total_in_library": int}

    Raises:
        LibraryError: If target_id is missing (no application association).
    """
    if not target_id:
        raise LibraryError(
            "Cannot save BreakTraces without an application target_id. "
            "Resolve an application URL first."
        )
    entries = load_library()
    now = _now_iso()
    new_count = 0
    saved_count = 0
    for result in run_result.results:
        if not (
            result.test_executed
            and result.invariant_violated
            and result.status == "vulnerable"
        ):
            continue
        if quality_filter is not None and not quality_filter(result):
            continue
        saved_count += 1
        fingerprint = fingerprint_for_result(result)
        if fingerprint in entries:
            continue  # rediscovered test - keep the original entry
        entry = LibraryEntry(
            id=_next_entry_id(entries, target_id),
            fingerprint=fingerprint,
            title=result.title,
            category=result.category,
            severity=result.severity,
            invariant=result.invariant,
            actor=result.actor,
            request=result.request,
            expected=result.expected,
            original_observed=result.observed,
            original_status=result.status,
            source=source,
            kind="regression",
            first_seen=now,
            target_id=target_id,
            origin=origin,
            hypothesis=result.hypothesis,
            target_adapter=run_result.target_adapter or "",
            provider=run_result.provider or "",
            model=run_result.model or "",
            origin_source=origin_source,
            assessment_id=assessment_id or run_result.assessment_id,
            application_version=application_version,
            test_definition=_test_definition_for(result),
            first_detected_at=now,
        )
        entries[fingerprint] = entry
        new_count += 1
    save_library(entries)
    return {
        "saved": saved_count,
        "new": new_count,
        "already_in_library": saved_count - new_count,
        "total_in_library": len(entries),
    }


def reset_application_entries(target_id: str) -> int:
    """Safely delete ONLY the Security Memory entries of ONE application.

    This is the demo-reproducibility reset: it makes a known demo lifecycle
    restart from a clean, deterministic Security Memory. Entries belonging to
    any other application (or legacy unassigned entries) are NEVER touched,
    so normal applications keep their persistent Security Memory.

    Args:
        target_id: The application whose entries should be removed.

    Returns:
        The number of entries removed.
    """
    entries = load_library()
    doomed = [
        fingerprint
        for fingerprint, entry in entries.items()
        if entry.target_id == target_id
    ]
    if not doomed:
        return 0
    for fingerprint in doomed:
        del entries[fingerprint]
    save_library(entries)
    return len(doomed)


def migrate_unassigned_entries(target_id: str, origin: str) -> int:
    """Adopt legacy M6 library entries (empty target_id) into an application.

    Deterministic migration: the first application ever created adopts all
    previously unassigned BreakTraces so existing demo history stays visible.
    Original evidence is preserved. Entries already assigned to an
    application are never touched.

    Returns:
        The number of entries migrated.
    """
    entries = load_library()
    migrated = 0
    for entry in entries.values():
        if not entry.target_id:
            entry.target_id = target_id
            entry.origin = origin
            migrated += 1
    if migrated:
        save_library(entries)
    return migrated


# ---------------------------------------------------------------------------
# Milestone 9 - Security Memory: loading + replay bookkeeping
# ---------------------------------------------------------------------------


def load_regression_entries(
    target_id: str, target_adapter: str = ""
) -> list[LibraryEntry]:
    """Load the regression BreakTraces of ONE application that are compatible
    with a given target adapter.

    Compatibility: the entry must have been produced for the same adapter
    (e.g. "juice_shop"). Entries from other adapters (or the demo app) are
    never replayed against a different Security Twin.
    """
    entries = load_library()
    scoped = [
        e
        for e in entries.values()
        if e.kind == "regression"
        and e.target_id == target_id
        and (not target_adapter or e.target_adapter == target_adapter)
    ]
    return sorted(scoped, key=lambda e: e.first_seen)


def mark_entries_replayed(items, version=None) -> int:
    """Update replay metadata for library entries after a Security Twin
    replay, preserving original evidence.

    items: list of RegressionReplayResult. The M9 "regression" status maps
    to the library's legacy "failed" vocabulary so existing dashboards and
    summaries keep working. Errors never count as regressions.

    version (optional): an ApplicationVersion (or mapping with a "ref") for
    the twin the entries were just replayed against; its ref is recorded as
    last_replayed_version (e.g. demo-v2-fixed) for the Security Memory UI.

    Returns:
        The number of entries updated.
    """
    entries = load_library()
    now = _now_iso()
    ref = (getattr(version, "ref", None) or (version or {}).get("ref") or "")
    by_id = {e.id: e for e in entries.values()}
    updated = 0
    for item in items:
        entry = by_id.get(item.entry_id)
        if entry is None:
            continue
        entry.last_replayed = now
        entry.last_replayed_at = now
        entry.replay_count += 1
        entry.current_status = {
            "passed": "passed",
            "regression": "failed",
            "error": "error",
        }.get(item.status, item.status)
        entry.latest_observed_status = item.observed_status
        if ref:
            entry.last_replayed_version = ref
        updated += 1
    if updated:
        save_library(entries)
    return updated


# ---------------------------------------------------------------------------
# Reading the library
# ---------------------------------------------------------------------------


def list_entries(target_id: str | None = None) -> LibraryListResponse:
    """List library entries, scoped to one application.

    Args:
        target_id: Only entries belonging to this application are returned.
            None returns only unassigned (legacy M6) entries, so BreakTraces
            from different applications are never mixed.
    """
    entries = load_library()
    scoped = [
        e for e in entries.values() if e.target_id == (target_id or "")
    ]
    ordered = sorted(scoped, key=lambda e: e.first_seen)
    return LibraryListResponse(total=len(ordered), entries=ordered)


def get_entry(entry_id: str) -> LibraryEntry | None:
    entries = load_library()
    for entry in entries.values():
        if entry.id == entry_id:
            return entry
    return None


# ---------------------------------------------------------------------------
# Replaying the library
# ---------------------------------------------------------------------------


def replay_library(target_id: str | None = None) -> LibraryReplayResult:
    """Replay every stored regression BreakTrace of ONE application, then
    update current status fields.

    Only BreakTraces belonging to the given application are replayed - never
    a mix from different applications. Original evidence and first_seen are
    preserved. replay_count increments, last_replayed and current status
    update from the actual execution.

    Target-aware semantics (Milestone 8):
    - demo entries (target_adapter "" or "demo") are replayed against the
      FIXED controlled demo application - the existing vulnerable -> fixed
      regression flow.
    - Juice Shop entries are re-executed honestly against a fresh Juice Shop
      instance in a new sandbox. There is no patched Juice Shop version, so
      the result is never called a "fix verification": statuses are passed /
      failed (still vulnerable) / error.

    Args:
        target_id: Application to replay. None replays only unassigned
            (legacy) entries.

    Raises:
        LibraryError: If there is nothing to replay.
        RuntimeError: If Daytona execution fails (library left untouched).
    """
    entries = load_library()
    regression = [
        e
        for e in entries.values()
        if e.kind == "regression" and e.target_id == (target_id or "")
    ]
    if not regression:
        raise LibraryError(
            "No regression tests stored in the library yet."
        )

    now = _now_iso()
    items: list[ReplayItem] = []
    by_id = {e.id: e for e in regression}

    def _mark(entry, status, observed_status):
        entry.last_replayed = now
        entry.replay_count += 1
        entry.current_status = status
        entry.latest_observed_status = observed_status

    demo_entries = [e for e in regression if e.target_adapter in ("", "demo")]
    juice_shop_entries = [
        e for e in regression if e.target_adapter == "juice_shop"
    ]

    # --- Demo entries: existing fixed-mode replay (M6, unchanged semantics) ---
    if demo_entries:
        from breaktrace_demo import MODE_FIXED, run_definitions

        definitions = [
            {
                "id": e.id,
                "title": e.title,
                "category": e.category,
                "severity": e.severity,
                "invariant": e.invariant,
                "actor": BreakTraceActor(
                    name=e.actor.name, user_id=e.actor.user_id
                ),
                "request": BreakTraceRequest(
                    method=e.request.method, path=e.request.path
                ),
                "expected": BreakTraceExpected(status=e.expected.status),
            }
            for e in demo_entries
        ]
        run = run_definitions(
            definitions,
            MODE_FIXED,
            source="library",
            assessment_id="LIBRARY-REPLAY",
        )
        for result in run.results:
            entry = by_id.get(result.id)
            if entry is None:
                continue
            _mark(entry, result.status, result.observed.status)
        items.extend(
            ReplayItem(id=r.id, status=r.status) for r in run.results
        )

    # --- Juice Shop entries: honest re-execution against a fresh instance ---
    if juice_shop_entries:
        from target_runner import replay_juice_shop_entries as _replay_js

        replayed = _replay_js(juice_shop_entries)
        for item in replayed:
            entry = by_id.get(item.id)
            if entry is None:
                continue
            if item.status == "error":
                entry.last_replayed = now
                entry.replay_count += 1
                entry.current_status = "error"
                entry.latest_observed_status = None
            else:
                _mark(entry, item.status, None)
        items.extend(replayed)

    save_library(entries)

    passed = sum(1 for i in items if i.status == "passed")
    failed = sum(1 for i in items if i.status == "failed")
    return LibraryReplayResult(
        replayed=len(items),
        passed=passed,
        regressions=failed,
        results=items,
    )


# ---------------------------------------------------------------------------
# Dashboard metrics
# ---------------------------------------------------------------------------


def get_dashboard_metrics(
    latest_run: AssessmentRunResult | None,
    target_id: str | None = None,
) -> DashboardMetrics:
    """Derive dashboard metrics for ONE application from the latest
    assessment run + that application's library entries.

    Metrics are application-scoped: only regression tests with the matching
    target_id are counted, so applications never mix.

    The regression score is a transparent ratio:
        passed_current_regression_tests / total_current_regression_tests * 100
    It is None ("Not enough data") when no regression test has been replayed.

    Args:
        latest_run: Most recent executed AssessmentRunResult (may be None).
        target_id: Application to scope to. None scopes to unassigned
            (legacy M6) entries only.
    """
    entries = load_library()
    regression = [
        e
        for e in entries.values()
        if e.kind == "regression" and e.target_id == (target_id or "")
    ]
    replayed = [e for e in regression if e.current_status is not None]
    failed = [e for e in replayed if e.current_status == "failed"]
    passed = len(replayed) - len(failed)

    replay_pass_rate = (
        round(passed / len(replayed) * 100, 1) if replayed else None
    )
    security_score = round(passed / len(replayed) * 100) if replayed else None

    return DashboardMetrics(
        tests_generated=(
            latest_run.summary.tests_generated if latest_run else None
        ),
        verified_vulnerabilities=(
            latest_run.summary.vulnerabilities_found if latest_run else None
        ),
        controls_passed=(
            latest_run.summary.controls_passed if latest_run else None
        ),
        regression_tests_saved=len(regression),
        current_regressions=len(failed),
        replay_pass_rate=replay_pass_rate,
        security_score=security_score,
    )