"""Self-check tests for Milestone 7 - application identity (no Daytona/API needed).

Covers:
- URL normalization (same-origin variants -> one target_id; http/https/port differ)
- Unsupported scheme + invalid URL rejection
- Resolve idempotency (no duplicates, assessment_count untouched by resolve)
- Two-application isolation (library + dashboard never mix)
- Persistence across reload (survives "restart")
- Legacy M6 migration (unassigned entries adopted by the first application)

Run from the backend/ directory:
    ./venv/Scripts/python.exe test_applications.py

All registry + library writes go to a throwaway temp directory - real
backend/data files are never touched.
"""

import os
import tempfile

import applications
import library
from models import (
    BreakTraceActor,
    BreakTraceExpected,
    BreakTraceObserved,
    BreakTraceRequest,
    LibraryEntry,
)

# Point the registry + library at a throwaway temp dir.
_TMP = tempfile.mkdtemp(prefix="breaktrace_m7_")
applications.DATA_DIR = _TMP
applications.APPLICATIONS_PATH = os.path.join(_TMP, "applications.json")
library.DATA_DIR = _TMP
library.LIBRARY_PATH = os.path.join(_TMP, "breaktraces.json")


def check(label, got, expected):
    if got != expected:
        print(f"FAIL {label}: expected {expected!r}, got {got!r}")
        raise SystemExit(1)
    print(f"ok   {label}: {got!r}")


def check_raises(label, fn):
    try:
        fn()
    except applications.ApplicationError:
        print(f"ok   {label}: rejected")
        return
    print(f"FAIL {label}: was not rejected")
    raise SystemExit(1)


def test_normalization():
    same_origin = [
        "https://example.com",
        "https://EXAMPLE.com/",
        "https://example.com/login",
        "https://example.com?x=1",
        "https://example.com/#dashboard",
        "https://example.com:443",
    ]
    target = applications.target_id_for("https://example.com")
    for url in same_origin:
        origin = applications.normalize_target_url(url)
        check(f"normalize {url}", origin, "https://example.com")
        check(
            f"target_id {url}",
            applications.target_id_for(origin) == target,
            True,
        )

    check(
        "http differs",
        applications.normalize_target_url("http://example.com"),
        "http://example.com",
    )
    check(
        "https:8443 preserved",
        applications.normalize_target_url("https://example.com:8443"),
        "https://example.com:8443",
    )
    check(
        "http:80 removed",
        applications.normalize_target_url("http://example.com:80"),
        "http://example.com",
    )
    check(
        "bare hostname defaults to https",
        applications.normalize_target_url("app-one.example"),
        "https://app-one.example",
    )
    check(
        "bare hostname with port",
        applications.normalize_target_url("example.com:8080"),
        "https://example.com:8080",
    )
    check(
        "display name",
        applications.display_name_for("https://example.com:8443"),
        "example.com:8443",
    )

    for bad in [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "data:text/plain,x",
        "ftp://example.com",
        "   ",
        "",
        "https://",
        "https://exa mple.com",
    ]:
        check_raises(f"reject {bad!r}", lambda b=bad: applications.normalize_target_url(b))


def test_resolve_idempotent():
    created, rec = applications.resolve_application("https://app-one.example")
    check("app-one created", created, True)
    check("app-one display", rec.display_name, "app-one.example")
    check("app-one origin", rec.origin, "https://app-one.example")

    created2, rec2 = applications.resolve_application("https://APP-ONE.example/login")
    check("re-resolve not created", created2, False)
    check("same target_id", rec2.target_id, rec.target_id)

    records = applications.load_applications()
    matches = [r for r in records.values() if r.target_id == rec.target_id]
    check("no duplicate records", len(matches), 1)
    check("resolve never bumps assessment_count", rec2.assessment_count, 0)
    check("resolve never sets last_assessed_at", rec2.last_assessed_at, None)


def _make_entry(entry_id, target_id, origin):
    return LibraryEntry(
        id=entry_id,
        fingerprint=entry_id,
        title="Cross-user invoice access",
        category="broken_access_control",
        severity="high",
        invariant="A user must never access another user's invoice.",
        actor=BreakTraceActor(name="Alice", user_id=1),
        request=BreakTraceRequest(method="GET", path="/api/invoices/2"),
        expected=BreakTraceExpected(status=403),
        original_observed=BreakTraceObserved(status=200, body={"id": 2}),
        original_status="vulnerable",
        source="test",
        kind="regression",
        first_seen="2026-08-22T00:00:00+00:00",
        target_id=target_id,
        origin=origin,
    )


def test_two_apps_isolated():
    _, app_a = applications.resolve_application("https://app-a.example")
    _, app_b = applications.resolve_application("https://app-b.example")

    entries = {
        "A-1": _make_entry("A-1", app_a.target_id, app_a.origin),
        "A-2": _make_entry("A-2", app_a.target_id, app_a.origin),
        "B-1": _make_entry("B-1", app_b.target_id, app_b.origin),
    }
    library.save_library(entries)

    list_a = library.list_entries(app_a.target_id)
    list_b = library.list_entries(app_b.target_id)
    check("app A sees only A", sorted(e.id for e in list_a.entries), ["A-1", "A-2"])
    check("app B sees only B", [e.id for e in list_b.entries], ["B-1"])

    dash_a = library.get_dashboard_metrics(None, app_a.target_id)
    dash_b = library.get_dashboard_metrics(None, app_b.target_id)
    check("dashboard A scoped (2)", dash_a.regression_tests_saved, 2)
    check("dashboard B scoped (1)", dash_b.regression_tests_saved, 1)
    check("dashboard A score not enough data", dash_a.security_score, None)

    summary_a = applications.build_application_summary(app_a)
    summary_b = applications.build_application_summary(app_b)
    check("summary A vulns", summary_a.verified_vulnerabilities, 2)
    check("summary B vulns", summary_b.verified_vulnerabilities, 1)
    check("summary A regression score None", summary_a.regression_score, None)


def test_persistence_and_record_assessment():
    # Simulate a backend restart: reload fresh from disk and re-resolve.
    created, rec = applications.resolve_application("https://app-one.example")
    check("persisted re-resolve not created", created, False)

    updated = applications.record_assessment_completed(rec.target_id)
    check("assessment_count bumped", updated.assessment_count, 1)
    check("last_assessed_at set", updated.last_assessed_at is not None, True)

    created_again, rec_again = applications.resolve_application("https://app-one.example")
    check("resolve after assessment still no-op", created_again, False)
    check("count stable after re-resolve", rec_again.assessment_count, 1)


def test_legacy_migration():
    # Wipe both files, seed one unassigned M6 entry, then create first app.
    for path in (applications.APPLICATIONS_PATH, library.LIBRARY_PATH):
        if os.path.exists(path):
            os.remove(path)
    legacy = _make_entry("LEGACY-001", "", "")
    library.save_library({legacy.fingerprint: legacy})

    created, rec = applications.resolve_application("https://first-app.example")
    check("first app created", created, True)

    loaded = library.load_library()
    migrated = list(loaded.values())[0]
    check("legacy adopted target_id", migrated.target_id, rec.target_id)
    check("legacy adopted origin", migrated.origin, rec.origin)
    check("legacy evidence preserved", migrated.original_status, "vulnerable")

    list_first = library.list_entries(rec.target_id)
    check("migrated entry visible in app library", [e.id for e in list_first.entries], ["LEGACY-001"])
    check("no unassigned entries remain", library.list_entries(None).total, 0)


if __name__ == "__main__":
    print("== Milestone 7 application identity self-checks ==")
    print(f"using temp data dir: {_TMP}\n")
    test_normalization()
    test_resolve_idempotent()
    test_two_apps_isolated()
    test_persistence_and_record_assessment()
    test_legacy_migration()
    print("\nALL CHECKS PASSED")
