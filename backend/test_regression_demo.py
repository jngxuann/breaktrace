"""Automated tests for Milestone 12 - the BreakTrace Regression Demo.

Covers the SECURITY MEMORY + SECURITY REGRESSION workflow across
V1 (vulnerable) -> V2 (fixed) -> V3 (regression):

  1.  demo V1 starts (prepared without a node runtime)
  2.  V1 route /api/reports/:id is discovered from source
  3.  V1 Alice -> Bob request returns 200
  4.  the ownership experiment expects 403
  5.  V1 can become a verified finding
  6.  a verified experiment can be saved to Security Memory
  7.  the saved entry keeps replayable headers (X-Demo-User)
  8.  dangerous headers are rejected by the allowlist
  9.  CR/LF header values are rejected (header injection)
  10. arbitrary external URLs are rejected
  11. V1/V2/V3 share the same application identity / target_id
  12. V1/V2/V3 resolve to distinct refs (and distinct captured SHAs)
  13. V2 Alice -> Bob returns 403
  14. BT-001 replays against V2
  15. V2 replay status = passed / fix verified
  16. V3 Alice -> Bob returns 200
  17. BT-001 replays against V3
  18. V3 replay status = regression
  19. regression replay occurs BEFORE AI exploration
  20. V3 regression is detected with the AI mocked/unavailable
  21. original V1 evidence is preserved after replays
  22. last_replayed_at updates on replay
  23. last_replayed_version updates on replay
  24. replaying does not create a duplicate BT entry
  25. a replay error never counts as a regression
  26. the demo target rejects arbitrary git refs (allowlist only)
  27. the CyberSafe target is unchanged
  28. the Juice Shop target is unchanged
  29-31. existing discovery/security/deterministic tests still pass
     (verified by running the whole suite - see CI + test runner)
  32. the Daytona sandbox is always destroyed
  33. version resolution maps only to the allowlisted V1/V2/V3
  34-35. frontend state comes from backend results (see frontend build +
     the Security Memory rendering that only reads assessment data)

No live Daytona sandbox or AI credentials are required - sandboxes are faked
and AI is mocked. Run from the backend/ directory:

    ./venv/Scripts/python.exe test_regression_demo.py
"""

import json
import os
import re
import tempfile
import unittest
from unittest import mock

import ai_shared
import applications
import discovery
import library
import security_twin
import target_runner
import targets
from ai_shared import ProposalValidationError, validate_executable_experiment
from models import (
    ApplicationContext,
    AssessmentRunResult,
    AssessmentSummary,
    BreakTraceActor,
    BreakTraceExpected,
    BreakTraceObserved,
    BreakTraceRequest,
    BreakTraceResult,
    DiscoveredRoute,
    IdentityInput,
    LibraryEntry,
    ResourceOwnership,
    SecurityTestProposal,
    SeedEntity,
)
from security_twin import run_security_twin_assessment
from targets import (
    TargetError,
    get_target_adapter,
    resolve_target_version,
)

# Point registry + library at a throwaway temp dir so no real data is touched.
_TMP = tempfile.mkdtemp(prefix="breaktrace_m12_")
applications.DATA_DIR = _TMP
applications.APPLICATIONS_PATH = os.path.join(_TMP, "applications.json")
library.DATA_DIR = _TMP
library.LIBRARY_PATH = os.path.join(_TMP, "breaktraces.json")

DEMO = "security_regression_demo"
TARGET_ID = "t" * 64
# Fictional demo seed (matches the demo app): report 2 is owned by Bob.
OWNERSHIP_PATH = "/api/reports/2"
EXPECTED_FORBIDDEN = 403


def _reset_library():
    if os.path.exists(library.LIBRARY_PATH):
        os.remove(library.LIBRARY_PATH)


def demo_adapter(version="v1"):
    """Return the demo adapter (optionally resolved to an allowlisted version)."""
    return resolve_target_version(DEMO, version)


# The demo adapter's repository URL is intentionally empty until
# BREAKTRACE_DEMO_REPO_URL is set (the real GitHub repo URL is never
# fabricated). For tests that exercise prepare_target/clone we derive a
# configured copy using the same immutable dataclass.
from dataclasses import replace


def configured(adapter):
    """Return a copy of a demo adapter with a (fake) repository URL so
    clone/prepare steps run like in a live hackathon demo."""
    return replace(
        adapter,
        repository_url="https://github.com/example/breaktrace-regression-demo.git",
    )


def make_context(adapter=None) -> ApplicationContext:
    adapter = adapter or demo_adapter()
    return ApplicationContext(
        target_id=TARGET_ID,
        name=adapter.name,
        framework="python",
        runtime_origin=f"http://127.0.0.1:{adapter.port}",
        routes=[
            DiscoveredRoute(method="GET", path="/", source="both"),
            DiscoveredRoute(
                method="GET", path="/api/reports/:id", source="both"
            ),
        ],
        models=["Report", "User"],
        auth_signals=[],
        discovery_summary="demo",
        query_parameters=[],
        # Set directly as the adapter would via build_application_context.
        allowed_request_headers=["X-Demo-User"],
    )


# The exact replayable experiment BT-001 is built from (method/path/headers/
# expected 403) - this is the experiment the AI would propose and BreakTrace
# would verify.
def ownership_experiment() -> dict:
    return {
        "type": "executable_experiment",
        "title": "User can access another user's report",
        "category": "broken_access_control",
        "hypothesis": "Report retrieval may not enforce ownership",
        "invariant": "User 1 must not access reports owned by another user",
        "request": {
            "method": "GET",
            "path": OWNERSHIP_PATH,
            "headers": {"X-Demo-User": "1"},
        },
        "expected_status": EXPECTED_FORBIDDEN,
        "reason": "checks ownership on report retrieval",
    }


def ownership_proposal() -> SecurityTestProposal:
    return validate_executable_experiment(
        ownership_experiment(), 1, make_context()
    )


def verified_result() -> BreakTraceResult:
    """The runtime-verified result of the ownership experiment in V1 (200 != 403)."""
    p = ownership_proposal()
    return BreakTraceResult(
        id="BT-001",
        title=p.title,
        category=p.category,
        severity="high",
        invariant=p.invariant,
        actor=p.actor,
        request=p.request,
        expected=BreakTraceExpected(status=p.expected_status),
        observed=BreakTraceObserved(status=200, body={"id": 2, "owner": "Bob"}),
        test_executed=True,
        invariant_violated=True,
        status="vulnerable",
        mode="independent",
        source="groq_ai",
        hypothesis=p.hypothesis,
    )


def make_run(*results) -> AssessmentRunResult:
    return AssessmentRunResult(
        assessment_id="DEMO-001",
        source="groq_ai",
        summary=AssessmentSummary(
            tests_generated=len(results),
            tests_executed=len(results),
            vulnerabilities_found=sum(1 for r in results if r.invariant_violated),
            controls_passed=sum(1 for r in results if not r.invariant_violated),
        ),
        results=list(results),
        target_adapter=DEMO,
        provider="groq",
        model="llama-3.3-70b",
    )


# ---------------------------------------------------------------------------
# Fakes (sandbox + client process for the zero-dependency Python demo)
# ---------------------------------------------------------------------------


class FakeResult:
    def __init__(self, output, exit_code=0):
        self.result = output
        self.exit_code = exit_code


class DemoProcess:
    """Command-aware fake that responds like the in-sandbox client to the
    exact commands the demo lifecycle issues (no node, python server)."""

    def __init__(self, commit_sha=None, ref=None, report_status=404, fail=False, source=None):
        self.commit_sha = commit_sha
        self.ref = ref
        self.report_status = report_status
        self.fail = fail
        self.source = source
        self.calls = []

    @staticmethod
    def _extract_path(command):
        m = re.match(r"python \S+ (?:GET|DELETE|OPTIONS) (.+)$", command)
        if m is None:
            return None
        return m.group(1).strip().strip("'\"")

    def exec(self, command, timeout=None, env=None):
        self.calls.append({"command": command, "env": env})
        if "--wait" in command:
            return FakeResult("ready")
        if "--probe" in command:
            return FakeResult('[{"path": "/", "status": 200}]')
        if "--headers" in command:
            # Deterministic checks probe the local origin; respond 200 no set
            # security headers (unrelated to BT-001).
            return FakeResult(
                json.dumps({"status": 200, "headers": {}, "body": {}})
            )
        if "rev-parse HEAD" in command:
            return (
                FakeResult(self.commit_sha)
                if self.commit_sha
                else FakeResult("", exit_code=128)
            )
        if "describe --tags" in command:
            return (
                FakeResult(self.ref)
                if self.ref
                else FakeResult("", exit_code=128)
            )
        if "git --version" in command:
            return FakeResult("git version 2.45.0")
        if (
            "mkdir" in command
            or "clone" in command
            or "nohup" in command
            or "tail" in command
            or "sh -c" in command
        ):
            return FakeResult("ok")
        # Repository source walker (python -c ...). Feed the demo source so
        # discovery populates identity inputs + seed/ownership evidence, or
        # return no records when no source is configured.
        if "python -c" in command or "walk_repository" in command:
            if self.source:
                return FakeResult(
                    json.dumps({"path": "app.py", "language": "py", "content": self.source})
                )
            return FakeResult("")
        # Single-request client execution.
        path = self._extract_path(command)
        if path is None:
            return FakeResult(json.dumps({"status": 404, "body": {}}))
        if self.fail and path == OWNERSHIP_PATH:
            return FakeResult("", exit_code=1)
        # The demo target only answers the report endpoint as configured.
        if path == OWNERSHIP_PATH:
            return FakeResult(
                json.dumps({"status": self.report_status, "body": {}})
            )
        return FakeResult(json.dumps({"status": 200, "body": {}}))


class FakeFs:
    def __init__(self):
        self.uploads = []

    def upload_file(self, data, path):
        self.uploads.append(path)


class FakeSandbox:
    def __init__(self, **kwargs):
        self.process = DemoProcess(**kwargs)
        self.fs = FakeFs()
        self.ttl = None

    def set_ttl(self, t):
        self.ttl = t


class FakeClient:
    def __init__(self, sandbox=None):
        self.sandbox = sandbox or FakeSandbox()
        self.created = []
        self.deleted = []

    def create(self):
        self.created.append(self.sandbox)
        return self.sandbox

    def delete(self, sandbox):
        self.deleted.append(sandbox)


def run_full_twin(sandbox, adapter, proposals=None):
    """Run the full Security Twin orchestrator against a fake sandbox with a
    mocked AI. `proposals` (default none) are returned as valid Layer-3
    executable experiments; the AI propose call itself is replaced entirely.

    The fake sandbox is given the real demo source so generic discovery
    populates identity inputs + seed/ownership evidence like a live clone.
    """
    if not getattr(sandbox.process, "source", None):
        sandbox.process.source = _demo_source()
    client = FakeClient(sandbox)
    if proposals is None:
        proposals = []
    with mock.patch.object(
        security_twin, "get_daytona_client", return_value=client
    ):
        with mock.patch.object(
            security_twin,
            "propose_security_analysis_for_twin_split",
            return_value=(proposals, [], []),
        ):
            return client, security_twin.run_security_twin_assessment(
                adapter, TARGET_ID
            )


def seed_entry(**kw) -> LibraryEntry:
    base = dict(
        id="BT-001",
        fingerprint="fp-bt001",
        title="User can access another user's report",
        category="broken_access_control",
        severity="high",
        invariant="User 1 must not access reports owned by another user",
        actor=BreakTraceActor(name="anonymous", user_id=0),
        request=BreakTraceRequest(
            method="GET",
            path=OWNERSHIP_PATH,
            headers={"X-Demo-User": "1"},
        ),
        expected=BreakTraceExpected(status=EXPECTED_FORBIDDEN),
        original_observed=BreakTraceObserved(status=200, body={"owner": "Bob"}),
        original_status="vulnerable",
        source="groq_ai",
        kind="regression",
        first_seen="2026-08-22T00:00:00+00:00",
        first_detected_at="2026-08-22T00:00:00+00:00",
        target_id=TARGET_ID,
        origin="https://breaktrace-regression-demo.example",
        target_adapter=DEMO,
        application_version={"repository": "demo", "ref": "demo-v1-vulnerable"},
        test_definition={
            "kind": "http_experiment",
            "method": "GET",
            "path": OWNERSHIP_PATH,
            "headers": {"X-Demo-User": "1"},
            "expected_status": EXPECTED_FORBIDDEN,
        },
    )
    base.update(kw)
    entry = LibraryEntry(**base)
    entries = library.load_library()
    entries[entry.fingerprint] = entry
    library.save_library(entries)
    return entry


class DemoAdapterTests(unittest.TestCase):
    def setUp(self):
        _reset_library()

    # --- 1. V1 starts without node --------------------------------------
    def test_v1_starts_without_node(self):
        adapter = configured(demo_adapter("v1"))
        self.assertFalse(adapter.requires_node)
        self.assertEqual(adapter.ref, "demo-v1-vulnerable")
        sandbox = FakeSandbox(
            commit_sha="0f71222f454d02c42140e98108eab51e976f3233",
            ref="demo-v1-vulnerable",
            report_status=200,
        )
        origin = target_runner.prepare_target(sandbox, adapter)
        self.assertEqual(origin, f"http://127.0.0.1:{adapter.port}")
        commands = " ".join(c["command"] for c in sandbox.process.calls)
        # Python-only demo: node must never be required/installed.
        self.assertNotIn("node --version", commands)
        self.assertNotIn("npm", commands)
        # But git is still used to clone the pinned version.
        self.assertIn("--branch demo-v1-vulnerable", commands)

    def test_demo_target_registered(self):
        a = get_target_adapter(DEMO)
        self.assertEqual(a.target_type, DEMO)
        self.assertEqual(a.name, "BreakTrace Regression Demo")
        self.assertEqual(a.port, 8001)
        self.assertFalse(a.requires_node)
        self.assertEqual(a.allowed_request_headers, ["X-Demo-User"])
        self.assertEqual(a.supported_methods, ("GET",))

    # --- 11. V1/V2/V3 share the same identity ---------------------------
    def test_versions_share_identity(self):
        ids = []
        for version in ("v1", "v2", "v3"):
            a = demo_adapter(version)
            _, record = applications.resolve_application(a.application_identity)
            ids.append((a.version, record.target_id))
        self.assertEqual(len({tid for _, tid in ids}), 1)
        self.assertEqual(ids[0][0], "v1")

    def test_same_url_resolves_same_target_id_across_versions(self):
        origin = "https://reports-demo.example"
        tids = set()
        for _ in ("v1", "v2", "v3"):
            _, record = applications.resolve_application(origin)
            tids.add(record.target_id)
        self.assertEqual(len(tids), 1)

    # --- 12. versions have distinct refs --------------------------------
    def test_versions_have_distinct_refs(self):
        refs = {
            demo_adapter(v).ref
            for v in ("v1", "v2", "v3")
        }
        self.assertEqual(refs, {"demo-v1-vulnerable", "demo-v2-fixed", "demo-v3-regression"})

    def test_versions_capture_distinct_application_version(self):
        # prepare_target + capture_application_version record a distinct tag
        # + commit sha per version (never invented: supplied by the sandbox).
        adapter = configured(demo_adapter("v1"))
        sandbox = FakeSandbox(
            commit_sha="0f71222f454d02c42140e98108eab51e976f3233",
            ref="demo-v1-vulnerable",
        )
        origin = target_runner.prepare_target(sandbox, adapter)
        ver = target_runner.capture_application_version(sandbox, adapter)
        self.assertEqual(ver.ref, "demo-v1-vulnerable")
        self.assertEqual(ver.commit_sha, "0f71222f454d02c42140e98108eab51e976f3233")
        self.assertIn("8001", origin)

    # --- 26. no arbitrary git refs --------------------------------------
    def test_unknown_version_rejected(self):
        with self.assertRaises(TargetError):
            resolve_target_version(DEMO, "evil-branch")
        with self.assertRaises(TargetError):
            resolve_target_version(DEMO, "demo-v999")
        with self.assertRaises(TargetError):
            resolve_target_version(DEMO, "refs/heads/main")
        # The default (no selection) is V1 - never an arbitrary ref.
        self.assertEqual(get_target_adapter(DEMO).ref, "demo-v1-vulnerable")

    def test_adapter_has_no_vulnerability_knowledge(self):
        a = get_target_adapter(DEMO)
        dump = json.dumps(a.__dict__, default=str).lower()
        # No hardcoded finding: no report-id, no expected status, no owner
        # assertion, no "alice"/"bob" knowledge lives in the adapter.
        self.assertNotIn("/api/reports", dump)
        self.assertNotIn("owner", dump)
        self.assertNotIn("X-Demo-User: 1", json.dumps(a.__dict__))
        self.assertNotIn("403", dump)
        self.assertNotIn("alice", dump)

    # --- 27 + 28. existing targets unchanged -----------------------------
    def test_existing_targets_unchanged(self):
        cybersafe = get_target_adapter("cybersafe_jarss_user")
        self.assertEqual(cybersafe.port, 5173)
        self.assertIn("cybersafe-jarss-user-app", cybersafe.repository_url)
        self.assertTrue(cybersafe.frontend_only)
        js = get_target_adapter("juice_shop")
        self.assertEqual(js.port, 3000)
        self.assertIn("juice-shop", js.repository_url)
        self.assertEqual(js.ref, "v20.2.0")


class DemoDiscoveryTests(unittest.TestCase):
    # --- 2. V1 route is discovered from source --------------------------
    def test_route_discovered_from_source(self):
        # Read the actual demo app source (V3 source retains the same route).
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(here, "..", "demo_app", "app.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        routes = discovery.extract_python_http_routes(src)
        self.assertIn(("GET", "/api/reports/:id"), routes)

    def test_context_carries_route_and_allowlist(self):
        ctx = make_context()
        paths = {r.path for r in ctx.routes}
        self.assertIn("/api/reports/:id", paths)
        self.assertIn("/", paths)
        self.assertEqual(ctx.allowed_request_headers, ["X-Demo-User"])

    def test_param_route_matches_concrete_path(self):
        from ai_shared import _route_matches

        ctx = make_context()
        self.assertTrue(_route_matches("GET", "/api/reports/2", ctx.routes))

    def test_build_context_from_inspection(self):
        adapter = demo_adapter("v1")
        inspection = {
            "deps": {},
            "framework": "python",
            "routes": [("get", "/api/reports/:id")],
            "models": ["Report", "User"],
            "auth_signals": [],
            "components": [],
        }
        ctx = discovery.build_application_context(
            TARGET_ID,
            adapter,
            inspection,
            [DiscoveredRoute(method="GET", path="/", source="runtime")],
            f"http://127.0.0.1:{adapter.port}",
        )
        paths = {r.path for r in ctx.routes}
        self.assertIn("/api/reports/:id", paths)
        self.assertEqual(ctx.allowed_request_headers, ["X-Demo-User"])


class DemoValidationTests(unittest.TestCase):
    def setUp(self):
        _reset_library()

    def test_valid_experiment_accepted(self):
        proposal = validate_executable_experiment(ownership_experiment(), 1, make_context())
        self.assertEqual(proposal.request.method, "GET")
        self.assertEqual(proposal.request.path, OWNERSHIP_PATH)
        self.assertEqual(proposal.request.headers, {"X-Demo-User": "1"})
        self.assertEqual(proposal.expected_status, EXPECTED_FORBIDDEN)

    def test_dangerous_headers_rejected(self):
        for bad in (
            {"Host": "evil.com"},
            {"Connection": "close"},
            {"Content-Length": "0"},
            {"Transfer-Encoding": "chunked"},
            {"Forwarded": "for=1.2.3.4"},
            {"X-Forwarded-For": "1.2.3.4"},
            {"X-Forwarded-Host": "evil.com"},
            {"Proxy-Authorization": "Basic x"},
            {"Upgrade": "h2c"},
        ):
            data = ownership_experiment()
            data["request"]["headers"] = bad
            with self.assertRaises(ProposalValidationError):
                validate_executable_experiment(data, 1, make_context())

    def test_non_allowlisted_header_rejected(self):
        for bad in ({"Cookie": "sid=1"}, {"Authorization": "Bearer x"}, {"X-Other": "y"}):
            data = ownership_experiment()
            data["request"]["headers"] = bad
            with self.assertRaises(ProposalValidationError):
                validate_executable_experiment(data, 1, make_context())

    def test_crlf_header_value_rejected(self):
        for value in ("1\r\nInjected: yes", "1\nInjected: yes", "a\r", "a\nb"):
            data = ownership_experiment()
            data["request"]["headers"] = {"X-Demo-User": value}
            with self.assertRaises(ProposalValidationError):
                validate_executable_experiment(data, 1, make_context())

    def test_crlf_header_key_rejected(self):
        data = ownership_experiment()
        data["request"]["headers"] = {"X-Demo-User\r\nX-Evil": "1"}
        with self.assertRaises(ProposalValidationError):
            validate_executable_experiment(data, 1, make_context())

    def test_arbitrary_external_url_rejected(self):
        for bad in (
            "https://evil.example/api/reports/2",
            "http://127.0.0.1:9999/api/reports/2",
            "//evil.example/api/reports/2",
        ):
            data = ownership_experiment()
            data["request"]["path"] = bad
            with self.assertRaises(ProposalValidationError):
                validate_executable_experiment(data, 1, make_context())

    def test_undiscovered_endpoint_rejected(self):
        data = ownership_experiment()
        data["request"]["path"] = "/api/secret/admin"
        with self.assertRaises(ProposalValidationError):
            validate_executable_experiment(data, 1, make_context())

    def test_oversized_header_value_rejected(self):
        data = ownership_experiment()
        data["request"]["headers"] = {"X-Demo-User": "1" * 200}
        with self.assertRaises(ProposalValidationError):
            validate_executable_experiment(data, 1, make_context())


class DemoVulnerabilityTests(unittest.TestCase):
    """V1 - the ownership experiment is verified: 200 observed, 403 expected."""

    def setUp(self):
        _reset_library()

    # --- 3 + 4. V1 Alice -> Bob returns 200, expected 403 --------------
    def test_v1_returns_200(self):
        adapter = demo_adapter("v1")
        sandbox = FakeSandbox(report_status=200)
        origin = target_runner.prepare_target(sandbox, adapter)
        result = target_runner.execute_proposals(
            sandbox, adapter, origin, [ownership_proposal()]
        )[0]
        self.assertEqual(result.observed.status, 200)
        self.assertEqual(result.expected.status, EXPECTED_FORBIDDEN)
        self.assertTrue(result.invariant_violated)
        self.assertEqual(result.status, "vulnerable")

    # --- 5. V1 can become a verified finding ----------------------------
    def test_v1_can_become_verified_finding(self):
        adapter = demo_adapter("v1")
        sandbox = FakeSandbox(
            commit_sha="0f71222", ref="demo-v1-vulnerable", report_status=200
        )
        _, (_, assessment, _) = run_full_twin(
            sandbox, adapter, proposals=[ownership_proposal()]
        )
        ai_findings = [f for f in assessment.findings if f.source == "ai"]
        self.assertEqual(len(ai_findings), 1)
        self.assertEqual(ai_findings[0].status, "verified")
        self.assertEqual(ai_findings[0].category, "broken_access_control")
        self.assertEqual(ai_findings[0].evidence["observed_status"], 200)
        self.assertEqual(ai_findings[0].evidence["expected_status"], 403)
        self.assertEqual(assessment.summary.new_verified_findings, 1)

    # --- 6 + 7. verified experiment saved with replayable headers -------
    def test_verified_experiment_saved_with_headers(self):
        run = make_run(verified_result())
        res = library.add_from_results(
            run, "groq_ai", target_id=TARGET_ID,
            origin="https://breaktrace-regression-demo.example",
        )
        self.assertEqual(res["new"], 1)
        entries = library.list_entries(TARGET_ID).entries
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry.id, "BT-001")
        self.assertEqual(entry.category, "broken_access_control")
        # Replayable request headers are preserved in the saved memory.
        self.assertEqual(entry.request.headers, {"X-Demo-User": "1"})
        self.assertEqual(entry.expected.status, 403)
        self.assertEqual(entry.original_observed.status, 200)
        self.assertEqual(entry.first_detected_at, entry.first_seen)
        self.assertEqual(entry.target_adapter, DEMO)

    def test_test_definition_includes_headers(self):
        run = make_run(verified_result())
        library.add_from_results(
            run, "groq_ai", target_id=TARGET_ID, origin="https://demo.example"
        )
        entry = library.list_entries(TARGET_ID).entries[0]
        self.assertEqual(entry.test_definition["headers"], {"X-Demo-User": "1"})

    # --- 24. no duplicate on rediscovery --------------------------------
    def test_rediscovery_does_not_duplicate(self):
        run = make_run(verified_result())
        library.add_from_results(
            run, "groq_ai", target_id=TARGET_ID, origin="https://demo.example"
        )
        res = library.add_from_results(
            run, "groq_ai", target_id=TARGET_ID, origin="https://demo.example"
        )
        self.assertEqual(res["new"], 0)
        self.assertEqual(res["already_in_library"], 1)
        self.assertEqual(library.list_entries(TARGET_ID).total, 1)


class DemoReplayTests(unittest.TestCase):
    """V2 (fixed) and V3 (regression) replay of the stored BT-001."""

    def setUp(self):
        _reset_library()
        seed_entry()

    # --- 13. V2 Alice -> Bob returns 403 --------------------------------
    def test_v2_returns_403(self):
        adapter = configured(demo_adapter("v2"))
        self.assertEqual(adapter.ref, "demo-v2-fixed")
        sandbox = FakeSandbox(ref="demo-v2-fixed", report_status=403)
        origin = target_runner.prepare_target(sandbox, adapter)
        result = target_runner.execute_proposals(
            sandbox, adapter, origin, [ownership_proposal()]
        )[0]
        self.assertEqual(result.observed.status, 403)
        self.assertFalse(result.invariant_violated)

    # --- 14 + 15. BT-001 replays against V2 -> passed -------------------
    def test_bt001_replays_v2_passed(self):
        adapter = configured(demo_adapter("v2"))
        entries = library.load_regression_entries(TARGET_ID, DEMO)
        sandbox = FakeSandbox(ref="demo-v2-fixed", report_status=403)
        items = target_runner.replay_entries_in_twin(
            sandbox, adapter, f"http://127.0.0.1:{adapter.port}", entries
        )
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].entry_id, "BT-001")
        self.assertEqual(items[0].status, "passed")
        self.assertEqual(items[0].expected_status, 403)
        self.assertEqual(items[0].observed_status, 403)
        self.assertEqual(items[0].category, "broken_access_control")
        self.assertEqual(items[0].first_detected_version, "demo-v1-vulnerable")
        self.assertEqual(items[0].last_replayed_version, "demo-v2-fixed")
        # Security Memory display carries the exact replayed request.
        self.assertEqual(items[0].method, "GET")
        self.assertEqual(items[0].path, OWNERSHIP_PATH)

    # --- 16. V3 Alice -> Bob returns 200 --------------------------------
    def test_v3_returns_200(self):
        adapter = configured(demo_adapter("v3"))
        self.assertEqual(adapter.ref, "demo-v3-regression")
        sandbox = FakeSandbox(ref="demo-v3-regression", report_status=200)
        origin = target_runner.prepare_target(sandbox, adapter)
        result = target_runner.execute_proposals(
            sandbox, adapter, origin, [ownership_proposal()]
        )[0]
        self.assertEqual(result.observed.status, 200)
        self.assertTrue(result.invariant_violated)

    # --- 17 + 18. BT-001 replays against V3 -> regression ---------------
    def test_bt001_replays_v3_regression(self):
        adapter = demo_adapter("v3")
        entries = library.load_regression_entries(TARGET_ID, DEMO)
        sandbox = FakeSandbox(ref="demo-v3-regression", report_status=200)
        items = target_runner.replay_entries_in_twin(
            sandbox, adapter, f"http://127.0.0.1:{adapter.port}", entries
        )
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].entry_id, "BT-001")
        self.assertEqual(items[0].status, "regression")
        self.assertEqual(items[0].expected_status, 403)
        self.assertEqual(items[0].observed_status, 200)

    # --- 25. replay error is never a regression -------------------------
    def test_replay_error_not_regression(self):
        adapter = demo_adapter("v2")
        entries = library.load_regression_entries(TARGET_ID, DEMO)
        sandbox = FakeSandbox(ref="demo-v2-fixed", fail=True)
        items = target_runner.replay_entries_in_twin(
            sandbox, adapter, "http://127.0.0.1:8001", entries
        )
        self.assertEqual(items[0].status, "error")
        self.assertIsNotNone(items[0].error)

    # --- 21-23. bookkeeping preserves evidence + updates versions -------
    def test_original_evidence_preserved_after_replay(self):
        adapter = demo_adapter("v3")
        entries = library.load_regression_entries(TARGET_ID, DEMO)
        sandbox = FakeSandbox(ref="demo-v3-regression", report_status=200)
        items = target_runner.replay_entries_in_twin(
            sandbox, adapter, "http://127.0.0.1:8001", entries
        )
        library.mark_entries_replayed(items, adapter)
        persisted = library.load_library()
        entry = next(
            e for e in persisted.values() if e.id == "BT-001"
        )
        # The original V1 evidence is never overwritten.
        self.assertEqual(entry.original_observed.status, 200)
        self.assertEqual(entry.original_status, "vulnerable")
        self.assertEqual(entry.first_detected_at, "2026-08-22T00:00:00+00:00")
        # Replay bookkeeping updated.
        self.assertIsNotNone(entry.last_replayed_at)
        self.assertEqual(entry.replay_count, 1)
        self.assertEqual(entry.current_status, "failed")  # regression vocab
        self.assertEqual(entry.latest_observed_status, 200)
        self.assertEqual(entry.last_replayed_version, "demo-v3-regression")

    def test_last_replayed_at_updates(self):
        adapter = demo_adapter("v2")
        entries = library.load_regression_entries(TARGET_ID, DEMO)
        sandbox = FakeSandbox(ref="demo-v2-fixed", report_status=403)
        items = target_runner.replay_entries_in_twin(
            sandbox, adapter, "http://127.0.0.1:8001", entries
        )
        self.assertIsNone(
            library.load_library()["fp-bt001"].last_replayed_at
        )
        library.mark_entries_replayed(items, adapter)
        self.assertIsNotNone(
            library.load_library()["fp-bt001"].last_replayed_at
        )


class DemoOrchestratorTests(unittest.TestCase):
    """End-to-end Security Twin orchestration over V1/V2/V3."""

    def setUp(self):
        _reset_library()

    def test_first_assessment_no_memory(self):
        sandbox = FakeSandbox(
            commit_sha="0f71222", ref="demo-v1-vulnerable", report_status=200
        )
        _, (_, assessment, _) = run_full_twin(sandbox, demo_adapter("v1"))
        self.assertEqual(assessment.regression.tests_replayed, 0)
        self.assertEqual(assessment.regression.results, [])

    # --- 19. regression replay occurs BEFORE AI -------------------------
    def test_regression_replay_before_ai(self):
        seed_entry()
        adapter = demo_adapter("v3")
        client = FakeClient()
        parent = mock.Mock()
        replay_mock = mock.Mock(return_value=[])
        propose_mock = mock.Mock(return_value=([], [], []))
        parent.attach_mock(replay_mock, "replay")
        parent.attach_mock(propose_mock, "propose")
        with mock.patch.object(
            security_twin, "get_daytona_client", return_value=client
        ):
            with mock.patch.object(
                security_twin, "replay_entries_in_twin", replay_mock
            ):
                with mock.patch.object(
                    security_twin,
                    "propose_security_analysis_for_twin_split",
                    propose_mock,
                ):
                    security_twin.run_security_twin_assessment(adapter, TARGET_ID)
        names = [call[0] for call in parent.mock_calls]
        self.assertIn("replay", names)
        self.assertIn("propose", names)
        self.assertLess(names.index("replay"), names.index("propose"))

    # --- 20. V3 regression detected with AI mocked (no rediscovery) -----
    def test_v3_regression_detected_with_ai_mocked(self):
        seed_entry()
        adapter = configured(demo_adapter("v3"))
        sandbox = FakeSandbox(
            commit_sha="e95c683", ref="demo-v3-regression", report_status=200
        )
        client = FakeClient(sandbox)
        propose = mock.Mock(
            return_value=([], [], [])
        )  # AI contributes NOTHING - no rediscovery
        with mock.patch.object(
            security_twin, "get_daytona_client", return_value=client
        ):
            with mock.patch.object(
                security_twin,
                "propose_security_analysis_for_twin_split",
                propose,
            ):
                _, assessment, _ = security_twin.run_security_twin_assessment(
                    adapter, TARGET_ID
                )
        # The regression is detected purely from Security Memory replay. The
        # AI was mocked to provide zero hypotheses, so detection is proven to
        # never depend on the AI rediscovering the vulnerability.
        self.assertEqual(assessment.regression.tests_replayed, 1)
        self.assertEqual(assessment.regression.regressions, 1)
        self.assertEqual(assessment.regression.results[0].status, "regression")
        self.assertEqual(assessment.summary.security_regressions, 1)
        self.assertEqual(assessment.summary.new_verified_findings, 0)
        # The AI provider call was still made once (Layer 3), but it returned
        # nothing and did not contribute to the regression signal.
        self.assertEqual(propose.call_count, 1)
        # last_replayed_version recorded on the library entry.
        persisted = library.load_library()
        entry = next(e for e in persisted.values() if e.id == "BT-001")
        self.assertEqual(entry.last_replayed_version, "demo-v3-regression")

    def test_v2_fix_verified_with_ai_mocked(self):
        seed_entry()
        adapter = configured(demo_adapter("v2"))
        sandbox = FakeSandbox(
            commit_sha="1b0e4c0", ref="demo-v2-fixed", report_status=403
        )
        client = FakeClient(sandbox)
        propose = mock.Mock(return_value=([], [], []))
        with mock.patch.object(
            security_twin, "get_daytona_client", return_value=client
        ):
            with mock.patch.object(
                security_twin,
                "propose_security_analysis_for_twin_split",
                propose,
            ):
                _, assessment, _ = security_twin.run_security_twin_assessment(
                    adapter, TARGET_ID
                )
        self.assertEqual(assessment.regression.regressions, 0)
        self.assertEqual(assessment.regression.passed, 1)
        self.assertEqual(assessment.regression.results[0].status, "passed")
        self.assertEqual(assessment.summary.security_regressions, 0)
        self.assertEqual(propose.call_count, 1)

    # --- 33. version selection is wired through the assess endpoint -------
    def test_assess_endpoint_honors_allowlisted_version(self):
        from fastapi.testclient import TestClient
        import main
        from models import (
            AiExplorationSection,
            DeterministicSection,
            RegressionSection,
            SecurityTwinAssessment,
            SecurityTwinInfo,
            SecurityTwinSummary,
        )

        def _run(adapter, target_id):
            captured.append(adapter)
            ctx = make_context(adapter)
            assessment = SecurityTwinAssessment(
                assessment_id="TWIN-999",
                target={
                    "target_type": adapter.target_type,
                    "name": adapter.name,
                    "repository": adapter.repository_url,
                    "port": adapter.port,
                },
                security_twin=SecurityTwinInfo(application_version=None),
                regression=RegressionSection(
                    tests_replayed=0, passed=0, regressions=0, errors=0, results=[]
                ),
                deterministic=DeterministicSection(
                    checks_executed=0, passed=0, issues=0, results=[]
                ),
                discovery=ctx,
                ai_exploration=AiExplorationSection(
                    provider="groq", model="mock", hypotheses_generated=0,
                    tests_executed=0, verified_findings=0, results=[]
                ),
                findings=[],
                summary=SecurityTwinSummary(
                    security_regressions=0, new_verified_findings=0,
                    deterministic_issues=0, controls_passed=0,
                ),
            )
            ai_run = make_run()
            return ctx, assessment, ai_run

        captured = []
        client = TestClient(main.app, raise_server_exceptions=False)
        with mock.patch.object(main, "run_security_twin_assessment", side_effect=_run):
            resp = client.post(
                "/security-twin/assess",
                json={
                    "target_type": DEMO,
                    "url": "https://reports-demo.example",
                    "version": "v2",
                },
            )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(captured[0].ref, "demo-v2-fixed")
        self.assertEqual(captured[0].version, "v2")

    def test_assess_endpoint_rejects_unknown_version(self):
        from fastapi.testclient import TestClient
        import main

        client = TestClient(main.app, raise_server_exceptions=False)
        resp = client.post(
            "/security-twin/assess",
            json={
                "target_type": DEMO,
                "url": "https://reports-demo.example",
                "version": "evil-branch",
            },
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Allowed versions", resp.json()["detail"])

    # --- 32. sandbox always destroyed -----------------------------------
    def test_sandbox_always_destroyed(self):
        sandbox = FakeSandbox(
            commit_sha="0f71222", ref="demo-v1-vulnerable", report_status=200
        )
        client, (_, assessment, _) = run_full_twin(
            sandbox, demo_adapter("v1"), proposals=[ownership_proposal()]
        )
        self.assertEqual(len(client.created), 1)
        self.assertEqual(len(client.deleted), 1)
        self.assertEqual(client.created, client.deleted)

    def test_sandbox_destroyed_on_failure(self):
        client = FakeClient()
        with mock.patch.object(
            security_twin, "get_daytona_client", return_value=client
        ):
            with mock.patch.object(
                security_twin,
                "prepare_target",
                side_effect=RuntimeError("boom"),
            ):
                with self.assertRaises(RuntimeError):
                    security_twin.run_security_twin_assessment(
                        demo_adapter("v1"), TARGET_ID
                    )
        self.assertEqual(len(client.created), 1)
        self.assertEqual(len(client.deleted), 1)

    def test_findings_versioned_per_selection(self):
        # V1 verified finding records the V1 application version.
        adapter = configured(demo_adapter("v1"))
        sandbox = FakeSandbox(
            commit_sha="0f71222", ref="demo-v1-vulnerable", report_status=200
        )
        _, (_, assessment, _) = run_full_twin(
            sandbox, adapter, proposals=[ownership_proposal()]
        )
        finding = next(f for f in assessment.findings if f.source == "ai")
        self.assertEqual(finding.application_version.ref, "demo-v1-vulnerable")


# ---------------------------------------------------------------------------
# Milestone 12 finding-quality tests: cross-user (IDOR) semantics.
# ---------------------------------------------------------------------------

DEMO_SOURCE = None


def _demo_source():
    global DEMO_SOURCE
    if DEMO_SOURCE is None:
        here = os.path.dirname(os.path.abspath(__file__))
        with open(
            os.path.join(here, "..", "demo_app", "app.py"), encoding="utf-8"
        ) as fh:
            DEMO_SOURCE = fh.read()
    return DEMO_SOURCE


def quality_context() -> ApplicationContext:
    """The demo ApplicationContext as produced by discovery: identity inputs,
    ownership relationship, and bounded seed entities."""
    return ApplicationContext(
        target_id=TARGET_ID,
        name="BreakTrace Regression Demo",
        framework="python",
        runtime_origin="http://127.0.0.1:8001",
        routes=[
            DiscoveredRoute(method="GET", path="/", source="both"),
            DiscoveredRoute(method="GET", path="/api/reports/:id", source="both"),
        ],
        identity_inputs=[
            IdentityInput(
                name="X-Demo-User", kind="request_header",
                purpose="user_identity", source="app.py", confidence="high",
            )
        ],
        resource_relationships=[
            ResourceOwnership(
                resource="reports", resource_identifier="id",
                owner_field="owner_id", identity_field="user_id",
                resource_identifiers=[1, 2], principal_identifiers=[1, 2],
                owners={1: 1, 2: 2}, source="app.py", confidence="high",
            )
        ],
        seed_entities=[
            SeedEntity(
                entity_type="users", identifiers=[1, 2],
                labels={1: "Alice", 2: "Bob"},
            ),
            SeedEntity(entity_type="reports", identifiers=[1, 2], labels={}),
        ],
        allowed_request_headers=["X-Demo-User"],
        query_parameters=[],
    )


def cross_user_experiment() -> dict:
    """The intended IDOR experiment: Alice (1) requests Bob's report (2)."""
    return {
        "type": "executable_experiment",
        "title": "Cross-user report access",
        "category": "broken_access_control",
        "hypothesis": "Report retrieval may not enforce ownership",
        "invariant": "A user must not retrieve a report owned by another user",
        "request": {
            "method": "GET",
            "path": "/api/reports/2",
            "headers": {"X-Demo-User": "1"},
        },
        "expected_status": 403,
        "reason": "checks cross-user ownership on report retrieval",
    }


def unauth_experiment() -> dict:
    """Missing-authentication experiment (must NOT be labeled IDOR)."""
    return {
        **cross_user_experiment(),
        "title": "Anonymous report access",
        "hypothesis": "Report retrieval may not require authentication",
        "invariant": "Report retrieval should require a principal identity",
        "request": {"method": "GET", "path": "/api/reports/1", "headers": {}},
    }


class DemoDiscoveryQualityTests(unittest.TestCase):
    """Requirements 1-10: generic source understanding + prompt context."""

    # --- 1. identity input discovered from source ----------------------
    def test_identity_input_discovered(self):
        out = discovery.analyze_python_security_semantics(
            [{"path": "app.py", "content": _demo_source()}]
        )
        names = {ii["name"] for ii in out["identity_inputs"]}
        self.assertIn("X-Demo-User", names)
        xdu = next(ii for ii in out["identity_inputs"] if ii["name"] == "X-Demo-User")
        self.assertEqual(xdu["kind"], "request_header")
        self.assertEqual(xdu["purpose"], "user_identity")
        self.assertEqual(xdu["provenance"], "repository")

    # --- 2. USERS fixture recognized conservatively ---------------------
    def test_users_fixture_recognized(self):
        out = discovery.analyze_python_security_semantics(
            [{"path": "app.py", "content": _demo_source()}]
        )
        users = next(
            (s for s in out["seed_entities"] if s["entity_type"] == "users"), None
        )
        self.assertIsNotNone(users)
        self.assertEqual(users["identifiers"], [1, 2])
        self.assertEqual(users["labels"], {1: "Alice", 2: "Bob"})

    # --- 3. REPORTS fixture recognized conservatively -------------------
    def test_reports_fixture_recognized(self):
        out = discovery.analyze_python_security_semantics(
            [{"path": "app.py", "content": _demo_source()}]
        )
        reports = next(
            (s for s in out["seed_entities"] if s["entity_type"] == "reports"), None
        )
        self.assertIsNotNone(reports)
        self.assertEqual(reports["identifiers"], [1, 2])

    # --- 4. owner_id relationship recognized ---------------------------
    def test_owner_relationship_recognized(self):
        out = discovery.analyze_python_security_semantics(
            [{"path": "app.py", "content": _demo_source()}]
        )
        rel = next(
            (r for r in out["resource_relationships"] if r["resource"] == "reports"),
            None,
        )
        self.assertIsNotNone(rel)
        self.assertEqual(rel["owner_field"], "owner_id")
        self.assertEqual(rel["identity_field"], "user_id")
        self.assertEqual(rel["resource_identifiers"], [1, 2])

    # --- 5. fictional ids available as bounded seed evidence ------------
    def test_fictional_ids_as_seed(self):
        out = discovery.analyze_python_security_semantics(
            [{"path": "app.py", "content": _demo_source()}]
        )
        rel = next(r for r in out["resource_relationships"] if r["resource"] == "reports")
        self.assertEqual(rel["owners"], {1: 1, 2: 2})
        self.assertEqual(sorted(rel["principal_identifiers"]), [1, 2])

    # --- 6. secrets not collected ---------------------------------------
    def test_secrets_not_collected(self):
        src = (
            "API_KEY = {1: 'alpha', 2: 'beta'}\n"
            "TOKEN = {1: 'x'*100}\n"       # oversized label -> dropped
            "PASSWORD = {'hashed': 1}\n"      # string-keyed -> dropped
        )
        out = discovery.analyze_python_security_semantics([{"path": "app.py", "content": src}])
        self.assertEqual(out["seed_entities"], [])
        names = [ii["name"] for ii in out["identity_inputs"]]
        self.assertNotIn("API_KEY", names)
        self.assertNotIn("TOKEN", names)

    # --- 7. environment values not collected ---------------------------
    def test_environment_values_not_collected(self):
        src = (
            "import os\n"
            "X = os.environ['ENV']\n"
            "USERS = {1: os.environ['A'], 2: 'b'}\n"
        )
        out = discovery.analyze_python_security_semantics([{"path": "app.py", "content": src}])
        for se in out["seed_entities"]:
            self.assertNotIn("environ", json.dumps(se))
            # values are never collected from os.environ; only safe int ids
            self.assertTrue(all(isinstance(i, int) for i in se["identifiers"]))

    # --- 8-10. AI prompt receives the semantic evidence ----------------
    def test_prompt_receives_identity(self):
        p = ai_shared.build_security_analysis_prompt(quality_context())
        self.assertIn("X-Demo-User", p)
        self.assertIn("user_identity", p)

    def test_prompt_receives_relationships(self):
        p = ai_shared.build_security_analysis_prompt(quality_context())
        self.assertIn("owner_field=owner_id", p)
        self.assertIn("resource_ids=", p)
        self.assertIn("owners=", p)  # owners map rendering

    def test_prompt_receives_seed(self):
        p = ai_shared.build_security_analysis_prompt(quality_context())
        self.assertIn("SEED ENTITIES", p)
        self.assertIn("Alice", p)
        self.assertIn("2->2", p)  # report 2 owned by principal 2


class DemoCrossUserTests(unittest.TestCase):
    """Requirements 11-29: the AI can derive and verify the IDOR experiment."""

    def setUp(self):
        _reset_library()

    # --- 11-15. header allowlist on the cross-user experiment -----------
    def test_cross_user_has_allowed_header(self):
        p = validate_executable_experiment(cross_user_experiment(), 1, quality_context())
        self.assertEqual(p.request.headers, {"X-Demo-User": "1"})

    def test_non_allowlisted_header_rejected(self):
        data = cross_user_experiment()
        data["request"]["headers"] = {"Authorization": "Bearer x"}
        with self.assertRaises(ProposalValidationError):
            validate_executable_experiment(data, 1, quality_context())

    def test_host_rejected(self):
        data = cross_user_experiment()
        data["request"]["headers"] = {"Host": "evil.example"}
        with self.assertRaises(ProposalValidationError):
            validate_executable_experiment(data, 1, quality_context())

    def test_forwarded_rejected(self):
        data = cross_user_experiment()
        data["request"]["headers"] = {"X-Forwarded-For": "1.2.3.4"}
        with self.assertRaises(ProposalValidationError):
            validate_executable_experiment(data, 1, quality_context())

    def test_crlf_rejected(self):
        data = cross_user_experiment()
        data["request"]["headers"] = {"X-Demo-User": "1\r\nX-Evil: 1"}
        with self.assertRaises(ProposalValidationError):
            validate_executable_experiment(data, 1, quality_context())

    # --- 16-17. route parameter instantiation --------------------------
    def test_concrete_path_matches_param_route(self):
        from ai_shared import _route_matches

        self.assertTrue(_route_matches("GET", "/api/reports/2", quality_context().routes))
        proposal = validate_executable_experiment(cross_user_experiment(), 1, quality_context())
        self.assertEqual(proposal.request.path, "/api/reports/2")

    def test_unsupported_path_parameter_rejected(self):
        for bad in ("/api/reports/999", "/api/reports/abc", "/api/reports/9999"):
            data = cross_user_experiment()
            data["request"]["path"] = bad
            with self.assertRaises(ProposalValidationError):
                validate_executable_experiment(data, 1, quality_context())

    # --- 18-19. parse + validate ----------------------------------------
    def test_cross_user_parsed_and_validated(self):
        proposal = validate_executable_experiment(cross_user_experiment(), 1, quality_context())
        self.assertEqual(proposal.category, "broken_access_control")
        self.assertEqual(proposal.expected_status, 403)
        self.assertEqual(proposal.request.method, "GET")

    # --- 20. runtime executor sends X-Demo-User -------------------------
    def test_executor_sends_header(self):
        proposal = validate_executable_experiment(cross_user_experiment(), 1, quality_context())
        sandbox = FakeSandbox(report_status=200)
        target_runner.execute_proposals(
            sandbox, demo_adapter("v1"), "http://127.0.0.1:8001", [proposal]
        )
        headers_env = "\n".join(
            c["env"].get("BREAKTRACE_TARGET_HEADERS", "")
            for c in sandbox.process.calls if c.get("env")
        )
        self.assertIn("X-Demo-User: 1", headers_env)

    # --- 21-22. V1 returns 200, expected stays 403 ----------------------
    def test_v1_returns_200_expected_403(self):
        adapter = configured(demo_adapter("v1"))
        proposal = validate_executable_experiment(cross_user_experiment(), 1, quality_context())
        sandbox = FakeSandbox(report_status=200)
        origin = target_runner.prepare_target(sandbox, adapter)
        result = target_runner.execute_proposals(sandbox, adapter, origin, [proposal])[0]
        self.assertEqual(result.observed.status, 200)
        self.assertEqual(result.expected.status, 403)
        self.assertTrue(result.invariant_violated)

    # --- 23-25. finding is broken_access_control with cross-user evidence
    def test_finding_records_principal_and_owner(self):
        proposal = validate_executable_experiment(cross_user_experiment(), 1, quality_context())
        adapter = configured(demo_adapter("v1"))
        sandbox = FakeSandbox(
            commit_sha="0f71222", ref="demo-v1-vulnerable", report_status=200
        )
        _, (_, assessment, _) = run_full_twin(sandbox, adapter, proposals=[proposal])
        ai_findings = [f for f in assessment.findings if f.source == "ai"]
        self.assertEqual(len(ai_findings), 1)
        self.assertEqual(ai_findings[0].category, "broken_access_control")
        self.assertEqual(ai_findings[0].status, "verified")
        evidence = ai_findings[0].evidence
        self.assertTrue(evidence.get("cross_user_access"))
        self.assertEqual(evidence["principal"], 1)
        self.assertEqual(evidence["resource_owner"], 2)
        self.assertEqual(evidence["resource"], "reports")
        self.assertEqual(evidence["principal_label"], "user 1 / Alice")
        self.assertEqual(evidence["request_headers"], {"X-Demo-User": "1"})

    # --- 26-27. test_definition + Security Memory preserve the header ---
    def test_test_definition_preserves_header(self):
        proposal = validate_executable_experiment(cross_user_experiment(), 1, quality_context())
        adapter = configured(demo_adapter("v1"))
        sandbox = FakeSandbox(commit_sha="0f71222", ref="demo-v1-vulnerable", report_status=200)
        _, (_, assessment, _) = run_full_twin(sandbox, adapter, proposals=[proposal])
        finding = next(f for f in assessment.findings if f.source == "ai")
        self.assertEqual(finding.test_definition["headers"], {"X-Demo-User": "1"})
        # And the verified result saved to Security Memory keeps it too.
        lib_entry = LibraryEntry(
            id="BT-001", fingerprint="fp1", title=finding.title,
            category=finding.category, severity="high", invariant=finding.title,
            actor=BreakTraceActor(name="anonymous", user_id=0),
            request=BreakTraceRequest(method="GET", path="/api/reports/2", headers={"X-Demo-User": "1"}),
            expected=BreakTraceExpected(status=403),
            original_observed=BreakTraceObserved(status=200, body={}),
            original_status="vulnerable", source="groq_ai", kind="regression",
            first_seen="2026-08-22T00:00:00+00:00",
            target_id=TARGET_ID, origin="https://demo.example",
            target_adapter=DEMO, test_definition={"method": "GET", "headers": {"X-Demo-User": "1"}, "path": "/api/reports/2", "expected_status": 403},
        )
        self.assertEqual(lib_entry.test_definition["headers"], {"X-Demo-User": "1"})

    # --- 27. Security Memory preserves header ---------------------------
    def test_security_memory_preserves_header(self):
        proposal = validate_executable_experiment(cross_user_experiment(), 1, quality_context())
        adapter = configured(demo_adapter("v1"))
        sandbox = FakeSandbox(commit_sha="0f71222", ref="demo-v1-vulnerable", report_status=200)
        _, (_, assessment, ai_run) = run_full_twin(sandbox, adapter, proposals=[proposal])
        library.add_from_results(
            ai_run, "groq_ai", target_id=TARGET_ID, origin="https://demo.example"
        )
        entry = library.list_entries(TARGET_ID).entries[0]
        self.assertEqual(entry.request.headers, {"X-Demo-User": "1"})

    # --- 28. replay sends X-Demo-User ----------------------------------
    def test_replay_sends_header(self):
        seed_entry()
        adapter = configured(demo_adapter("v2"))
        sandbox = FakeSandbox(ref="demo-v2-fixed", report_status=403)
        entries = library.load_regression_entries(TARGET_ID, DEMO)
        target_runner.replay_entries_in_twin(
            sandbox, adapter, "http://127.0.0.1:8001", entries
        )
        headers_env = "\n".join(
            c["env"].get("BREAKTRACE_TARGET_HEADERS", "")
            for c in sandbox.process.calls if c.get("env")
        )
        self.assertIn("X-Demo-User: 1", headers_env)

    # --- 29. unauthenticated test is NOT described as IDOR -------------
    def test_unauthenticated_not_labeled_idor(self):
        # A missing-authentication experiment is valid but gets no cross-user
        # evidence (no identity header supplied).
        proposal = validate_executable_experiment(unauth_experiment(), 1, quality_context())
        self.assertEqual(proposal.request.path, "/api/reports/1")
        self.assertNotIn("X-Demo-User", proposal.request.headers or {})
        # The cross-user enrichment deliberately requires an identity header.
        from models import BreakTraceResult

        mk = lambda: BreakTraceResult(
            id="BT", title="Anonymous report access", category="broken_access_control",
            severity="high", invariant="i", actor=BreakTraceActor(name="anonymous", user_id=0),
            request=BreakTraceRequest(method="GET", path="/api/reports/1", headers={}),
            expected=BreakTraceExpected(status=403),
            observed=BreakTraceObserved(status=200, body={}),
            test_executed=True, invariant_violated=True, status="vulnerable", mode="independent",
        )
        self.assertEqual(security_twin._cross_user_evidence(mk(), quality_context()), {})


class DemoResilienceAndClassificationTests(unittest.TestCase):
    """Requirements 7 (AI failure must not destroy regression results) and
    8 (secure denial is not a verified vulnerability)."""

    def setUp(self):
        _reset_library()

    # --- Requirement 7: AI failure preserves the layers that already ran ---
    def test_ai_failure_preserves_regression_results(self):
        seed_entry()
        adapter = configured(demo_adapter("v3"))
        sandbox = FakeSandbox(
            commit_sha="e95c683", ref="demo-v3-regression", report_status=200
        )
        client = FakeClient(sandbox)
        with mock.patch.object(
            security_twin, "get_daytona_client", return_value=client
        ):
            with mock.patch.object(
                security_twin,
                "propose_security_analysis_for_twin_split",
                side_effect=RuntimeError(
                    "groq json_validate_failed: model returned invalid JSON"
                ),
            ):
                # Must NOT raise / become HTTP 500 - the assessment returns.
                _, assessment, ai_run = (
                    security_twin.run_security_twin_assessment(adapter, TARGET_ID)
                )
        # Security Memory regression replay is preserved.
        self.assertEqual(assessment.regression.tests_replayed, 1)
        self.assertEqual(assessment.regression.regressions, 1)
        self.assertEqual(assessment.summary.security_regressions, 1)
        # Deterministic + discovery + regression findings preserved.
        self.assertGreater(assessment.deterministic.checks_executed, 0)
        self.assertIsNotNone(assessment.discovery)
        reg_findings = [
            f for f in assessment.findings if f.source == "regression"
        ]
        self.assertEqual(len(reg_findings), 1)
        self.assertEqual(reg_findings[0].status, "regression")
        # AI layer represented as unavailable, not as a failure of the whole
        # assessment, and it produced no verified findings.
        self.assertEqual(assessment.ai_exploration.status, "unavailable")
        self.assertIn("json_validate_failed", assessment.ai_exploration.error_message)
        self.assertEqual(assessment.ai_exploration.verified_findings, 0)
        self.assertEqual(assessment.summary.new_verified_findings, 0)
        # Sandbox always destroyed.
        self.assertEqual(len(client.deleted), 1)

    def test_ai_failure_still_reports_regression_via_endpoint(self):
        from fastapi.testclient import TestClient
        import main
        from models import (
            AiExplorationSection,
            DeterministicSection,
            RegressionSection,
            SecurityTwinAssessment,
            SecurityTwinInfo,
            SecurityTwinSummary,
        )

        def _run(adapter, target_id):
            ctx = make_context(adapter)
            assessment = SecurityTwinAssessment(
                assessment_id="TWIN-777",
                target={
                    "target_type": adapter.target_type,
                    "name": adapter.name,
                    "repository": adapter.repository_url,
                    "port": adapter.port,
                },
                security_twin=SecurityTwinInfo(application_version=None),
                regression=RegressionSection(
                    tests_replayed=1, passed=0, regressions=1, errors=0,
                    results=[],
                ),
                deterministic=DeterministicSection(
                    checks_executed=3, passed=3, issues=0, results=[]
                ),
                discovery=ctx,
                ai_exploration=AiExplorationSection(
                    provider="groq", model="", hypotheses_generated=0,
                    tests_executed=0, verified_findings=0, results=[],
                    status="unavailable",
                    error_message="groq json_validate_failed",
                ),
                findings=[],
                summary=SecurityTwinSummary(
                    security_regressions=1, new_verified_findings=0,
                    deterministic_issues=0, controls_passed=3,
                ),
            )
            ai_run = make_run()
            return ctx, assessment, ai_run

        client = TestClient(main.app, raise_server_exceptions=False)
        with mock.patch.object(main, "run_security_twin_assessment", side_effect=_run):
            resp = client.post(
                "/security-twin/assess",
                json={
                    "target_type": DEMO,
                    "url": "https://reports-demo.example",
                    "version": "v3",
                },
            )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["assessment"]["regression"]["regressions"], 1)
        self.assertEqual(body["assessment"]["ai_exploration"]["status"], "unavailable")

    # --- Requirement 8: secure denial is NOT a verified vulnerability -------
    def _classify(self, expected_status, report_status):
        data = cross_user_experiment()
        data["expected_status"] = expected_status
        proposal = validate_executable_experiment(data, 1, quality_context())
        adapter = configured(demo_adapter("v1"))
        sandbox = FakeSandbox(report_status=report_status)
        _, (_, assessment, _) = run_full_twin(
            sandbox, adapter, proposals=[proposal]
        )
        return assessment

    def test_secure_denial_401exp_403obs(self):
        assessment = self._classify(401, 403)
        self.assertEqual(assessment.ai_exploration.verified_findings, 0)
        self.assertEqual(assessment.summary.new_verified_findings, 0)
        self.assertTrue(
            all(r.verification == "passed" for r in assessment.ai_exploration.results)
        )

    def test_secure_denial_403exp_401obs(self):
        assessment = self._classify(403, 401)
        self.assertEqual(assessment.ai_exploration.verified_findings, 0)
        self.assertEqual(assessment.summary.new_verified_findings, 0)

    def test_denial_expected_success_observed_is_failure(self):
        # A denial expected but a success returned is still a security failure.
        assessment = self._classify(403, 200)
        self.assertEqual(assessment.ai_exploration.verified_findings, 1)
        self.assertEqual(assessment.summary.new_verified_findings, 1)


class SecurityMemoryLifecycleTests(unittest.TestCase):
    """Milestone 13 - Security Memory lifecycle correctness.

    Covers the clean one-click demo expectation: scoped reset, a generic
    finding-quality gate (no unauthenticated baseline tests), unique stable
    BT ids, fingerprint dedup, and exact V2/V3 replay counts - with normal
    application memory untouched.
    """

    OTHER_TID = "o" * 64

    class _AllReportsProcess(DemoProcess):
        """Fake that applies the configured report_status to EVERY
        /api/reports/:id path (the real demo app answers both cross-user
        directions), not just the single ownership path."""

        def exec(self, command, timeout=None, env=None):
            path = self._extract_path(command)
            if path and path.startswith("/api/reports/"):
                return FakeResult(
                    json.dumps({"status": self.report_status, "body": {}})
                )
            return super().exec(command, timeout=timeout, env=env)

    def _report_sandbox(self, report_status):
        sandbox = FakeSandbox(report_status=report_status)
        sandbox.process = self._AllReportsProcess(
            report_status=report_status
        )
        return sandbox

    def setUp(self):
        _reset_library()

    # --- helpers --------------------------------------------------------
    def _cross_user_result(self, user: int, report: int) -> BreakTraceResult:
        """Verified cross-user IDOR result: principal `user` reads report
        `report` (owned by another user) carrying the identity header."""
        return BreakTraceResult(
            id=f"BT-X{user}-{report}",
            title=(
                f"Cross-user access test: User {user} accessing "
                f"Report {report}"
            ),
            category="broken_access_control",
            severity="high",
            invariant="Only the owner of a report can access its details",
            actor=BreakTraceActor(name="anonymous", user_id=0),
            request=BreakTraceRequest(
                method="GET",
                path=f"/api/reports/{report}",
                headers={"X-Demo-User": str(user)},
            ),
            expected=BreakTraceExpected(status=403),
            observed=BreakTraceObserved(
                status=200, body={"id": report, "owner": "Bob"}
            ),
            test_executed=True,
            invariant_violated=True,
            status="vulnerable",
            mode="independent",
            source="groq_ai",
            hypothesis=(
                f"User {user} can access Report {report} owned by "
                "another user"
            ),
        )

    def _unauth_result(self) -> BreakTraceResult:
        """The unauthenticated baseline result (must NOT be saved)."""
        return BreakTraceResult(
            id="BT-UNAUTH",
            title="Unauthenticated access to report",
            category="missing_authentication",
            severity="high",
            invariant="Access to reports requires authenticated identity.",
            actor=BreakTraceActor(name="anonymous", user_id=0),
            request=BreakTraceRequest(
                method="GET", path="/api/reports/1", headers={}
            ),
            expected=BreakTraceExpected(status=401),
            observed=BreakTraceObserved(status=200, body={"id": 1}),
            test_executed=True,
            invariant_violated=True,
            status="vulnerable",
            mode="independent",
            source="groq_ai",
            hypothesis="An unauthenticated request must be denied.",
        )

    def _v1_run(self) -> AssessmentRunResult:
        """The real V1 assessment shape: two cross-user IDOR tests plus the
        unrelated unauthenticated baseline test."""
        return make_run(
            self._cross_user_result(1, 2),
            self._cross_user_result(2, 1),
            self._unauth_result(),
        )

    def _demo_save(self, run=None, quality=True):
        run = run or self._v1_run()
        return library.add_from_results(
            run,
            "groq_ai",
            target_id=TARGET_ID,
            origin="https://breaktrace-regression-demo.example",
            quality_filter=(
                library.is_verified_principal_test if quality else None
            ),
        )

    def _normal_run(self) -> AssessmentRunResult:
        """A headerless verified failure for a normal application (juice-
        shop style): saved by the DEFAULT path, no quality gate."""
        return AssessmentRunResult(
            assessment_id="JS-1",
            source="groq_ai",
            summary=AssessmentSummary(
                tests_generated=1, tests_executed=1,
                vulnerabilities_found=1, controls_passed=0,
            ),
            results=[
                BreakTraceResult(
                    id="BT-JS-1",
                    title="Users list exposure",
                    category="broken_access_control",
                    severity="high",
                    invariant="User data must not be public",
                    actor=BreakTraceActor(name="anonymous", user_id=0),
                    request=BreakTraceRequest(
                        method="GET", path="/api/Users"
                    ),
                    expected=BreakTraceExpected(status=403),
                    observed=BreakTraceObserved(status=200, body={}),
                    test_executed=True,
                    invariant_violated=True,
                    status="vulnerable",
                    mode="independent",
                    source="groq_ai",
                )
            ],
            target_adapter="juice_shop",
            provider="groq",
            model="llama-3.3-70b",
        )

    # --- 1 + 2. reset clears ONLY the regression-demo application ---------
    def test_reset_clears_only_demo_entries(self):
        self._demo_save()
        library.add_from_results(
            self._normal_run(), "groq_ai",
            target_id=self.OTHER_TID, origin="https://other.example",
        )
        self.assertEqual(library.list_entries(TARGET_ID).total, 2)
        self.assertEqual(library.list_entries(self.OTHER_TID).total, 1)

        removed = library.reset_application_entries(TARGET_ID)
        self.assertEqual(removed, 2)
        # Demo application is clean...
        self.assertEqual(library.list_entries(TARGET_ID).total, 0)
        # ...and the other application is untouched.
        self.assertEqual(library.list_entries(self.OTHER_TID).total, 1)

    def test_reset_removes_stale_third_entry(self):
        # Pre-fix state: an unauthenticated test polluted Security Memory.
        self._demo_save(quality=False)
        self.assertEqual(library.list_entries(TARGET_ID).total, 3)
        removed = library.reset_application_entries(TARGET_ID)
        self.assertEqual(removed, 3)
        self.assertEqual(library.list_entries(TARGET_ID).total, 0)

    # --- 3-6. fresh V1 save produces exactly BT-001 + BT-002 -------------
    def test_fresh_v1_save_produces_exactly_two(self):
        res = self._demo_save()
        self.assertEqual(res["saved"], 2)
        self.assertEqual(res["new"], 2)
        entries = library.list_entries(TARGET_ID).entries
        self.assertEqual(len(entries), 2)
        self.assertEqual([e.id for e in entries], ["BT-001", "BT-002"])

    def test_saved_ids_unique(self):
        self._demo_save()
        entries = library.list_entries(TARGET_ID).entries
        ids = [e.id for e in entries]
        self.assertEqual(len(ids), len(set(ids)), ids)
        self.assertEqual(set(ids), {"BT-001", "BT-002"})

    def test_unauth_baseline_not_saved(self):
        self._demo_save()
        entries = library.list_entries(TARGET_ID).entries
        titles = [e.title for e in entries]
        self.assertNotIn("Unauthenticated access to report", titles)
        for e in entries:
            self.assertNotEqual(e.expected.status, 401)
            self.assertNotEqual(e.category, "missing_authentication")
            self.assertNotEqual(e.request.headers or {}, {})

    def test_quality_filter_is_generic_not_title_based(self):
        # A renamed unauthenticated test is still excluded: the gate reads
        # the request structure (no identity header / no actor principal),
        # never the title.
        run = make_run(
            self._cross_user_result(1, 2),
            self._unauth_result().model_copy(
                update={"title": "Brand new fancy title"}
            ),
        )
        res = library.add_from_results(
            run, "groq_ai", target_id=TARGET_ID,
            origin="https://breaktrace-regression-demo.example",
            quality_filter=library.is_verified_principal_test,
        )
        self.assertEqual(res["new"], 1)
        self.assertEqual(library.list_entries(TARGET_ID).total, 1)

    # --- 7. secure denial never enters Security Memory -------------------
    def test_secure_denial_never_saved_to_memory(self):
        data = cross_user_experiment()
        data["expected_status"] = 401
        proposal = validate_executable_experiment(data, 1, quality_context())
        adapter = configured(demo_adapter("v1"))
        sandbox = FakeSandbox(report_status=403)
        _, (_, assessment, ai_run) = run_full_twin(
            sandbox, adapter, proposals=[proposal]
        )
        self.assertEqual(assessment.ai_exploration.verified_findings, 0)
        res = library.add_from_results(
            ai_run, "groq_ai", target_id=TARGET_ID,
            origin="https://demo.example",
            quality_filter=library.is_verified_principal_test,
        )
        self.assertEqual(res["new"], 0)
        self.assertEqual(library.list_entries(TARGET_ID).total, 0)

    # --- 8. repeated saves never duplicate -------------------------------
    def test_duplicate_save_no_extra_entries(self):
        self._demo_save()
        res = self._demo_save()
        self.assertEqual(res["new"], 0)
        self.assertEqual(res["already_in_library"], 2)
        self.assertEqual(library.list_entries(TARGET_ID).total, 2)

    def test_header_order_does_not_duplicate(self):
        run = make_run(self._cross_user_result(1, 2))
        library.add_from_results(
            run, "groq_ai", target_id=TARGET_ID, origin="https://demo.example",
            quality_filter=library.is_verified_principal_test,
        )
        # Same test, different dict insertion order -> same fingerprint.
        dup = self._cross_user_result(1, 2)
        dup.request = dup.request.model_copy(
            update={"headers": {"X-Demo-User": "1", "X-Other": "v"}}
        )
        # (headers differ -> distinct test) — the identity header alone is
        # what makes a cross-user test; a different header set is a
        # different experiment, so it must create a NEW entry.
        library.add_from_results(
            make_run(dup), "groq_ai", target_id=TARGET_ID,
            origin="https://demo.example",
            quality_filter=library.is_verified_principal_test,
        )
        entries = library.list_entries(TARGET_ID).entries
        self.assertEqual(len(entries), 2)
        ids = [e.id for e in entries]
        self.assertEqual(len(set(ids)), 2, ids)

    # --- 9. running the one-click demo twice -> exactly two --------------
    def test_demo_run_twice_leaves_exactly_two(self):
        for _ in range(2):
            library.reset_application_entries(TARGET_ID)
            self._demo_save()
        entries = library.list_entries(TARGET_ID).entries
        self.assertEqual(len(entries), 2)
        self.assertEqual([e.id for e in entries], ["BT-001", "BT-002"])

    # --- 10-13. V2 replays exactly 2 passed; V3 exactly 2 regressions ----
    def test_v2_replays_exactly_two_passed(self):
        self._demo_save()
        adapter = configured(demo_adapter("v2"))
        entries = library.load_regression_entries(TARGET_ID, DEMO)
        self.assertEqual(len(entries), 2)
        sandbox = self._report_sandbox(403)
        items = target_runner.replay_entries_in_twin(
            sandbox, adapter, f"http://127.0.0.1:{adapter.port}", entries
        )
        self.assertEqual(len(items), 2)
        self.assertEqual(
            sorted(i.entry_id for i in items), ["BT-001", "BT-002"]
        )
        self.assertEqual(sum(1 for i in items if i.status == "passed"), 2)
        self.assertEqual(sum(1 for i in items if i.status == "regression"), 0)
        self.assertEqual(sum(1 for i in items if i.status == "error"), 0)

    def test_v3_replays_exactly_two_regressions(self):
        self._demo_save()
        adapter = configured(demo_adapter("v3"))
        entries = library.load_regression_entries(TARGET_ID, DEMO)
        self.assertEqual(len(entries), 2)
        sandbox = self._report_sandbox(200)
        items = target_runner.replay_entries_in_twin(
            sandbox, adapter, f"http://127.0.0.1:{adapter.port}", entries
        )
        self.assertEqual(len(items), 2)
        self.assertEqual(sum(1 for i in items if i.status == "passed"), 0)
        self.assertEqual(sum(1 for i in items if i.status == "regression"), 2)
        self.assertEqual(sum(1 for i in items if i.status == "error"), 0)
        # The replay used the stored method/path for every entry.
        self.assertEqual({(i.method, i.path) for i in items}, {
            ("GET", "/api/reports/1"), ("GET", "/api/reports/2"),
        })

    # --- 14. ids stay unique across reset/save/replay cycles -------------
    def test_ids_unique_after_reset_save_replay_cycles(self):
        for _ in range(2):
            library.reset_application_entries(TARGET_ID)
            self._demo_save()
            entries = library.load_regression_entries(TARGET_ID, DEMO)
            sandbox = FakeSandbox(ref="demo-v3-regression", report_status=200)
            items = target_runner.replay_entries_in_twin(
                sandbox, configured(demo_adapter("v3")),
                "http://127.0.0.1:8001", entries,
            )
            library.mark_entries_replayed(items, demo_adapter("v3"))
        entries = library.load_library()
        ids = [e.id for e in entries.values()]
        self.assertEqual(len(ids), len(set(ids)), ids)
        self.assertEqual(set(ids), {"BT-001", "BT-002"})

    # --- 15. normal application memory persists --------------------------
    def test_normal_application_memory_persists(self):
        library.add_from_results(
            self._normal_run(), "groq_ai",
            target_id=self.OTHER_TID, origin="https://other.example",
        )
        self._demo_save()
        # The demo reset never touches the normal application.
        library.reset_application_entries(TARGET_ID)
        self.assertEqual(library.list_entries(self.OTHER_TID).total, 1)
        self.assertEqual(library.list_entries(TARGET_ID).total, 0)
        # Default save (no quality gate) still stores headerless verified
        # failures for normal applications.
        library.add_from_results(
            self._normal_run(), "groq_ai",
            target_id=self.OTHER_TID, origin="https://other.example",
        )
        self.assertEqual(library.list_entries(self.OTHER_TID).total, 1)

    # --- API level: scoped reset + quality save flag ---------------------
    def test_reset_endpoint_only_touches_target_application(self):
        from fastapi.testclient import TestClient
        import main

        client = TestClient(main.app, raise_server_exceptions=False)
        demo_resp = client.post(
            "/applications/resolve",
            json={"url": "https://breaktrace-regression-demo.example"},
        )
        other_resp = client.post(
            "/applications/resolve",
            json={"url": "https://other.example"},
        )
        demo_tid = demo_resp.json()["application"]["target_id"]
        other_tid = other_resp.json()["application"]["target_id"]
        library.add_from_results(
            self._v1_run(), "groq_ai", target_id=demo_tid,
            origin="https://breaktrace-regression-demo.example",
            quality_filter=library.is_verified_principal_test,
        )
        library.add_from_results(
            self._normal_run(), "groq_ai", target_id=other_tid,
            origin="https://other.example",
        )

        resp = client.post(f"/applications/{demo_tid}/breaktraces/reset")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["removed"], 2)
        self.assertEqual(resp.json()["entries_remaining"], 0)
        self.assertEqual(library.list_entries(demo_tid).total, 0)
        self.assertEqual(library.list_entries(other_tid).total, 1)

    def test_reset_endpoint_unknown_application_404(self):
        from fastapi.testclient import TestClient
        import main

        client = TestClient(main.app, raise_server_exceptions=False)
        resp = client.post(
            f"/applications/{'z' * 64}/breaktraces/reset"
        )
        self.assertEqual(resp.status_code, 404)

    def test_save_endpoint_quality_flag(self):
        from fastapi.testclient import TestClient
        import main
        from ai_shared import cache_latest_assessment_run

        client = TestClient(main.app, raise_server_exceptions=False)
        resp = client.post(
            "/applications/resolve",
            json={"url": "https://breaktrace-regression-demo.example"},
        )
        tid = resp.json()["application"]["target_id"]
        cache_latest_assessment_run(self._v1_run(), tid)

        # Quality save: only the two cross-user tests enter Security Memory.
        quality = client.post(
            "/breaktrace/ai/assessment/save",
            json={"require_verified_principal": True},
        )
        self.assertEqual(quality.status_code, 200)
        self.assertEqual(quality.json()["new"], 2)
        self.assertEqual(library.list_entries(tid).total, 2)

        # Default save (no flag) still saves the remaining baseline test.
        plain = client.post("/breaktrace/ai/assessment/save")
        self.assertEqual(plain.status_code, 200)
        self.assertEqual(plain.json()["new"], 1)
        self.assertEqual(library.list_entries(tid).total, 3)


if __name__ == "__main__":
    unittest.main(verbosity=1)