"""Automated tests for Milestone 9 - Security Twin architecture.

Covers (per the M9 spec):
  1.  Security Twin creates through existing Daytona infrastructure
  2.  Cleanup after successful assessment
  3.  Cleanup after failed assessment
  4.  Application version captured when available
  5.  Missing version remains null (never invented)
  6.  First assessment with no library produces zero regression tests
  7.  Existing BreakTraces replay BEFORE AI exploration
  8.  Passed replay classified correctly
  9.  Failed historical condition classified as regression
  10. Replay error does not count as regression
  11. Replay does not call AI
  12. Deterministic checks do not call AI
  13. Header check uses real response headers
  14. Missing CSP classification works
  15. X-Content-Type-Options classification works
  16. Cookie values are redacted
  17. Cookie attribute checks work
  18. CORS check is bounded
  19. Exposure checks only use allowlisted paths
  20. Exposure checks cannot target external origins
  21. AI exploration still uses provider dispatcher
  22. Groq still works
  23. Nosana still works
  24. Invalid AI proposals remain rejected
  25. AI proposal is not automatically a verified finding
  26. Runtime-verified AI failure becomes verified
  27. Unified summary derives from result arrays
  28. No dashboard metrics are hardcoded
  29. Existing M8 target assessment still works
  30. Existing demo target still works
  31. Existing application recognition still works
  32. Existing BreakTrace Library still loads
  33. Existing legacy entries remain compatible
  34. Existing chain analysis remains working
  35. Existing scoped dashboard remains working

No live Daytona sandbox or AI credentials are required - sandboxes are faked
and AI propose is patched. Run from the backend/ directory:

    ./venv/Scripts/python.exe test_security_twin.py
"""

import json
import os
import re
import tempfile
import unittest
from unittest import mock

import ai_provider
import ai_shared
import applications
import checks
import groq_client
import library
import nosana_client
import security_twin
import target_runner
from ai_shared import ProposalValidationError, validate_discovery_assessment_proposals
from checks.cookies import CookieSecurityCheck
from checks.cors import CorsSecurityCheck, TEST_ORIGIN
from checks.exposure import EXPOSURE_ALLOWLIST, ExposureSecurityCheck
from checks.headers import HeaderSecurityCheck
from models import (
    ApplicationContext,
    AssessmentRunResult,
    DiscoveredRoute,
    LibraryEntry,
    SecurityAssessmentProposal,
)
from security_twin import SecurityTwin, run_security_twin_assessment
from targets import get_target_adapter

# Point registry + library at a throwaway temp dir so no real data is touched.
_TMP = tempfile.mkdtemp(prefix="breaktrace_m9_")
applications.DATA_DIR = _TMP
applications.APPLICATIONS_PATH = os.path.join(_TMP, "applications.json")
library.DATA_DIR = _TMP
library.LIBRARY_PATH = os.path.join(_TMP, "breaktraces.json")

TARGET_ID = "t" * 64


def _reset_library():
    if os.path.exists(library.LIBRARY_PATH):
        os.remove(library.LIBRARY_PATH)


def make_context() -> ApplicationContext:
    return ApplicationContext(
        target_id=TARGET_ID,
        name="OWASP Juice Shop",
        framework="Express",
        runtime_origin="http://127.0.0.1:3000",
        routes=[
            DiscoveredRoute(method="GET", path="/api/Users", source="both"),
            DiscoveredRoute(method="GET", path="/api/Products/:id", source="runtime"),
            DiscoveredRoute(method="GET", path="/rest/products/search", source="both"),
        ],
        auth_signals=["jsonwebtoken", "helmet"],
        models=["User", "Product"],
        security_relevant_components=["lib/insecurity.ts"],
        discovery_summary="fixture",
        query_parameters=["q"],
    )


def _assessment() -> SecurityAssessmentProposal:
    return SecurityAssessmentProposal.model_validate(
        {
            "proposals": [
                {
                    "title": "Users list exposure",
                    "category": "broken_access_control",
                    "hypothesis": "The users endpoint may expose accounts without auth",
                    "invariant": "User data must not be accessible without authorization",
                    "actor": {"name": "anonymous", "user_id": 0},
                    "request": {"method": "GET", "path": "/api/Users"},
                    "expected_status": 403,
                    "reason": "checks access control on the users list",
                },
                {
                    "title": "Parametric product access",
                    "category": "broken_access_control",
                    "hypothesis": "Product details may be accessible",
                    "invariant": "Products are public catalog data",
                    "actor": {"name": "anonymous", "user_id": 0},
                    "request": {"method": "GET", "path": "/api/Products/1"},
                    "expected_status": 200,
                    "reason": "checks a parameterized product endpoint",
                },
                {
                    "title": "Search input validation",
                    "category": "input_validation",
                    "hypothesis": "Search may mishandle crafted queries",
                    "invariant": "Search reflects only bounded input",
                    "actor": {"name": "anonymous", "user_id": 0},
                    "request": {"method": "GET", "path": "/rest/products/search?q=test"},
                    "expected_status": 200,
                    "reason": "checks input handling on search",
                },
            ]
        }
    )


def _seed_entry(
    entry_id: str,
    path: str,
    expected_status: int,
    target_id: str = TARGET_ID,
    target_adapter: str = "juice_shop",
) -> LibraryEntry:
    from models import (
        BreakTraceActor,
        BreakTraceExpected,
        BreakTraceObserved,
        BreakTraceRequest,
    )

    entry = LibraryEntry(
        id=entry_id,
        fingerprint=f"fp-{entry_id}",
        title=f"Stored test {entry_id}",
        category="broken_access_control",
        severity="high",
        invariant="The stored security condition must hold.",
        actor=BreakTraceActor(name="anonymous", user_id=0),
        request=BreakTraceRequest(method="GET", path=path),
        expected=BreakTraceExpected(status=expected_status),
        original_observed=BreakTraceObserved(status=200, body={}),
        original_status="vulnerable",
        source="ai",
        kind="regression",
        first_seen="2026-08-22T00:00:00+00:00",
        target_id=target_id,
        origin="https://js.example",
        target_adapter=target_adapter,
    )
    entries = library.load_library()
    entries[entry.fingerprint] = entry
    library.save_library(entries)
    return entry


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeResult:
    def __init__(self, output, exit_code=0):
        self.result = output
        self.exit_code = exit_code


class FakeProcess:
    """Command-aware fake. Responds like the in-sandbox client for the
    commands the M9 lifecycle actually issues."""

    def __init__(
        self,
        commit_sha=None,
        ref="v20.2.0",
        headers=None,
        header_responses=None,
        responses=None,
        fail_paths=None,
    ):
        self.commit_sha = commit_sha
        self.ref = ref
        self.headers = headers or {}
        self.header_responses = header_responses or {}
        self.responses = responses or {}
        self.fail_paths = set(fail_paths or [])
        self.calls = []

    @staticmethod
    def _extract_path(command):
        """Extract the request path from a client command.

        shlex.quote() leaves safe paths like /api/Users unquoted, so the
        path is everything after the method token, stripped of any quotes.
        """
        match = re.match(
            r"python \S+ --headers (?:GET|DELETE|OPTIONS) (.+)$", command
        )
        if match is None:
            match = re.match(r"python \S+ (?:GET|DELETE) (.+)$", command)
        if match is None:
            return None
        return match.group(1).strip().strip("'\"")

    def exec(self, command, timeout=None, env=None):
        self.calls.append({"command": command, "env": env})
        if "--wait" in command:
            return FakeResult("ready")
        if "--probe" in command:
            return FakeResult('[{"path": "/", "status": 200}]')
        if "--headers" in command:
            path = self._extract_path(command) or "/"
            resp = self.header_responses.get(
                path, {"status": 200, "headers": self.headers, "body": {}}
            )
            return FakeResult(json.dumps(resp))
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
        if "node --version" in command:
            return FakeResult("v22.19.0\n10.9.0\n2.45.0")
        if "cat " in command or "ls " in command:
            return FakeResult("")
        if (
            "mkdir" in command
            or "clone" in command
            or "npm" in command
            or "nohup" in command
            or "tail" in command
        ):
            return FakeResult("ok")
        # Single-request mode (AI tests + regression replay).
        path = self._extract_path(command)
        if path is None:
            return FakeResult(json.dumps({"status": 200, "body": {}}))
        if path in self.fail_paths:
            return FakeResult("", exit_code=1)
        resp = self.responses.get(path, {"status": 200, "body": {}})
        return FakeResult(json.dumps(resp))


class FakeFs:
    def __init__(self):
        self.uploads = []

    def upload_file(self, data, path):
        self.uploads.append(path)


class FakeSandbox:
    def __init__(self, **kwargs):
        self.process = FakeProcess(**kwargs)
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


def _make_runtime(sandbox: FakeSandbox):
    """Build a TwinRuntime bound to a fake sandbox for isolated check tests."""
    runtime = security_twin._twin_runtime(
        SecurityTwin(get_target_adapter("juice_shop"), TARGET_ID)
    )
    runtime.sandbox = sandbox
    runtime.client_path = "/tmp/breaktrace/target_client.py"
    runtime.origin = "http://127.0.0.1:3000"
    return runtime


def run_full_twin(sandbox: FakeSandbox, assessment=None, rejected=None):
    """Run the full orchestrator against a fake sandbox with a patched AI.

    `assessment` is a SecurityAssessmentProposal (or a bare list of valid
    proposals) whose proposals are treated as VALID. `rejected` optionally
    adds rejected-proposal entries (dicts with index/hypothesis/reason) to
    exercise the split-validation path.
    """
    client = FakeClient(sandbox)
    if isinstance(assessment, list):
        valid = assessment
    else:
        proposal = assessment if assessment is not None else _assessment()
        valid = proposal.proposals
    with mock.patch.object(
        security_twin, "get_daytona_client", return_value=client
    ):
        with mock.patch.object(
            security_twin,
            "propose_security_analysis_for_twin_split",
            return_value=(valid, [], rejected or []),
        ):
            return (
                client,
                security_twin.run_security_twin_assessment(
                    get_target_adapter("juice_shop"), TARGET_ID
                ),
            )


class M9SecurityTwinTests(unittest.TestCase):
    def setUp(self):
        _reset_library()

    # --- 1. Twin creates through existing Daytona infrastructure ---------
    def test_twin_creates_through_daytona(self):
        client = FakeClient()
        twin = SecurityTwin(get_target_adapter("juice_shop"), TARGET_ID)
        with mock.patch.object(
            security_twin, "get_daytona_client", return_value=client
        ):
            twin.create()
        self.assertEqual(len(client.created), 1)
        self.assertEqual(twin.status, "created")
        self.assertEqual(twin.sandbox.ttl, 10)  # TTL safety net
        self.assertEqual(
            twin.repository,
            get_target_adapter("juice_shop").repository_url,
        )

    # --- 2. Cleanup after successful assessment --------------------------
    def test_cleanup_after_successful_assessment(self):
        sandbox = FakeSandbox(
            headers={
                "content-security-policy": "default-src 'self'",
                "x-content-type-options": "nosniff",
                "referrer-policy": "no-referrer",
                "x-frame-options": "DENY",
            },
            header_responses={
                "/.env": {"status": 404, "headers": {}, "body": {}},
                "/.git/config": {"status": 404, "headers": {}, "body": {}},
            },
        )
        client, (context, assessment, ai_run) = run_full_twin(sandbox)
        self.assertEqual(len(client.created), 1)
        self.assertEqual(len(client.deleted), 1)
        self.assertEqual(client.created, client.deleted)
        self.assertEqual(assessment.assessment_id[:5], "TWIN-")

    # --- 3. Cleanup after failed assessment ------------------------------
    def test_cleanup_after_failed_assessment(self):
        client = FakeClient()
        with mock.patch.object(
            security_twin, "get_daytona_client", return_value=client
        ):
            with mock.patch.object(
                security_twin,
                "prepare_target",
                side_effect=RuntimeError("setup boom"),
            ):
                with self.assertRaises(RuntimeError):
                    security_twin.run_security_twin_assessment(
                        get_target_adapter("juice_shop"), TARGET_ID
                    )
        self.assertEqual(len(client.created), 1)
        self.assertEqual(len(client.deleted), 1)

    # --- 4. Version captured when available ------------------------------
    def test_application_version_captured(self):
        sandbox = FakeSandbox(commit_sha="abc123def456", ref="v20.2.0")
        _, (_, assessment, _) = run_full_twin(sandbox)
        version = assessment.security_twin.application_version
        self.assertIsNotNone(version)
        self.assertEqual(version.commit_sha, "abc123def456")
        self.assertEqual(version.ref, "v20.2.0")
        self.assertIn("juice-shop", version.repository)
        # Version travels with the findings too.
        self.assertTrue(
            all(
                f.application_version == version
                for f in assessment.findings
                if f.application_version is not None
            )
        )

    # --- 5. Missing version remains null --------------------------------
    def test_missing_version_remains_null(self):
        sandbox = FakeSandbox(commit_sha=None, ref=None)
        _, (_, assessment, _) = run_full_twin(sandbox)
        self.assertIsNone(assessment.security_twin.application_version)

    # --- 6. First assessment with no library -----------------------------
    def test_first_assessment_zero_regression(self):
        sandbox = FakeSandbox()
        _, (_, assessment, _) = run_full_twin(sandbox)
        self.assertEqual(assessment.regression.tests_replayed, 0)
        self.assertEqual(assessment.regression.regressions, 0)
        self.assertEqual(assessment.regression.results, [])
        self.assertEqual(assessment.summary.security_regressions, 0)

    # --- 7. BreakTraces replay BEFORE AI exploration ---------------------
    def test_replay_before_ai_exploration(self):
        _seed_entry("BT-JS-001", "/api/Users", 403)
        client = FakeClient()
        parent = mock.Mock()
        replay_mock = mock.Mock(return_value=[])
        propose_mock = mock.Mock(return_value=(_assessment().proposals, [], []))
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
                    security_twin.run_security_twin_assessment(
                        get_target_adapter("juice_shop"), TARGET_ID
                    )
        names = [call[0] for call in parent.mock_calls]
        self.assertIn("replay", names)
        self.assertIn("propose", names)
        self.assertLess(names.index("replay"), names.index("propose"))

    # --- 8. Passed replay classification ---------------------------------
    def test_passed_replay_classified(self):
        _seed_entry("BT-JS-PASS", "/api/Users", 403)
        sandbox = FakeSandbox(responses={"/api/Users": {"status": 403, "body": {}}})
        _, (_, assessment, _) = run_full_twin(sandbox)
        self.assertEqual(assessment.regression.tests_replayed, 1)
        self.assertEqual(assessment.regression.passed, 1)
        self.assertEqual(assessment.regression.regressions, 0)
        self.assertEqual(assessment.regression.results[0].status, "passed")

    # --- 9. Failed historical condition = regression ---------------------
    def test_regression_classified(self):
        _seed_entry("BT-JS-REG", "/api/Users", 403)
        sandbox = FakeSandbox(responses={"/api/Users": {"status": 200, "body": {}}})
        _, (_, assessment, _) = run_full_twin(sandbox)
        self.assertEqual(assessment.regression.tests_replayed, 1)
        self.assertEqual(assessment.regression.regressions, 1)
        self.assertEqual(assessment.regression.results[0].status, "regression")
        self.assertEqual(assessment.summary.security_regressions, 1)
        # Regression findings carry status "regression".
        reg_findings = [
            f for f in assessment.findings if f.source == "regression"
        ]
        self.assertEqual(reg_findings[0].status, "regression")

    # --- 10. Replay error does not count as regression -------------------
    def test_replay_error_not_regression(self):
        # Use a path the AI layer never touches so only the replay fails.
        _seed_entry("BT-JS-ERR", "/api/Admin", 403)
        sandbox = FakeSandbox(fail_paths={"/api/Admin"})
        _, (_, assessment, _) = run_full_twin(sandbox)
        self.assertEqual(assessment.regression.tests_replayed, 1)
        self.assertEqual(assessment.regression.errors, 1)
        self.assertEqual(assessment.regression.regressions, 0)
        self.assertEqual(assessment.regression.results[0].status, "error")
        self.assertEqual(assessment.summary.security_regressions, 0)

    # --- 11. Replay does not call AI -------------------------------------
    def test_replay_does_not_call_ai(self):
        _seed_entry("BT-JS-NOAI", "/api/Users", 403)
        sandbox = FakeSandbox(responses={"/api/Users": {"status": 403, "body": {}}})
        propose = mock.Mock(return_value=(_assessment().proposals, [], []))
        client = FakeClient(sandbox)
        with mock.patch.object(
            security_twin, "get_daytona_client", return_value=client
        ):
            with mock.patch.object(
                security_twin,
                "propose_security_analysis_for_twin_split",
                propose,
            ):
                _, assessment, _ = security_twin.run_security_twin_assessment(
                    get_target_adapter("juice_shop"), TARGET_ID
                )
        # Replay used stored experiments; AI only ever called once for Layer 3.
        self.assertEqual(propose.call_count, 1)
        self.assertEqual(assessment.regression.tests_replayed, 1)
        # The stored request was executed inside the sandbox without AI.
        commands = " ".join(c["command"] for c in sandbox.process.calls)
        self.assertIn("/api/Users", commands)

    # --- 12. Deterministic checks do not call AI -------------------------
    def test_deterministic_checks_do_not_call_ai(self):
        sandbox = FakeSandbox()
        runtime = security_twin._twin_runtime(
            SecurityTwin(get_target_adapter("juice_shop"), TARGET_ID)
        )
        runtime.sandbox = sandbox
        runtime.client_path = "/tmp/breaktrace/target_client.py"
        with mock.patch.object(
            security_twin, "propose_security_analysis_for_twin_split"
        ) as propose:
            findings = security_twin.run_deterministic_checks(
                runtime, TARGET_ID, "TWIN-001", None
            )
        propose.assert_not_called()
        self.assertGreater(len(findings), 0)

    # --- 13. Header check uses real response headers ---------------------
    def test_header_check_uses_real_headers(self):
        sandbox = FakeSandbox(
            headers={
                "content-security-policy": "default-src 'self'",
                "x-content-type-options": "nosniff",
                "referrer-policy": "no-referrer",
                "x-frame-options": "DENY",
            }
        )
        runtime = _make_runtime(sandbox)
        findings = HeaderSecurityCheck().run(runtime)
        self.assertEqual(findings, [])  # all headers present -> passed
        # The check really read the response headers from the sandbox.
        self.assertTrue(
            any("--headers" in c["command"] for c in sandbox.process.calls)
        )

    # --- 14. Missing CSP classification ----------------------------------
    def test_missing_csp_classified(self):
        sandbox = FakeSandbox(
            headers={
                "x-content-type-options": "nosniff",
                "referrer-policy": "no-referrer",
                "x-frame-options": "DENY",
            }
        )
        runtime = _make_runtime(sandbox)
        findings = HeaderSecurityCheck().run(runtime)
        titles = [f.title for f in findings]
        self.assertIn("Missing Content-Security-Policy header", titles)
        csp = next(f for f in findings if "Content-Security-Policy" in f.title)
        self.assertEqual(csp.status, "verified")
        self.assertEqual(csp.evidence["missing_header"], "Content-Security-Policy")
        self.assertEqual(
            csp.evidence["observed_headers"]["x-content-type-options"], "nosniff"
        )

    # --- 15. X-Content-Type-Options classification -----------------------
    def test_missing_xcto_classified(self):
        sandbox = FakeSandbox(
            headers={"content-security-policy": "default-src 'self'"}
        )
        runtime = _make_runtime(sandbox)
        findings = HeaderSecurityCheck().run(runtime)
        titles = [f.title for f in findings]
        self.assertIn("Missing X-Content-Type-Options header", titles)

    # --- 16. Cookie values are redacted ----------------------------------
    def test_cookie_values_redacted(self):
        sandbox = FakeSandbox(
            headers={
                "set-cookie": [
                    "session=super-secret-token-12345; Path=/",
                    "authid=abc123; Secure; HttpOnly; SameSite=Lax",
                ]
            }
        )
        runtime = _make_runtime(sandbox)
        findings = CookieSecurityCheck().run(runtime)
        self.assertEqual(len(findings), 1)  # fully-secure cookie -> no finding
        evidence = findings[0].evidence
        self.assertEqual(evidence["cookie_name"], "session")
        self.assertNotIn("super-secret-token", evidence["cookie_value"])
        self.assertIn("*", evidence["cookie_value"])

    # --- 17. Cookie attribute checks -------------------------------------
    def test_cookie_attribute_checks(self):
        sandbox = FakeSandbox(
            headers={"set-cookie": "session=abc; Path=/"}
        )
        runtime = _make_runtime(sandbox)
        findings = CookieSecurityCheck().run(runtime)
        self.assertEqual(len(findings), 1)
        self.assertEqual(
            sorted(findings[0].evidence["missing_attributes"]),
            ["HttpOnly", "SameSite", "Secure"],
        )

    # --- 18. CORS check is bounded ---------------------------------------
    def test_cors_check_bounded(self):
        sandbox = FakeSandbox(
            headers={"access-control-allow-origin": "*"}
        )
        runtime = _make_runtime(sandbox)
        CorsSecurityCheck().run(runtime)
        commands = [c["command"] for c in sandbox.process.calls]
        self.assertEqual(len(commands), 2)  # simple GET + one OPTIONS preflight
        methods = set()
        paths = set()
        for command in commands:
            match = re.match(
                r"python \S+ --headers (GET|OPTIONS) (.+)$", command
            )
            self.assertIsNotNone(match, f"unexpected command: {command}")
            methods.add(match.group(1))
            paths.add(match.group(2).strip().strip("'\""))
        self.assertEqual(methods, {"GET", "OPTIONS"})
        self.assertEqual(paths, {"/"})
        # The test origin only ever travels via the env, never in the command.
        for call in sandbox.process.calls:
            self.assertNotIn(TEST_ORIGIN, call["command"])
            self.assertIn(TEST_ORIGIN, call["env"]["BREAKTRACE_TARGET_HEADERS"])

    def test_cors_wildcard_with_credentials_finding(self):
        sandbox = FakeSandbox(
            headers={
                "access-control-allow-origin": "*",
                "access-control-allow-credentials": "true",
            }
        )
        runtime = _make_runtime(sandbox)
        findings = CorsSecurityCheck().run(runtime)
        self.assertGreaterEqual(len(findings), 1)
        self.assertIn("wildcard", findings[0].title)

    # --- 19. Exposure checks only use allowlisted paths ------------------
    def test_exposure_only_allowlisted_paths(self):
        sandbox = FakeSandbox()
        runtime = _make_runtime(sandbox)
        ExposureSecurityCheck().run(runtime)
        paths = set()
        for call in sandbox.process.calls:
            if "--headers" not in call["command"]:
                continue
            path = FakeProcess._extract_path(call["command"])
            self.assertIsNotNone(path, call["command"])
            paths.add(path)
        self.assertEqual(paths, set(EXPOSURE_ALLOWLIST))
        self.assertEqual(paths, {"/.env", "/.git/config"})

    # --- 20. Exposure checks cannot target external origins --------------
    def test_exposure_no_external_origins(self):
        sandbox = FakeSandbox()
        runtime = _make_runtime(sandbox)
        ExposureSecurityCheck().run(runtime)
        for call in sandbox.process.calls:
            self.assertNotIn("http://", call["command"])
            self.assertNotIn("https://", call["command"])
            self.assertEqual(
                call["env"]["BREAKTRACE_TARGET_ORIGIN"],
                "http://127.0.0.1:3000",
            )

    def test_exposure_validated_content(self):
        # /.env returns 200 with env-like body -> verified exposure.
        sandbox = FakeSandbox(
            header_responses={
                "/.env": {
                    "status": 200,
                    "headers": {},
                    "body": "DB_PASSWORD=supersecret\nPORT=3000\n",
                },
                "/.git/config": {
                    "status": 200,
                    "headers": {},
                    "body": "[core]\n\trepositoryformatversion = 0\n",
                },
            }
        )
        runtime = _make_runtime(sandbox)
        findings = ExposureSecurityCheck().run(runtime)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f.status == "verified" for f in findings))
        self.assertTrue(all(f.severity == "high" for f in findings))

    def test_exposure_200_alone_is_not_finding(self):
        # 200 with HTML body must NOT be treated as verified exposure.
        sandbox = FakeSandbox(
            header_responses={
                "/.env": {
                    "status": 200,
                    "headers": {},
                    "body": "<html><body>Not Found fallback page</body></html>",
                },
                "/.git/config": {
                    "status": 200,
                    "headers": {},
                    "body": "<html>welcome</html>",
                },
            }
        )
        runtime = _make_runtime(sandbox)
        findings = ExposureSecurityCheck().run(runtime)
        self.assertEqual(findings, [])

    # --- 21. AI exploration uses provider dispatcher ---------------------
    def test_ai_uses_provider_dispatcher(self):
        context = make_context()
        with mock.patch.object(
            ai_provider, "get_provider_name", return_value="groq"
        ):
            with mock.patch.object(
                groq_client,
                "propose_discovery_assessment",
                return_value=_assessment(),
            ) as groq_mock:
                ai_provider.propose_security_assessment_for_twin(
                    context, extra_context="already covered"
                )
                groq_mock.assert_called_once_with(
                    context, extra_context="already covered"
                )
        with mock.patch.object(
            ai_provider, "get_provider_name", return_value="nosana"
        ):
            with mock.patch.object(
                nosana_client,
                "propose_discovery_assessment",
                return_value=_assessment(),
            ) as nosana_mock:
                ai_provider.propose_security_assessment_for_twin(
                    context, extra_context="already covered"
                )
                nosana_mock.assert_called_once_with(
                    context, extra_context="already covered"
                )

    def test_ai_split_uses_provider_dispatcher(self):
        context = make_context()
        with mock.patch.object(
            ai_provider, "get_provider_name", return_value="groq"
        ):
            with mock.patch.object(
                groq_client,
                "propose_discovery_assessment_split",
                return_value=([], []),
            ) as groq_mock:
                result = ai_provider.propose_security_assessment_for_twin_split(
                    context, extra_context="covered"
                )
                self.assertEqual(result, ([], []))
                groq_mock.assert_called_once_with(
                    context, extra_context="covered"
                )
        with mock.patch.object(
            ai_provider, "get_provider_name", return_value="nosana"
        ):
            with mock.patch.object(
                nosana_client,
                "propose_discovery_assessment_split",
                return_value=([], []),
            ) as nosana_mock:
                result = ai_provider.propose_security_assessment_for_twin_split(
                    context, extra_context="covered"
                )
                self.assertEqual(result, ([], []))
                nosana_mock.assert_called_once_with(
                    context, extra_context="covered"
                )

    # --- 22 + 23. Groq and Nosana still work -----------------------------
    def test_groq_and_nosana_still_work(self):
        self.assertTrue(callable(groq_client.propose_discovery_assessment))
        self.assertTrue(callable(nosana_client.propose_discovery_assessment))
        self.assertTrue(
            callable(ai_provider.propose_security_assessment_for_twin)
        )
        self.assertTrue(
            callable(ai_provider.propose_security_assessment_for_twin_split)
        )
        self.assertTrue(callable(groq_client.propose_discovery_assessment_split))
        self.assertTrue(callable(nosana_client.propose_discovery_assessment_split))

    # --- 24. Invalid AI proposals remain rejected ------------------------
    def test_invalid_ai_proposals_rejected(self):
        data = _assessment().model_dump()
        data["proposals"][0]["request"]["path"] = "https://evil.example/x"
        with self.assertRaises(ProposalValidationError):
            validate_discovery_assessment_proposals(data, make_context())

    # --- 25. AI proposal is not automatically a verified finding ---------
    def test_ai_proposal_not_automatically_finding(self):
        sandbox = FakeSandbox(
            responses={
                "/api/Users": {"status": 403, "body": {}},
                "/api/Products/1": {"status": 200, "body": {}},
                "/rest/products/search?q=test": {"status": 200, "body": {}},
            }
        )
        _, (_, assessment, _) = run_full_twin(sandbox)
        self.assertEqual(assessment.ai_exploration.hypotheses_generated, 3)
        self.assertEqual(assessment.ai_exploration.verified_findings, 0)
        ai_findings = [
            f for f in assessment.findings if f.source == "ai"
        ]
        self.assertTrue(all(f.status == "passed" for f in ai_findings))
        self.assertEqual(assessment.summary.new_verified_findings, 0)

    # --- 26. Runtime-verified AI failure becomes verified ----------------
    def test_ai_runtime_verified_finding(self):
        sandbox = FakeSandbox(
            responses={
                "/api/Users": {"status": 200, "body": {"users": []}},
                "/api/Products/1": {"status": 200, "body": {}},
                "/rest/products/search?q=test": {"status": 200, "body": {}},
            }
        )
        _, (_, assessment, _) = run_full_twin(sandbox)
        self.assertEqual(assessment.ai_exploration.verified_findings, 1)
        self.assertEqual(assessment.summary.new_verified_findings, 1)
        ai_findings = [
            f for f in assessment.findings if f.source == "ai"
        ]
        verified = [f for f in ai_findings if f.status == "verified"]
        self.assertEqual(len(verified), 1)
        self.assertEqual(verified[0].title, "Users list exposure")
        self.assertEqual(
            verified[0].evidence["observed_status"], 200
        )

    # --- 27 + 28. Unified summary derives from result arrays -------------
    def test_summary_derives_from_result_arrays(self):
        _seed_entry("BT-JS-SUM", "/api/Users", 403)
        sandbox = FakeSandbox(
            headers={
                "content-security-policy": "default-src 'self'",
                "x-content-type-options": "nosniff",
                "referrer-policy": "no-referrer",
                "x-frame-options": "DENY",
            },
            header_responses={
                "/.env": {"status": 404, "headers": {}, "body": {}},
                "/.git/config": {"status": 404, "headers": {}, "body": {}},
            },
            responses={
                "/api/Users": {"status": 403, "body": {}},  # replay passes
                "/api/Products/1": {"status": 200, "body": {}},
                "/rest/products/search?q=test": {"status": 200, "body": {}},
            },
        )
        _, (_, assessment, _) = run_full_twin(sandbox)

        reg = assessment.regression
        det = assessment.deterministic
        ai = assessment.ai_exploration
        summary = assessment.summary

        self.assertEqual(
            summary.security_regressions,
            sum(1 for r in reg.results if r.status == "regression"),
        )
        self.assertEqual(
            summary.new_verified_findings,
            sum(1 for f in assessment.findings
                if f.source == "ai" and f.status == "verified"),
        )
        self.assertEqual(
            summary.deterministic_issues,
            sum(1 for f in assessment.findings
                if f.source == "deterministic" and f.status == "verified"),
        )
        self.assertEqual(
            summary.controls_passed,
            sum(1 for f in assessment.findings if f.status == "passed"),
        )
        # Section counts match the arrays they are derived from.
        self.assertEqual(det.checks_executed, len(det.results))
        self.assertEqual(det.passed, sum(1 for r in det.results if r.status == "passed"))
        self.assertEqual(det.issues, sum(1 for r in det.results if r.status == "verified"))
        self.assertEqual(reg.tests_replayed, len(reg.results))
        self.assertEqual(ai.tests_executed, len(ai.results))
        # Deterministic checks all passed in this configuration (HTTP checks
        # + source checks).
        self.assertEqual(det.issues, 0)
        self.assertEqual(det.passed, det.checks_executed)
        # The only passing controls: deterministic + 1 regression + 3 AI.
        self.assertEqual(summary.controls_passed, det.passed + 1 + 3)
        # No hardcoded metric keys beyond the derived summary.
        self.assertEqual(
            set(summary.model_dump().keys()),
            {
                "security_regressions",
                "new_verified_findings",
                "deterministic_issues",
                "controls_passed",
            },
        )

    # --- 29. Existing M8 target assessment still works -------------------
    def test_m8_target_assessment_endpoint_still_works(self):
        from fastapi.testclient import TestClient
        import main

        client = TestClient(main.app, raise_server_exceptions=False)
        with mock.patch.object(
            main,
            "run_target_assessment",
            return_value=(make_context(), AssessmentRunResult(
                assessment_id="JS-x",
                source="groq_ai",
                summary=__import__("models").AssessmentSummary(
                    tests_generated=1, tests_executed=1,
                    vulnerabilities_found=0, controls_passed=1,
                ),
                results=[],
                target_adapter="juice_shop",
            )),
        ):
            resp = client.post(
                "/breaktrace/target/assess",
                json={"target_type": "juice_shop", "url": "https://m8-kept.example"},
            )
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertIn("context", payload)
        self.assertIn("results", payload)
        self.assertIn("summary", payload)

    # --- 30. Existing demo target still works ----------------------------
    def test_demo_target_still_rejected_with_guidance(self):
        from fastapi.testclient import TestClient
        import main

        client = TestClient(main.app, raise_server_exceptions=False)
        resp = client.post(
            "/breaktrace/target/assess",
            json={"target_type": "demo", "url": "https://demo.example"},
        )
        self.assertEqual(resp.status_code, 400)
        resp2 = client.post(
            "/security-twin/assess",
            json={"target_type": "demo", "url": "https://demo.example"},
        )
        self.assertEqual(resp2.status_code, 400)

    # --- 31. Existing application recognition still works ----------------
    def test_application_recognition_still_works(self):
        from fastapi.testclient import TestClient
        import main

        client = TestClient(main.app, raise_server_exceptions=False)
        first = client.post(
            "/applications/resolve", json={"url": "https://recog.example"}
        )
        second = client.post(
            "/applications/resolve", json={"url": "https://recog.example/login"}
        )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertTrue(first.json()["created"])
        self.assertFalse(second.json()["created"])
        self.assertEqual(
            first.json()["application"]["target_id"],
            second.json()["application"]["target_id"],
        )

    # --- 32 + 33. Library loads; legacy entries remain compatible --------
    def test_library_loads_and_legacy_entries_compatible(self):
        _reset_library()
        self.assertEqual(library.load_library(), {})
        legacy = {
            "id": "LEGACY-9",
            "fingerprint": "legacy9",
            "title": "Old demo test",
            "category": "broken_access_control",
            "severity": "high",
            "invariant": "invariant",
            "actor": {"name": "Alice", "user_id": 1},
            "request": {"method": "GET", "path": "/api/invoices/2"},
            "expected": {"status": 403},
            "original_observed": {"status": 200, "body": {}},
            "original_status": "vulnerable",
            "source": "nosana_ai",
            "kind": "regression",
            "first_seen": "2026-08-01T00:00:00+00:00",
        }
        # Old-format dict (no M9 fields) still validates and loads.
        entry = LibraryEntry.model_validate(legacy)
        self.assertEqual(entry.origin_source, "")
        self.assertIsNone(entry.application_version)
        library.save_library({entry.fingerprint: entry})
        self.assertEqual(len(library.load_library()), 1)

    # --- 34. Existing chain analysis remains working ---------------------
    def test_chain_analysis_still_works(self):
        from models import (
            AssessmentSummary,
            BreakTraceActor,
            BreakTraceExpected,
            BreakTraceObserved,
            BreakTraceRequest,
            BreakTraceResult,
        )

        run = AssessmentRunResult(
            assessment_id="CHAIN-X",
            source="groq_ai",
            summary=AssessmentSummary(
                tests_generated=1, tests_executed=1,
                vulnerabilities_found=1, controls_passed=0,
            ),
            results=[
                BreakTraceResult(
                    id="BT-001",
                    title="Users list exposure",
                    category="broken_access_control",
                    severity="high",
                    invariant="no public users",
                    actor=BreakTraceActor(name="anonymous", user_id=0),
                    request=BreakTraceRequest(method="GET", path="/api/Users"),
                    expected=BreakTraceExpected(status=403),
                    observed=BreakTraceObserved(status=200, body={}),
                    test_executed=True,
                    invariant_violated=True,
                    status="vulnerable",
                    mode="independent",
                )
            ],
            target_adapter="juice_shop",
        )
        analysis = ai_shared.validate_chain_analysis(
            {
                "type": "shared_root_cause",
                "title": "Shared access control weakness",
                "summary": "Both findings share a missing authorization check.",
                "breaktrace_ids": ["BT-001"],
                "steps": [
                    {"breaktrace_id": "BT-001", "description": "first step"}
                ],
                "root_cause": "missing authz",
                "impact": "data exposure",
                "confidence": "medium",
            },
            run.results,
        )
        self.assertEqual(analysis.type, "shared_root_cause")
        self.assertEqual(analysis.breaktrace_ids, ["BT-001"])

    # --- 35. Existing scoped dashboard remains working -------------------
    def test_scoped_dashboard_still_works(self):
        _seed_entry("BT-JS-DASH", "/api/Users", 403, target_id="dash-app")
        metrics = library.get_dashboard_metrics(None, "dash-app")
        self.assertEqual(metrics.regression_tests_saved, 1)
        self.assertEqual(metrics.current_regressions, 0)
        # Other applications never leak into this dashboard.
        other = library.get_dashboard_metrics(None, "other-app")
        self.assertEqual(other.regression_tests_saved, 0)


# ---------------------------------------------------------------------------
# Rejected-proposal reliability tests (Security Twin Layer 3)
#
# A rejected AI proposal must NEVER abort the whole assessment: valid
# proposals still execute, invalid ones are recorded as rejected with a
# reason, and the unified result returns normally.
# ---------------------------------------------------------------------------


class M9RejectedProposalTests(unittest.TestCase):
    def setUp(self):
        _reset_library()

    def _run(self, sandbox, valid=None, rejected=None):
        return run_full_twin(
            sandbox, assessment=valid, rejected=rejected
        )

    def _valid_two(self):
        # /api/Users + /api/Products/1 are both discovered routes.
        return list(_assessment().proposals[:2])

    def _rejected_secret(self):
        return [
            {
                "index": 3,
                "hypothesis": "The app may expose a hidden secret endpoint",
                "reason": (
                    "Proposal 3 rejected: GET '/api/secret' is not a "
                    "discovered endpoint of this application."
                ),
            }
        ]

    def _sandbox_ok(self):
        return FakeSandbox(
            responses={
                "/api/Users": {"status": 403, "body": {}},
                "/api/Products/1": {"status": 200, "body": {}},
            }
        )

    # --- 1. one invalid + two valid proposals -> two execute -------------
    def test_one_invalid_two_valid_execute_two(self):
        sandbox = self._sandbox_ok()
        _, (_, assessment, ai_run) = self._run(
            sandbox,
            valid=self._valid_two(),
            rejected=self._rejected_secret(),
        )
        self.assertEqual(assessment.ai_exploration.hypotheses_generated, 3)
        self.assertEqual(assessment.ai_exploration.hypotheses_rejected, 1)
        self.assertEqual(assessment.ai_exploration.tests_executed, 2)
        self.assertEqual(len(ai_run.results), 2)

    # --- 2. invalid proposal never executes ------------------------------
    def test_invalid_proposal_never_executes(self):
        sandbox = self._sandbox_ok()
        _, (_, assessment, _) = self._run(
            sandbox,
            valid=self._valid_two(),
            rejected=self._rejected_secret(),
        )
        commands = " ".join(c["command"] for c in sandbox.process.calls)
        self.assertIn("/api/Users", commands)
        self.assertIn("/api/Products/1", commands)
        self.assertNotIn("/api/secret", commands)
        self.assertEqual(assessment.ai_exploration.tests_executed, 2)

    # --- 3. invalid proposal recorded as rejected with reason ------------
    def test_invalid_proposal_recorded_as_rejected(self):
        sandbox = self._sandbox_ok()
        _, (_, assessment, _) = self._run(
            sandbox,
            valid=self._valid_two(),
            rejected=self._rejected_secret(),
        )
        rejected_items = [
            i for i in assessment.ai_exploration.results
            if i.verification == "rejected"
        ]
        self.assertEqual(len(rejected_items), 1)
        item = rejected_items[0]
        self.assertEqual(item.verification, "rejected")
        self.assertIsNotNone(item.rejection_reason)
        self.assertIn("not a discovered endpoint", item.rejection_reason)
        # A rejected proposal is never a finding.
        self.assertFalse(
            any(
                f.title == "Rejected hypothesis"
                for f in assessment.findings
            )
        )

    # --- 4. invalid proposal does not abort the assessment ---------------
    def test_invalid_proposal_does_not_abort(self):
        sandbox = self._sandbox_ok()
        client, (context, assessment, ai_run) = self._run(
            sandbox,
            valid=self._valid_two(),
            rejected=self._rejected_secret(),
        )
        self.assertEqual(assessment.assessment_id[:5], "TWIN-")
        self.assertIsNotNone(context)
        self.assertEqual(assessment.ai_exploration.tests_executed, 2)
        self.assertEqual(len(client.deleted), 1)  # twin destroyed normally

    # --- 5. all proposals invalid -> assessment still succeeds -----------
    def test_all_invalid_assessment_still_succeeds(self):
        sandbox = self._sandbox_ok()
        rejected = [
            {"index": i, "hypothesis": f"bad {i}", "reason": f"reason {i}"}
            for i in (1, 2, 3)
        ]
        client, (_, assessment, ai_run) = self._run(
            sandbox, valid=[], rejected=rejected
        )
        self.assertEqual(assessment.assessment_id[:5], "TWIN-")
        self.assertEqual(assessment.ai_exploration.hypotheses_generated, 3)
        self.assertEqual(assessment.ai_exploration.hypotheses_rejected, 3)
        self.assertEqual(assessment.ai_exploration.tests_executed, 0)
        self.assertEqual(assessment.ai_exploration.verified_findings, 0)
        self.assertEqual(len(ai_run.results), 0)
        self.assertEqual(len(client.deleted), 1)

    # --- 6. all invalid -> zero AI tests executed ------------------------
    def test_all_invalid_zero_ai_tests(self):
        sandbox = self._sandbox_ok()
        rejected = [
            {"index": i, "hypothesis": f"bad {i}", "reason": f"reason {i}"}
            for i in (1, 2, 3)
        ]
        _, (_, assessment, _) = self._run(
            sandbox, valid=[], rejected=rejected
        )
        self.assertEqual(assessment.ai_exploration.tests_executed, 0)
        self.assertEqual(assessment.ai_exploration.verified_findings, 0)
        self.assertEqual(
            sum(1 for i in assessment.ai_exploration.results
                if i.verification == "rejected"),
            3,
        )
        self.assertEqual(assessment.summary.new_verified_findings, 0)

    # --- 7. deterministic results preserved ------------------------------
    def test_deterministic_preserved_when_all_rejected(self):
        sandbox = self._sandbox_ok()
        rejected = [
            {"index": i, "hypothesis": f"bad {i}", "reason": f"reason {i}"}
            for i in (1, 2, 3)
        ]
        _, (_, assessment, _) = self._run(
            sandbox, valid=[], rejected=rejected
        )
        self.assertGreater(assessment.deterministic.checks_executed, 0)
        self.assertEqual(
            len(assessment.deterministic.results),
            assessment.deterministic.checks_executed,
        )

    # --- 8. discovery preserved ------------------------------------------
    def test_discovery_preserved_when_all_rejected(self):
        sandbox = self._sandbox_ok()
        rejected = [
            {"index": i, "hypothesis": f"bad {i}", "reason": f"reason {i}"}
            for i in (1, 2, 3)
        ]
        _, (_, assessment, _) = self._run(
            sandbox, valid=[], rejected=rejected
        )
        self.assertIsNotNone(assessment.discovery)
        self.assertGreater(len(assessment.discovery.routes), 0)

    # --- 9. regression results preserved ---------------------------------
    def test_regression_preserved_when_all_rejected(self):
        _seed_entry("BT-JS-REJ", "/api/Users", 403)
        sandbox = FakeSandbox(
            responses={"/api/Users": {"status": 403, "body": {}}},
            header_responses={
                "/.env": {"status": 404, "headers": {}, "body": {}},
                "/.git/config": {"status": 404, "headers": {}, "body": {}},
            },
        )
        rejected = [
            {"index": i, "hypothesis": f"bad {i}", "reason": f"reason {i}"}
            for i in (1, 2, 3)
        ]
        _, (_, assessment, _) = self._run(
            sandbox, valid=[], rejected=rejected
        )
        self.assertEqual(assessment.regression.tests_replayed, 1)
        self.assertEqual(assessment.regression.passed, 1)
        self.assertEqual(assessment.regression.results[0].status, "passed")

    # --- 10. external/undiscovered endpoint remains rejected ------------
    def test_external_undiscovered_endpoint_remains_rejected(self):
        from ai_shared import split_discovery_assessment

        context = make_context()
        data = _assessment().model_dump()
        data["proposals"][0]["request"]["path"] = "https://evil.example/x"
        data["proposals"][1]["request"]["path"] = "/api/secret"
        valid, rejected = split_discovery_assessment(data, context)
        # Only the third (still-valid) proposal survives.
        self.assertEqual(len(valid), 1)
        self.assertEqual(valid[0].request.path, "/rest/products/search?q=test")
        self.assertEqual(len(rejected), 2)
        reasons = " ".join(r["reason"] for r in rejected)
        # External URL and undiscovered endpoint are both rejected (the
        # URL first fails the sandbox-local path check).
        self.assertIn("sandbox-local path", reasons)
        self.assertIn("not a discovered endpoint", reasons)

    # --- 11. existing valid M8/M9 AI assessments still work -------------- 
    def test_existing_valid_assessment_still_works(self):
        sandbox = self._sandbox_ok()
        _, (_, assessment, ai_run) = self._run(sandbox, valid=None)
        self.assertEqual(assessment.ai_exploration.hypotheses_generated, 3)
        self.assertEqual(assessment.ai_exploration.hypotheses_rejected, 0)
        self.assertEqual(assessment.ai_exploration.tests_executed, 3)
        self.assertEqual(len(ai_run.results), 3)

    def test_split_prompt_includes_machine_readable_routes(self):
        from ai_shared import build_discovery_assessment_prompt

        prompt = build_discovery_assessment_prompt(make_context())
        self.assertIn("machine-readable allowlist", prompt)
        self.assertIn('"GET /api/Users"', prompt)
        self.assertIn(
            "You may ONLY propose experiments against one of these "
            "discovered routes",
            prompt,
        )


    # --- Endpoint smoke test: /security-twin/assess ----------------------
    def test_security_twin_endpoint_happy_path(self):
        from fastapi.testclient import TestClient
        import main

        client = TestClient(main.app, raise_server_exceptions=False)
        context = make_context()
        with mock.patch.object(
            main,
            "run_security_twin_assessment",
            return_value=(
                context,
                __import__("models").SecurityTwinAssessment(
                    assessment_id="TWIN-001",
                    target={"target_type": "juice_shop", "name": "OWASP Juice Shop"},
                    security_twin=__import__("models").SecurityTwinInfo(),
                    regression=__import__("models").RegressionSection(
                        tests_replayed=0, passed=0, regressions=0, errors=0
                    ),
                    deterministic=__import__("models").DeterministicSection(
                        checks_executed=0, passed=0, issues=0
                    ),
                    discovery=context,
                    ai_exploration=__import__("models").AiExplorationSection(
                        provider="groq", model="m", hypotheses_generated=0,
                        tests_executed=0, verified_findings=0,
                    ),
                    summary=__import__("models").SecurityTwinSummary(
                        security_regressions=0, new_verified_findings=0,
                        deterministic_issues=0, controls_passed=0,
                    ),
                ),
                AssessmentRunResult(
                    assessment_id="TWIN-001", source="groq_ai",
                    summary=__import__("models").AssessmentSummary(
                        tests_generated=0, tests_executed=0,
                        vulnerabilities_found=0, controls_passed=0,
                    ),
                    results=[], target_adapter="juice_shop",
                ),
            ),
        ):
            resp = client.post(
                "/security-twin/assess",
                json={"target_type": "juice_shop", "url": "https://twin.example"},
            )
        self.assertEqual(resp.status_code, 200)
        payload = resp.json()
        self.assertIn("assessment", payload)
        self.assertEqual(payload["assessment"]["assessment_id"], "TWIN-001")
        self.assertIn("context", payload)
        self.assertIn("application", payload)

    def test_security_twin_endpoint_unknown_target_400(self):
        from fastapi.testclient import TestClient
        import main

        client = TestClient(main.app, raise_server_exceptions=False)
        resp = client.post(
            "/security-twin/assess",
            json={"target_type": "evil-site", "url": "https://example.com"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Unsupported target", resp.json()["detail"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
