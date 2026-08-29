"""Automated tests for Milestone 8 - repository-based sandbox analysis.

Covers (per the M8 spec):
  1.  Target adapter resolution
  2.  Unsupported target rejection
  3.  Juice Shop setup command construction (pinned ref per node version)
  4.  Discovery parser
  5.  ApplicationContext validation
  6.  Discovered-route validation
  7.  Request cannot leave sandbox-local target
  8.  AI cannot request arbitrary external URL
  9.  AI cannot provide shell commands
  10. AI cannot use undiscovered endpoint
  11. Invalid method rejected
  12. Existing demo app still works
  13. Provider switching still works
  14. Juice Shop results can enter BreakTrace Library
  15. Application history remains target-scoped
  16-18. Sandbox cleanup on setup/discovery/test failure

No live Daytona sandbox or AI credentials are required - sandboxes are faked
and AI propose is patched. Run from the backend/ directory:

    ./venv/Scripts/python.exe test_targets.py
"""

import json
import os
import shlex
import tempfile
import unittest
from unittest import mock

import ai_provider
import ai_shared
import applications
import discovery
import library
import target_runner
import targets
from ai_shared import ProposalValidationError, validate_discovery_assessment_proposals
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
    SecurityAssessmentProposal,
)
from targets import TargetError, get_target_adapter

# Point registry + library at a throwaway temp dir so no real data is touched.
_TMP = tempfile.mkdtemp(prefix="breaktrace_m8_")
applications.DATA_DIR = _TMP
applications.APPLICATIONS_PATH = os.path.join(_TMP, "applications.json")
library.DATA_DIR = _TMP
library.LIBRARY_PATH = os.path.join(_TMP, "breaktrakes.json")


def make_context() -> ApplicationContext:
    return ApplicationContext(
        target_id="t" * 64,
        name="Fixture App",
        framework="Express",
        runtime_origin="http://127.0.0.1:3000",
        routes=[
            DiscoveredRoute(method="GET", path="/api/Users", source="repository"),
            DiscoveredRoute(method="GET", path="/api/Products/:id", source="runtime"),
            DiscoveredRoute(method="GET", path="/rest/products/search", source="both"),
        ],
        auth_signals=["jsonwebtoken", "helmet"],
        models=["User", "Product"],
        security_relevant_components=["lib/insecurity.ts"],
        discovery_summary="fixture",
        query_parameters=["q"],
    )


def valid_proposals() -> dict:
    return {
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


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeResult:
    def __init__(self, output, exit_code=0):
        self.result = output
        self.exit_code = exit_code


class FakeProcess:
    def __init__(self, default_output='{"status": 200, "body": {}}'):
        self.default_output = default_output
        self.calls = []

    def exec(self, command, timeout=None, env=None):
        self.calls.append({"command": command, "env": env})
        if "--probe" in command:
            return FakeResult('[{"path": "/", "status": 200}]')
        return FakeResult(self.default_output)


class FakeFs:
    def __init__(self):
        self.uploads = []

    def upload_file(self, data, path):
        self.uploads.append(path)


class FakeSandbox:
    def __init__(self, default_output='{"status": 200, "body": {}}'):
        self.process = FakeProcess(default_output)
        self.fs = FakeFs()
        self.ttl = None

    def set_ttl(self, t):
        self.ttl = t


class FakeClient:
    def __init__(self, default_output='{"status": 200, "body": {}}'):
        self.default_output = default_output
        self.created = []
        self.deleted = []

    def create(self):
        sandbox = FakeSandbox(self.default_output)
        self.created.append(sandbox)
        return sandbox

    def delete(self, sandbox):
        self.deleted.append(sandbox)


class M8Tests(unittest.TestCase):
    # --- 1. Target adapter resolution -----------------------------------
    def test_adapter_resolution(self):
        adapter = get_target_adapter("juice_shop")
        self.assertEqual(adapter.name, "OWASP Juice Shop")
        self.assertEqual(adapter.port, 3000)
        self.assertIn("juice-shop", adapter.repository_url)
        self.assertIn("GET", adapter.supported_methods)

    # --- 2. Unsupported target rejection --------------------------------
    def test_unsupported_target_rejection(self):
        with self.assertRaises(TargetError):
            get_target_adapter("https://some-random-site.com")
        with self.assertRaises(TargetError):
            get_target_adapter("")

    def test_unknown_target_via_endpoint_is_400(self):
        from fastapi.testclient import TestClient
        import main

        client = TestClient(main.app, raise_server_exceptions=False)
        resp = client.post(
            "/breaktrace/target/assess",
            json={"target_type": "evil-site", "url": "https://example.com"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("Unsupported target", resp.json()["detail"])

    def test_demo_target_via_assess_is_rejected_with_guidance(self):
        from fastapi.testclient import TestClient
        import main

        client = TestClient(main.app, raise_server_exceptions=False)
        resp = client.post(
            "/breaktrace/target/assess",
            json={"target_type": "demo", "url": "https://example.com"},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("existing AI SECURITY ASSESSMENT", resp.json()["detail"])

    # --- 3. Juice Shop setup command construction -----------------------
    def test_setup_command_construction(self):
        adapter = get_target_adapter("juice_shop")
        # node 22+ -> pinned primary ref
        ref = targets.resolve_ref(adapter, 22)
        self.assertEqual(ref, "v20.2.0")
        clone = (
            f"git clone --depth 1 --branch {ref} "
            f"{adapter.repository_url} {adapter.repo_dir}"
        )
        self.assertIn("--depth 1", clone)
        self.assertIn("juice-shop.git", clone)
        self.assertIn("v20.2.0", clone)
        # node 20/21 -> legacy ref
        self.assertEqual(targets.resolve_ref(adapter, 20), "v17.1.1")
        # install + start come from the trusted adapter definition
        self.assertIn("npm install", adapter.install_command)
        self.assertIn("npm start", adapter.start_command)

    # --- 4. Discovery parser --------------------------------------------
    def test_discovery_parser(self):
        source = """
        import express from 'express';
        const app = express();
        app.get('/rest/products/search', search());
        app.post('/api/Feedbacks', feedback());
        router.delete('/api/BasketItems/:id', remove());
        app.use('/static', express.static('public'));
        app.get(`/dynamic/${x}`, handler);   // template literal - ignored
        app.get("/double-quoted", handler);
        """
        routes = discovery.extract_routes_from_source(source)
        self.assertIn(("get", "/rest/products/search"), routes)
        self.assertIn(("post", "/api/Feedbacks"), routes)
        self.assertIn(("delete", "/api/BasketItems/:id"), routes)
        self.assertIn(("get", "/double-quoted"), routes)
        self.assertNotIn(("use", "/static"), routes)
        self.assertFalse(any("${" in p for _, p in routes))

    def test_framework_and_auth_detection(self):
        deps = {
            "express": "^4",
            "sequelize": "^6",
            "jsonwebtoken": "0.4",
            "helmet": "^4",
            "socket.io": "^3",
        }
        framework = discovery.detect_framework(deps)
        self.assertIn("Express", framework)
        self.assertIn("Sequelize", framework)
        signals = discovery.auth_signals_from_deps(deps)
        self.assertIn("jsonwebtoken", signals)
        self.assertIn("helmet", signals)

    # --- 5. ApplicationContext validation -------------------------------
    def test_application_context_validation(self):
        inspection = {
            "deps": {"express": "x"},
            "framework": "Express",
            "routes": [("get", "/api/Users")],
            "models": ["User"],
            "auth_signals": ["jsonwebtoken"],
            "components": ["lib/insecurity.ts"],
        }
        probed = [
            DiscoveredRoute(method="GET", path="/api/Users", source="runtime"),
            DiscoveredRoute(method="GET", path="/api/Products", source="runtime"),
        ]
        context = discovery.build_application_context(
            "abc", get_target_adapter("juice_shop"), inspection, probed,
            "http://127.0.0.1:3000",
        )
        self.assertEqual(context.runtime_origin, "http://127.0.0.1:3000")
        by_path = {r.path: r.source for r in context.routes}
        self.assertEqual(by_path["/api/Users"], "both")  # repo + runtime
        self.assertEqual(by_path["/api/Products"], "runtime")
        self.assertIn("Express", context.framework)
        self.assertEqual(context.models, ["User"])
        # Pydantic round-trip stays valid
        ApplicationContext.model_validate(context.model_dump(mode="json"))

    # --- 6-11. Discovery-based validator --------------------------------
    def test_valid_assessment_accepted(self):
        context = make_context()
        assessment = validate_discovery_assessment_proposals(valid_proposals(), context)
        self.assertIsInstance(assessment, SecurityAssessmentProposal)
        self.assertEqual(len(assessment.proposals), 3)

    def test_undiscovered_endpoint_rejected(self):
        context = make_context()
        data = valid_proposals()
        data["proposals"][0]["request"]["path"] = "/api/SecretAdmin"
        with self.assertRaises(ProposalValidationError):
            validate_discovery_assessment_proposals(data, context)

    def test_external_url_rejected(self):
        context = make_context()
        data = valid_proposals()
        data["proposals"][0]["request"]["path"] = "https://evil.example/api/Users"
        with self.assertRaises(ProposalValidationError):
            validate_discovery_assessment_proposals(data, context)

    def test_protocol_relative_url_rejected(self):
        context = make_context()
        data = valid_proposals()
        data["proposals"][0]["request"]["path"] = "//evil.example/api/Users"
        with self.assertRaises(ProposalValidationError):
            validate_discovery_assessment_proposals(data, context)

    def test_shell_command_rejected(self):
        context = make_context()
        data = valid_proposals()
        data["proposals"][0]["command"] = "rm -rf /"
        with self.assertRaises(ProposalValidationError):
            validate_discovery_assessment_proposals(data, context)

    def test_shell_in_proposal_rejected(self):
        context = make_context()
        data = valid_proposals()
        data["proposals"][1]["script"] = "python -c 'print(1)'"
        with self.assertRaises(ProposalValidationError):
            validate_discovery_assessment_proposals(data, context)

    def test_invalid_method_rejected(self):
        context = make_context()
        data = valid_proposals()
        data["proposals"][0]["request"]["method"] = "POST"
        with self.assertRaises(ProposalValidationError):
            validate_discovery_assessment_proposals(data, context)

    def test_forbidden_query_token_rejected(self):
        context = make_context()
        data = valid_proposals()
        data["proposals"][0]["request"]["path"] = "/rest/products/search?q=a;b"
        with self.assertRaises(ProposalValidationError):
            validate_discovery_assessment_proposals(data, context)

    def test_param_route_matching(self):
        context = make_context()
        data = valid_proposals()
        data["proposals"][0]["request"]["path"] = "/api/Products/42"
        assessment = validate_discovery_assessment_proposals(data, context)
        self.assertEqual(len(assessment.proposals), 3)

    # --- 7. Request stays on the sandbox-local target -------------------
    def test_execution_commands_stay_local(self):
        adapter = get_target_adapter("juice_shop")
        origin = f"http://127.0.0.1:{adapter.port}"
        context = make_context()
        assessment = validate_discovery_assessment_proposals(valid_proposals(), context)
        sandbox = FakeSandbox(default_output='{"status": 200, "body": {}}')
        target_runner.execute_proposals(sandbox, adapter, origin, assessment.proposals)
        self.assertEqual(len(sandbox.process.calls), 3)
        for call in sandbox.process.calls:
            # The origin is only ever the adapter's sandbox-local origin and
            # never appears inside the command string itself.
            self.assertEqual(
                call["env"], {"BREAKTRACE_TARGET_ORIGIN": origin}
            )
            self.assertNotIn("http://", call["command"])
            # Paths are shlex-quoted so shell metacharacters cannot break out.
        for proposal in assessment.proposals:
            quoted = shlex.quote(proposal.request.path)
            self.assertTrue(
                any(quoted in c["command"] for c in sandbox.process.calls),
                f"{quoted} not found quoted in executed commands",
            )

    # --- 12. Existing demo app still works ------------------------------
    def test_demo_app_and_m7_still_work(self):
        from fastapi.testclient import TestClient
        import main

        client = TestClient(main.app, raise_server_exceptions=False)
        self.assertEqual(client.get("/health").status_code, 200)
        resp = client.post(
            "/applications/resolve", json={"url": "https://demo-kept.example"}
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json()["created"])
        # The demo adapter is still listed.
        self.assertIn(
            "demo", [t.target_type for t in targets.list_targets()]
        )
        # The M5 assessment validator is untouched (Alice/Bob path still valid
        # for the demo allowlist).
        self.assertTrue(hasattr(ai_shared, "validate_assessment_proposals"))

    # --- 13. Provider switching still works -----------------------------
    def test_provider_switching_still_works(self):
        name = ai_provider.get_provider_name()
        self.assertIn(name, ("nosana", "groq"))
        self.assertTrue(callable(ai_provider.propose_security_assessment))
        self.assertTrue(callable(ai_provider.propose_security_assessment_for_context))
        # Both transports expose the discovery propose entry point.
        import groq_client
        import nosana_client

        self.assertTrue(callable(groq_client.propose_discovery_assessment))
        self.assertTrue(callable(nosana_client.propose_discovery_assessment))

    # --- 14. Juice Shop results can enter the library -------------------
    def test_juice_shop_results_enter_library(self):
        run = AssessmentRunResult(
            assessment_id="JS-abc123",
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
                    invariant="User data must not be public",
                    actor=BreakTraceActor(name="anonymous", user_id=0),
                    request=BreakTraceRequest(method="GET", path="/api/Users"),
                    expected=BreakTraceExpected(status=403),
                    observed=BreakTraceObserved(status=200, body={"users": []}),
                    test_executed=True,
                    invariant_violated=True,
                    status="vulnerable",
                    mode="independent",
                    hypothesis="users may leak",
                )
            ],
            target_adapter="juice_shop",
            provider="groq",
            model="llama-3.3-70b",
        )
        library.add_from_results(
            run, "groq_ai", target_id="app-tid", origin="https://js.example"
        )
        response = library.list_entries("app-tid")
        self.assertEqual(response.total, 1)
        entry = response.entries[0]
        self.assertEqual(entry.target_adapter, "juice_shop")
        self.assertEqual(entry.provider, "groq")
        self.assertEqual(entry.model, "llama-3.3-70b")
        self.assertEqual(entry.hypothesis, "users may leak")
        self.assertEqual(entry.original_status, "vulnerable")

    def test_save_requires_target_association(self):
        run = AssessmentRunResult(
            assessment_id="X", source="ai",
            summary=AssessmentSummary(tests_generated=1, tests_executed=1, vulnerabilities_found=1, controls_passed=0),
            results=[
                BreakTraceResult(
                    id="BT-001", title="t", category="c", severity="high",
                    invariant="i", actor=BreakTraceActor(name="a", user_id=0),
                    request=BreakTraceRequest(method="GET", path="/x"),
                    expected=BreakTraceExpected(status=403),
                    observed=BreakTraceObserved(status=200, body={}),
                    test_executed=True, invariant_violated=True,
                    status="vulnerable", mode="independent",
                )
            ],
        )
        with self.assertRaises(library.LibraryError):
            library.add_from_results(run, "ai")

    # --- 15. Application history remains target-scoped ------------------
    def test_history_target_scoped(self):
        _, app_a = applications.resolve_application("https://scope-a.example")
        _, app_b = applications.resolve_application("https://scope-b.example")
        run = AssessmentRunResult(
            assessment_id="A", source="ai",
            summary=AssessmentSummary(tests_generated=1, tests_executed=1, vulnerabilities_found=1, controls_passed=0),
            results=[
                BreakTraceResult(
                    id="BT-001", title="t", category="c", severity="high",
                    invariant="i", actor=BreakTraceActor(name="a", user_id=0),
                    request=BreakTraceRequest(method="GET", path="/x"),
                    expected=BreakTraceExpected(status=403),
                    observed=BreakTraceObserved(status=200, body={}),
                    test_executed=True, invariant_violated=True,
                    status="vulnerable", mode="independent",
                )
            ],
            target_adapter="juice_shop",
        )
        library.add_from_results(run, "ai", app_a.target_id, app_a.origin)
        self.assertEqual(library.list_entries(app_a.target_id).total, 1)
        self.assertEqual(library.list_entries(app_b.target_id).total, 0)

    # --- 16-18. Sandbox cleanup on failure ------------------------------
    def _assert_sandbox_cleaned_up(self, extra_patches):
        """Run the full lifecycle with the given patches and assert the
        sandbox is always deleted."""
        import contextlib

        client = FakeClient()
        patches = [
            mock.patch.object(
                target_runner, "get_daytona_client", return_value=client
            ),
            # Make prepare_target succeed so failures happen at the chosen
            # stage; the setup-failure test overrides this patch.
            mock.patch.object(
                target_runner,
                "prepare_target",
                return_value="http://127.0.0.1:3000",
            ),
        ]
        patches.extend(extra_patches)
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            with self.assertRaises(RuntimeError):
                target_runner.run_target_assessment(
                    get_target_adapter("juice_shop"), "t" * 64
                )
        self.assertEqual(len(client.created), 1)
        self.assertEqual(len(client.deleted), 1)

    def test_cleanup_on_setup_failure(self):
        self._assert_sandbox_cleaned_up(
            [
                mock.patch.object(
                    target_runner,
                    "prepare_target",
                    side_effect=RuntimeError("setup boom"),
                )
            ]
        )

    def test_cleanup_on_discovery_failure(self):
        self._assert_sandbox_cleaned_up(
            [
                mock.patch.object(
                    target_runner,
                    "inspect_repository",
                    side_effect=RuntimeError("discovery boom"),
                )
            ]
        )

    def test_cleanup_on_test_failure(self):
        from ai_shared import validate_discovery_assessment_proposals as _v

        assessment = _v(valid_proposals(), make_context())
        self._assert_sandbox_cleaned_up(
            [
                mock.patch.object(
                    ai_provider,
                    "propose_security_assessment_for_context",
                    return_value=assessment,
                ),
                mock.patch.object(
                    target_runner,
                    "execute_proposals",
                    side_effect=RuntimeError("test boom"),
                ),
            ]
        )


if __name__ == "__main__":
    unittest.main(verbosity=1)
