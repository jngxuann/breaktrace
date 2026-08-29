"""Automated tests for Milestone 10 - CyberSafe JARSS primary target.

Covers (per the spec):
  1.  cybersafe_jarss_user adapter registered
  2.  adapter contains no vulnerability knowledge
  3.  repository is correct
  4.  stable application identity is correct
  5.  startup script derived from actual package.json
  6.  Vite/React generic discovery
  7.  frontend route discovery
  8.  API reference discovery
  9.  environment reference discovery
  10. auth signal discovery
  11. storage signal discovery
  12. discovery does not automatically create vulnerabilities
  13. external API reference is not automatically attacked
  14. live Vercel URL is never used as security execution target
  15. deterministic checks target sandbox-local origin
  16. AI proposals cannot leave sandbox
  17. unverifiable backend-dependent hypothesis classified honestly
  18. verified finding can enter Security Memory
  19. replay happens before new AI exploration
  20. same application identity survives new commits
  21. Juice Shop adapter remains functional
  22. demo adapter remains functional
  23. Groq provider remains functional
  24. Nosana provider remains functional
  25. cleanup still occurs on assessment failure

No live Daytona sandbox or AI credentials are required - sandboxes are faked
and AI propose is patched. Run from the backend/ directory:

    ./venv/Scripts/python.exe test_cybersafe_target.py
"""

import json
import os
import tempfile
import unittest
from unittest import mock

import applications
import discovery
import groq_client
import library
import nosana_client
import security_twin
import target_runner
from checks.base import TwinRuntime
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
from targets import get_target_adapter

from test_security_twin import (
    TARGET_ID,
    FakeClient,
    FakeSandbox,
    _assessment,
    _reset_library,
    _seed_entry,
)

_TMP = tempfile.mkdtemp(prefix="breaktrace_m10_")
applications.DATA_DIR = _TMP
applications.APPLICATIONS_PATH = os.path.join(_TMP, "applications.json")
library.DATA_DIR = _TMP
library.LIBRARY_PATH = os.path.join(_TMP, "breaktraces.json")

IDENTITY = "https://cybersafe-jarss-user-app.vercel.app"
REPOSITORY = "https://github.com/jngxuann/cybersafe-jarss-user-app.git"
PINNED_COMMIT = "d1f6e0d4e869eed83f14078690e27d5de1a05d6f"


def adapter():
    return get_target_adapter("cybersafe_jarss_user")


def run_full_twin(sandbox, target_type="cybersafe_jarss_user", assessment=None):
    client = FakeClient(sandbox)
    proposal = assessment if assessment is not None else _assessment()
    with mock.patch.object(
        security_twin, "get_daytona_client", return_value=client
    ):
        with mock.patch.object(
            security_twin,
            "propose_security_analysis_for_twin_split",
            return_value=(proposal.proposals, [], []),
        ):
            return (
                client,
                security_twin.run_security_twin_assessment(
                    get_target_adapter(target_type), TARGET_ID
                ),
            )


class CyberSafeAdapterTests(unittest.TestCase):
    """Requirements 1-5: adapter registration, safety, identity, startup."""

    def setUp(self):
        _reset_library()

    # --- 1. adapter registered ------------------------------------------
    def test_adapter_registered(self):
        a = adapter()
        self.assertEqual(a.target_type, "cybersafe_jarss_user")
        self.assertEqual(a.name, "CyberSafe JARSS User App")
        self.assertEqual(a.port, 5173)
        self.assertIn("cybersafe", a.repo_dir)
        # Listed FIRST (primary target) and in /targets.
        self.assertEqual(
            get_target_adapter("cybersafe_jarss_user").target_type,
            "cybersafe_jarss_user",
        )
        from targets import list_targets

        order = [t.target_type for t in list_targets()]
        self.assertEqual(order[0], "cybersafe_jarss_user")

    # --- 2. no vulnerability knowledge ----------------------------------
    def test_adapter_contains_no_vulnerability_knowledge(self):
        a = adapter()
        known_fields = {
            "target_type", "name", "description", "repository_url", "ref",
            "ref_legacy", "min_node_major", "port", "repo_dir",
            "install_command", "start_command", "ready_path",
            "supported_methods", "application_identity", "env",
            "frontend_only",
            # Milestone 12 - shared adapter fields (no vulnerability knowledge;
            # only prep facts + a fixed version allowlist for the demo).
            "requires_node", "allowed_request_headers", "canonical_versions",
            "version",
        }
        self.assertEqual(set(a.__dataclass_fields__.keys()), known_fields)
        dump = json.dumps(a.__dict__, default=str).lower()
        for forbidden in (
            "vulnerab", "exploit", "known_bug", "test_known", "payload",
            "weakness", "cve-",
        ):
            self.assertNotIn(forbidden, dump)
        # The adapter knows ONLY preparation mechanics, not answers.
        self.assertEqual(a.ready_path, "/")
        self.assertEqual(a.supported_methods, ("GET", "DELETE"))
        self.assertNotIn("secret", " ".join(a.env.values()).lower())

    # --- 3. repository correct ------------------------------------------
    def test_repository_correct(self):
        self.assertEqual(adapter().repository_url, REPOSITORY)

    # --- 4. stable application identity ---------------------------------
    def test_application_identity_correct(self):
        self.assertEqual(adapter().application_identity, IDENTITY)
        origin = applications.normalize_target_url(IDENTITY)
        self.assertEqual(origin, IDENTITY)
        tid1 = applications.target_id_for(origin)
        tid2 = applications.target_id_for(
            applications.normalize_target_url(
                "https://cybersafe-jarss-user-app.vercel.app/anything"
            )
        )
        self.assertEqual(tid1, tid2)  # deterministic + path-insensitive

    # --- 5. startup script derived from actual package.json -------------
    def test_startup_derived_from_package_json(self):
        # The real repo scripts are {"dev": "vite", "build": "vite build"}
        # with a package-lock.json (lockfileVersion 3), so:
        self.assertEqual(
            adapter().install_command,
            "npm ci --no-audit --no-fund --loglevel=error",
        )
        self.assertIn("npm run dev -- --host 0.0.0.0", adapter().start_command)
        # No server.port in vite.config.ts -> Vite default 5173.
        self.assertEqual(adapter().port, 5173)


class CyberSafeDiscoveryTests(unittest.TestCase):
    """Requirements 6-14: generic frontend discovery + safety."""

    # --- 6. Vite/React generic discovery --------------------------------
    def test_vite_react_framework_detection(self):
        framework = discovery.detect_framework(
            {"react": "18.3.1", "vite": "6.4.3", "@vitejs/plugin-react": "x"}
        )
        self.assertIn("React", framework)
        self.assertIn("Vite", framework)

    # --- 7. frontend route discovery ------------------------------------
    def test_frontend_route_discovery(self):
        lines = [
            ("src/App.tsx", 5, "const router = createBrowserRouter([{ path: '/home' }]);"),
            ("src/App.tsx", 6, "const router = createBrowserRouter([{ path: '/report' }]);"),
            ("src/App.tsx", 9, "<Route path=\"/rewards\" element={<Rewards />} />"),
        ]
        routes = discovery.extract_frontend_routes_from_lines(lines)
        self.assertIn("/home", routes)
        self.assertIn("/report", routes)
        self.assertIn("/rewards", routes)

    # --- 8. API reference discovery -------------------------------------
    def test_api_reference_discovery(self):
        lines = [
            ("src/app/supabase.ts", 2, "const c = createClient('https://xyz.supabase.co', key);"),
            ("src/app/App.tsx", 10, "await supabase.from('reports').select('*');"),
            ("src/app/App.tsx", 11, "const r = await fetch('https://api.example.com/v1/data');"),
        ]
        refs = discovery.extract_api_references_from_lines(lines)
        urls = {(r["url"], r["kind"]) for r in refs}
        self.assertIn(("https://xyz.supabase.co", "external"), urls)
        self.assertIn(("https://api.example.com/v1/data", "external"), urls)
        self.assertIn(("reports", "supabase_table"), urls)

    # --- 9. environment reference discovery -----------------------------
    def test_environment_reference_discovery(self):
        lines = [
            ("src/app/supabase.ts", 3, "const url = import.meta.env.VITE_SUPABASE_URL;"),
            ("src/app/supabase.ts", 4, "const key = import.meta.env.VITE_SUPABASE_ANON_KEY;"),
            ("src/api.ts", 1, "const host = process.env.VITE_API_HOST;"),
        ]
        envs = discovery.extract_environment_references_from_lines(lines)
        self.assertIn("VITE_SUPABASE_URL", envs)
        self.assertIn("VITE_SUPABASE_ANON_KEY", envs)
        self.assertIn("VITE_API_HOST", envs)

    # --- 10. auth signal discovery --------------------------------------
    def test_auth_signal_discovery(self):
        signals = discovery.auth_signals_from_deps(
            {"jsonwebtoken": "x", "supabase": "x", "react": "x"}
        )
        self.assertIn("jsonwebtoken", signals)
        self.assertNotIn("react", signals)
        components = discovery.security_components_from_file_list(
            ["src/app/LoginPage.tsx", "src/app/ui/button.tsx", "src/app/AdminPanel.tsx"]
        )
        self.assertIn("src/app/LoginPage.tsx", components)
        self.assertNotIn("src/app/ui/button.tsx", components)

    # --- 11. storage signal discovery -----------------------------------
    def test_storage_signal_discovery(self):
        lines = [
            ("src/App.tsx", 3, 'localStorage.setItem("auth_token", token);'),
            ("src/App.tsx", 4, "const x = sessionStorage.getItem('session_id');"),
        ]
        signals = discovery.extract_storage_signals_from_lines(lines)
        pairs = {(s["storage_type"], s["key"]) for s in signals}
        self.assertIn(("localStorage", "auth_token"), pairs)
        self.assertIn(("sessionStorage", "session_id"), pairs)

    # --- 12. discovery never creates vulnerabilities --------------------
    def test_discovery_does_not_create_vulnerabilities(self):
        frontend = {
            "frontend_routes": ["/home", "/rewards"],
            "api_references": [
                {"url": "https://xyz.supabase.co", "kind": "external"},
                {"url": "reports", "kind": "supabase_table"},
            ],
            "environment_references": ["VITE_SUPABASE_URL"],
            "storage_signals": [
                {"storage_type": "localStorage", "key": "auth_token"}
            ],
            "components": ["src/app/LoginPage.tsx"],
            "external_services": ["supabase"],
        }
        inspection = {
            "deps": {"react": "x", "vite": "x"},
            "framework": "React + Vite",
            "routes": [],
            "models": [],
            "auth_signals": ["supabase"],
            "components": [],
        }
        context = discovery.build_application_context(
            TARGET_ID,
            adapter(),
            inspection,
            [DiscoveredRoute(method="GET", path="/", source="runtime")],
            "http://127.0.0.1:5173",
            frontend_inspection=frontend,
        )
        # Signals are descriptive - the context has NO finding/status fields.
        self.assertFalse(hasattr(context, "findings"))
        self.assertFalse(hasattr(context, "status"))
        self.assertEqual(context.external_services, ["supabase"])
        self.assertEqual(len(context.frontend_routes), 2)
        self.assertEqual(len(context.api_references), 2)
        self.assertIn("/rewards", [r.path for r in context.frontend_routes])

    # --- 13. external API reference is never attacked -------------------
    def test_external_api_reference_not_attacked(self):
        sandbox = FakeSandbox()
        _, (context, _, _) = run_full_twin(sandbox)
        commands = " ".join(c["command"] for c in sandbox.process.calls)
        # Whatever the external references are, no sandbox command may carry
        # an absolute URL or a table name as an execution target.
        self.assertNotIn("supabase.co", commands)
        self.assertNotIn("http://", commands)

    # --- 14. live Vercel URL never an execution target ------------------
    def test_live_vercel_url_never_execution_target(self):
        sandbox = FakeSandbox()
        _, (context, assessment, _) = run_full_twin(sandbox)
        for call in sandbox.process.calls:
            self.assertNotIn("vercel.app", call["command"])
            env = call["env"] or {}
            self.assertNotIn("vercel.app", " ".join(env.values()))
        # The identity only appears in application metadata, never in probes.
        self.assertEqual(assessment.target["application_identity"], IDENTITY)

    # --- 15. deterministic checks target sandbox-local origin -----------
    def test_deterministic_checks_sandbox_local_origin(self):
        sandbox = FakeSandbox()
        runtime = TwinRuntime(
            sandbox, adapter(), "http://127.0.0.1:5173",
            "/tmp/breaktrace/target_client.py",
        )
        from checks.headers import HeaderSecurityCheck

        HeaderSecurityCheck().run(runtime)
        for call in sandbox.process.calls:
            self.assertEqual(
                call["env"]["BREAKTRACE_TARGET_ORIGIN"],
                "http://127.0.0.1:5173",
            )


class CyberSafeTwinTests(unittest.TestCase):
    """Requirements 16-25: twin behavior for the primary target."""

    def setUp(self):
        _reset_library()

    # --- 16. AI proposals cannot leave sandbox --------------------------
    def test_ai_proposals_cannot_leave_sandbox(self):
        from ai_shared import (
            ProposalValidationError,
            validate_discovery_assessment_proposals,
        )

        context = ApplicationContext(
            target_id=TARGET_ID,
            name="CyberSafe",
            runtime_origin="http://127.0.0.1:5173",
            routes=[DiscoveredRoute(method="GET", path="/", source="runtime")],
        )
        data = _assessment().model_dump()
        data["proposals"][0]["request"]["path"] = "https://evil.example/x"
        with self.assertRaises(ProposalValidationError):
            validate_discovery_assessment_proposals(data, context)

    # --- 17. unverifiable backend-dependent hypothesis classified -------
    def test_backend_dependent_hypothesis_classified_honestly(self):
        # The twin only serves the SPA shell -> no verified claims.
        shell = {"status": 200, "body": "<!DOCTYPE html><div id=\"root\"></div>"}
        sandbox = FakeSandbox(
            responses={
                "/api/Users": shell,
                "/api/Products/1": shell,
                "/rest/products/search?q=test": shell,
            }
        )
        _, (context, assessment, ai_run) = run_full_twin(sandbox)
        self.assertEqual(assessment.ai_exploration.hypotheses_generated, 3)
        self.assertEqual(assessment.ai_exploration.verified_findings, 0)
        verifications = {
            item.verification for item in assessment.ai_exploration.results
        }
        self.assertEqual(verifications, {"not_verifiable_in_twin"})
        self.assertEqual(assessment.summary.new_verified_findings, 0)
        # No AI findings at all - nothing was falsely reported.
        self.assertEqual(
            [f for f in assessment.findings if f.source == "ai"], []
        )
        # The cached M8-compat run must not present them as vulnerable.
        self.assertEqual(ai_run.summary.vulnerabilities_found, 0)
        self.assertTrue(
            all(r.status == "not_verifiable" for r in ai_run.results)
        )

    def test_ready_path_still_passed_in_frontend_twin(self):
        # GET / (the ready path) returning the app shell is a REAL control.
        proposals = _assessment().model_dump()
        proposals["proposals"][0]["request"]["path"] = "/"
        proposals["proposals"][0]["expected_status"] = 200
        assessment_obj = SecurityAssessmentProposal.model_validate(proposals)
        sandbox = FakeSandbox(
            responses={
                "/": {"status": 200, "body": "<!DOCTYPE html><div id=\"root\"></div>"},
                "/api/Products/1": {"status": 200, "body": "<!DOCTYPE html>"},
                "/rest/products/search?q=test": {"status": 200, "body": "<!DOCTYPE html>"},
            }
        )
        _, (_, assessment, _) = run_full_twin(sandbox, assessment=assessment_obj)
        by_path = {
            item.experiment["path"]: item.verification
            for item in assessment.ai_exploration.results
        }
        self.assertEqual(by_path.get("/"), "passed")
        self.assertIn("not_verifiable_in_twin", by_path.values())

    # --- 18. verified finding can enter Security Memory -----------------
    def test_verified_finding_enters_security_memory(self):
        run = AssessmentRunResult(
            assessment_id="TWIN-X",
            source="groq_ai",
            summary=AssessmentSummary(
                tests_generated=1, tests_executed=1,
                vulnerabilities_found=1, controls_passed=0,
            ),
            results=[
                BreakTraceResult(
                    id="BT-001",
                    title="Exposed admin route",
                    category="broken_access_control",
                    severity="high",
                    invariant="Admin data must not be public",
                    actor=BreakTraceActor(name="anonymous", user_id=0),
                    request=BreakTraceRequest(method="GET", path="/admin"),
                    expected=BreakTraceExpected(status=403),
                    observed=BreakTraceObserved(status=200, body={}),
                    test_executed=True,
                    invariant_violated=True,
                    status="vulnerable",
                    mode="independent",
                    hypothesis="admin may be public",
                )
            ],
            target_adapter="cybersafe_jarss_user",
            provider="groq",
            model="llama",
        )
        library.add_from_results(
            run, "groq_ai", target_id="cyber-tid",
            origin=IDENTITY, assessment_id="TWIN-X",
        )
        entries = library.load_regression_entries("cyber-tid", "cybersafe_jarss_user")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].target_adapter, "cybersafe_jarss_user")
        self.assertEqual(entries[0].assessment_id, "TWIN-X")
        self.assertIsNotNone(entries[0].test_definition)

    # --- 19. replay before new AI exploration ----------------------------
    def test_replay_before_new_ai_exploration(self):
        _seed_entry(
            "BT-CS-001", "/api/Users", 403,
            target_adapter="cybersafe_jarss_user",
        )
        sandbox = FakeSandbox(
            responses={"/api/Users": {"status": 403, "body": {}}}
        )
        _, (_, assessment, _) = run_full_twin(sandbox)
        self.assertEqual(assessment.regression.tests_replayed, 1)
        self.assertEqual(assessment.regression.passed, 1)

    # --- 20. same application identity survives new commits -------------
    def test_identity_survives_new_commits(self):
        _, rec_a = applications.resolve_application(IDENTITY)
        _, rec_b = applications.resolve_application(
            "https://cybersafe-jarss-user-app.vercel.app/#/somewhere"
        )
        self.assertEqual(rec_a.target_id, rec_b.target_id)
        # Library entries are keyed by target_id, not by commit.
        _seed_entry(
            "BT-CS-2", "/api/Users", 403,
            target_id=rec_a.target_id,
            target_adapter="cybersafe_jarss_user",
        )
        entries = library.load_regression_entries(
            rec_a.target_id, "cybersafe_jarss_user"
        )
        self.assertEqual(len(entries), 1)

    # --- 21. Juice Shop adapter remains functional ----------------------
    def test_juice_shop_adapter_functional(self):
        js = get_target_adapter("juice_shop")
        self.assertEqual(js.name, "OWASP Juice Shop")
        self.assertEqual(js.port, 3000)
        self.assertEqual(js.ref, "v20.2.0")
        self.assertEqual(js.frontend_only, False)

    # --- 22. demo adapter remains functional ----------------------------
    def test_demo_adapter_functional(self):
        demo = get_target_adapter("demo")
        self.assertEqual(demo.target_type, "demo")
        from fastapi.testclient import TestClient
        import main

        client = TestClient(main.app, raise_server_exceptions=False)
        resp = client.post(
            "/security-twin/assess",
            json={"target_type": "demo", "url": IDENTITY},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("existing AI SECURITY ASSESSMENT", resp.json()["detail"])

    # --- 23 + 24. providers remain functional ---------------------------
    def test_groq_and_nosana_functional(self):
        self.assertTrue(callable(groq_client.propose_discovery_assessment))
        self.assertTrue(callable(nosana_client.propose_discovery_assessment))
        self.assertTrue(
            callable(
                security_twin.propose_security_analysis_for_twin_split
            )
        )
        self.assertTrue(
            callable(groq_client.propose_security_analysis_for_twin_split)
        )
        self.assertTrue(
            callable(nosana_client.propose_security_analysis_for_twin_split)
        )
        import ai_provider

        with mock.patch.object(
            ai_provider, "get_provider_name", return_value="groq"
        ):
            with mock.patch.object(
                groq_client,
                "propose_discovery_assessment",
                return_value=_assessment(),
            ) as gm:
                ai_provider.propose_security_assessment_for_twin(
                    ApplicationContext(
                        target_id="x", name="x",
                        runtime_origin="http://127.0.0.1:5173",
                    ),
                    extra_context="covered",
                )
                gm.assert_called_once()
        with mock.patch.object(
            ai_provider, "get_provider_name", return_value="nosana"
        ):
            with mock.patch.object(
                nosana_client,
                "propose_discovery_assessment",
                return_value=_assessment(),
            ) as nm:
                ai_provider.propose_security_assessment_for_twin(
                    ApplicationContext(
                        target_id="x", name="x",
                        runtime_origin="http://127.0.0.1:5173",
                    ),
                    extra_context="covered",
                )
                nm.assert_called_once()

    # --- 25. cleanup still occurs on assessment failure -----------------
    def test_cleanup_on_assessment_failure(self):
        client = FakeClient()
        with mock.patch.object(
            security_twin, "get_daytona_client", return_value=client
        ):
            with mock.patch.object(
                security_twin,
                "prepare_target",
                side_effect=RuntimeError("startup boom"),
            ):
                with self.assertRaises(RuntimeError):
                    security_twin.run_security_twin_assessment(
                        adapter(), TARGET_ID
                    )
        self.assertEqual(len(client.created), 1)
        self.assertEqual(len(client.deleted), 1)

    # --- Endpoint smoke: cybersafe via /security-twin/assess ------------
    def test_endpoint_accepts_cybersafe_target(self):
        from fastapi.testclient import TestClient
        import main
        from models import (
            AiExplorationSection,
            AssessmentSummary,
            DeterministicSection,
            RegressionSection,
            SecurityTwinAssessment,
            SecurityTwinInfo,
            SecurityTwinSummary,
        )

        context = ApplicationContext(
            target_id="x", name="CyberSafe JARSS User App",
            runtime_origin="http://127.0.0.1:5173",
        )
        fake = (
            context,
            SecurityTwinAssessment(
                assessment_id="TWIN-100",
                target={"target_type": "cybersafe_jarss_user",
                        "name": "CyberSafe JARSS User App"},
                security_twin=SecurityTwinInfo(),
                regression=RegressionSection(
                    tests_replayed=0, passed=0, regressions=0, errors=0
                ),
                deterministic=DeterministicSection(
                    checks_executed=0, passed=0, issues=0
                ),
                discovery=context,
                ai_exploration=AiExplorationSection(
                    provider="groq", model="m", hypotheses_generated=0,
                    tests_executed=0, verified_findings=0,
                ),
                summary=SecurityTwinSummary(
                    security_regressions=0, new_verified_findings=0,
                    deterministic_issues=0, controls_passed=0,
                ),
            ),
            AssessmentRunResult(
                assessment_id="TWIN-100", source="groq_ai",
                summary=AssessmentSummary(
                    tests_generated=0, tests_executed=0,
                    vulnerabilities_found=0, controls_passed=0,
                ),
                results=[], target_adapter="cybersafe_jarss_user",
            ),
        )
        client = TestClient(main.app, raise_server_exceptions=False)
        with mock.patch.object(main, "run_security_twin_assessment", return_value=fake):
            resp = client.post(
                "/security-twin/assess",
                json={"target_type": "cybersafe_jarss_user", "url": IDENTITY},
            )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(
            resp.json()["assessment"]["assessment_id"], "TWIN-100"
        )


if __name__ == "__main__":
    unittest.main(verbosity=1)
