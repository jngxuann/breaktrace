"""Automated tests for Milestone 11 - executable_experiment vs security_observation.

Covers (per the M11 spec):
  1.  AI may return only security observations
  2.  AI may return only executable experiments
  3.  AI may return a mixture
  4.  exactly 3 executable experiments are no longer required
  5.  maximum total analyses remains bounded
  6.  security observation contains no executable request
  7.  observation cannot be marked verified
  8.  observation does not increment verified findings
  9.  observation does not increment vulnerability count
  10. observation cannot enter Security Memory
  11. observation cannot become a regression test
  12. executable experiment still uses strict route allowlist
  13. invented /api/users rejected
  14. invented /api/admin rejected
  15. Supabase users table does not imply /api/users
  16. Supabase reports table does not imply /api/reports
  17. invented ?admin=true rejected without evidence
  18. invented ?debug=true rejected without evidence
  19. discovered query parameter may be used
  20. SPA fallback cannot validate an invented route
  21. GET / 200 alone cannot prove an authorization vulnerability
  22. no Supabase auth usage does not automatically create vulnerability
  23. Supabase anon key does not automatically create secret finding
  24. security observation evidence must map to ApplicationContext
  25. Groq path supports observations
  26. Nosana path supports observations
  27. existing deterministic checks unchanged
  28. existing regression replay unchanged
  29. existing discovery-only endpoint unchanged
  30. existing Daytona lifecycle unchanged

No live Daytona sandbox or AI credentials are required - sandboxes are faked
and the AI dispatchers are patched. Run from the backend/ directory:

    ./venv/Scripts/python.exe test_security_analysis.py
"""

import tempfile
import unittest
from unittest import mock

import ai_provider
import groq_client
import library
import nosana_client
import security_twin
from ai_shared import (
    ProposalValidationError,
    parse_ai_security_analysis,
)
from models import (
    ApplicationContext,
    DataResource,
    DiscoveredRoute,
    ExternalService,
    SecurityObservation,
    StorageResource,
)
from targets import get_target_adapter

from test_security_twin import (
    TARGET_ID,
    FakeClient,
    FakeSandbox,
    _reset_library,
)

import applications

_TMP = tempfile.mkdtemp(prefix="breaktrace_m11_")
applications.DATA_DIR = _TMP
applications.APPLICATIONS_PATH = _TMP + "/applications.json"
library.DATA_DIR = _TMP
library.LIBRARY_PATH = _TMP + "/breaktraces.json"


def _cyber_context(extra_routes=None, query_params=None) -> ApplicationContext:
    routes = [DiscoveredRoute(method="GET", path="/", source="runtime")]
    routes.extend(extra_routes or [])
    return ApplicationContext(
        target_id=TARGET_ID,
        name="CyberSafe JARSS User App",
        framework="React + Vite",
        runtime_origin="http://127.0.0.1:5173",
        routes=routes,
        data_resources=[
            DataResource(
                name="reports", service="supabase",
                operations=["select", "insert", "update"],
            ),
            DataResource(
                name="users", service="supabase",
                operations=["select", "insert", "update"],
            ),
        ],
        storage_resources=[
            StorageResource(
                name="report-evidence", service="supabase",
                operations=["upload"],
            )
        ],
        external_service_sdks=[
            ExternalService(type="supabase", source="src/lib/supabase.ts")
        ],
        authentication_usage=[
            "No Supabase auth usage detected in scanned source"
        ],
        environment_references=["VITE_SUPABASE_URL", "VITE_SUPABASE_ANON_KEY"],
        spa_fallback_detected=True,
        query_parameters=list(query_params or []),
    )


def _exp(path, title="Experiment title", expected=403, hypothesis="A hypothesis",
         invariant="The invariant", reason="A reason"):
    return {
        "type": "executable_experiment",
        "title": title,
        "category": "broken_access_control",
        "hypothesis": hypothesis,
        "invariant": invariant,
        "request": {"method": "GET", "path": path},
        "expected_status": expected,
        "reason": reason,
    }


def _obs(title="Authorization depends on Supabase policies",
         category="broken_access_control",
         reason="The frontend accesses Supabase resources directly.",
         evidence=None,
         **over):
    obs = {
        "type": "security_observation",
        "title": title,
        "category": category,
        "reason": reason,
        "evidence": evidence if evidence is not None else ["Supabase SDK detected"],
        "verification": "not_verifiable_in_twin",
        "verification_requirement": "A controlled Supabase policy environment",
    }
    obs.update(over)
    return obs


def _parse(context, analyses):
    return parse_ai_security_analysis({"analyses": analyses}, context)


class M11ValidationTests(unittest.TestCase):
    """Requirements 1-6 + 12-20, 24: parse + individual validation paths."""

    def setUp(self):
        _reset_library()

    # --- 1. AI may return only security observations --------------------
    def test_only_security_observations(self):
        ctx = _cyber_context()
        experiments, observations, rejected = _parse(
            ctx, [_obs(), _obs(title="Storage authorization"),
                  _obs(title="Client/server trust boundary")]
        )
        self.assertEqual(len(observations), 3)
        self.assertEqual(experiments, [])
        self.assertEqual(rejected, [])
        self.assertTrue(
            all(o.verification == "not_verifiable_in_twin" for o in observations)
        )

    # --- 2. AI may return only executable experiments -------------------
    def test_only_executable_experiments(self):
        ctx = _cyber_context()
        experiments, observations, rejected = _parse(
            ctx, [_exp("/"), _exp("/", title="Second"),
                  _exp("/", title="Third")]
        )
        self.assertEqual(len(experiments), 3)
        self.assertEqual(observations, [])
        self.assertEqual(rejected, [])
        # Verified-finding potential only exists for experiments.
        self.assertIsNotNone(experiments[0].request)

    # --- 3. AI may return a mixture -------------------------------------
    def test_mixed_experiments_and_observations(self):
        ctx = _cyber_context()
        experiments, observations, rejected = _parse(
            ctx, [_exp("/"), _obs(), _exp("/", title="Second")]
        )
        self.assertEqual(len(experiments), 2)
        self.assertEqual(len(observations), 1)
        self.assertEqual(rejected, [])

    # --- 4. exactly 3 executable experiments no longer required ---------
    def test_non_three_experiment_count_accepted(self):
        ctx = _cyber_context()
        # Zero executable experiments is a valid successful assessment.
        experiments, observations, rejected = _parse(ctx, [_obs()])
        self.assertEqual(experiments, [])
        self.assertEqual(len(observations), 1)
        # Two (not three) executable experiments are also fine.
        experiments2, _, _ = _parse(ctx, [_exp("/"), _exp("/", title="Second")])
        self.assertEqual(len(experiments2), 2)

    # --- 5. maximum total analyses remains bounded ----------------------
    def test_maximum_analyses_bounded(self):
        ctx = _cyber_context()
        with self.assertRaises(ProposalValidationError):
            _parse(ctx, [_exp("/") for _ in range(4)])

    # --- 6. observation contains no executable request ------------------
    def test_observation_with_request_rejected(self):
        ctx = _cyber_context()
        experiments, observations, rejected = _parse(
            ctx,
            [
                _obs(),
                {
                    **_obs(title="Bad obs"),
                    "request": {"method": "GET", "path": "/api/reports"},
                },
            ],
        )
        # The valid observation survives; the request-carrying one is rejected.
        self.assertEqual(len(observations), 1)
        self.assertEqual(len(rejected), 1)
        self.assertIn("no executable request", rejected[0]["reason"])

    # --- 7. observation cannot be marked verified -----------------------
    def test_observation_cannot_be_verified(self):
        ctx = _cyber_context()
        experiments, observations, rejected = _parse(
            ctx, [_obs(verification="verified")]
        )
        self.assertEqual(observations, [])
        self.assertEqual(len(rejected), 1)

    # --- 12. executable experiment strict route allowlist ---------------
    def test_experiment_strict_route_allowlist(self):
        ctx = _cyber_context()
        experiments, observations, rejected = _parse(
            ctx, [_exp("/api/DoesNotExist")]
        )
        self.assertEqual(experiments, [])
        self.assertEqual(len(rejected), 1)
        self.assertIn("not a discovered endpoint", rejected[0]["reason"])

    # --- 13. invented /api/users rejected -------------------------------
    def test_invented_api_users_rejected(self):
        ctx = _cyber_context()
        experiments, _, rejected = _parse(ctx, [_exp("/api/users")])
        self.assertEqual(experiments, [])
        self.assertEqual(len(rejected), 1)

    # --- 14. invented /api/admin rejected -------------------------------
    def test_invented_api_admin_rejected(self):
        ctx = _cyber_context()
        experiments, _, rejected = _parse(ctx, [_exp("/api/admin")])
        self.assertEqual(experiments, [])
        self.assertEqual(len(rejected), 1)
        self.assertIn("not a discovered endpoint", rejected[0]["reason"])

    # --- 15 + 16. Supabase tables do not imply REST endpoints -----------
    def test_supabase_tables_do_not_imply_rest_endpoints(self):
        ctx = _cyber_context()  # has users + reports tables, route GET / only
        for path in ("/api/users", "/api/reports"):
            experiments, _, rejected = _parse(ctx, [_exp(path)])
            self.assertEqual(experiments, [], path)
            self.assertEqual(len(rejected), 1, path)
            self.assertIn(
                "not a discovered endpoint", rejected[0]["reason"], path
            )

    # --- 17. invented ?admin=true rejected without evidence -------------
    def test_invented_admin_query_rejected(self):
        ctx = _cyber_context()  # no query_parameters discovered
        experiments, _, rejected = _parse(ctx, [_exp("/?admin=true")])
        self.assertEqual(experiments, [])
        self.assertEqual(len(rejected), 1)
        self.assertIn(
            "query parameter 'admin' was not discovered", rejected[0]["reason"]
        )

    # --- 18. invented ?debug=true rejected without evidence -------------
    def test_invented_debug_query_rejected(self):
        ctx = _cyber_context()
        experiments, _, rejected = _parse(ctx, [_exp("/?debug=true")])
        self.assertEqual(experiments, [])
        self.assertEqual(len(rejected), 1)
        self.assertIn(
            "query parameter 'debug' was not discovered", rejected[0]["reason"]
        )

    # --- 19. discovered query parameter may be used ---------------------
    def test_discovered_query_parameter_allowed(self):
        ctx2 = _cyber_context(
            extra_routes=[DiscoveredRoute(method="GET", path="/", source="both")],
            query_params=["q"],
        )
        experiments, _, rejected = _parse(ctx2, [_exp("/?q=test")])
        self.assertEqual(len(experiments), 1)
        self.assertEqual(rejected, [])
        self.assertEqual(experiments[0].request.path, "/?q=test")

    # --- 20. SPA fallback cannot validate an invented route -------------
    def test_spa_fallback_cannot_validate_invented_route(self):
        ctx = _cyber_context()  # spa_fallback_detected=True, GET / only
        experiments, _, rejected = _parse(ctx, [_exp("/api/nonexistent")])
        self.assertEqual(experiments, [])
        # Even though SPA fallback may return 200, the route is not discovered.
        self.assertEqual(len(rejected), 1)
        self.assertTrue(any("not a discovered endpoint" in r["reason"]
                            for r in rejected))

    # --- 24. observation evidence must map to ApplicationContext --------
    def test_observation_evidence_required(self):
        ctx = _cyber_context()
        experiments, observations, rejected = _parse(
            ctx, [_obs(evidence=[])]
        )
        self.assertEqual(observations, [])
        self.assertEqual(len(rejected), 1)
        self.assertIn("evidence", rejected[0]["reason"])

    def test_observation_evidence_references_discovered_signals(self):
        ctx = _cyber_context()
        _, observations, _ = _parse(
            ctx,
            [
                _obs(
                    evidence=[
                        "Supabase SDK detected",
                        "reports: select / insert / update",
                        "No Supabase auth usage detected",
                    ]
                )
            ],
        )
        self.assertEqual(len(observations), 1)
        self.assertEqual(
            observations[0].evidence, [
                "Supabase SDK detected",
                "reports: select / insert / update",
                "No Supabase auth usage detected",
            ]
        )


class M11TwinTests(unittest.TestCase):
    """Requirements 8-11, 21-23: observations never become findings; honest
    classification in a real twin run."""

    def setUp(self):
        _reset_library()

    def _run(self, mock_return, sandbox=None):
        client = FakeClient(sandbox or FakeSandbox())
        with mock.patch.object(
            security_twin, "get_daytona_client", return_value=client
        ):
            with mock.patch.object(
                security_twin,
                "propose_security_analysis_for_twin_split",
                return_value=mock_return,
            ):
                result = security_twin.run_security_twin_assessment(
                    get_target_adapter("cybersafe_jarss_user"), TARGET_ID
                )
        return client, result

    def test_observations_only_twin(self):
        objs = [_obs(), _obs(title="Storage authorization"),
                _obs(title="Trust boundary")]
        client, (_, assessment, ai_run) = self._run(([], objs, []))
        self.assertEqual(assessment.ai_exploration.observations, 3)
        self.assertEqual(assessment.ai_exploration.executable_experiments, 0)
        self.assertEqual(assessment.ai_exploration.tests_executed, 0)
        self.assertEqual(assessment.ai_exploration.verified_findings, 0)
        self.assertEqual(assessment.summary.new_verified_findings, 0)
        # No AI findings at all.
        self.assertEqual([f for f in assessment.findings if f.source == "ai"], [])
        self.assertEqual(ai_run.summary.vulnerabilities_found, 0)
        # Observations are represented with kind="observation".
        kinds = {i.kind for i in assessment.ai_exploration.results}
        self.assertEqual(kinds, {"observation"})
        self.assertEqual(
            assessment.ai_exploration.results[0].verification,
            "not_verifiable_in_twin",
        )
        self.assertEqual(len(client.deleted), 1)  # twin destroyed normally

    def test_observation_does_not_increment_vulnerability_count(self):
        client, result = self._run(([], [_obs()], []))
        ai_run = result[2]  # run_security_twin_assessment -> (context, assessment, ai_run)
        self.assertEqual(ai_run.summary.vulnerabilities_found, 0)

    def test_observation_cannot_enter_security_memory(self):
        _reset_library()
        client, result = self._run(([], [_obs()], []))
        ai_run = result[2]  # run_security_twin_assessment -> (context, assessment, ai_run)
        # Observations are absent from the executed run entirely, so the
        # Security Memory save path (add_from_results) sees nothing to save.
        self.assertEqual(ai_run.results, [])
        library.add_from_results(
            ai_run, "groq_ai", target_id=TARGET_ID,
            origin="https://cybersafe-jarss-user-app.vercel.app",
        )
        entries = library.load_library()
        self.assertEqual(entries, {})

    def test_observation_cannot_become_regression_test(self):
        _reset_library()
        self._run(([], [_obs()], []))
        entries = library.load_library()
        self.assertEqual(entries, {})
        self.assertEqual(
            library.load_regression_entries(TARGET_ID, "cybersafe_jarss_user"),
            [],
        )

    # --- 21. GET / 200 alone cannot prove an authorization vuln --------
    def test_get_root_200_alone_not_authorization_finding(self):
        # An authorization experiment expects 403 but the SPA shell returns
        # 200 - this must be classified not_verifiable_in_twin, never verified.
        sandbox = FakeSandbox(
            responses={
                "/": {
                    "status": 200,
                    "body": "<!DOCTYPE html><div id=\"root\"></div>",
                }
            }
        )
        client, (_, assessment, ai_run) = self._run(
            ([_exp("/", expected=403)], [], []), sandbox=sandbox
        )
        self.assertEqual(assessment.ai_exploration.verified_findings, 0)
        self.assertEqual(assessment.summary.new_verified_findings, 0)
        verifications = {i.verification for i in assessment.ai_exploration.results}
        self.assertIn("not_verifiable_in_twin", verifications)
        self.assertNotIn("verified", verifications)

    # --- 22. no Supabase auth usage does not auto-create vulnerability --
    def test_no_auth_usage_does_not_auto_create_vulnerability(self):
        # Context has the auth-usage signal; the AI returns an observation.
        # No "Broken Authentication" finding is manufactured.
        client, (_, assessment, _) = self._run(([], [_obs()], []))
        self.assertEqual(assessment.ai_exploration.verified_findings, 0)
        self.assertEqual([f for f in assessment.findings if f.source == "ai"], [])

    # --- 23. Supabase anon key does not auto-create secret finding ------
    def test_anon_key_does_not_auto_create_secret_finding(self):
        client, (_, assessment, _) = self._run(
            ([], [_obs(title="Storage boundary")], [])
        )
        self.assertEqual(assessment.ai_exploration.verified_findings, 0)
        self.assertEqual([f for f in assessment.findings if f.source == "ai"], [])


class M11UnchangedTests(unittest.TestCase):
    """Requirements 25-30: provider support + surrounding architecture."""

    def setUp(self):
        _reset_library()

    def _run(self, mock_return, sandbox=None):
        client = FakeClient(sandbox or FakeSandbox())
        with mock.patch.object(
            security_twin, "get_daytona_client", return_value=client
        ):
            with mock.patch.object(
                security_twin,
                "propose_security_analysis_for_twin_split",
                return_value=mock_return,
            ):
                result = security_twin.run_security_twin_assessment(
                    get_target_adapter("cybersafe_jarss_user"), TARGET_ID
                )
        return client, result

    # --- 25. Groq path supports observations ----------------------------
    def test_groq_path_supports_observations(self):
        ctx = _cyber_context()
        with mock.patch.object(
            ai_provider, "get_provider_name", return_value="groq"
        ):
            with mock.patch.object(
                groq_client,
                "propose_security_analysis_for_twin_split",
                return_value=(
                    [],
                    [SecurityObservation(title="T", category="c", reason="r",
                                         evidence=["e"])],
                    [],
                ),
            ) as gm:
                result = ai_provider.propose_security_analysis_for_twin_split(
                    ctx, extra_context="covered"
                )
        self.assertEqual(len(result[1]), 1)
        self.assertEqual(result[1][0].title, "T")
        gm.assert_called_once_with(ctx, extra_context="covered")

    # --- 26. Nosana path supports observations --------------------------
    def test_nosana_path_supports_observations(self):
        ctx = _cyber_context()
        with mock.patch.object(
            ai_provider, "get_provider_name", return_value="nosana"
        ):
            with mock.patch.object(
                nosana_client,
                "propose_security_analysis_for_twin_split",
                return_value=(
                    [],
                    [SecurityObservation(title="T", category="c", reason="r",
                                         evidence=["e"])],
                    [],
                ),
            ) as nm:
                result = ai_provider.propose_security_analysis_for_twin_split(
                    ctx, extra_context="covered"
                )
        self.assertEqual(len(result[1]), 1)
        nm.assert_called_once_with(ctx, extra_context="covered")

    # --- 27. existing deterministic checks unchanged --------------------
    def test_deterministic_checks_unchanged(self):
        sandbox = FakeSandbox()
        runtime = security_twin._twin_runtime(
            security_twin.SecurityTwin(
                get_target_adapter("cybersafe_jarss_user"), TARGET_ID
            )
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

    # --- 28. existing regression replay unchanged -----------------------
    def test_regression_replay_unchanged(self):
        sandbox = FakeSandbox(
            responses={"/api/Users": {"status": 403, "body": {}}}
        )
        # Seed a stored BreakTrace for the cybersafe adapter.
        from test_security_twin import _seed_entry
        _seed_entry(
            "BT-CS-REP", "/api/Users", 403,
            target_adapter="cybersafe_jarss_user",
        )
        client, (_, assessment, _) = self._run(([], [], []), sandbox=sandbox)
        self.assertEqual(assessment.regression.tests_replayed, 1)
        self.assertEqual(assessment.regression.passed, 1)

    # --- 29. existing discovery-only endpoint unchanged -----------------
    def test_discovery_only_endpoint_unchanged(self):
        class Client:
            def __init__(self):
                self.sandbox = FakeSandbox()
                self.created = 0
                self.deleted = 0

            def create(self):
                self.created += 1
                return self.sandbox

            def delete(self, sandbox):
                self.deleted += 1

        client = Client()
        with mock.patch.object(
            security_twin, "get_daytona_client", return_value=client
        ):
            with mock.patch.object(
                security_twin, "prepare_target", return_value="http://127.0.0.1:5173"
            ):
                with mock.patch.object(
                    security_twin, "propose_security_analysis_for_twin_split"
                ) as ai:
                    context = security_twin.run_security_twin_discovery(
                        get_target_adapter("cybersafe_jarss_user"), "x" * 64
                    )
        ai.assert_not_called()
        self.assertEqual(client.created, 1)
        self.assertEqual(client.deleted, 1)
        self.assertIsNotNone(context)

    # --- 30. existing Daytona lifecycle unchanged -----------------------
    def test_daytona_lifecycle_unchanged(self):
        client, _ = self._run(([], [_obs()], []))
        self.assertEqual(len(client.created), 1)
        self.assertEqual(len(client.deleted), 1)
        self.assertEqual(client.created, client.deleted)


if __name__ == "__main__":
    unittest.main(verbosity=1)