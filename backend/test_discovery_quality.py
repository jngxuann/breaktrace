"""Discovery quality tests for frontend-heavy repositories."""

import json
import os
import tempfile
import unittest
from unittest import mock

import discovery
import library
import security_twin
from models import ApplicationContext, DiscoveredRoute
from targets import get_target_adapter

# Isolate this module's data dir so `python -m unittest discover` never sees
# regression entries seeded by other test modules.
_TMP = tempfile.mkdtemp(prefix="breaktrace_m10_disc_")
library.DATA_DIR = _TMP
library.LIBRARY_PATH = _TMP + "/breaktraces.json"


class Result:
    def __init__(self, result, exit_code=0):
        self.result = result
        self.exit_code = exit_code


class SourceSandbox:
    """Fake sandbox that returns a JSON-lines repository archive and probes."""

    def __init__(self, records, spa=True):
        self.records = records
        self.spa = spa
        self.fs = mock.Mock()
        self.process = self
        self.commands = []

    def _response(self, path):
        if self.spa:
            body = "<!doctype html><html><body><div id=\"root\"></div></body></html>"
            return {"status": 200, "headers": {"content-type": "text/html"}, "body": body}
        if path == "/":
            return {"status": 200, "headers": {"content-type": "text/html"}, "body": "home"}
        return {"status": 404, "headers": {"content-type": "text/html"}, "body": "not found"}

    def exec(self, command, timeout=None, env=None):
        self.commands.append({"command": command, "env": env})
        if "python -c" in command and "BREAKTRACE_REPO_ROOT" in (env or {}):
            return Result("\n".join(json.dumps(r) for r in self.records))
        if "--headers" in command:
            path = command.split("--headers GET ", 1)[-1].strip("'\"")
            return Result(json.dumps(self._response(path)))
        if "--probe" in command:
            paths = command.rsplit(" ", 1)[-1].strip("'\"").split("|")
            if self.spa:
                return Result(json.dumps([{"path": p, "status": 200} for p in paths]))
            return Result(json.dumps([{"path": p, "status": 200 if p == "/" else 404} for p in paths]))
        if "--wait" in command:
            return Result("ready")
        return Result("ok")


class DiscoveryQualityTests(unittest.TestCase):
    def setUp(self):
        self.adapter = get_target_adapter("cybersafe_jarss_user")
        # Discovery must never produce Security Memory entries, so start this
        # test run from an empty library (the shared module global may point
        # at another module's temp dir when run under unittest discover).
        if os.path.exists(library.LIBRARY_PATH):
            os.remove(library.LIBRARY_PATH)

    def _records(self):
        return [
            {"path": "package.json", "language": "json", "content": json.dumps({
                "name": "cybersafe", "scripts": {"dev": "vite"},
                "dependencies": {"react": "18", "react-dom": "18", "@supabase/supabase-js": "2"},
                "devDependencies": {"vite": "6", "@vitejs/plugin-react": "5"},
            })},
            {"path": "src/app/App.tsx", "language": "tsx", "content": """
                export function App() {
                  const submit = async () => {
                    await supabase
                      .from("reports")
                      .insert({title: "x"});
                    await supabase.from('reports').select('*');
                    await supabase.storage.from("report-evidence").upload("x", file);
                  };
                  return <button onClick={submit}>Submit Report</button>;
                }
            """},
            {"path": "src/app/supabase.ts", "language": "ts", "content": """
                import { createClient } from '@supabase/supabase-js';
                const url = import.meta.env.VITE_SUPABASE_URL;
                const key = import.meta.env.VITE_SUPABASE_ANON_KEY;
                export const supabase = createClient(url, key);
            """},
            {"path": "src/app/Rewards.tsx", "language": "tsx", "content": "export const Rewards = () => <h1>Rewards</h1>;"},
        ]

    def test_package_metadata_and_recursive_tsx_walk(self):
        sandbox = SourceSandbox(self._records())
        inspection = discovery.inspect_repository(sandbox, self.adapter)
        self.assertTrue(inspection["diagnostics"]["package_json_found"])
        self.assertTrue(inspection["diagnostics"]["package_json_parsed"])
        self.assertGreaterEqual(inspection["diagnostics"]["extensions"]["tsx"], 2)
        self.assertIn("React", inspection["frameworks"])
        self.assertIn("Vite", inspection["frameworks"])
        self.assertIn("@supabase/supabase-js", inspection["deps"])

    def test_multiline_supabase_resources_operations_and_capability(self):
        sandbox = SourceSandbox(self._records())
        inspection = discovery.inspect_repository(sandbox, self.adapter)
        frontend = discovery.inspect_frontend_source(sandbox, self.adapter, inspection)
        reports = next(r for r in frontend["data_resources"] if r["name"] == "reports")
        evidence = next(r for r in frontend["storage_resources"] if r["name"] == "report-evidence")
        self.assertIn("insert", reports["operations"])
        self.assertIn("select", reports["operations"])
        self.assertIn("upload", evidence["operations"])
        self.assertIn("report submission", [c["name"] for c in frontend["capabilities"]])
        self.assertIn("evidence upload", [c["name"] for c in frontend["capabilities"]])

    def test_auth_sdk_without_auth_usage_is_descriptive(self):
        sandbox = SourceSandbox(self._records())
        inspection = discovery.inspect_repository(sandbox, self.adapter)
        frontend = discovery.inspect_frontend_source(sandbox, self.adapter, inspection)
        self.assertEqual(frontend["auth_usage"], [])
        self.assertIn("@supabase/supabase-js", inspection["deps"])

    def test_auth_usage_is_detected_when_present(self):
        records = self._records()
        records.append({"path": "src/auth.ts", "language": "ts", "content": "await supabase.auth.getSession();"})
        sandbox = SourceSandbox(records)
        inspection = discovery.inspect_repository(sandbox, self.adapter)
        frontend = discovery.inspect_frontend_source(sandbox, self.adapter, inspection)
        self.assertTrue(any("getSession" in signal for signal in frontend["auth_usage"]))

    def test_table_names_are_not_http_routes(self):
        sandbox = SourceSandbox(self._records())
        inspection = discovery.inspect_repository(sandbox, self.adapter)
        frontend = discovery.inspect_frontend_source(sandbox, self.adapter, inspection)
        context = discovery.build_application_context(
            "x", self.adapter, inspection, [DiscoveredRoute(method="GET", path="/", source="runtime")],
            "http://127.0.0.1:5173", frontend, {"spa_fallback_detected": True},
        )
        self.assertEqual(context.models, [])
        self.assertEqual(context.runtime_routes[0].path, "/")
        self.assertFalse(any(r.path == "/api/reports" for r in context.routes))
        self.assertEqual([r.name for r in context.data_resources], ["reports"])

    def test_spa_fallback_filters_api_candidates_and_wildcards(self):
        sandbox = SourceSandbox(self._records(), spa=True)
        result = discovery.probe_runtime(
            sandbox, self.adapter, "http://127.0.0.1:5173", ["/", "/api/foo"]
        )
        routes, diagnostics = result
        self.assertTrue(diagnostics["spa_fallback_detected"])
        self.assertEqual([r.path for r in routes], ["/"])
        self.assertNotIn("/api/*", [r.path for r in routes])

    def test_non_spa_runtime_root_is_retained(self):
        sandbox = SourceSandbox(self._records(), spa=False)
        routes, diagnostics = discovery.probe_runtime(
            sandbox, self.adapter, "http://127.0.0.1:5173", ["/"]
        )
        self.assertFalse(diagnostics["spa_fallback_detected"])
        self.assertEqual([r.path for r in routes], ["/"])

    def test_discovery_context_has_no_vulnerability_claims(self):
        sandbox = SourceSandbox(self._records())
        inspection = discovery.inspect_repository(sandbox, self.adapter)
        frontend = discovery.inspect_frontend_source(sandbox, self.adapter, inspection)
        context = discovery.build_application_context(
            "x", self.adapter, inspection, [], "http://127.0.0.1:5173", frontend
        )
        self.assertFalse(hasattr(context, "findings"))
        self.assertTrue(context.capabilities)
        self.assertTrue(context.discovery_diagnostics)

    def test_discovery_only_lifecycle_makes_no_ai_call_and_cleans_up(self):
        class Client:
            def __init__(self):
                self.sandbox = SourceSandbox(self._records())
                self.created = 0
                self.deleted = 0

            def _records(self):
                return DiscoveryQualityTests()._records()

            def create(self):
                self.created += 1
                return self.sandbox

            def delete(self, sandbox):
                self.deleted += 1

        client = Client()
        with mock.patch.object(security_twin, "get_daytona_client", return_value=client):
            with mock.patch.object(security_twin, "prepare_target", return_value="http://127.0.0.1:5173"):
                with mock.patch.object(security_twin, "propose_security_analysis_for_twin_split") as ai:
                    context = security_twin.run_security_twin_discovery(self.adapter, "x" * 64)
        ai.assert_not_called()
        self.assertEqual(client.created, 1)
        self.assertEqual(client.deleted, 1)
        self.assertTrue(context.discovery_diagnostics)

    def test_discovery_diagnostics_are_safe_and_bounded(self):
        sandbox = SourceSandbox(self._records())
        inspection = discovery.inspect_repository(sandbox, self.adapter)
        diagnostics = inspection["diagnostics"]
        self.assertEqual(diagnostics["repository_root"], self.adapter.repo_dir)
        self.assertIsInstance(diagnostics["source_files_scanned"], int)
        self.assertIn("tsx", diagnostics["extensions"])
        serialized = json.dumps(diagnostics)
        self.assertNotIn("VITE_SUPABASE_ANON_KEY", serialized)

    def test_observations_are_not_executable_findings(self):
        # Discovery context carries external service/data signals only. No
        # SecurityFinding or regression entry is produced from observation.
        sandbox = SourceSandbox(self._records())
        inspection = discovery.inspect_repository(sandbox, self.adapter)
        frontend = discovery.inspect_frontend_source(sandbox, self.adapter, inspection)
        context = discovery.build_application_context(
            "x", self.adapter, inspection, [], "http://127.0.0.1:5173", frontend
        )
        self.assertTrue(context.data_resources)
        self.assertTrue(context.external_service_sdks)
        self.assertFalse(hasattr(context, "findings"))
        self.assertFalse(any(e.kind == "regression" for e in library.load_library().values()))


if __name__ == "__main__":
    unittest.main(verbosity=1)
