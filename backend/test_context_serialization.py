import unittest

from ai_shared import build_discovery_assessment_prompt
from models import (
    ApplicationCapability,
    ApplicationContext,
    DataResource,
    DiscoveredRoute,
    ExternalService,
    StorageResource,
)


class ContextSerializationTests(unittest.TestCase):
    def cyber_safe_context(self):
        return ApplicationContext(
            target_id="cybersafe-test",
            name="CyberSafe JARSS User App",
            framework="React / Vite",
            frameworks=["React", "Vite"],
            dependencies=["react", "vite", "@supabase/supabase-js"],
            runtime_origin="http://127.0.0.1:5173",
            routes=[DiscoveredRoute(method="GET", path="/", source="runtime")],
            runtime_routes=[DiscoveredRoute(method="GET", path="/", source="runtime")],
            external_service_sdks=[ExternalService(type="Supabase", provenance="repository")],
            data_resources=[
                DataResource(name="reports", service="Supabase", operations=["select", "insert"]),
                DataResource(name="users", service="Supabase", operations=["select"]),
            ],
            storage_resources=[
                StorageResource(name="report-evidence", service="Supabase", operations=["upload"]),
            ],
            capabilities=[
                ApplicationCapability(name="report submission", source="src/app/App.tsx")
            ],
            authentication_provider=["Supabase SDK detected"],
            authentication_usage=["No Supabase auth usage detected"],
            environment_references=["VITE_SUPABASE_URL", "VITE_SUPABASE_ANON_KEY"],
            spa_fallback_detected=True,
        )

    def test_typed_context_serializes_to_json_compatible_data(self):
        context = self.cyber_safe_context()
        dumped = context.model_dump()
        self.assertEqual(dumped["external_service_sdks"][0]["type"], "Supabase")
        self.assertEqual(dumped["data_resources"][0]["name"], "reports")
        self.assertEqual(dumped["storage_resources"][0]["name"], "report-evidence")
        self.assertEqual(dumped["capabilities"][0]["name"], "report submission")

    def test_prompt_builds_from_real_shaped_typed_context(self):
        prompt = build_discovery_assessment_prompt(self.cyber_safe_context())
        self.assertIn("React, Vite", prompt)
        self.assertIn("Supabase", prompt)
        self.assertIn("reports", prompt)
        self.assertIn("users", prompt)
        self.assertIn("report-evidence", prompt)
        self.assertIn("GET /", prompt)
        self.assertIn("SPA FALLBACK DETECTED\nTrue", prompt)
        self.assertIn("DATA RESOURCES (NOT REST ENDPOINTS)\nreports", prompt)
        self.assertNotIn("DISCOVERED ENDPOINTS (human-readable)\n- GET /api/users", prompt)

    def test_legacy_mapping_context_values_remain_supported(self):
        context = self.cyber_safe_context()
        context.external_service_sdks = [{"type": "Supabase"}]
        context.capabilities = [{"name": "report submission"}]
        prompt = build_discovery_assessment_prompt(context)
        self.assertIn("Supabase", prompt)
        self.assertIn("report submission", prompt)


if __name__ == "__main__":
    unittest.main()
