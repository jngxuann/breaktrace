"""Focused tests for Groq transport diagnostics.

Run from backend/:
    venv/Scripts/python.exe test_groq_diagnostics.py
"""

import json
import logging
import os
import unittest
from unittest import mock

import httpx

import groq_client
from ai_shared import ProposalValidationError, validate_discovery_assessment_proposals
from models import ApplicationContext, DiscoveredRoute


API_KEY = "gsk_test_NEVER_LOG_THIS_KEY"


def _context():
    return ApplicationContext(
        target_id="x" * 64,
        name="Fixture",
        framework="Vite/React",
        runtime_origin="http://127.0.0.1:5173",
        routes=[
            DiscoveredRoute(method="GET", path="/", source="runtime"),
            DiscoveredRoute(method="GET", path="/api/items", source="repository"),
            DiscoveredRoute(method="GET", path="/health", source="runtime"),
        ],
        auth_signals=[],
        models=[],
        security_relevant_components=[],
        discovery_summary="fixture",
    )


def _proposal(path="/"):
    return {
        "title": "Bounded test",
        "category": "security_configuration",
        "hypothesis": "The route may not enforce its expected control",
        "invariant": "The route should return the expected response",
        "actor": {"name": "anonymous", "user_id": 0},
        "request": {"method": "GET", "path": path},
        "expected_status": 200,
        "reason": "Checks the discovered route",
    }


def _response(status, payload, request=None):
    request = request or httpx.Request("POST", "https://api.groq.com/openai/v1/chat/completions")
    return httpx.Response(status, request=request, json=payload)


class GroqDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(
            os.environ,
            {"GROQ_API_KEY": API_KEY, "GROQ_MODEL": "openai/gpt-oss-20b"},
            clear=False,
        )
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def test_http_400_body_is_surfaced_safely(self):
        response = _response(
            400,
            {
                "error": {
                    "message": "Invalid parameter: response_format",
                    "type": "invalid_request_error",
                    "code": "invalid_request",
                }
            },
        )
        with mock.patch.object(groq_client.httpx, "post", return_value=response):
            with self.assertRaises(groq_client.GroqUnavailableError) as raised:
                groq_client._chat_completion("{}")
        message = str(raised.exception)
        self.assertIn("HTTP 400", message)
        self.assertIn("Invalid parameter: response_format", message)
        self.assertIn("type=invalid_request_error", message)
        self.assertIn("code=invalid_request", message)

    def test_api_key_never_appears_in_errors(self):
        response = _response(
            400,
            {
                "error": {
                    "message": f"bad bearer {API_KEY}",
                    "type": "invalid_request_error",
                    "code": "bad_request",
                }
            },
        )
        with mock.patch.object(groq_client.httpx, "post", return_value=response):
            with self.assertRaises(groq_client.GroqUnavailableError) as raised:
                groq_client._chat_completion("{}")
        message = str(raised.exception)
        self.assertNotIn(API_KEY, message)
        self.assertIn("[REDACTED]", message)

    def test_malformed_structured_output_request_is_diagnosed(self):
        response = _response(
            400,
            {"error": {"message": "json_schema must contain strict", "type": "invalid_request_error"}},
        )
        with mock.patch.object(groq_client.httpx, "post", return_value=response):
            with self.assertRaisesRegex(
                groq_client.GroqUnavailableError,
                r"Groq returned HTTP 400:.*json_schema must contain strict",
            ):
                groq_client._chat_completion("prompt")

    def test_json_object_response_parses_correctly(self):
        response = _response(
            200,
            {"choices": [{"message": {"content": json.dumps({"proposals": []})}}]},
        )
        with mock.patch.object(groq_client.httpx, "post", return_value=response):
            result = groq_client._generate_json("return JSON")
        self.assertEqual(result, {"proposals": []})

    def test_request_metadata_is_logged_without_secrets(self):
        response = _response(
            200,
            {"choices": [{"message": {"content": "{}"}}]},
        )
        with self.assertLogs(groq_client.logger, level=logging.INFO) as logs:
            with mock.patch.object(groq_client.httpx, "post", return_value=response):
                groq_client._chat_completion("prompt text")
        output = "\n".join(logs.output)
        self.assertIn("model=openai/gpt-oss-20b", output)
        self.assertIn("messages=2", output)
        self.assertIn("prompt_chars=", output)
        self.assertIn("response_format=True", output)
        self.assertIn("response_format_type=json_object", output)
        self.assertIn("max_tokens=4096", output)
        self.assertNotIn(API_KEY, output)
        self.assertNotIn("Authorization", output)

    def test_exact_current_payload_has_json_object_and_no_tools(self):
        response = _response(
            200,
            {"choices": [{"message": {"content": "{}"}}]},
        )
        with mock.patch.object(groq_client.httpx, "post", return_value=response) as post:
            groq_client._chat_completion("prompt")
        payload = post.call_args.kwargs["json"]
        self.assertEqual(payload["model"], "openai/gpt-oss-20b")
        self.assertEqual(payload["response_format"], {"type": "json_object"})
        self.assertEqual(payload["temperature"], 0.2)
        self.assertEqual(payload["max_tokens"], 4096)
        self.assertNotIn("tools", payload)
        self.assertNotIn("stream", payload)
        self.assertNotIn("reasoning_effort", payload)
        self.assertNotIn("max_completion_tokens", payload)

    def test_existing_proposal_validation_remains_strict(self):
        data = {"proposals": [_proposal("/api/secret"), _proposal("/api/items"), _proposal("/health")]}
        with self.assertRaises(ProposalValidationError):
            validate_discovery_assessment_proposals(data, _context())

    def test_valid_groq_response_still_works(self):
        data = {"proposals": [_proposal("/"), _proposal("/api/items"), _proposal("/health")]}
        response = _response(
            200,
            {"choices": [{"message": {"content": json.dumps(data)}}]},
        )
        with mock.patch.object(groq_client.httpx, "post", return_value=response):
            assessment = groq_client.propose_discovery_assessment(_context())
        self.assertEqual(len(assessment.proposals), 3)
        self.assertEqual([p.request.path for p in assessment.proposals], ["/", "/api/items", "/health"])

    def test_json_object_fallback_is_validated_strictly(self):
        data = {"proposals": [_proposal("/"), _proposal("/api/items"), _proposal("/api/secret")]}
        response = _response(
            200,
            {"choices": [{"message": {"content": json.dumps(data)}}]},
        )
        with mock.patch.object(groq_client.httpx, "post", return_value=response):
            with self.assertRaises(ProposalValidationError):
                groq_client.propose_discovery_assessment(_context())


if __name__ == "__main__":
    unittest.main(verbosity=1)
