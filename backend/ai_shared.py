"""Shared AI provider logic for BreakTrace.

This module holds everything that does NOT depend on the specific inference
backend (Nosana/Ollama vs Groq):

- the hardcoded controlled application context + prompts
- JSON extraction from raw model output
- the strict allowlist + Pydantic validation gate
- the short-lived in-memory proposal/assessment caches

Providers are responsible ONLY for transport + response extraction:
application context -> LLM -> raw structured JSON. Everything from Pydantic
validation onward is shared and identical for every provider.
"""

import json
import re
import time

from pydantic import ValidationError

from models import (
    AttackRelationshipAnalysis,
    BreakTraceActor,
    ExecutableExperimentInput,
    SecurityAssessmentProposal,
    SecurityObservation,
    SecurityTestProposal,
)


# ---------------------------------------------------------------------------
# Generic provider errors
# ---------------------------------------------------------------------------


class ProviderConfigError(RuntimeError):
    """Configuration is missing or invalid for the configured AI provider."""


class ProviderUnavailableError(RuntimeError):
    """The AI provider endpoint is unreachable, errored, or returned
    unparseable output."""


class ProposalValidationError(RuntimeError):
    """The model output failed Pydantic or allowlist validation."""


class DuplicateProposalsError(ProposalValidationError):
    """The model returned duplicate method/path combinations.

    Subclass of ProposalValidationError so it maps to the same clean 422
    response, but the assessment flow can catch it to make ONE retry.
    """


# ---------------------------------------------------------------------------
# JSON extraction
# ---------------------------------------------------------------------------


def extract_json(text: str) -> dict | None:
    """Best-effort extraction of a JSON object from model output.

    Tries strict JSON parsing first, then falls back to grabbing the first
    {...} block in the text (in case the model wrapped the JSON in prose or
    markdown code fences).
    """
    text = text.strip()
    try:
        data = json.loads(text)
        return data if isinstance(data, dict) else None
    except (ValueError, TypeError):
        pass
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match is None:
        return None
    try:
        data = json.loads(match.group(0))
        return data if isinstance(data, dict) else None
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Allowlist validation
# ---------------------------------------------------------------------------

# For M4 the allowed capabilities are intentionally tiny: Alice, GET, one of
# the two known invoices, and only statuses the demo app can actually produce.
_ALLOWED_ACTOR_NAME = "Alice"
_ALLOWED_ACTOR_USER_ID = 1
_ALLOWED_METHODS = {"GET"}
_ALLOWED_PATH_RE = re.compile(r"^/api/invoices/([0-9]+)$")
_ALLOWED_INVOICE_IDS = {1, 2}
_ALLOWED_EXPECTED_STATUSES = {200, 403, 404}
_MAX_TEXT_LEN = 300

# Characters that must never appear in a proposed path (query injection,
# traversal, shell syntax, external hosts, ...). The path regex above already
# rejects these; this is defense in depth.
_FORBIDDEN_PATH_TOKENS = ("://", "..", ";", "|", "?", "#", "\\", " ", "\t")

# Milestone 5 assessment allowlist. Slightly wider than M4: the demo app now
# exposes an admin endpoint and a protected DELETE, and only 403 is a
# meaningful "secure" expectation for these invariants.
_ALLOWED_ASSESSMENT_METHODS = {"GET", "DELETE"}
_ALLOWED_ASSESSMENT_REQUESTS = {
    ("GET", "/api/invoices/1"),
    ("GET", "/api/invoices/2"),
    ("GET", "/api/admin/users"),
    ("DELETE", "/api/invoices/1"),
    ("DELETE", "/api/invoices/2"),
}
_ALLOWED_ASSESSMENT_EXPECTED_STATUSES = {403}
_ASSESSMENT_COUNT = 3


def _validate_text_fields(proposal: SecurityTestProposal) -> None:
    """Sanity-check the free-form AI text fields.

    Title/hypothesis/invariant/reason are display-only, but must still be
    non-empty, bounded in length, and free of control characters.

    Raises:
        ProposalValidationError: If any text field is unacceptable.
    """
    for field_name in ("title", "category", "hypothesis", "invariant", "reason"):
        value = getattr(proposal, field_name)
        if not value.strip():
            raise ProposalValidationError(
                f"Proposal rejected: {field_name} is empty."
            )
        if len(value) > _MAX_TEXT_LEN:
            raise ProposalValidationError(
                f"Proposal rejected: {field_name} exceeds {_MAX_TEXT_LEN} chars."
            )
        if any(ord(ch) < 32 and ch not in "\n\t" for ch in value):
            raise ProposalValidationError(
                f"Proposal rejected: {field_name} contains control characters."
            )


def validate_proposal(data: dict) -> SecurityTestProposal:
    """Parse model output into a SecurityTestProposal and enforce the
    allowlist.

    Raises:
        ProposalValidationError: If the output is not a valid proposal or
            violates the allowlist.
    """
    try:
        proposal = SecurityTestProposal.model_validate(data)
    except ValidationError as exc:
        raise ProposalValidationError(
            f"Model output did not match the required proposal schema: {exc}"
        ) from exc

    # Actor: only Alice (user_id 1).
    if (
        proposal.actor.name != _ALLOWED_ACTOR_NAME
        or proposal.actor.user_id != _ALLOWED_ACTOR_USER_ID
    ):
        raise ProposalValidationError(
            "Proposal rejected: actor must be Alice (user_id 1)."
        )

    # Method: only GET.
    if proposal.request.method not in _ALLOWED_METHODS:
        raise ProposalValidationError(
            f"Proposal rejected: method {proposal.request.method!r} is not allowed."
        )

    # Path: only /api/invoices/{integer} with a known invoice id.
    path = proposal.request.path
    match = _ALLOWED_PATH_RE.match(path)
    if match is None or any(token in path for token in _FORBIDDEN_PATH_TOKENS):
        raise ProposalValidationError(
            f"Proposal rejected: path {path!r} is not an allowed endpoint."
        )
    if int(match.group(1)) not in _ALLOWED_INVOICE_IDS:
        raise ProposalValidationError(
            f"Proposal rejected: invoice id in {path!r} is not in the allowlist."
        )

    # Expected status: only statuses the demo app can produce.
    if proposal.expected_status not in _ALLOWED_EXPECTED_STATUSES:
        raise ProposalValidationError(
            f"Proposal rejected: expected status {proposal.expected_status} "
            "is not allowed."
        )

    _validate_text_fields(proposal)
    return proposal


def _validate_assessment_proposal(
    proposal: SecurityTestProposal, index: int
) -> None:
    """Enforce the assessment allowlist on ONE proposal.

    Strictly validated fields: actor, method, path, expected_status.
    Free-form fields (title, hypothesis, invariant, reason) are only
    sanity-checked - exact wording is never required.

    Raises:
        ProposalValidationError: If the proposal violates the allowlist.
    """
    if (
        proposal.actor.name != _ALLOWED_ACTOR_NAME
        or proposal.actor.user_id != _ALLOWED_ACTOR_USER_ID
    ):
        raise ProposalValidationError(
            f"Proposal {index} rejected: actor must be Alice (user_id 1)."
        )

    pair = (proposal.request.method, proposal.request.path)
    if pair not in _ALLOWED_ASSESSMENT_REQUESTS:
        raise ProposalValidationError(
            f"Proposal {index} rejected: {proposal.request.method} "
            f"{proposal.request.path!r} is not an allowed request."
        )
    if any(
        token in proposal.request.path for token in _FORBIDDEN_PATH_TOKENS
    ):
        raise ProposalValidationError(
            f"Proposal {index} rejected: path contains forbidden tokens."
        )

    if proposal.expected_status not in _ALLOWED_ASSESSMENT_EXPECTED_STATUSES:
        raise ProposalValidationError(
            f"Proposal {index} rejected: expected status "
            f"{proposal.expected_status} is not allowed (only 403)."
        )

    _validate_text_fields(proposal)


def validate_assessment_proposals(data) -> SecurityAssessmentProposal:
    """Parse model output into exactly 3 proposals and enforce the allowlist
    on every one of them.

    Also rejects duplicate (method, path) combinations so the assessment
    covers three DISTINCT invariants.

    Raises:
        ProposalValidationError: Schema/allowlist failure.
        DuplicateProposalsError: Duplicate method/path pairs (triggers one
            retry upstream).
    """
    # Tolerate a bare list as well as the {"proposals": [...]} wrapper.
    if isinstance(data, list):
        data = {"proposals": data}
    try:
        assessment = SecurityAssessmentProposal.model_validate(data)
    except ValidationError as exc:
        raise ProposalValidationError(
            "Model output did not match the required assessment schema "
            f"(exactly 3 proposals): {exc}"
        ) from exc

    for index, proposal in enumerate(assessment.proposals, start=1):
        _validate_assessment_proposal(proposal, index)

    pairs = [(p.request.method, p.request.path) for p in assessment.proposals]
    if len(set(pairs)) != len(pairs):
        raise DuplicateProposalsError(
            "Proposal rejected: duplicate method/path pairs. Each of the 3 "
            "proposals must test a distinct request."
        )

    return assessment


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

# Controlled application context. Hardcoded - the AI may only reason about
# this exact, deliberately vulnerable application.
_APPLICATION_CONTEXT = """
APPLICATION
This is a multi-user invoice application.

USERS
Alice: user_id = 1
Bob: user_id = 2

AUTHENTICATION
The currently authenticated user is Alice (user_id = 1).

RESOURCES
Invoices contain: id, owner_id, owner, amount

DATA
Invoice 1: id = 1, owner_id = 1, owner = Alice, amount = 120
Invoice 2: id = 2, owner_id = 2, owner = Bob, amount = 450

ENDPOINTS
GET /api/invoices/{invoice_id}
Returns an invoice by ID.

SECURITY GOAL
Identify ONE authorization-related security invariant worth testing.
Create ONE bounded HTTP test that can determine whether the invariant is enforced.
Only use endpoints explicitly provided above.
Do not invent endpoints.
Do not generate shell commands.
Do not generate scripts.
Do not generate URLs outside this application.
"""

_JSON_SCHEMA = """
{
  "title": "short test title",
  "category": "e.g. broken_access_control",
  "hypothesis": "one-sentence security hypothesis",
  "invariant": "the security invariant being tested",
  "actor": {"name": "Alice", "user_id": 1},
  "request": {"method": "GET", "path": "/api/invoices/{invoice_id}"},
  "expected_status": 403,
  "reason": "why this request tests the invariant"
}
"""


def build_single_test_prompt() -> str:
    return (
        "You are a defensive application security test planner.\n"
        "Your task is to identify ONE security invariant worth testing from "
        "the provided application description.\n"
        "You may only propose a bounded HTTP request using the provided "
        "actors, resources, and endpoints.\n"
        "You are NOT executing the test.\n"
        "Do not generate shell commands, scripts, exploit code, external "
        "URLs, or additional endpoints.\n"
        "Return JSON only.\n"
        f"\n{_APPLICATION_CONTEXT}\n"
        "Return exactly one JSON object matching this schema:\n"
        f"{_JSON_SCHEMA}"
    )


# ---------------------------------------------------------------------------
# Milestone 5 - multi-proposal assessment prompt
# ---------------------------------------------------------------------------

# Expanded controlled application context: three users with roles, an
# admin-only endpoint and a state-changing DELETE. Still hardcoded - the AI
# may only reason about this exact demo application.
_ASSESSMENT_APPLICATION_CONTEXT = """
APPLICATION
This is a multi-user invoice application.

USERS
Alice: user_id = 1, role = user
Bob: user_id = 2, role = user
Admin: user_id = 99, role = admin

AUTHENTICATION
The currently authenticated user is Alice (user_id = 1, role = user).

RESOURCES
Invoices contain: id, owner_id, owner, amount

DATA
Invoice 1: id = 1, owner_id = 1, owner = Alice, amount = 120
Invoice 2: id = 2, owner_id = 2, owner = Bob, amount = 450

ENDPOINTS
GET /api/invoices/{invoice_id}
Returns an invoice by ID.

GET /api/admin/users
Returns a list of users (admin-only).

DELETE /api/invoices/{invoice_id}
Attempts to delete an invoice.

SECURITY OBJECTIVE
Identify DISTINCT authorization/security invariants worth testing.
"""

_ASSESSMENT_JSON_SCHEMA = """
{
  "proposals": [
    {
      "title": "short test title",
      "category": "e.g. broken_access_control",
      "hypothesis": "one-sentence security hypothesis",
      "invariant": "the security invariant being tested",
      "actor": {"name": "Alice", "user_id": 1},
      "request": {"method": "GET or DELETE", "path": "one of the provided endpoints"},
      "expected_status": 403,
      "reason": "why this request tests the invariant"
    }
  ]
}
"""


def build_assessment_prompt() -> str:
    return (
        "You are a defensive application security test planner.\n"
        "Analyze the provided application description.\n"
        f"Generate exactly {_ASSESSMENT_COUNT} DISTINCT authorization-related "
        "security tests.\n"
        "Each test must test a DIFFERENT security invariant.\n"
        "Use only the actors, resources, methods, IDs and endpoints provided.\n"
        "Do not assume whether the application is vulnerable - you are "
        "proposing hypotheses to verify.\n"
        "You are NOT executing the tests.\n"
        "Do not generate shell commands, scripts, exploit code, external "
        "URLs, or additional endpoints.\n"
        "Return JSON only.\n"
        f"\n{_ASSESSMENT_APPLICATION_CONTEXT}\n"
        f"Return exactly one JSON object with a \"proposals\" array "
        f"containing exactly {_ASSESSMENT_COUNT} objects, each matching this "
        "schema:\n"
        f"{_ASSESSMENT_JSON_SCHEMA}\n"
        "Each proposal must use a UNIQUE method + path combination."
    )


# ---------------------------------------------------------------------------
# Milestone 8 - discovery-based assessment (independent application targets)
# ---------------------------------------------------------------------------

# The AI reasons from DISCOVERED application context (routes, auth signals,
# models) instead of the hardcoded Alice/Bob description. Tests stay
# declarative: method + path + expected_status only, restricted to routes
# discovered from the sandbox-local instance. No shell, no code, no URLs.
_DISCOVERY_METHODS = {"GET", "DELETE"}
_DISCOVERY_EXPECTED_STATUSES = {200, 401, 403, 404}
_DISCOVERY_MAX_QUERY_LEN = 200
_DISCOVERY_FORBIDDEN_QUERY_TOKENS = ("://", ";", "|", "\\", " ", "\t", "\n", "\r")
_DISCOVERY_FORBIDDEN_KEYS = ("command", "script", "code", "payload", "exec")
_DISCOVERY_MAX_ACTOR_NAME = 60

# Milestone 12 - safe request-header allowlist for executable experiments.
# Only a tiny controlled set of headers may be sent (e.g. X-Demo-User for the
# regression demo). Dangerous hop-by-hop / destination-controlling / sensitive
# headers are always rejected, and values must be bounded strings with no
# CR/LF.
_ALLOWED_EXPERIMENT_HEADERS = {"X-Demo-User"}
_FORBIDDEN_HEADER_NAMES = {
    "host", "connection", "content-length", "transfer-encoding", "te",
    "trailer", "proxy-authenticate", "proxy-authorization", "forwarded",
    "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "upgrade",
}
_MAX_HEADER_KEY_LEN = 64
_MAX_HEADER_VALUE_LEN = 100

_DISCOVERY_INSTRUCTIONS = """
You are performing an authorized educational security assessment of an
intentionally vulnerable application running inside an isolated sandbox.

Analyze the supplied application context.

Identify security assumptions and trust boundaries that are worth testing,
preferring diverse, high-value security properties (access-control
assumptions, authentication boundaries, sensitive-data exposure, input
validation, state/business-rule violations) rather than multiple variations
of the same test.

Generate exactly 3 DISTINCT bounded security hypotheses.
Each hypothesis must be expressible as ONE declarative HTTP request using
ONLY the discovered endpoints listed above.
A request may include a short query string (max 200 chars).

You are proposing HYPOTHESES, not vulnerabilities. Do not assume a
vulnerability exists. Do not claim a vulnerability unless runtime execution
verifies it.

Do not generate shell commands, scripts, code, absolute URLs, or endpoints
not listed above.
Return JSON only.
"""


def _context_value(item, field: str, default=""):
    """Read a context field across typed Pydantic and legacy mapping values."""
    if isinstance(item, str):
        return item
    if hasattr(item, field):
        return getattr(item, field)
    if isinstance(item, dict):
        return item.get(field, default)
    return default


def _semantic_prompt_block(context) -> str:
    """Generic authorization-semantics context + reasoning guidance.

    Surfaces the conservative discovery signals (identity inputs, resource
    ownership relationships, fictional seed entities) and tells the AI how to
    reason about cross-user authorization without hardcoding any IDs.
    """
    identity_inputs = getattr(context, "identity_inputs", []) or []
    relationships = getattr(context, "resource_relationships", []) or []
    seed_entities = getattr(context, "seed_entities", []) or []

    def _kv(item, key, default=""):
        return str(getattr(item, key, default) or default)

    identity_text = "\n".join(
        f"- {_kv(ii,'name')} (kind={_kv(ii,'kind')}, purpose={_kv(ii,'purpose')}, "
        f"source={_kv(ii,'source')}, confidence={_kv(ii,'confidence')})"
        for ii in identity_inputs[:20]
    ) or "none detected"
    rel_lines = []
    for rel in relationships[:20]:
        owners_txt = ", ".join(
            f"{k}->{v}" for k, v in sorted((getattr(rel, "owners", None) or {}).items())
        )
        rel_lines.append(
            f"- resource={_kv(rel,'resource')}, id_field={_kv(rel,'resource_identifier')}, "
            f"owner_field={_kv(rel,'owner_field')}, identity_field={_kv(rel,'identity_field')}, "
            f"resource_ids={sorted(getattr(rel,'resource_identifiers',[]) or [])}, "
            f"principal_ids={sorted(getattr(rel,'principal_identifiers',[]) or [])}, "
            f"owners={owners_txt or '{}'}, confidence={_kv(rel,'confidence')}"
        )
    rel_text = "\n".join(rel_lines) or "none detected"
    seed_lines = []
    for se in seed_entities[:20]:
        labels_txt = "-".join(
            f"{k}:{v}" for k, v in sorted((getattr(se, "labels", None) or {}).items())
        )
        seed_lines.append(
            f"- {_kv(se,'entity_type')} ids={sorted(getattr(se,'identifiers',[]) or [])}"
            + (f" labels={labels_txt}" if labels_txt else "")
        )
    seed_text = "\n".join(seed_lines) or "none detected"
    return (
        f"IDENTITY INPUTS (request fields consumed as the caller identity; never "
        f"a real credential value)\n{identity_text}\n"
        f"RESOURCE OWNERSHIP RELATIONSHIPS (discovered statically - which resource "
        f"record field stores its owner)\n{rel_text}\n"
        f"SEED ENTITIES (clearly fictional static fixtures - select IDs only from "
        f"these; never invent ids that are not listed)\n{seed_text}\n"
        "AUTHENTICATION vs AUTHORIZATION (distinguish the two):\n"
        "- AUTHENTICATION question: can an anonymous caller (no identity input) "
        "reach a resource that should require a principal identity? That tests "
        "missing authentication, NOT IDOR.\n"
        "- AUTHORIZATION question: an authenticated principal requests a resource "
        "owned by a DIFFERENT principal (e.g. principal A -> GET /resource/:id "
        "owned by B -> expect denial such as 403). If an identity input exists, "
        "a resource route has an owner field, and the seed lists at least two "
        "distinct principals/resources, PREFER the cross-user (IDOR / broken "
        "access control) experiment and supply the matching identity header "
        "with the principal's id from the seed evidence. Do NOT label an "
        "unauthenticated request as IDOR.\n"
    )


def build_discovery_assessment_prompt(context, extra_context: str | None = None) -> str:
    """Build the AI prompt from DISCOVERED application context.

    The AI may only reason about the discovered endpoints of the sandbox-local
    instance - never about other hosts. The discovered routes are provided
    both as a human-readable list and as an explicit machine-readable JSON
    array, with a STRICT instruction to propose experiments ONLY against
    those routes. `extra_context` (Milestone 9) carries the deterministic-
    check and regression-replay summaries so the AI avoids duplicating
    already-covered conditions.

    Validation remains mandatory regardless: the LLM can still hallucinate
    endpoints, and every proposal passes the same allowlist gate.
    """
    routes_text = "\n".join(
        f"- {r.method} {r.path} (discovered via {r.source})"
        for r in context.routes[:80]
    )
    routes_json = json.dumps(
        [f"{r.method} {r.path}" for r in context.routes[:80]],
        separators=(",", ":"),
    )
    auth_text = ", ".join(context.auth_signals) or "none detected"
    models_text = ", ".join(context.models) or "none detected"
    components_text = ", ".join(context.security_relevant_components) or "none"
    frameworks_text = ", ".join(getattr(context, "frameworks", [])) or context.framework or "unknown"
    services_text = ", ".join(
        _context_value(service, "type")
        for service in (getattr(context, "external_service_sdks", []) or getattr(context, "external_services", []))
    ) or "none detected"
    data_text = ", ".join(
        f"{resource.name} ({', '.join(resource.operations) or 'operation unknown'})"
        for resource in getattr(context, "data_resources", [])
    ) or "none detected"
    storage_text = ", ".join(
        f"{resource.name} ({', '.join(resource.operations) or 'operation unknown'})"
        for resource in getattr(context, "storage_resources", [])
    ) or "none detected"
    capability_text = ", ".join(
        _context_value(capability, "name")
        for capability in getattr(context, "capabilities", [])
    ) or "none detected"
    auth_usage_text = ", ".join(getattr(context, "authentication_usage", [])) or "none detected"
    semantic_block = _semantic_prompt_block(context)
    prompt = (
        _DISCOVERY_INSTRUCTIONS
        + f"\n\nAPPLICATION\n{context.name}\n"
        f"FRAMEWORKS (descriptive signals)\n{frameworks_text}\n"
        f"DEPENDENCIES (names only)\n{', '.join(getattr(context, 'dependencies', [])) or 'none detected'}\n"
        f"EXTERNAL SERVICES / SDKs\n{services_text}\n"
        f"SANDBOX-LOCAL ORIGIN (never test any other host)\n"
        f"{context.runtime_origin}\n"
        f"AUTHENTICATION PROVIDER SIGNALS\n{', '.join(getattr(context, 'authentication_provider', [])) or 'none detected'}\n"
        f"AUTHENTICATION USAGE SIGNALS\n{auth_usage_text}\n"
        f"MODELS (server-side only; never infer from service tables)\n{models_text}\n"
        f"DATA RESOURCES (NOT REST ENDPOINTS)\n{data_text}\n"
        f"STORAGE RESOURCES (NOT REST ENDPOINTS)\n{storage_text}\n"
        f"CAPABILITIES (descriptive only)\n{capability_text}\n"
        f"SECURITY-RELEVANT COMPONENTS\n{components_text}\n"
        f"{semantic_block}"
        f"DISCOVERED ENDPOINTS (human-readable)\n{routes_text}\n"
        f"DISCOVERED ENDPOINTS (machine-readable allowlist)\n{routes_json}\n"
        f"SPA FALLBACK DETECTED\n{getattr(context, 'spa_fallback_detected', False)}\n"
        "IMPORTANT: Supabase table names are NOT REST endpoints. Do not "
        "convert data resources such as users or reports into /api/users or "
        "/api/reports. Do not invent /api/admin.\n"
        "STRICT RULE: You may ONLY propose experiments against one of these "
        "discovered routes, and executable HTTP experiments may only use "
        "runtime/repository routes in this allowlist. Any other route will "
        "be rejected by validation. Do NOT invent endpoints.\n"
        "If a hypothesis concerns an external service not running in this "
        "Security Twin, represent it as a security observation with "
        "verification not_verifiable_in_twin, not as a verified finding.\n"
    )
    if extra_context:
        prompt += (
            "\nALREADY COVERED CONTEXT (do NOT duplicate these; propose "
            "only NEW application-specific hypotheses):\n"
            f"{extra_context}\n"
        )
    prompt += (
        f"\n{_ASSESSMENT_JSON_SCHEMA}\n"
        "Each proposal must use a UNIQUE method + path combination."
    )
    return prompt


_PARAM_RE = re.compile(r":[A-Za-z_][A-Za-z0-9_]*")


def _path_matches(candidate: str, discovered: str) -> bool:
    """Match a concrete path against a discovered route (with :params)."""
    if candidate == discovered:
        return True
    if ":" not in discovered:
        return False
    regex_parts = []
    for part in discovered.split("/"):
        if _PARAM_RE.fullmatch(part):
            regex_parts.append("[^/]+")
        else:
            regex_parts.append(re.escape(part))
    return re.fullmatch("/".join(regex_parts), candidate) is not None


def _route_matches(method: str, base_path: str, routes) -> bool:
    """True if (method, path) corresponds to a discovered route."""
    for route in routes:
        if route.method not in ("ANY", method):
            continue
        if _path_matches(base_path, route.path):
            return True
    return False


def _reject_code_fields_in(obj: dict, label: str) -> None:
    """Raise if `obj` contains a forbidden smuggling key."""
    for key in _DISCOVERY_FORBIDDEN_KEYS:
        if key in obj:
            raise ProposalValidationError(
                f"Proposal rejected: field {key!r} in {label} is not "
                "allowed (no shell commands, scripts, code, or payloads)."
            )


def _reject_code_fields(data) -> None:
    """Reject any attempt to smuggle commands/scripts/code/URLs through
    unknown proposal keys. The declarative schema has no such fields; this
    is defense in depth.

    Raises:
        ProposalValidationError: If a forbidden key is present.
    """
    if isinstance(data, dict):
        _reject_code_fields_in(data, "top level")
        for i, proposal in enumerate(data.get("proposals") or [], start=1):
            if isinstance(proposal, dict):
                _reject_code_fields_in(proposal, f"proposal {i}")


def _query_param_names(path: str) -> list[str]:
    """Extract the query parameter NAMES from a path with a query string.

    e.g. "/api/x?admin=true&debug=1" -> ["admin", "debug"]. Names are taken
    as the text before the first '=' (or the whole token when no '=' is
    present, e.g. a bare flag "/x?debug"). Non-identifier tokens that cannot
    be a real parameter name are ignored.
    """
    _, sep, query = path.partition("?")
    if not sep:
        return []
    names: list[str] = []
    seen: set = set()
    for pair in query.split("&"):
        name = pair.split("=", 1)[0]
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) and name not in seen:
            seen.add(name)
            names.append(name)
    return names


def _discovered_query_params(context) -> set:
    """The query parameter names evidenced in the discovered context."""
    return set(getattr(context, "query_parameters", None) or [])


def _validate_experiment_headers(request, context, index: int) -> None:
    """Enforce a tight, safe allowlist on executable-experiment request
    headers.

    Rejects dangerous headers (host/connection/content-length/transfer-
    encoding/proxy-*/forwarded/x-forwarded-*/hop-by-hop), any header not in
    the allowlist, non-string keys/values, CR/LF (header injection), and
    over-length values. Requests remain sandbox-local regardless.

    Raises:
        ProposalValidationError: If a header violates the policy.
    """
    headers = getattr(request, "headers", None) or {}
    if not headers:
        return
    allowed = set(getattr(context, "allowed_request_headers", None) or [])
    allowed |= set(_ALLOWED_EXPERIMENT_HEADERS)
    for key, value in (headers or {}).items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ProposalValidationError(
                f"Experiment {index} rejected: request headers must have "
                "string keys and values."
            )
        if key.lower() in _FORBIDDEN_HEADER_NAMES:
            raise ProposalValidationError(
                f"Experiment {index} rejected: header {key!r} is forbidden."
            )
        if key not in allowed:
            raise ProposalValidationError(
                f"Experiment {index} rejected: header {key!r} is not in the "
                "allowed header allowlist for this application."
            )
        if any(ch in key for ch in ("\r", "\n", ":")) or any(
            ch in value for ch in ("\r", "\n")
        ):
            raise ProposalValidationError(
                f"Experiment {index} rejected: header {key!r} contains "
                "CR/LF or invalid characters (header injection blocked)."
            )
        if len(key) > _MAX_HEADER_KEY_LEN or len(value) > _MAX_HEADER_VALUE_LEN:
            raise ProposalValidationError(
                f"Experiment {index} rejected: header {key!r} key/value "
                "exceeds the length limit."
            )


def _route_param_seed_values(base, context):
    """Return (resource_name, identifiers, param_value) when `base` matches a
    discovered parameterized route whose parameter's preceding path segment
    names a discovered resource with non-empty seed identifiers.

    This is how concrete route parameters are bound to seed evidence: the
    value instantiated into `:id` must be one of the ids actually seen in
    repository source. Returns None when there is no such constraint.
    """
    for route in getattr(context, "routes", []) or []:
        template = route.path.split("?")[0].rstrip("/")
        if ":" not in template or not _path_matches(base.rstrip("/"), template):
            continue
        tsegs = template.split("/")
        pidxs = [i for i, s in enumerate(tsegs) if s.startswith(":")]
        if not pidxs or pidxs[0] == 0:
            continue
        j = pidxs[0]
        segs = base.rstrip("/").split("/")
        if j >= len(segs):
            continue
        resource_name = tsegs[j - 1]
        val = segs[j]
        for rel in getattr(context, "resource_relationships", []) or []:
            if (getattr(rel, "resource", "") or "").lower() == resource_name.lower():
                ids = [int(i) for i in (getattr(rel, "resource_identifiers", []) or [])]
                if ids:
                    return resource_name, ids, val
    return None


def _validate_discovery_proposal(
    proposal: SecurityTestProposal, index: int, context
) -> None:
    """Enforce the discovery allowlist on ONE proposal (Milestone 11 strict
    executable-experiment validation).

    Guarantees per executable experiment: supported method, sandbox-local
    path matching a DISCOVERED route (no external URLs, no undiscovered
    endpoints, no ://, no forbidden query tokens), bounded query strings and
    text fields, and - crucially - NO invented query parameters. Every query
    parameter in the path must be evidenced in the discovered ApplicationContext
    (query_parameters); otherwise the experiment is rejected and is NEVER
    executed.

    Milestone 12 - when the parameterized route is linked to a discovered
    resource with seed identifiers, the concrete `:param` value must be one of
    those identifiers (no guessed path values unrelated to evidence).

    Raises:
        ProposalValidationError: If the proposal violates the allowlist.
    """
    method = proposal.request.method
    path = proposal.request.path
    base, sep, query = path.partition("?")

    if method not in _DISCOVERY_METHODS:
        raise ProposalValidationError(
            f"Proposal {index} rejected: method {method!r} is not "
            f"supported (allowed: {', '.join(sorted(_DISCOVERY_METHODS))})."
        )
    if not base.startswith("/"):
        raise ProposalValidationError(
            f"Proposal {index} rejected: request path must be a "
            "sandbox-local path."
        )
    if "://" in path or path.startswith("//"):
        raise ProposalValidationError(
            f"Proposal {index} rejected: absolute/external URLs are "
            "never allowed."
        )
    if not _route_matches(method, base, context.routes):
        raise ProposalValidationError(
            f"Proposal {index} rejected: {method} {base!r} is not a "
            "discovered endpoint of this application."
        )
    if sep:
        if len(query) > _DISCOVERY_MAX_QUERY_LEN:
            raise ProposalValidationError(
                f"Proposal {index} rejected: query string exceeds "
                f"{_DISCOVERY_MAX_QUERY_LEN} chars."
            )
        if any(
            token in query for token in _DISCOVERY_FORBIDDEN_QUERY_TOKENS
        ):
            raise ProposalValidationError(
                f"Proposal {index} rejected: query string contains "
                "forbidden characters."
            )
        # Milestone 11 - no invented query parameters. Each parameter must be
        # evidenced by repository/runtime discovery. We do NOT strip the query
        # and fall back to '/': the experiment is rejected outright.
        evidenced = _discovered_query_params(context)
        for name in _query_param_names(path):
            if name not in evidenced:
                raise ProposalValidationError(
                    f"Proposal {index} rejected: query parameter {name!r} "
                    "was not discovered in repository or runtime context."
                )
    # Milestone 12 - safe request-header allowlist (X-Demo-User etc.).
    _validate_experiment_headers(proposal.request, context, index)
    # Milestone 12 - bind parameterized route values to discovered seed ids.
    bound = _route_param_seed_values(base, context)
    if bound is not None:
        _, seed_ids, val = bound
        try:
            ival = int(val)
        except (TypeError, ValueError):
            ival = None
        if ival is None or ival not in seed_ids:
            raise ProposalValidationError(
                f"Proposal {index} rejected: {method} {base!r} instantiates "
                f"the route parameter with {val!r}, which is not in the "
                f"discovered seed identifiers {sorted(seed_ids)}. Path "
                "parameters must use a value evidenced in repository source."
            )
    if proposal.expected_status not in _DISCOVERY_EXPECTED_STATUSES:
        raise ProposalValidationError(
            f"Proposal {index} rejected: expected status "
            f"{proposal.expected_status} is not allowed "
            f"({sorted(_DISCOVERY_EXPECTED_STATUSES)})."
        )
    if len(proposal.actor.name) > _DISCOVERY_MAX_ACTOR_NAME:
        raise ProposalValidationError(
            f"Proposal {index} rejected: actor name is too long."
        )
    _validate_text_fields(proposal)


def validate_discovery_assessment_proposals(data, context) -> SecurityAssessmentProposal:
    """Validate an AI assessment against DISCOVERED application context.

    Strict path (Milestone 8): if ANY proposal fails, the whole assessment is
    rejected. The Security Twin pipeline uses the per-proposal split variant
    (split_discovery_assessment) instead, so one rejected proposal can never
    abort an assessment.

    Guarantees:
    - exactly 3 distinct proposals
    - method is supported (GET/DELETE)
    - path is a sandbox-local path matching a DISCOVERED route (no external
      URLs, no undiscovered endpoints, no ://, no forbidden query tokens)
    - bounded query strings and text fields
    - no shell/script/code/payload keys

    Raises:
        ProposalValidationError: Any validation failure.
        DuplicateProposalsError: Duplicate method/path pairs.
    """
    if isinstance(data, list):
        data = {"proposals": data}
    _reject_code_fields(data)

    try:
        assessment = SecurityAssessmentProposal.model_validate(data)
    except ValidationError as exc:
        raise ProposalValidationError(
            "Model output did not match the required assessment schema "
            f"(exactly 3 proposals): {exc}"
        ) from exc

    for index, proposal in enumerate(assessment.proposals, start=1):
        _validate_discovery_proposal(proposal, index, context)

    pairs = [(p.request.method, p.request.path) for p in assessment.proposals]
    if len(set(pairs)) != len(pairs):
        raise DuplicateProposalsError(
            "Proposal rejected: duplicate method/path pairs. Each of the 3 "
            "proposals must test a distinct request."
        )
    return assessment


def split_discovery_assessment(data, context):
    """Validate an AI assessment against DISCOVERED context, ONE proposal at
    a time (Security Twin Layer 3 reliability fix).

    A rejected proposal must never abort the whole assessment: valid
    proposals are returned for execution and invalid ones are recorded with
    a reason. The validator itself is NOT weakened - every proposal still
    passes the same allowlist gate as the strict path, and rejected
    proposals are never executed and never become findings.

    Returns:
        (valid: list[SecurityTestProposal], rejected: list[dict])
        where each rejected entry is:
            {"index": int, "hypothesis": str, "reason": str}

    Raises:
        ProposalValidationError: ONLY for whole-response structural failures
            (not a dict, missing proposals array, top-level smuggling keys).
    """
    if isinstance(data, list):
        data = {"proposals": data}
    if not isinstance(data, dict):
        raise ProposalValidationError(
            "Model output was not a JSON object with a proposals array."
        )
    _reject_code_fields_in(data, "top level")

    raw = data.get("proposals")
    if not isinstance(raw, list):
        raise ProposalValidationError(
            "Model output did not contain a proposals array."
        )

    valid: list[SecurityTestProposal] = []
    rejected: list[dict] = []
    seen_pairs: set = set()
    for index, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            rejected.append(
                {
                    "index": index,
                    "hypothesis": "",
                    "reason": f"Proposal {index} rejected: not a JSON object.",
                }
            )
            continue
        try:
            _reject_code_fields_in(item, f"proposal {index}")
        except ProposalValidationError as exc:
            rejected.append(
                {"index": index, "hypothesis": "", "reason": str(exc)}
            )
            continue
        try:
            proposal = SecurityTestProposal.model_validate(item)
        except ValidationError as exc:
            rejected.append(
                {
                    "index": index,
                    "hypothesis": str(item.get("hypothesis", "")),
                    "reason": (
                        f"Proposal {index} rejected: model output did not "
                        "match the required proposal schema."
                    ),
                }
            )
            continue
        try:
            _validate_discovery_proposal(proposal, index, context)
        except ProposalValidationError as exc:
            rejected.append(
                {
                    "index": index,
                    "hypothesis": proposal.hypothesis,
                    "reason": str(exc),
                }
            )
            continue
        pair = (proposal.request.method, proposal.request.path)
        if pair in seen_pairs:
            rejected.append(
                {
                    "index": index,
                    "hypothesis": proposal.hypothesis,
                    "reason": (
                        f"Proposal {index} rejected: duplicate method/path "
                        "pair (each proposal must test a distinct request)."
                    ),
                }
            )
            continue
        seen_pairs.add(pair)
        valid.append(proposal)
    return valid, rejected


# ---------------------------------------------------------------------------
# Milestone 11 - executable_experiment vs security_observation
#
# The AI is NOT forced to invent HTTP tests. It returns up to 3 analyses in
# {"analyses": [...]}, each independently an executable_experiment OR a
# security_observation. These two validation paths stay fully separate:
#
#   validate_executable_experiment() - strict; identical allowlist gate to
#       the M8/M9 path, plus invented query-parameter rejection. Only
#       runtime-verified experiments may become findings.
#   validate_security_observation()  - no executable surface allowed, never
#       verifiable, never a finding, never saved to Security Memory.
# ---------------------------------------------------------------------------

_MAX_OBSERVATION_TEXT_LEN = 600


def validate_executable_experiment(
    data: dict, index: int, context
) -> SecurityTestProposal:
    """Parse ONE executable_experiment and enforce the strict allowlist.

    The actor optional at the LLM layer is defaulted to the anonymous actor;
    every other field is validated exactly as in _validate_discovery_proposal,
    including the requirement that any query parameter be discovered.

    Raises:
        ProposalValidationError: If the experiment violates the allowlist.
    """
    if data.get("type") == "executable_experiment":
        data = {k: v for k, v in data.items() if k != "type"}
    try:
        inp = ExecutableExperimentInput.model_validate(data)
    except ValidationError as exc:
        raise ProposalValidationError(
            f"Experiment {index} rejected: model output did not match the "
            f"required executable_experiment schema: {exc}"
        ) from exc
    proposal = SecurityTestProposal(
        title=inp.title,
        category=inp.category,
        hypothesis=inp.hypothesis,
        invariant=inp.invariant,
        actor=inp.actor or BreakTraceActor(name="anonymous", user_id=0),
        request=inp.request,
        expected_status=inp.expected_status,
        reason=inp.reason,
    )
    _validate_discovery_proposal(proposal, index, context)
    return proposal


def validate_security_observation(
    data: dict, index: int = 1
) -> SecurityObservation:
    """Parse ONE security_observation.

    Guarantees:
      - type is security_observation
      - no request / experiment / expected_status / url / payload / code keys
      - evidence references the discovered context (non-empty, bounded)
      - verification is ALWAYS "not_verifiable_in_twin" (Literal)
      - the observation is never marked verified and never carries an
        executable surface

    Raises:
        ProposalValidationError: If the observation is invalid or attempts to
            smuggle an executable surface.
    """
    _reject_code_fields_in(data, f"observation {index}")
    for forbidden in (
        "request", "experiment", "expected_status", "url", "method", "path",
        "shell", "command", "auth_headers", "headers",
    ):
        if forbidden in data:
            raise ProposalValidationError(
                f"Observation {index} rejected: field {forbidden!r} is not "
                "allowed (a security observation contains no executable "
                "request or payload)."
            )
    if data.get("type") not in (None, "security_observation"):
        raise ProposalValidationError(
            f"Observation {index} rejected: type must be "
            "'security_observation'."
        )
    try:
        obs = SecurityObservation.model_validate(data)
    except ValidationError as exc:
        raise ProposalValidationError(
            f"Observation {index} rejected: model output did not match the "
            f"required security_observation schema: {exc}"
        ) from exc
    for field in ("title", "category", "reason"):
        value = getattr(obs, field)
        if not (value or "").strip():
            raise ProposalValidationError(
                f"Observation {index} rejected: {field} is empty."
            )
        if len(value) > _MAX_OBSERVATION_TEXT_LEN:
            raise ProposalValidationError(
                f"Observation {index} rejected: {field} exceeds "
                f"{_MAX_OBSERVATION_TEXT_LEN} chars."
            )
    if obs.verification != "not_verifiable_in_twin":
        raise ProposalValidationError(
            f"Observation {index} rejected: verification must be "
            "not_verifiable_in_twin."
        )
    if not obs.evidence:
        raise ProposalValidationError(
            f"Observation {index} rejected: evidence must reference at "
            "least one discovered context signal."
        )
    for ev in obs.evidence:
        if len(ev) > _MAX_OBSERVATION_TEXT_LEN:
            raise ProposalValidationError(
                f"Observation {index} rejected: evidence entry too long."
            )
    return obs


_SECURITY_ANALYSIS_INSTRUCTIONS = """
You are performing an authorized educational security assessment of an
application running inside an isolated sandbox (a Security Twin).

CRITICAL: YOU ARE NOT REQUIRED TO PRODUCE AN HTTP REQUEST.

Your task is to identify USEFUL SECURITY ANALYSES based on the discovered
application evidence. Generate up to 3 DISTINCT analyses ({max_analyses} or
fewer). Each analysis is independently ONE of two types:

A. executable_experiment
   Use ONLY when BreakTrace has a genuine SANDBOX-LOCAL executable surface
   that it can actually test: a discovered route running inside this twin.
   An experiment is a bounded declarative HTTP request against a DISCOVERED
   route using only DISCOVERED resources and DISCOVERED query parameters.

B. security_observation
   Use when the security question depends on something OUTSIDE the current
   twin or cannot be safely verified inside it (for example external
   Supabase RLS/storage policies, backend trust boundaries). An observation
   is application-specific security reasoning, NOT a vulnerability and NOT a
   finding. Prefer an honest security observation over a fabricated
   executable test.

RULES THAT ALWAYS APPLY:
- A hypothesis is not a vulnerability. A security observation is not a finding.
- Supabase table names are NOT REST endpoints. A "reports" or "users"
  table does not imply /api/reports or /api/users.
- Do NOT invent /api/users, /api/reports, /api/admin, or any other endpoint.
- Do NOT invent query parameters. A request may only use a query parameter
  if it is listed under DISCOVERED QUERY PARAMETERS.
- GET / returning 200 does not demonstrate authorization. SPA fallback
  returning 200 doesn't demonstrate route existence.
- External Supabase behavior is NOT verified by this frontend twin.
- "No Supabase auth usage detected" is NOT automatically a "Broken
  Authentication" vulnerability. A Supabase anon key is NOT automatically an
  exposed secret. Reason about security boundaries; do not manufacture
  findings.
- Do not generate shell commands, scripts, code, absolute URLs, or endpoints
  not listed above. Do not attach a request/payload to an observation.
- Return JSON only.
"""

_SECURITY_ANALYSIS_SCHEMA = """
{
  "analyses": [
    {
      "type": "executable_experiment",
      "title": "short experiment title",
      "category": "e.g. broken_access_control",
      "hypothesis": "one-sentence security hypothesis",
      "invariant": "the security invariant being tested",
      "request": {"method": "GET", "path": "a DISCOVERED route, optionally with a DISCOVERED query parameter", "headers": {"X-Demo-User": "1"}},
      "expected_status": 403,
      "reason": "why this request tests the invariant inside this twin"
    },
    {
      "type": "security_observation",
      "title": "short observation title",
      "category": "e.g. broken_access_control",
      "reason": "why this security question cannot be verified inside this twin",
      "evidence": ["discovered signal 1", "discovered signal 2"],
      "verification": "not_verifiable_in_twin",
      "verification_requirement": "what external environment would be required to verify this"
    }
  ]
}
"""


_ANALYSIS_MAX = 3


def build_security_analysis_prompt(
    context, extra_context: str | None = None
) -> str:
    """Build the Milestone 11 AI prompt from DISCOVERED application context.

    The AI selects executable_experiment vs security_observation based on
    what the discovered application actually lets BreakTrace verify. For a
    frontend-only twin serving GET / with SPA fallback, the model should
    strongly prefer observations for questions about Supabase or other
    external services. Query parameters are only listed when discovered.
    Validation remains mandatory regardless: every analysis still passes the
    shared allowlist gate.
    """
    routes_text = "\n".join(
        f"- {r.method} {r.path} (discovered via {r.source})"
        for r in context.routes[:80]
    )
    routes_json = json.dumps(
        [f"{r.method} {r.path}" for r in context.routes[:80]],
        separators=(",", ":"),
    )
    query_json = json.dumps(list(context.query_parameters), separators=(",", ":"))
    auth_text = ", ".join(context.auth_signals) or "none detected"
    components_text = ", ".join(context.security_relevant_components) or "none"
    frameworks_text = ", ".join(getattr(context, "frameworks", [])) or context.framework or "unknown"
    services_text = ", ".join(
        _context_value(service, "type")
        for service in (getattr(context, "external_service_sdks", []) or getattr(context, "external_services", []))
    ) or "none detected"
    data_text = ", ".join(
        f"{resource.name} ({', '.join(resource.operations) or 'operation unknown'})"
        for resource in getattr(context, "data_resources", [])
    ) or "none detected"
    storage_text = ", ".join(
        f"{resource.name} ({', '.join(resource.operations) or 'operation unknown'})"
        for resource in getattr(context, "storage_resources", [])
    ) or "none detected"
    capability_text = ", ".join(
        _context_value(capability, "name")
        for capability in getattr(context, "capabilities", [])
    ) or "none detected"
    models_text = ", ".join(context.models) or "none detected"
    auth_usage_text = ", ".join(getattr(context, "authentication_usage", [])) or "none detected"
    semantic_block = _semantic_prompt_block(context)
    prompt = (
        _SECURITY_ANALYSIS_INSTRUCTIONS.format(max_analyses=_ANALYSIS_MAX)
        + f"\n\nAPPLICATION\n{context.name}\n"
        f"FRAMEWORKS (descriptive signals)\n{frameworks_text}\n"
        f"EXTERNAL SERVICES / SDKs\n{services_text}\n"
        f"SANDBOX-LOCAL ORIGIN (never test any other host)\n"
        f"{context.runtime_origin}\n"
        f"AUTHENTICATION USAGE SIGNALS\n{auth_usage_text}\n"
        f"MODELS (server-side only; never infer from service tables)\n{models_text}\n"
        f"DATA RESOURCES (NOT REST ENDPOINTS)\n{data_text}\n"
        f"STORAGE RESOURCES (NOT REST ENDPOINTS)\n{storage_text}\n"
        f"CAPABILITIES (descriptive only)\n{capability_text}\n"
        f"SECURITY-RELEVANT COMPONENTS\n{components_text}\n"
        f"{semantic_block}"
        f"DISCOVERED QUERY PARAMETERS (ONLY these may appear on executable experiments)\n{query_json}\n"
        f"ALLOWED REQUEST HEADERS (only these, with bounded values, may appear on executable_experiment requests)\n{json.dumps(list(getattr(context, 'allowed_request_headers', [])), separators=(',', ':'))}\n"
        f"DISCOVERED ENDPOINTS (human-readable)\n{routes_text}\n"
        f"DISCOVERED ENDPOINTS (machine-readable allowlist)\n{routes_json}\n"
        f"SPA FALLBACK DETECTED\n{getattr(context, 'spa_fallback_detected', False)}\n"
        "IMPORTANT: Supabase table names are NOT REST endpoints. Do not "
        "convert data resources such as users or reports into /api/users or "
        "/api/reports. Do not invent /api/admin. Do not invent query "
        "parameters.\n"
        "STRICT RULE for executable_experiment: use ONLY one of these "
        "discovered routes, with ONLY a discovered query parameter. Any other "
        "route or query parameter will be REJECTED by validation and never "
        "executed.\n"
        "If a security question concerns an external service not running in "
        "this Security Twin, represent it as a security_observation with "
        "verification not_verifiable_in_twin - never as a verified finding.\n"
    )
    if extra_context:
        prompt += (
            "\nALREADY COVERED CONTEXT (do NOT duplicate these; propose "
            "only NEW application-specific analyses):\n"
            f"{extra_context}\n"
        )
    prompt += (
        f"\nReturn exactly one JSON object matching this schema (\"analyses\" "
        f"array with up to {_ANALYSIS_MAX} items, each type is either "
        "executable_experiment or security_observation):\n"
        f"{_SECURITY_ANALYSIS_SCHEMA}\n"
    )
    return prompt


def parse_ai_security_analysis(data, context):
    """Validate a mixed AI security-analysis output, one analysis at a time
    (Milestone 11).

    Each analysis is independently an executable_experiment or a
    security_observation. Invalid analyses are recorded as rejected and the
    valid ones are returned - a rejected analysis NEVER aborts the flow and
    NEVER becomes a finding. This replaces the old fixed "exactly 3 executable
    proposals" requirement: the AI may return any mixture (including all
    observations), bounded to _ANALYSIS_MAX analyses.

    Returns:
        (experiments: list[SecurityTestProposal],
         observations: list[SecurityObservation],
         rejected: list[dict])
        where each rejected entry is {"index", "hypothesis", "reason"}.

    Raises:
        ProposalValidationError: ONLY for whole-response structural failures
            (not an object with an analyses array, or top-level smuggling keys).
    """
    if not isinstance(data, dict):
        raise ProposalValidationError(
            "Model output was not a JSON object with an analyses array."
        )
    _reject_code_fields_in(data, "top level")
    raw = data.get("analyses")
    if not isinstance(raw, list):
        raise ProposalValidationError(
            "Model output did not contain an analyses array."
        )
    if len(raw) > _ANALYSIS_MAX:
        raise ProposalValidationError(
            f"Model returned {len(raw)} analyses; at most {_ANALYSIS_MAX} "
            "are allowed."
        )

    experiments: list[SecurityTestProposal] = []
    observations: list[SecurityObservation] = []
    rejected: list[dict] = []
    for index, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            rejected.append(
                {
                    "index": index,
                    "hypothesis": "",
                    "reason": f"Analysis {index} rejected: not a JSON object.",
                }
            )
            continue
        try:
            _reject_code_fields_in(item, f"analysis {index}")
        except ProposalValidationError as exc:
            rejected.append(
                {"index": index, "hypothesis": "", "reason": str(exc)}
            )
            continue
        try:
            kind = item.get("type")
            if kind == "security_observation":
                observations.append(validate_security_observation(item, index))
            elif kind in ("executable_experiment", None):
                experiments.append(validate_executable_experiment(item, index, context))
            else:
                raise ProposalValidationError(
                    f"Analysis {index} rejected: unknown type {kind!r}. "
                    "Valid types: executable_experiment, security_observation."
                )
        except ProposalValidationError as exc:
            rejected.append(
                {
                    "index": index,
                    "hypothesis": str(item.get("hypothesis", "")),
                    "reason": str(exc),
                }
            )
        except ValidationError as exc:
            rejected.append(
                {
                    "index": index,
                    "hypothesis": str(item.get("hypothesis", "")),
                    "reason": (
                        f"Analysis {index} rejected: model output did not "
                        "match the required analysis schema."
                    ),
                }
            )
    return experiments, observations, rejected


# ---------------------------------------------------------------------------
# Short-lived in-memory proposal cache (demo only - no database)
# ---------------------------------------------------------------------------

_CACHE_TTL_SECONDS = 15 * 60
_cache: dict = {"proposal": None, "timestamp": 0.0}


def cache_validated_proposal(proposal: SecurityTestProposal) -> None:
    """Store a validated proposal in the short-lived demo cache.

    Called by each provider after their proposal passes the shared validation
    gate, so follow-up run/replay requests reuse the same test without another
    AI call.
    """
    _cache["proposal"] = proposal
    _cache["timestamp"] = time.monotonic()


def get_cached_proposal() -> SecurityTestProposal | None:
    """Return the last validated proposal if it is still fresh."""
    proposal = _cache["proposal"]
    if proposal is not None and time.monotonic() - _cache["timestamp"] < _CACHE_TTL_SECONDS:
        return proposal
    return None


# ---------------------------------------------------------------------------
# Short-lived in-memory assessment cache (demo only - no database)
#
# The validated 3-proposal assessment is cached alongside its assessment_id so
# that /assessment/run and /assessment/replay execute the EXACT SAME tests.
# Replay NEVER asks the AI provider again.
# ---------------------------------------------------------------------------

_assessment_cache: dict = {
    "assessment": None,
    "assessment_id": None,
    "timestamp": 0.0,
}
_assessment_number: int = 0


def next_assessment_number() -> int:
    """Return the next sequential assessment number."""
    global _assessment_number
    _assessment_number += 1
    return _assessment_number


def cache_validated_assessment(
    assessment: SecurityAssessmentProposal, assessment_id: str
) -> None:
    """Store a validated assessment in the short-lived demo cache.

    Called by each provider after their assessment passes the shared
    validation gate, so run/replay reuse the exact same tests without another
    AI call.
    """
    _assessment_cache["assessment"] = assessment
    _assessment_cache["assessment_id"] = assessment_id
    _assessment_cache["timestamp"] = time.monotonic()


def get_cached_assessment() -> tuple[SecurityAssessmentProposal, str] | None:
    """Return (assessment, assessment_id) if the last validated assessment is
    still fresh."""
    entry = _assessment_cache
    if (
        entry["assessment"] is not None
        and time.monotonic() - entry["timestamp"] < _CACHE_TTL_SECONDS
    ):
        return entry["assessment"], entry["assessment_id"]
    return None


# ---------------------------------------------------------------------------
# Milestone 6 - attack-chain relationship analysis prompt
# ---------------------------------------------------------------------------

_ATTACK_CHAIN_INSTRUCTIONS = """
You are analyzing VERIFIED security test results.

Determine whether any verified vulnerabilities can form a meaningful attack path or share a common security root cause.

RULES:
- You may ONLY reference supplied BreakTrace IDs.
- You may NOT invent successful requests, credentials, vulnerabilities, privileges, or exploit steps.
- A safe/passed BreakTrace (status "safe" or "passed") cannot be represented as a successful attack step.
- If the evidence does not support a true sequential exploit chain, classify the relationship as "correlated_findings" or "shared_root_cause" rather than falsely claiming exploit chaining.
- Use "none" if there is no meaningful relationship between the findings.

FAVOR "shared_root_cause" when multiple findings share the same underlying authorization weakness.
ONLY use "attack_chain" when there is clear evidence that one finding enables the next.
"""

_ATTACK_CHAIN_JSON_SCHEMA = """
{
  "type": "attack_chain | correlated_findings | shared_root_cause | none",
  "title": "short analysis title",
  "summary": "one-paragraph summary of the relationship",
  "breaktrace_ids": ["BT-AI-001", "BT-AI-002"],
  "steps": [
    {
      "breaktrace_id": "BT-AI-001",
      "description": "what this step achieves and how it relates to the chain"
    }
  ],
  "root_cause": "the shared root cause if applicable",
  "impact": "potential security impact of these findings",
  "confidence": "low | medium | high"
}
"""


def build_chain_analysis_prompt(results: list) -> str:
    """Build a prompt that asks the AI to analyze relationships between
    verified security test results.

    Includes ALL test results (vulnerable and safe) so the AI knows the full
    context, but the instructions prohibit representing safe findings as
    attack steps.
    """
    parts: list[str] = []
    for r in results:
        status_label = (
            "VULNERABLE" if getattr(r, "invariant_violated", False)
            else "SAFE"
        )
        parts.append(
            f"{r.id}\n"
            f"Title: {r.title}\n"
            f"Category: {r.category}\n"
            f"Actor: {r.actor.name} (user_id {r.actor.user_id})\n"
            f"Request: {r.request.method} {r.request.path}\n"
            f"Expected: {r.expected.status}\n"
            f"Observed: {r.observed.status}\n"
            f"Status: {status_label}"
        )
    evidence = "\n-------------------------\n".join(parts)

    return (
        _ATTACK_CHAIN_INSTRUCTIONS
        + f"\n\nVERIFIED TEST RESULTS:\n{evidence}\n"
        "Return JSON only. Return exactly one JSON object matching this schema:\n"
        f"{_ATTACK_CHAIN_JSON_SCHEMA}"
    )


# ---------------------------------------------------------------------------
# Milestone 6 - chain-analysis validation
# ---------------------------------------------------------------------------

_MAX_CHAIN_TEXT_LEN = 500


def validate_chain_analysis(
    data: dict, results: list
) -> AttackRelationshipAnalysis:
    """Parse model output into an AttackRelationshipAnalysis and enforce that
    every referenced BreakTrace ID is a verified vulnerable finding.

    Safe/passed results can never appear as attack-chain steps.

    Raises:
        ProposalValidationError: If the output fails schema validation or
            references non-existent, non-vulnerable, or safe result IDs.
    """
    vulnerable_ids = {
        r.id
        for r in results
        if getattr(r, "test_executed", False)
        and getattr(r, "invariant_violated", False)
        and getattr(r, "status", "") == "vulnerable"
    }

    try:
        analysis = AttackRelationshipAnalysis.model_validate(data)
    except ValidationError as exc:
        raise ProposalValidationError(
            f"Chain analysis output did not match the required schema: {exc}"
        ) from exc

    # --- Text field sanity ---
    for field_name in ("title", "summary", "root_cause", "impact"):
        value = getattr(analysis, field_name)
        if not (value or "").strip():
            raise ProposalValidationError(
                f"Chain analysis rejected: {field_name} is empty."
            )
        if len(value) > _MAX_CHAIN_TEXT_LEN:
            raise ProposalValidationError(
                f"Chain analysis rejected: {field_name} exceeds "
                f"{_MAX_CHAIN_TEXT_LEN} chars."
            )
        if any(ord(ch) < 32 and ch not in "\n\t" for ch in value):
            raise ProposalValidationError(
                f"Chain analysis rejected: {field_name} contains control "
                "characters."
            )

    for i, step in enumerate(analysis.steps, start=1):
        if not step.description.strip():
            raise ProposalValidationError(
                f"Chain step {i} description is empty."
            )
        if len(step.description) > _MAX_CHAIN_TEXT_LEN:
            raise ProposalValidationError(
                f"Chain step {i} description exceeds {_MAX_CHAIN_TEXT_LEN} chars."
            )

    # --- ID validation ---
    if analysis.type == "none":
        if analysis.breaktrace_ids or analysis.steps:
            raise ProposalValidationError(
                "Chain analysis type 'none' must have empty breaktrace_ids and steps."
            )
        return analysis

    if not analysis.breaktrace_ids:
        raise ProposalValidationError(
            "Chain analysis must reference at least one BreakTrace ID."
        )
    if not vulnerable_ids:
        raise ProposalValidationError(
            "No verified vulnerabilities exist to reference in chain analysis."
        )

    for bid in analysis.breaktrace_ids:
        if bid not in vulnerable_ids:
            raise ProposalValidationError(
                f"Chain analysis references {bid!r} which is not a verified "
                "vulnerable BreakTrace."
            )

    for step in analysis.steps:
        if step.breaktrace_id not in vulnerable_ids:
            raise ProposalValidationError(
                f"Chain step references {step.breaktrace_id!r} which is not "
                "a verified vulnerable BreakTrace."
            )

    return analysis


# ---------------------------------------------------------------------------
# Milestone 6 + 7 - latest executed assessment run (in-memory, no database)
#
# Since Milestone 7 runs are keyed by application target_id so chain analysis
# and library save only ever operate on the ACTIVE APPLICATION's latest run -
# findings from different applications are never mixed.
# ---------------------------------------------------------------------------

_latest_runs: dict = {}
_last_cached = None


def cache_latest_assessment_run(run_result, target_id: str | None = None) -> None:
    """Store the latest executed AssessmentRunResult for an application.

    Chain analysis and library save read it back with the same target_id.
    The most recently cached run stays available globally for backward
    compatibility.
    """
    global _last_cached
    _latest_runs[target_id or ""] = run_result
    _last_cached = run_result


def get_latest_assessment_run(target_id: str | None = None):
    """Return the most recent executed AssessmentRunResult for an
    application, or None.

    Args:
        target_id: Only the run cached under this application is returned.
            None returns the most recently cached run overall (backward
            compatible with pre-M7 callers).
    """
    if target_id is not None:
        return _latest_runs.get(target_id)
    return _last_cached


# ---------------------------------------------------------------------------
# Milestone 6 - chain analysis numbering
# ---------------------------------------------------------------------------

_chain_number: int = 0


def next_chain_number() -> int:
    """Return the next sequential chain-analysis number."""
    global _chain_number
    _chain_number += 1
    return _chain_number