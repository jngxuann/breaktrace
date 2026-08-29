"""Nosana-hosted Ollama client for BreakTrace.

This module is responsible ONLY for the Nosana/Ollama AI transport layer:

- loading Nosana configuration (NOSANA_API_URL, NOSANA_MODEL)
- calling the Ollama HTTP API (/api/generate, /api/tags)
- returning a typed SecurityTestProposal or SecurityAssessmentProposal

All prompts, JSON parsing, validation, and caching are in ai_shared.py and are
shared identically by every AI provider (Nosana, Groq, ...). This module only
handles the Ollama-specific transport and delegates everything else.
"""

import os

import httpx

from dotenv import load_dotenv

from ai_shared import (
    DuplicateProposalsError,
    ProviderConfigError,
    ProviderUnavailableError,
    ProposalValidationError,
    build_assessment_prompt,
    build_chain_analysis_prompt,
    build_discovery_assessment_prompt,
    build_single_test_prompt,
    build_security_analysis_prompt,
    cache_validated_assessment,
    cache_validated_proposal,
    extract_json,
    next_assessment_number,
    next_chain_number,
    parse_ai_security_analysis,
    validate_assessment_proposals,
    validate_chain_analysis,
    split_discovery_assessment,
    validate_discovery_assessment_proposals,
    validate_proposal,
)

# Load credentials from backend/.env (NOSANA_API_URL, NOSANA_MODEL).
load_dotenv()

# Re-export shared error classes for backward compatibility with any module
# that still imports them by their Nosana names.

class NosanaConfigError(ProviderConfigError):
    """Nosana configuration is missing or invalid."""


class NosanaUnavailableError(ProviderUnavailableError):
    """The Nosana/Ollama endpoint is unreachable or returned unparseable output."""


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def get_nosana_config() -> tuple[str, str]:
    """Return (base_url, model) from the environment.

    Raises:
        NosanaConfigError: If NOSANA_API_URL or NOSANA_MODEL is missing.
    """
    api_url = os.getenv("NOSANA_API_URL")
    if not api_url:
        raise NosanaConfigError(
            "NOSANA_API_URL is not set. Add it to backend/.env "
            "(see backend/.env.example)."
        )
    model = os.getenv("NOSANA_MODEL")
    if not model:
        raise NosanaConfigError(
            "NOSANA_MODEL is not set. Add it to backend/.env "
            "(see backend/.env.example)."
        )
    return api_url.strip().rstrip("/"), model.strip()


def _api_url(path: str) -> str:
    base, _ = get_nosana_config()
    return f"{base}{path}"


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


def get_nosana_health() -> dict:
    """Verify Nosana config exists and the Ollama endpoint + model are usable.

    Returns:
        {"status": "ok", "provider": "Nosana", "runtime": "Ollama",
         "model": "<model>"}

    Raises:
        NosanaConfigError: Missing config.
        NosanaUnavailableError: Endpoint unreachable, errored, or the
            configured model is not available.
    """
    _, model = get_nosana_config()
    try:
        resp = httpx.get(_api_url("/api/tags"), timeout=httpx.Timeout(30.0, connect=10.0))
    except httpx.HTTPError as exc:
        raise NosanaUnavailableError(f"Nosana/Ollama endpoint unreachable: {exc}") from exc

    if resp.status_code != 200:
        raise NosanaUnavailableError(
            f"Nosana/Ollama /api/tags returned HTTP {resp.status_code}"
        )

    try:
        data = resp.json()
    except ValueError as exc:
        raise NosanaUnavailableError("Nosana/Ollama /api/tags returned non-JSON") from exc

    names = [m.get("name", "") for m in (data.get("models") or [])]
    available = any(name == model or name.startswith(model) for name in names)
    if not available:
        shown = ", ".join(names[:5]) if names else "(none listed)"
        raise NosanaUnavailableError(
            f"Model {model!r} is not available on the Nosana deployment. "
            f"Available models: {shown}"
        )
    return {"status": "ok", "provider": "Nosana", "runtime": "Ollama", "model": model}


# ---------------------------------------------------------------------------
# Ollama generate call
# ---------------------------------------------------------------------------

_GENERATE_TIMEOUT = httpx.Timeout(180.0, connect=10.0)  # RTX 3060 inference is slow


def _call_generate(prompt: str, *, force_json_format: bool) -> str:
    """POST /api/generate and return the model's response text.

    Raises:
        NosanaConfigError: Missing config.
        NosanaUnavailableError: Endpoint unreachable, timed out, returned a
            non-200 HTTP status, a non-JSON body, or no output text.
    """
    url = _api_url("/api/generate")
    payload = {
        "model": get_nosana_config()[1],
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.2},
    }
    if force_json_format:
        payload["format"] = "json"

    try:
        resp = httpx.post(url, json=payload, timeout=_GENERATE_TIMEOUT)
    except httpx.TimeoutException as exc:
        raise NosanaUnavailableError(
            "Nosana/Ollama request timed out (inference may be slow). "
            "Please try again."
        ) from exc
    except httpx.HTTPError as exc:
        raise NosanaUnavailableError(f"Nosana/Ollama endpoint unreachable: {exc}") from exc

    if resp.status_code != 200:
        raise NosanaUnavailableError(
            f"Nosana/Ollama /api/generate returned HTTP {resp.status_code}"
        )

    try:
        data = resp.json()
    except ValueError as exc:
        raise NosanaUnavailableError(
            "Nosana/Ollama returned a malformed (non-JSON) response"
        ) from exc

    text = data.get("response")
    if not isinstance(text, str) or not text.strip():
        raise NosanaUnavailableError("Nosana/Ollama response contained no output text")
    return text


def _generate_json(prompt: str) -> dict:
    """Call the Ollama model and return a parsed JSON dict.

    Falls back gracefully: if format=\"json\" is unsupported by the deployed
    Ollama version or the output is unparseable, make ONE repair/retry
    request asking for JSON-only output.

    Raises:
        NosanaConfigError, NosanaUnavailableError: As documented above.
    """
    try:
        text = _call_generate(prompt, force_json_format=True)
        data = extract_json(text)
        if data is not None:
            return data
    except NosanaUnavailableError:
        # Possibly format="json" is unsupported here - retry without it.
        pass

    retry_prompt = (
        prompt
        + "\n\nIMPORTANT: Respond with ONE valid JSON object only. "
        "No markdown, no code fences, no explanations."
    )
    text = _call_generate(retry_prompt, force_json_format=False)
    data = extract_json(text)
    if data is None:
        raise NosanaUnavailableError(
            "Nosana returned malformed JSON after retry - could not parse "
            "a valid proposal."
        )
    return data


# ---------------------------------------------------------------------------
# Proposal flow (Nosana transport + shared validation + shared caching)
# ---------------------------------------------------------------------------


def propose_security_test() -> SecurityTestProposal:
    """Ask Nosana/Ollama for ONE bounded security test and validate it.

    Returns:
        A validated SecurityTestProposal.

    Raises:
        NosanaConfigError, NosanaUnavailableError, ProposalValidationError.
    """
    from models import SecurityTestProposal

    data = _generate_json(build_single_test_prompt())
    proposal = validate_proposal(data)
    cache_validated_proposal(proposal)
    return proposal


def analyze_relationships(results: list) -> "AttackRelationshipAnalysis":
    """Ask Nosana/Ollama to analyze relationships between VERIFIED security
    results.

    Returns:
        A validated AttackRelationshipAnalysis referencing only verified
        vulnerable BreakTrace IDs.

    Raises:
        NosanaConfigError, NosanaUnavailableError, ProposalValidationError.
    """
    from models import AttackRelationshipAnalysis

    data = _generate_json(build_chain_analysis_prompt(results))
    analysis = validate_chain_analysis(data, results)
    analysis.analysis_id = f"CHAIN-{next_chain_number():03d}"
    return analysis


def propose_security_assessment() -> tuple:
    """Ask Nosana/Ollama for exactly 3 distinct bounded security tests and
    validate the whole set against the strict allowlist.

    If the model returns duplicate method/path combinations, make ONE retry
    asking for unique pairs. If the retry still fails, the error propagates
    as a clean ProposalValidationError.

    Returns:
        (validated SecurityAssessmentProposal, assessment_id).

    Raises:
        NosanaConfigError, NosanaUnavailableError, ProposalValidationError.
    """
    from models import SecurityAssessmentProposal

    data = _generate_json(build_assessment_prompt())
    try:
        assessment = validate_assessment_proposals(data)
    except DuplicateProposalsError:
        retry_prompt = (
            build_assessment_prompt()
            + "\n\nIMPORTANT: your previous response contained duplicate "
            "method/path pairs. Each of the 3 proposals must use a UNIQUE "
            "method + path combination."
        )
        data = _generate_json(retry_prompt)
        assessment = validate_assessment_proposals(data)

    assessment_id = f"ASSESS-{next_assessment_number():03d}"
    cache_validated_assessment(assessment, assessment_id)
    return assessment, assessment_id


def propose_discovery_assessment(context, extra_context: str | None = None) -> "SecurityAssessmentProposal":
    """Ask Nosana/Ollama for exactly 3 DISTINCT bounded hypotheses about a
    DISCOVERED application context (Milestone 8).

    Hypotheses are validated against the discovered routes - the model cannot
    reference undiscovered endpoints, external URLs, or arbitrary methods.
    One retry on duplicate method/path pairs. `extra_context` (Milestone 9)
    tells the model which conditions deterministic checks and regression
    replay already covered so it does not duplicate them.

    Returns:
        A validated SecurityAssessmentProposal (intent only).

    Raises:
        NosanaConfigError, NosanaUnavailableError, ProposalValidationError.
    """
    from models import SecurityAssessmentProposal

    data = _generate_json(
        build_discovery_assessment_prompt(context, extra_context=extra_context)
    )
    try:
        assessment = validate_discovery_assessment_proposals(data, context)
    except DuplicateProposalsError:
        retry_prompt = (
            build_discovery_assessment_prompt(context, extra_context=extra_context)
            + "\n\nIMPORTANT: your previous response contained duplicate "
            "method/path pairs. Each of the 3 proposals must use a UNIQUE "
            "method + path combination."
        )
        data = _generate_json(retry_prompt)
        assessment = validate_discovery_assessment_proposals(data, context)
    return assessment


def propose_discovery_assessment_split(
    context, extra_context: str | None = None
):
    """Ask Nosana/Ollama for bounded hypotheses about a DISCOVERED
    application context, validating EACH proposal independently (Security
    Twin Layer 3).

    A single invalid proposal NEVER aborts the assessment: it is recorded
    as rejected (with a reason) and the valid proposals are returned for
    execution. The allowlist gate is identical to the strict path.

    Returns:
        (valid: list[SecurityTestProposal], rejected: list[dict])
        where each rejected entry is {"index", "hypothesis", "reason"}.

    Raises:
        NosanaConfigError, NosanaUnavailableError, ProposalValidationError
            (only for whole-response structural failures).
    """
    data = _generate_json(
        build_discovery_assessment_prompt(context, extra_context=extra_context)
    )
    return split_discovery_assessment(data, context)


def propose_security_analysis_for_twin_split(
    context, extra_context: str | None = None
):
    """Ask Nosana/Ollama for a MIXED set of up to 3 security analyses - each
    independently an executable_experiment or a security_observation
    (Milestone 11).

    The AI is no longer forced to produce executable HTTP tests. Executable
    experiments are validated with the strict discovery allowlist (including
    invented query-parameter rejection) and only runtime-verified ones may
    become findings. Security observations carry no executable surface, are
    never verified, and never enter Security Memory.

    Returns:
        (experiments: list[SecurityTestProposal],
         observations: list[SecurityObservation],
         rejected: list[dict])

    Raises:
        NosanaConfigError, NosanaUnavailableError, ProposalValidationError
            (only for whole-response structural failures).
    """
    data = _generate_json(
        build_security_analysis_prompt(context, extra_context=extra_context)
    )
    return parse_ai_security_analysis(data, context)