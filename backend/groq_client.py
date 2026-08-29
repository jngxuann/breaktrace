"""Groq API client for BreakTrace.

This module is responsible ONLY for the Groq AI transport layer:

- loading Groq configuration (GROQ_API_KEY, GROQ_MODEL)
- calling the Groq OpenAI-compatible chat completions endpoint
- returning a typed SecurityTestProposal or SecurityAssessmentProposal

All prompts, JSON parsing, validation, and caching are in ai_shared.py and are
shared identically by every AI provider (Nosana, Groq, ...). This module only
handles the Groq-specific transport and delegates everything else.
"""

import json as _json
import logging
import os
import re

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

load_dotenv()

logger = logging.getLogger(__name__)

# Never include credentials in diagnostics, even if a provider echoes them.
_SECRET_RE = re.compile(
    r"(?i)(bearer\s+|(?:groq[_ -]?api[_ -]?key|api[_ -]?key)\s*[:=]\s*)"
    r"[^\s,;]+|\bgsk_[A-Za-z0-9_-]+\b"
)
_MAX_ERROR_BODY_CHARS = 2000


# ---------------------------------------------------------------------------
# Groq-specific errors
# ---------------------------------------------------------------------------


class GroqConfigError(ProviderConfigError):
    """Groq configuration is missing or invalid."""


class GroqUnavailableError(ProviderUnavailableError):
    """The Groq API endpoint is unreachable or returned unparseable output."""


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


def get_groq_config() -> tuple[str, str]:
    """Return (api_key, model) from the environment.

    Raises:
        GroqConfigError: If GROQ_API_KEY or GROQ_MODEL is missing.
    """
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise GroqConfigError(
            "GROQ_API_KEY is not set. Add it to backend/.env "
            "(see backend/.env.example)."
        )
    model = os.getenv("GROQ_MODEL")
    if not model:
        raise GroqConfigError(
            "GROQ_MODEL is not set. Add it to backend/.env "
            "(see backend/.env.example)."
        )
    return api_key.strip(), model.strip()


def _get_groq_model() -> str:
    """Return the configured Groq model name, or empty string if unset."""
    return (os.getenv("GROQ_MODEL") or "").strip()


# ---------------------------------------------------------------------------
# Groq chat completions endpoint
# ---------------------------------------------------------------------------

_GROQ_API_BASE = "https://api.groq.com/openai/v1"
_GROQ_TIMEOUT = httpx.Timeout(120.0, connect=10.0)


def _safe_error_body(resp: httpx.Response) -> str:
    """Extract safe provider diagnostics without exposing credentials."""
    try:
        data = resp.json()
    except ValueError:
        text = resp.text
    else:
        if isinstance(data, dict):
            error = data.get("error")
            if isinstance(error, dict):
                parts = []
                for key in ("message", "type", "code"):
                    value = error.get(key)
                    if value is not None:
                        parts.append(f"{key}={value}")
                text = "; ".join(parts) or _json.dumps(data)
            else:
                text = _json.dumps(data)
        else:
            text = _json.dumps(data)
    text = _SECRET_RE.sub(r"\\1[REDACTED]", str(text))
    return text[:_MAX_ERROR_BODY_CHARS]


def _log_request_metadata(model: str, payload: dict) -> None:
    """Log non-sensitive metadata for one outgoing Groq request."""
    response_format = payload.get("response_format")
    logger.info(
        "Groq request metadata: model=%s endpoint=%s messages=%d "
        "prompt_chars=%d response_format=%s response_format_type=%s "
        "reasoning_effort=%s max_tokens=%s max_completion_tokens=%s",
        model,
        f"{_GROQ_API_BASE}/chat/completions",
        len(payload.get("messages", [])),
        sum(len(str(message.get("content", ""))) for message in payload.get("messages", [])),
        response_format is not None,
        response_format.get("type") if isinstance(response_format, dict) else None,
        payload.get("reasoning_effort"),
        payload.get("max_tokens"),
        payload.get("max_completion_tokens"),
    )


def _chat_completion(prompt: str) -> str:
    """Call Groq chat completions and return the assistant's message text.

    Uses the OpenAI-compatible endpoint. If the model supports structured JSON
    output, response_format is set to json_object; otherwise the prompt already
    explicitly requests JSON-only output.

    Raises:
        GroqConfigError: Missing credentials.
        GroqUnavailableError: Timeout, auth failure, rate limit, 5xx,
            or missing/malformed response.
    """
    api_key, model = get_groq_config()
    url = f"{_GROQ_API_BASE}/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a security test planner. You MUST respond with "
                    "valid JSON only — no markdown, no code fences, no "
                    "commentary outside the JSON object."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 4096,
        "response_format": {"type": "json_object"},
    }

    _log_request_metadata(model, payload)
    try:
        resp = httpx.post(url, json=payload, headers=headers, timeout=_GROQ_TIMEOUT)
    except httpx.TimeoutException as exc:
        raise GroqUnavailableError(
            "Groq request timed out. Please try again."
        ) from exc
    except httpx.HTTPError as exc:
        raise GroqUnavailableError(f"Groq endpoint unreachable: {exc}") from exc

    # Map known HTTP errors to clear messages without leaking the API key.
    if resp.status_code == 401 or resp.status_code == 403:
        raise GroqUnavailableError(
            "Groq authentication failed. Check your GROQ_API_KEY."
        )
    if resp.status_code == 429:
        raise GroqUnavailableError("Groq rate limit exceeded. Please wait and try again.")
    if resp.status_code >= 500:
        raise GroqUnavailableError(
            f"Groq server error (HTTP {resp.status_code}). Please try again later."
        )
    if resp.status_code < 200 or resp.status_code >= 300:
        diagnostic = _safe_error_body(resp)
        raise GroqUnavailableError(
            f"Groq returned HTTP {resp.status_code}: {diagnostic}"
        )

    try:
        data = resp.json()
    except ValueError as exc:
        raise GroqUnavailableError(
            "Groq returned a malformed (non-JSON) response."
        ) from exc

    try:
        content = data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise GroqUnavailableError(
            "Groq response was missing expected content fields."
        ) from exc

    if not isinstance(content, str) or not content.strip():
        raise GroqUnavailableError("Groq response contained no output text.")

    return content


def _generate_json(prompt: str) -> dict:
    """Call the Groq model and return a parsed JSON dict.

    If the first response is unparseable JSON (despite json_object format),
    make ONE retry with an explicit JSON-only instruction.

    Raises:
        GroqConfigError, GroqUnavailableError.
    """
    text = _chat_completion(prompt)
    data = extract_json(text)
    if data is not None:
        return data

    # One retry with stronger instructions.
    retry_prompt = (
        prompt
        + "\n\nIMPORTANT: Respond with ONE valid JSON object only. "
        "No markdown, no code fences, no explanations. "
        "The response must be parseable as valid JSON."
    )
    text = _chat_completion(retry_prompt)
    data = extract_json(text)
    if data is None:
        raise GroqUnavailableError(
            "Groq returned malformed JSON after retry - could not parse "
            "a valid proposal."
        )
    return data


# ---------------------------------------------------------------------------
# Proposal flow (Groq transport + shared validation + shared caching)
# ---------------------------------------------------------------------------


def propose_security_test() -> "SecurityTestProposal":
    """Ask Groq for ONE bounded security test and validate it.

    Returns:
        A validated SecurityTestProposal.

    Raises:
        GroqConfigError, GroqUnavailableError, ProposalValidationError.
    """
    from models import SecurityTestProposal

    data = _generate_json(build_single_test_prompt())
    proposal = validate_proposal(data)
    cache_validated_proposal(proposal)
    return proposal


def analyze_relationships(results: list) -> "AttackRelationshipAnalysis":
    """Ask Groq to analyze relationships between VERIFIED security results.

    Returns:
        A validated AttackRelationshipAnalysis referencing only verified
        vulnerable BreakTrace IDs.

    Raises:
        GroqConfigError, GroqUnavailableError, ProposalValidationError.
    """
    from models import AttackRelationshipAnalysis

    data = _generate_json(build_chain_analysis_prompt(results))
    analysis = validate_chain_analysis(data, results)
    analysis.analysis_id = f"CHAIN-{next_chain_number():03d}"
    return analysis


def propose_security_assessment() -> tuple:
    """Ask Groq for exactly 3 distinct bounded security tests and validate the
    whole set against the strict allowlist.

    If the model returns duplicate method/path combinations, make ONE retry
    asking for unique pairs. If the retry still fails, the error propagates.

    Returns:
        (validated SecurityAssessmentProposal, assessment_id).

    Raises:
        GroqConfigError, GroqUnavailableError, ProposalValidationError.
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
    """Ask Groq for exactly 3 DISTINCT bounded hypotheses about a DISCOVERED
    application context (Milestone 8).

    Hypotheses are validated against the discovered routes - the model cannot
    reference undiscovered endpoints, external URLs, or arbitrary methods.
    One retry on duplicate method/path pairs. `extra_context` (Milestone 9)
    tells the model which conditions deterministic checks and regression
    replay already covered so it does not duplicate them.

    Returns:
        A validated SecurityAssessmentProposal (intent only).

    Raises:
        GroqConfigError, GroqUnavailableError, ProposalValidationError.
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
    """Ask Groq for bounded hypotheses about a DISCOVERED application
    context, validating EACH proposal independently (Security Twin Layer 3).

    A single invalid proposal NEVER aborts the assessment: it is recorded
    as rejected (with a reason) and the valid proposals are returned for
    execution. The allowlist gate is identical to the strict path.

    Returns:
        (valid: list[SecurityTestProposal], rejected: list[dict])
        where each rejected entry is {"index", "hypothesis", "reason"}.

    Raises:
        GroqConfigError, GroqUnavailableError, ProposalValidationError
            (only for whole-response structural failures).
    """
    data = _generate_json(
        build_discovery_assessment_prompt(context, extra_context=extra_context)
    )
    return split_discovery_assessment(data, context)


def propose_security_analysis_for_twin_split(
    context, extra_context: str | None = None
):
    """Ask Groq for a MIXED set of up to 3 security analyses - each
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
        GroqConfigError, GroqUnavailableError, ProposalValidationError
            (only for whole-response structural failures).
    """
    data = _generate_json(
        build_security_analysis_prompt(context, extra_context=extra_context)
    )
    return parse_ai_security_analysis(data, context)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


def get_groq_health() -> dict:
    """Report Groq configuration status.

    Does NOT perform a live API call (to avoid unnecessary cost/latency on
    health checks). The /ai/health endpoint reports config status based on
    whether the required env vars are present.

    Returns:
        {"status": "ok", "provider": "groq", "model": "<model>",
         "configured": <bool>}
    """
    model = _get_groq_model()
    api_key = (os.getenv("GROQ_API_KEY") or "").strip()
    configured = bool(api_key and model)
    return {
        "status": "ok",
        "provider": "groq",
        "model": model or "",
        "configured": configured,
    }