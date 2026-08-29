"""Configurable AI provider router for BreakTrace.

Reads AI_PROVIDER from the environment and routes all AI inference requests
through the selected provider (nosana or groq). Both providers receive the
same prompts, pass through the same validation gate, and cache results in the
same shared cache.

This is the single module that main.py (and any future caller) should import
for AI proposal generation. Direct provider imports are only for diagnostics
(/nosana/health, which intentionally bypasses this router).
"""

import os

from dotenv import load_dotenv

from ai_shared import (
    ProviderConfigError,
    ProviderUnavailableError,
    ProposalValidationError,
    get_cached_assessment,
    get_cached_proposal,
)

load_dotenv()

# ---------------------------------------------------------------------------
# Provider routing
# ---------------------------------------------------------------------------


def get_provider_name() -> str:
    """Return the currently configured AI provider name.

    Validates that AI_PROVIDER is either "nosana" or "groq". Defaults to
    "nosana" for backward compatibility.

    Raises:
        ProviderConfigError: If AI_PROVIDER is set to an unknown value.
    """
    provider = (os.getenv("AI_PROVIDER") or "nosana").strip().lower()
    if provider not in ("nosana", "groq"):
        raise ProviderConfigError(
            f"Unknown AI_PROVIDER {provider!r}. Valid values: nosana, groq."
        )
    return provider


def get_provider_metadata() -> dict:
    """Return metadata about the current AI provider.

    Used to annotate proposal/assessment responses with provider information
    so the UI can display which provider was used.
    """
    provider = get_provider_name()
    if provider == "nosana":
        from nosana_client import get_nosana_config

        try:
            _, model = get_nosana_config()
        except ProviderConfigError:
            model = (os.getenv("NOSANA_MODEL") or "").strip()
        return {"provider": "nosana", "runtime": "Ollama", "model": model}

    # groq
    from groq_client import _get_groq_model  # noqa: E402

    model = _get_groq_model()
    return {"provider": "groq", "model": model}


# ---------------------------------------------------------------------------
# AI health endpoint
# ---------------------------------------------------------------------------


def get_ai_health() -> dict:
    """Report the current AI provider's configuration status.

    Returns the same shape regardless of provider, so the frontend can
    render a consistent provider label.

    Raises:
        ProviderConfigError: If AI_PROVIDER is set to an unknown value.
    """
    provider = get_provider_name()
    if provider == "nosana":
        model = (os.getenv("NOSANA_MODEL") or "").strip()
        api_url = (os.getenv("NOSANA_API_URL") or "").strip()
        configured = bool(api_url and model)
        return {
            "status": "ok",
            "provider": "nosana",
            "runtime": "Ollama",
            "model": model or "",
            "configured": configured,
        }

    # groq
    model = (os.getenv("GROQ_MODEL") or "").strip()
    api_key = (os.getenv("GROQ_API_KEY") or "").strip()
    configured = bool(api_key and model)
    return {
        "status": "ok",
        "provider": "groq",
        "model": model or "",
        "configured": configured,
    }


# ---------------------------------------------------------------------------
# Dispatched proposal functions
# ---------------------------------------------------------------------------


def propose_security_test() -> "SecurityTestProposal":
    """Ask the configured AI provider for ONE bounded security test.

    Returns:
        A validated SecurityTestProposal (same Pydantic model regardless of
        provider).

    Raises:
        ProviderConfigError: If the provider or its credentials are misconfigured.
        ProviderUnavailableError: If the provider is unreachable.
        ProposalValidationError: If the output fails the allowlist.
    """
    from models import SecurityTestProposal

    provider = get_provider_name()
    if provider == "nosana":
        from nosana_client import propose_security_test as _propose
    else:
        from groq_client import propose_security_test as _propose
    return _propose()


def propose_security_assessment() -> tuple:
    """Ask the configured AI provider for exactly 3 distinct security tests.

    Returns:
        (validated SecurityAssessmentProposal, assessment_id).

    Raises:
        ProviderConfigError: If the provider or its credentials are misconfigured.
        ProviderUnavailableError: If the provider is unreachable.
        ProposalValidationError: If the output fails the allowlist.
    """
    provider = get_provider_name()
    if provider == "nosana":
        from nosana_client import propose_security_assessment as _propose
    else:
        from groq_client import propose_security_assessment as _propose
    return _propose()


def propose_security_assessment_for_context(context) -> "SecurityAssessmentProposal":
    """Ask the configured AI provider for hypotheses about a DISCOVERED
    application context (Milestone 8).

    The provider receives the discovery prompt; the shared route-based
    validator keeps output constrained to discovered endpoints.

    Returns:
        A validated SecurityAssessmentProposal (exactly 3 distinct tests).

    Raises:
        ProviderConfigError, ProviderUnavailableError, ProposalValidationError.
    """
    from models import SecurityAssessmentProposal

    provider = get_provider_name()
    if provider == "nosana":
        from nosana_client import propose_discovery_assessment as _propose
    else:
        from groq_client import propose_discovery_assessment as _propose
    return _propose(context)


def propose_security_assessment_for_twin(
    context, extra_context: str | None = None
) -> "SecurityAssessmentProposal":
    """Ask the configured AI provider for hypotheses about a DISCOVERED
    application context (Milestone 9 Security Twin, Layer 3).

    Same validation gate as the M8 discovery flow, plus an optional
    `extra_context` summary of the deterministic checks and regression replay
    that already ran, so the AI proposes NEW application-specific hypotheses
    instead of duplicating covered conditions.

    Returns:
        A validated SecurityAssessmentProposal (exactly 3 distinct tests).

    Raises:
        ProviderConfigError, ProviderUnavailableError, ProposalValidationError.
    """
    from models import SecurityAssessmentProposal

    provider = get_provider_name()
    if provider == "nosana":
        from nosana_client import propose_discovery_assessment as _propose
    else:
        from groq_client import propose_discovery_assessment as _propose
    return _propose(context, extra_context=extra_context)


def propose_security_assessment_for_twin_split(
    context, extra_context: str | None = None
):
    """Ask the configured AI provider for hypotheses, validating EACH
    proposal independently (Security Twin Layer 3 reliability fix).

    A rejected AI proposal must NEVER abort the whole assessment: valid
    proposals come back for execution and invalid ones are recorded with a
    reason. The allowlist gate is identical to the strict path - rejected
    proposals are never executed and never become findings.

    Returns:
        (valid: list[SecurityTestProposal], rejected: list[dict])
        where each rejected entry is {"index", "hypothesis", "reason"}.

    Raises:
        ProviderConfigError, ProviderUnavailableError, ProposalValidationError
            (only for whole-response structural failures).
    """
    provider = get_provider_name()
    if provider == "nosana":
        from nosana_client import propose_discovery_assessment_split as _propose
    else:
        from groq_client import propose_discovery_assessment_split as _propose
    return _propose(context, extra_context=extra_context)


def propose_security_analysis_for_twin_split(
    context, extra_context: str | None = None
):
    """Ask the configured AI provider for a MIXED set of up to 3 security
    analyses (Milestone 11) - each independently an executable_experiment or
    a security_observation.

    The AI is no longer forced to invent HTTP tests. Executable experiments
    are validated with the strict discovery allowlist (including invented
    query-parameter rejection) and only runtime-verified ones become
    findings. Security observations carry no executable surface, are never
    verified, and never enter Security Memory.

    Returns:
        (experiments: list[SecurityTestProposal],
         observations: list[SecurityObservation],
         rejected: list[dict])

    Raises:
        ProviderConfigError, ProviderUnavailableError, ProposalValidationError
            (only for whole-response structural failures).
    """
    provider = get_provider_name()
    if provider == "nosana":
        from nosana_client import propose_security_analysis_for_twin_split as _propose
    else:
        from groq_client import propose_security_analysis_for_twin_split as _propose
    return _propose(context, extra_context=extra_context)


def analyze_attack_relationships(results: list) -> "AttackRelationshipAnalysis":
    """Ask the configured AI provider to analyze relationships between
    VERIFIED security results.

    Both providers receive the same shared prompt and validation; only the
    transport differs.

    Returns:
        A validated AttackRelationshipAnalysis.

    Raises:
        ProviderConfigError: If the provider or its credentials are misconfigured.
        ProviderUnavailableError: If the provider is unreachable.
        ProposalValidationError: If the analysis references invented IDs.
    """
    provider = get_provider_name()
    if provider == "nosana":
        from nosana_client import analyze_relationships as _analyze
    else:
        from groq_client import analyze_relationships as _analyze
    return _analyze(results)