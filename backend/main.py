"""BreakTrace backend — FastAPI application.

Endpoints:
  GET  /health               -> liveness check
  POST /sandbox-test         -> create a Daytona sandbox, run the test
                                command, return its output
  POST /breaktrace/demo      -> run BT-001 against the VULNERABLE app
  POST /breaktrace/replay    -> replay the SAME BT-001 against the FIXED app
  GET  /nosana/health        -> verify the Nosana/Ollama deployment
  GET  /ai/health            -> report the current AI provider configuration
  POST /breaktrace/ai/propose -> ask AI provider for ONE bounded security
                                test and return the VALIDATED proposal
  POST /breaktrace/ai/run    -> execute the validated AI proposal against
                                the VULNERABLE app in Daytona
  POST /breaktrace/ai/replay -> replay the SAME AI proposal against the
                                FIXED app in Daytona
  POST /breaktrace/ai/assessment/propose -> ask AI provider for exactly 3
                                DISTINCT bounded security tests and return
                                the VALIDATED assessment (nothing executed)
  POST /breaktrace/ai/assessment/run    -> execute all validated tests against
                                ONE vulnerable app in a single Daytona sandbox
  POST /breaktrace/ai/assessment/replay -> replay the EXACT SAME validated
                                tests against the fixed app (no new AI call)

The AI provider (Nosana or Groq) only proposes intent; every proposal passes a
strict allowlist and is converted into the internal test representation before
the existing Daytona execution layer runs it. All Daytona logic lives in
daytona_runner.py / breaktrace_demo.py; this module only wires routing and
HTTP concerns.
"""

import os

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from ai_provider import (
    ProviderConfigError,
    ProviderUnavailableError,
    ProposalValidationError,
    analyze_attack_relationships,
    get_ai_health,
    get_cached_assessment,
    get_cached_proposal,
    get_provider_metadata,
    get_provider_name,
    propose_security_assessment,
    propose_security_test,
)
from ai_shared import (
    cache_latest_assessment_run,
    get_latest_assessment_run,
)
from applications import (
    ApplicationError,
    build_application_summary,
    get_application,
    record_assessment_completed,
    resolve_application,
)
from breaktrace_demo import (
    MODE_FIXED,
    MODE_VULNERABLE,
    build_replay_result,
    execute_breaktrace,
    proposal_to_definition,
    run_assessment,
    run_breaktrace,
)
from daytona_runner import run_sandbox_test
from library import (
    LibraryError,
    add_from_results,
    get_dashboard_metrics,
    get_entry,
    is_verified_principal_test,
    list_entries,
    reset_application_entries,
    replay_library,
)
from models import (
    ResolveApplicationRequest,
    SaveAssessmentRequest,
    TargetAssessRequest,
)
from nosana_client import (
    NosanaConfigError,
    NosanaUnavailableError,
    get_nosana_health,
)
from security_twin import run_security_twin_assessment, run_security_twin_discovery
from target_runner import run_target_assessment
from targets import (
    TargetError,
    get_target_adapter,
    list_targets,
    resolve_target_version,
)

app = FastAPI(title="BreakTrace API", version="0.8.0")

# Active application (in-memory, hackathon scope). Persistent records live in
# applications.json; this only remembers which application the current
# session targets after /applications/resolve. Resolving the same URL after a
# backend restart recovers the same persistent record.
_active_target_id: str | None = None


def _to_http_error(exc: Exception) -> HTTPException:
    """Map known backend exceptions to clean FastAPI errors.

    Never leaks environment variables or credentials - only the messages
    constructed above are surfaced.
    """
    if isinstance(exc, ProposalValidationError):
        return HTTPException(status_code=422, detail=str(exc))
    if isinstance(exc, ProviderUnavailableError):
        return HTTPException(status_code=502, detail=str(exc))
    if isinstance(exc, ProviderConfigError):
        return HTTPException(status_code=500, detail=str(exc))
    if isinstance(exc, LibraryError):
        return HTTPException(status_code=500, detail=str(exc))
    if isinstance(exc, ApplicationError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, TargetError):
        return HTTPException(status_code=400, detail=str(exc))
    return HTTPException(status_code=500, detail=str(exc))


def _active_application():
    """Return the active application record, or raise a clean 400.

    Since Milestone 7 every assessment belongs to an application: runs,
    saves, chain analysis, dashboard, library and replay are scoped to the
    application selected via POST /applications/resolve.
    """
    if _active_target_id is None:
        raise HTTPException(
            status_code=400,
            detail=(
                "No application selected. POST /applications/resolve with an "
                "application URL first."
            ),
        )
    record = get_application(_active_target_id)
    if record is None:
        raise HTTPException(
            status_code=400,
            detail="The active application record no longer exists.",
        )
    return record


# CORS. Local development origins are always allowed so the Next.js dev
# server can reach this API. The deployed frontend origin(s) are supplied via
# FRONTEND_ORIGIN (a comma-separated list, e.g. https://breaktrace.vercel.app)
# so production never needs a wildcard.
#
# We intentionally do NOT use allow_origins=["*"] in production.

def _cors_origins() -> list[str]:
    """Merge local dev origins with the FRONTEND_ORIGIN allowlist."""
    origins = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    for raw in os.getenv("FRONTEND_ORIGIN", "").split(","):
        origin = raw.strip().rstrip("/")
        if origin and origin not in origins:
            origins.append(origin)
    return origins


app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "BreakTrace"}


@app.post("/sandbox-test")
def sandbox_test() -> dict:
    try:
        return run_sandbox_test()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/breaktrace/demo")
def breaktrace_demo():
    """Run BT-001 against the deliberately vulnerable application."""
    try:
        return run_breaktrace(mode=MODE_VULNERABLE)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/breaktrace/replay")
def breaktrace_replay():
    """Replay the EXACT SAME BT-001 against the fixed application."""
    try:
        return run_breaktrace(mode=MODE_FIXED)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/nosana/health")
def nosana_health():
    """Verify the Nosana-hosted Ollama deployment is configured and reachable.

    Checks NOSANA_API_URL, NOSANA_MODEL, and that the model is listed by the
    Ollama /api/tags endpoint. No credentials are exposed.
    """
    try:
        return get_nosana_health()
    except HTTPException:
        raise
    except Exception as exc:
        raise _to_http_error(exc) from exc


@app.get("/ai/health")
def ai_health():
    """Report the current AI provider configuration.

    Returns the provider name, model, runtime (for Nosana/Ollama), and
    whether the provider is fully configured.
    """
    try:
        return get_ai_health()
    except HTTPException:
        raise
    except Exception as exc:
        raise _to_http_error(exc) from exc


# ---------------------------------------------------------------------------
# AI source label helper
# ---------------------------------------------------------------------------


def _ai_source() -> str:
    """Return the source label for AI-generated tests.

    Uses provider-specific values so Groq results are never mislabeled as
    Nosana-generated.
    """
    provider = get_provider_name()
    return f"{provider}_ai"


# ---------------------------------------------------------------------------
# Single proposal endpoints
# ---------------------------------------------------------------------------


@app.post("/breaktrace/ai/propose")
def breaktrace_ai_propose():
    """Ask the configured AI provider for ONE bounded security test.

    Sends the hardcoded controlled application context, parses the model's
    JSON, validates it against the strict allowlist, and returns the typed
    proposal. NOTHING is executed here.
    """
    try:
        proposal = propose_security_test()
        metadata = get_provider_metadata()
        # Include provider metadata alongside proposal fields without breaking
        # the frontend (extra keys are safely ignored by TS casts).
        return {**proposal.model_dump(), **metadata}
    except HTTPException:
        raise
    except Exception as exc:
        raise _to_http_error(exc) from exc


def _validated_proposal():
    """Reuse the most recent validated proposal if fresh, else ask the AI.

    The browser never supplies the proposal - the backend always decides what
    gets executed.
    """
    cached = get_cached_proposal()
    return cached if cached is not None else propose_security_test()


@app.post("/breaktrace/ai/run")
def breaktrace_ai_run():
    """Execute the validated AI proposal against the vulnerable app."""
    try:
        proposal = _validated_proposal()
        definition = proposal_to_definition(proposal)
        result = execute_breaktrace(
            definition,
            MODE_VULNERABLE,
            source=_ai_source(),
            hypothesis=proposal.hypothesis,
        )
        metadata = get_provider_metadata()
        return {"proposal": proposal.model_dump(), "result": result, **metadata}
    except HTTPException:
        raise
    except Exception as exc:
        raise _to_http_error(exc) from exc


@app.post("/breaktrace/ai/replay")
def breaktrace_ai_replay():
    """Replay the SAME validated AI proposal against the fixed app.

    Reuses the identical AI-generated test definition (no new AI call, no new
    test) - only the application mode changes to fixed.
    """
    try:
        proposal = _validated_proposal()
        definition = proposal_to_definition(proposal)
        result = execute_breaktrace(
            definition,
            MODE_FIXED,
            source=_ai_source(),
            hypothesis=proposal.hypothesis,
        )
        metadata = get_provider_metadata()
        return {"proposal": proposal.model_dump(), "result": result, **metadata}
    except HTTPException:
        raise
    except Exception as exc:
        raise _to_http_error(exc) from exc


# ---------------------------------------------------------------------------
# Assessment endpoints
# ---------------------------------------------------------------------------


def _validated_assessment():
    """Reuse the most recent validated assessment if fresh, else ask the AI.

    The browser never supplies the assessment - the backend always decides
    what gets executed and replayed.
    """
    cached = get_cached_assessment()
    return cached if cached is not None else propose_security_assessment()


@app.post("/breaktrace/ai/assessment/propose")
def breaktrace_assessment_propose():
    """Ask the configured AI provider for exactly 3 DISTINCT bounded security
    tests.

    Sends the expanded application context, parses the model's JSON, applies
    Pydantic validation, the strict allowlist, and the duplicate check, then
    returns the validated assessment. NOTHING is executed here.
    """
    try:
        assessment, _ = propose_security_assessment()
        metadata = get_provider_metadata()
        # assessment.model_dump() returns {"proposals": [...]}; adding
        # provider/metadata keys alongside is backward-compatible with the
        # frontend which reads only .proposals.
        return {**assessment.model_dump(), **metadata}
    except HTTPException:
        raise
    except Exception as exc:
        raise _to_http_error(exc) from exc


@app.post("/breaktrace/ai/assessment/run")
def breaktrace_assessment_run():
    """Execute ALL validated assessment tests against the vulnerable app in
    ONE fresh disposable Daytona sandbox.

    Since Milestone 7 the assessment belongs to the ACTIVE APPLICATION: on
    completion last_assessed_at is updated and assessment_count increments.
    The executed run is cached under the active target_id so chain analysis
    and library save never mix applications.
    """
    try:
        record = _active_application()
        assessment, assessment_id = _validated_assessment()
        run_result = run_assessment(
            assessment.proposals,
            MODE_VULNERABLE,
            source=_ai_source(),
            assessment_id=assessment_id,
        )
        cache_latest_assessment_run(run_result, record.target_id)
        record_assessment_completed(record.target_id)
        return run_result
    except HTTPException:
        raise
    except Exception as exc:
        raise _to_http_error(exc) from exc


@app.post("/breaktrace/ai/assessment/replay")
def breaktrace_assessment_replay():
    """Replay the EXACT SAME validated assessment against the fixed app.

    No new AI inference - the cached validated proposals are reused. A fresh
    Daytona sandbox runs the app in fixed mode and the same tests are
    executed, producing a compact per-test verdict + aggregate summary.
    """
    try:
        assessment, assessment_id = _validated_assessment()
        result = run_assessment(
            assessment.proposals,
            MODE_FIXED,
            source=_ai_source(),
            assessment_id=assessment_id,
        )
        return build_replay_result(assessment_id, result.results)
    except HTTPException:
        raise
    except Exception as exc:
        raise _to_http_error(exc) from exc


# ---------------------------------------------------------------------------
# Milestone 7 - application identity (URL origin)
# ---------------------------------------------------------------------------


@app.post("/applications/resolve")
def applications_resolve(payload: ResolveApplicationRequest):
    """Normalize an application URL and resolve it to an application record.

    Idempotent: the same normalized origin NEVER creates a duplicate record.
    A new URL automatically creates a new application; an existing URL loads
    its previous data (summary + scoped library). assessment_count is never
    bumped by resolving - only actual assessments increment it.

    IMPORTANT: entering a URL only identifies the application/project. It
    NEVER triggers scanning or attacks against that external URL - security
    execution always runs against the controlled Daytona demo application.
    """
    global _active_target_id
    try:
        created, record = resolve_application(payload.url)
        _active_target_id = record.target_id
        summary = build_application_summary(record)
        return {
            "created": created,
            "application": record.model_dump(mode="json"),
            "summary": summary.model_dump(mode="json"),
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise _to_http_error(exc) from exc


@app.get("/applications/{target_id}")
def applications_get(target_id: str):
    """Return an application record + its current summary."""
    try:
        record = get_application(target_id)
        if record is None:
            raise HTTPException(
                status_code=404,
                detail=f"Unknown application {target_id!r}.",
            )
        summary = build_application_summary(record)
        return {
            "application": record.model_dump(mode="json"),
            "summary": summary.model_dump(mode="json"),
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise _to_http_error(exc) from exc


@app.get("/applications/{target_id}/breaktraces")
def applications_breaktraces(target_id: str):
    """List ONLY the BreakTraces belonging to this application.

    BreakTraces from other target_ids are never included.
    """
    try:
        if get_application(target_id) is None:
            raise HTTPException(
                status_code=404,
                detail=f"Unknown application {target_id!r}.",
            )
        return list_entries(target_id)
    except HTTPException:
        raise
    except Exception as exc:
        raise _to_http_error(exc) from exc


@app.post("/applications/{target_id}/breaktraces/reset")
def applications_breaktraces_reset(target_id: str):
    """Safely reset the Security Memory of ONE application.

    Only entries belonging to this application are removed - the Security
    Memory of every other application is preserved. This exists so the known
    regression-demo lifecycle can start every inspection from a clean,
    reproducible Security Memory (BT-001, BT-002 fresh from the baseline
    assessment).
    """
    try:
        if get_application(target_id) is None:
            raise HTTPException(
                status_code=404,
                detail=f"Unknown application {target_id!r}.",
            )
        removed = reset_application_entries(target_id)
        return {
            "target_id": target_id,
            "removed": removed,
            "entries_remaining": 0,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise _to_http_error(exc) from exc


# ---------------------------------------------------------------------------
# Milestone 8 - independent target adapters (repository-based analysis)
# ---------------------------------------------------------------------------


@app.get("/targets")
def targets_list():
    """List the supported authorized training targets.

    Only explicitly supported adapters exist - arbitrary public websites are
    never targets.
    """
    try:
        return {"targets": list_targets()}
    except HTTPException:
        raise
    except Exception as exc:
        raise _to_http_error(exc) from exc


@app.post("/breaktrace/target/assess")
def breaktrace_target_assess(payload: TargetAssessRequest):
    """Run the full M8 lifecycle for an independent training target.

    Daytona sandbox -> clone pinned repo -> install -> start -> ready ->
    discovery -> AI hypotheses from DISCOVERED context -> validated -> tests
    executed against the sandbox-local instance -> evidence -> cleanup.

    The M7 application identity (payload.url) only selects/creates the
    application record and its history. It is NEVER scanned or probed - all
    security execution happens against the sandbox-local instance.
    """
    global _active_target_id
    try:
        adapter = resolve_target_version(payload.target_type, payload.version)
        if adapter.target_type == "demo":
            raise HTTPException(
                status_code=400,
                detail=(
                    "The BreakTrace Demo App uses the existing AI SECURITY "
                    "ASSESSMENT flow. Choose OWASP Juice Shop for "
                    "repository-based analysis."
                ),
            )

        # Application identity (M7): resolve from the supplied URL, or fall
        # back to the already-active application.
        if payload.url.strip():
            _, record = resolve_application(payload.url)
        else:
            record = _active_application()
        _active_target_id = record.target_id

        context, run_result = run_target_assessment(
            adapter, record.target_id
        )
        cache_latest_assessment_run(run_result, record.target_id)
        record_assessment_completed(record.target_id)

        metadata = get_provider_metadata()
        return {
            "application": record.model_dump(mode="json"),
            "context": context.model_dump(mode="json"),
            "results": [
                r.model_dump(mode="json") for r in run_result.results
            ],
            "summary": run_result.summary.model_dump(mode="json"),
            **metadata,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise _to_http_error(exc) from exc


# ---------------------------------------------------------------------------
# Milestone 9 - Security Twin unified assessment
# ---------------------------------------------------------------------------


@app.post("/security-twin/discover")
def security_twin_discover(payload: TargetAssessRequest):
    """Run repository and bounded sandbox-local discovery without AI.

    The supplied URL is application identity only; no request is sent to it.
    The adapter creates and destroys the isolated Security Twin.
    """
    global _active_target_id
    try:
        adapter = resolve_target_version(payload.target_type, payload.version)
        if adapter.target_type == "security_regression_demo":
            raise HTTPException(
                status_code=400,
                detail=(
                    "The BreakTrace Regression Demo uses the full Security Twin "
                    "/security-twin/assess flow, not /security-twin/discover."
                ),
            )
        if adapter.target_type == "demo":
            raise HTTPException(
                status_code=400,
                detail="The demo target does not use the repository discovery flow.",
            )
        if payload.url.strip():
            _, record = resolve_application(payload.url)
        else:
            record = _active_application()
        _active_target_id = record.target_id
        context = run_security_twin_discovery(adapter, record.target_id)
        return {
            "application": record.model_dump(mode="json"),
            "context": context.model_dump(mode="json"),
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise _to_http_error(exc) from exc


@app.post("/security-twin/assess")
def security_twin_assess(payload: TargetAssessRequest):
    """Run the full M9 Security Twin assessment for an authorized training
    target (e.g. OWASP Juice Shop).

    ONE Security Twin (one Daytona sandbox) serves every layer:

        replay Security Memory FIRST -> deterministic checks -> discovery ->
        AI security exploration -> validation -> runtime verification ->
        unified findings -> Security Memory bookkeeping -> destroy twin.

    The M7 application identity (payload.url) only selects/creates the
    application record and history. It is NEVER scanned or probed - all
    security execution happens against the sandbox-local instance.

    The executed AI layer is cached under the application's target_id so the
    existing save + chain-analysis endpoints keep working unchanged.
    """
    global _active_target_id
    try:
        adapter = resolve_target_version(payload.target_type, payload.version)
        if adapter.target_type == "demo":
            raise HTTPException(
                status_code=400,
                detail=(
                    "The BreakTrace Demo App uses the existing AI SECURITY "
                    "ASSESSMENT flow. Choose OWASP Juice Shop for Security "
                    "Twin analysis."
                ),
            )

        # Application identity (M7): resolve from the supplied URL, or fall
        # back to the already-active application.
        if payload.url.strip():
            _, record = resolve_application(payload.url)
        else:
            record = _active_application()
        _active_target_id = record.target_id

        context, assessment, ai_run = run_security_twin_assessment(
            adapter, record.target_id
        )
        cache_latest_assessment_run(ai_run, record.target_id)
        record_assessment_completed(record.target_id)

        return {
            "application": record.model_dump(mode="json"),
            "context": context.model_dump(mode="json"),
            "assessment": assessment.model_dump(mode="json"),
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise _to_http_error(exc) from exc


# ---------------------------------------------------------------------------
# Milestone 6 - attack-chain relationship analysis
# ---------------------------------------------------------------------------


@app.post("/breaktrace/ai/assessment/analyze-chain")
def breaktrace_assessment_analyze_chain():
    """Analyze relationships between VERIFIED assessment findings.

    Uses ONLY the latest executed assessment results (no new Daytona run, no
    new security tests). The configured AI provider interprets the evidence;
    the shared validator rejects invented BreakTrace IDs and any step that
    references a safe finding as a successful exploit.
    """
    try:
        _active_application()
        run_result = get_latest_assessment_run(_active_target_id)
        if run_result is None:
            raise HTTPException(
                status_code=400,
                detail=(
                    "No assessment has been executed for this application "
                    "yet. Run /breaktrace/ai/assessment/run first."
                ),
            )
        vulnerable = [
            r
            for r in run_result.results
            if r.test_executed
            and r.invariant_violated
            and r.status == "vulnerable"
        ]
        if not vulnerable:
            raise HTTPException(
                status_code=422,
                detail=(
                    "No verified vulnerabilities found in the latest "
                    "assessment to analyze."
                ),
            )
        analysis = analyze_attack_relationships(run_result.results)
        metadata = get_provider_metadata()
        return {**analysis.model_dump(), **metadata}
    except HTTPException:
        raise
    except Exception as exc:
        raise _to_http_error(exc) from exc


@app.post("/breaktrace/ai/assessment/save")
def breaktrace_assessment_save(payload: SaveAssessmentRequest | None = None):
    """Save verified vulnerable findings from the latest assessment into the
    regression library.

    Only test_executed + invariant_violated + status==vulnerable results are
    saved. Safe controls stay out of the regression library. Duplicate tests
    update nothing (existing entry preserved).

    require_verified_principal (optional) applies a generic finding-quality
    gate so only verified failures attributable to an authenticated principal
    enter Security Memory - unauthenticated baseline checks are excluded.
    """
    try:
        payload = payload or SaveAssessmentRequest()
        record = _active_application()
        run_result = get_latest_assessment_run(record.target_id)
        if run_result is None:
            raise HTTPException(
                status_code=400,
                detail=(
                    "No assessment has been executed for this application "
                    "yet. Run /breaktrace/ai/assessment/run first."
                ),
            )
        source = run_result.source or _ai_source()
        # Every saved BreakTrace is associated with the active application.
        return add_from_results(
            run_result,
            source,
            record.target_id,
            record.origin,
            quality_filter=(
                is_verified_principal_test
                if payload.require_verified_principal
                else None
            ),
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise _to_http_error(exc) from exc


# ---------------------------------------------------------------------------
# Milestone 6 - regression library
# ---------------------------------------------------------------------------


@app.get("/breaktrace/library")
def breaktrace_library_list():
    """List stored BreakTrace regression tests, scoped to the ACTIVE
    application (or legacy unassigned entries when none is selected).

    BreakTraces from other applications are never listed.
    """
    try:
        return list_entries(_active_target_id)
    except HTTPException:
        raise
    except Exception as exc:
        raise _to_http_error(exc) from exc


@app.get("/breaktrace/library/{entry_id}")
def breaktrace_library_get(entry_id: str):
    """Return one stored BreakTrace regression test."""
    try:
        entry = get_entry(entry_id)
        if entry is None:
            raise HTTPException(
                status_code=404,
                detail=f"No BreakTrace {entry_id!r} in the library.",
            )
        return entry
    except HTTPException:
        raise
    except Exception as exc:
        raise _to_http_error(exc) from exc


@app.post("/breaktrace/library/replay")
def breaktrace_library_replay():
    """Replay all stored regression BreakTraces against the FIXED controlled
    application in ONE Daytona sandbox.

    Updates replay_count, last_replayed and current status per entry while
    preserving the original evidence.
    """
    try:
        return replay_library(_active_target_id)
    except HTTPException:
        raise
    except Exception as exc:
        raise _to_http_error(exc) from exc


# ---------------------------------------------------------------------------
# Milestone 6 - dashboard
# ---------------------------------------------------------------------------


@app.get("/breaktrace/dashboard")
def breaktrace_dashboard():
    """Derive dashboard metrics for the ACTIVE APPLICATION from real
    assessment + library data. Never computed globally across applications.
    """
    try:
        latest = (
            get_latest_assessment_run(_active_target_id)
            if _active_target_id is not None
            else None
        )
        return get_dashboard_metrics(latest, _active_target_id)
    except HTTPException:
        raise
    except Exception as exc:
        raise _to_http_error(exc) from exc