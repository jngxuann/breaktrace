"""Pydantic models for BreakTrace results."""

from typing import Literal

from pydantic import BaseModel, field_validator


class BreakTraceActor(BaseModel):
    """Who performed the adversarial action."""

    name: str
    user_id: int


class BreakTraceRequest(BaseModel):
    """The adversarial request that was executed.

    headers (Milestone 11) optionally carries a strict, allowlisted set of
    request headers needed for controlled tests (e.g. X-Demo-User). Dangerous
    headers are rejected at validation time.
    """

    method: str
    path: str
    headers: dict[str, str] | None = None


class BreakTraceExpected(BaseModel):
    """What should happen if the security invariant holds."""

    status: int


class BreakTraceObserved(BaseModel):
    """What actually happened when the request was executed.

    body may be a parsed JSON object, a raw string (e.g. an SPA HTML shell),
    or None when the response carried no body.
    """

    status: int
    body: dict | str | None = None


class SecurityTestProposal(BaseModel):
    """A bounded HTTP security test proposed by an AI (Nosana/Qwen).

    This is INTENT only. Nothing here is executed until the proposal has
    passed BreakTrace's allowlist validation and been converted into the
    internal test representation used by the Daytona execution layer.
    """

    title: str
    category: str
    hypothesis: str
    invariant: str
    actor: BreakTraceActor
    request: BreakTraceRequest
    expected_status: int
    reason: str


class BreakTraceResult(BaseModel):
    """A structured, replayable security regression test result.

    The same test definition (actor, request, expected) is executed against
    an application running in a given mode. `invariant_violated` tells
    whether the observed behavior deviated from the expected secure behavior;
    a violation means the vulnerability was reproduced in this run.

    `source` records where the test definition came from ("breaktrace" for
    the built-in demo, "nosana_ai" for Nosana-proposed tests, "groq_ai" for
    Groq-proposed tests) and `hypothesis` carries the AI's reasoning when
    present.
    """

    id: str
    title: str
    category: str
    severity: str
    invariant: str
    actor: BreakTraceActor
    request: BreakTraceRequest
    expected: BreakTraceExpected
    observed: BreakTraceObserved
    test_executed: bool
    invariant_violated: bool
    status: str
    mode: str
    source: str = "breaktrace"
    hypothesis: str | None = None


class SecurityAssessmentProposal(BaseModel):
    """A validated set of exactly 3 distinct AI-proposed security tests.

    This is INTENT only - nothing is executed until the allowlist gate and the
    Daytona execution layer have both approved it.
    """

    proposals: list[SecurityTestProposal]

    @field_validator("proposals")
    @classmethod
    def exactly_three_proposals(cls, value: list[SecurityTestProposal]) -> list[SecurityTestProposal]:
        if len(value) != 3:
            raise ValueError(
                f"Exactly 3 proposals are required, got {len(value)}."
            )
        return value


class AssessmentSummary(BaseModel):
    """Aggregate counts computed from actual execution results."""

    tests_generated: int
    tests_executed: int
    vulnerabilities_found: int
    controls_passed: int


class AssessmentRunResult(BaseModel):
    """The full result of executing a validated assessment in Daytona.

    Since Milestone 8 runs may come from an independent target (e.g. OWASP
    Juice Shop) rather than the embedded demo app: target_adapter records
    which adapter produced the run, and provider/model record the AI
    transport that generated the hypotheses. Demo runs leave these empty.
    """

    assessment_id: str
    source: str
    summary: AssessmentSummary
    results: list[BreakTraceResult]
    target_adapter: str = ""
    provider: str = ""
    model: str = ""


class ReplaySummary(BaseModel):
    """Aggregate counts for replaying an assessment against the fixed app."""

    tests_replayed: int
    passed: int
    failed: int


class ReplayItem(BaseModel):
    """Compact per-test replay verdict (id + status)."""

    id: str
    status: str


class AssessmentReplayResult(BaseModel):
    """The aggregate result of replaying all BreakTraces in fixed mode."""

    assessment_id: str
    mode: str
    summary: ReplaySummary
    results: list[ReplayItem]


# ---------------------------------------------------------------------------
# Milestone 6 - attack-chain relationship analysis
# ---------------------------------------------------------------------------


class AttackChainStep(BaseModel):
    """One step in a proposed attack relationship, referencing a VERIFIED
    BreakTrace result."""

    breaktrace_id: str
    description: str


class AttackRelationshipAnalysis(BaseModel):
    """The AI's structured interpretation of relationships between verified
    security findings.

    This is INTERPRETATION of existing evidence, never new evidence: every
    referenced breaktrace_id must correspond to a BreakTrace result where
    test_executed=True and invariant_violated=True. Safe/passed findings can
    never be represented as successful attack steps.
    """

    analysis_id: str | None = None
    type: Literal[
        "attack_chain", "correlated_findings", "shared_root_cause", "none"
    ]
    title: str
    summary: str
    breaktrace_ids: list[str] = []
    steps: list[AttackChainStep] = []
    root_cause: str
    impact: str
    confidence: Literal["low", "medium", "high"]


# ---------------------------------------------------------------------------
# Milestone 6 - regression library + dashboard
# ---------------------------------------------------------------------------


class LibraryEntry(BaseModel):
    """One persistent regression test in the BreakTrace library.

    Distinguishes ORIGINAL status (the verified failure that created the
    BreakTrace) from CURRENT status (the latest replay against the fixed
    application). The original evidence is never overwritten by replays.

    Since Milestone 7 every entry belongs to ONE application (target_id +
    origin). Legacy M6 entries have empty target_id and are migrated to the
    first application created (see applications.migrate_unassigned_entries).
    """

    id: str
    fingerprint: str
    title: str
    category: str
    severity: str
    invariant: str
    actor: BreakTraceActor
    request: BreakTraceRequest
    expected: BreakTraceExpected
    original_observed: BreakTraceObserved
    original_status: str
    source: str
    kind: str = "regression"
    first_seen: str
    last_replayed: str | None = None
    replay_count: int = 0
    current_status: str | None = None
    latest_observed_status: int | None = None
    target_id: str = ""
    origin: str = ""
    hypothesis: str | None = None
    target_adapter: str = ""
    provider: str = ""
    model: str = ""
    # Milestone 9 - Security Memory enrichment (all optional; legacy M6/M7
    # entries stay fully compatible).
    origin_source: str = ""          # "ai" | "deterministic" | "regression"
    assessment_id: str = ""
    application_version: dict | None = None
    test_definition: dict | None = None
    first_detected_at: str = ""      # defaults to first_seen when empty
    last_replayed_at: str | None = None
    # Milestone 12 - commit/ref of the last version this test was replayed
    # against (e.g. V1/V2/V3 info surfaced in the Security Memory UI).
    last_replayed_version: str | None = None


class LibraryListResponse(BaseModel):
    """All stored BreakTrace regression tests."""

    total: int
    entries: list[LibraryEntry]


class LibraryReplayResult(BaseModel):
    """Aggregate result of replaying the whole library in fixed mode."""

    replayed: int
    passed: int
    regressions: int
    results: list[ReplayItem]


class DashboardMetrics(BaseModel):
    """High-level metrics derived ONLY from real assessment + library data."""

    tests_generated: int | None = None
    verified_vulnerabilities: int | None = None
    controls_passed: int | None = None
    regression_tests_saved: int = 0
    current_regressions: int = 0
    replay_pass_rate: float | None = None
    security_score: int | None = None


# ---------------------------------------------------------------------------
# Milestone 7 - application identity
# ---------------------------------------------------------------------------


class ApplicationRecord(BaseModel):
    """One recognized BreakTrace application, identified by its normalized
    URL origin.

    The target_id is a deterministic SHA-256 of the normalized origin, so
    the same application is always found again (even after a backend
    restart) without storing raw URLs as filenames.
    """

    target_id: str
    origin: str
    display_name: str
    created_at: str
    last_assessed_at: str | None = None
    assessment_count: int = 0


class ApplicationSummary(BaseModel):
    """Application-scoped summary derived ONLY from real data.

    verified_vulnerabilities counts the stored regression BreakTraces for
    this application (every verified vulnerability becomes one regression
    test). regression_score is None ("Not enough data") until at least one
    regression test has been replayed.
    """

    application: ApplicationRecord
    verified_vulnerabilities: int = 0
    regression_tests: int = 0
    current_regressions: int = 0
    regression_score: int | None = None
    last_assessed_at: str | None = None


class ResolveApplicationRequest(BaseModel):
    """Payload for POST /applications/resolve."""

    url: str


class SaveAssessmentRequest(BaseModel):
    """Payload for POST /breaktrace/ai/assessment/save (optional).

    require_verified_principal opts into a generic finding-quality gate: only
    verified failures attributable to an authenticated principal (actor with
    a real user_id or a request identity header) are saved to Security
    Memory. Unauthenticated baseline checks are excluded. Normal saves keep
    the default behaviour when the flag is omitted.
    """

    require_verified_principal: bool = False


class ResolveApplicationResponse(BaseModel):
    """Response for POST /applications/resolve."""

    created: bool
    application: ApplicationRecord
    summary: ApplicationSummary


# ---------------------------------------------------------------------------
# Milestone 8 - target adapters + application discovery
# ---------------------------------------------------------------------------


class TargetInfo(BaseModel):
    """Public description of one authorized training target adapter."""

    target_type: str
    name: str
    description: str
    repository: str
    port: int
    local_origin: str
    supported_methods: list[str]
    application_identity: str = ""
    # Milestone 12 - an ordered list of selectable, allowlisted versions for
    # targets like the regression demo (each is {key, label, ref}). The
    # frontend renders a version selector and sends `version` on assess.
    versions: list[dict] = []


class TargetAssessRequest(BaseModel):
    """Payload for POST /breaktrace/target/assess.

    target_type selects the authorized training target adapter (e.g.
    "juice_shop"). url is the M7 application identity origin - it only
    selects/creates the application record and history; it is NEVER scanned
    or probed.
    """

    target_type: str
    url: str = ""
    # Milestone 12 - optional allowlisted version key (e.g. "v1"). Only
    # adapter-defined versions are accepted; arbitrary refs never execute.
    version: str = ""


class DiscoveredRoute(BaseModel):
    """One application endpoint discovered from the repository, the running
    instance, or both. `source` preserves provenance."""

    method: str
    path: str
    source: Literal["repository", "runtime", "both"] = "repository"


class FrontendRoute(BaseModel):
    """One client-side route discovered from frontend source (e.g. a React
    Router path). DISCOVERY SIGNAL only - never a vulnerability claim.
    """

    path: str
    component: str = ""
    source: Literal["repository", "runtime", "both"] = "repository"


class DiscoveryEvidence(BaseModel):
    """Bounded provenance for one repository discovery signal."""

    source: str = ""
    provenance: Literal["repository", "runtime", "both"] = "repository"
    confidence: Literal["low", "medium", "high"] = "medium"


class ApplicationCapability(BaseModel):
    """Evidence-backed application capability, not a vulnerability claim."""

    name: str
    source: str = ""
    provenance: Literal["repository", "runtime", "both"] = "repository"
    confidence: Literal["low", "medium", "high"] = "medium"


class ExternalService(BaseModel):
    """External service/SDK referenced by the repository."""

    type: str
    provenance: Literal["repository", "runtime", "both"] = "repository"
    source: str = ""
    confidence: Literal["low", "medium", "high"] = "high"


class IdentityInput(BaseModel):
    """One way the application reads the caller's identity from a request
    (Milestone 12 - conservative repository discovery).

    DISCOVERY SIGNAL only: it records that a header (e.g. X-Demo-User) is
    consumed as identity. It is NEVER a secret or a credential value.

    kind/purpose stay generic (not demo-specific): a header whose name hints
    at user/identity is marked purpose="user_identity", otherwise
    "request_header".
    """

    name: str
    kind: Literal["request_header"] = "request_header"
    purpose: Literal["user_identity", "request_header"] = "request_header"
    provenance: Literal["repository", "runtime", "both"] = "repository"
    source: str = ""
    confidence: Literal["low", "medium", "high"] = "medium"


class ResourceOwnership(BaseModel):
    """Conservative ownership metadata for one resource family inferred from
    repository source (Milestone 12).

    Derived only from static fixtures/manifest structures, never from
    production data. `owners` maps resource identifier -> owner principal
    identifier (e.g. report 2 -> user 2). `resource_identifiers` and
    `principal_identifiers` are the bounded numeric ids actually seen in
    source (seed evidence).
    """

    resource: str
    resource_identifier: str = "id"
    owner_field: str = ""
    identity_field: str = "user_id"
    resource_identifiers: list[int] = []
    principal_identifiers: list[int] = []
    owners: dict[int, int] = {}
    provenance: Literal["repository", "runtime", "both"] = "repository"
    source: str = ""
    confidence: Literal["low", "medium", "high"] = "low"


class SeedEntity(BaseModel):
    """A clearly fictional static fixture seen in repository source, with
    only its bounded identifiers recorded (Milestone 12).

    Conservative: integer-keyed literal dicts only, small and capped; labels
    are short, non-sensitive strings (e.g. fictional user names). Never
    secrets, never environment values, never production database contents.
    """

    entity_type: str
    identifiers: list[int] = []
    labels: dict = {}
    provenance: Literal["repository", "runtime", "both"] = "repository"
    source: str = ""
    confidence: Literal["low", "medium", "high"] = "high"


class DataResource(BaseModel):
    """Data-service resource and operations evidenced in source."""

    name: str
    service: str
    operations: list[str] = []
    provenance: Literal["repository", "runtime", "both"] = "repository"
    source: str = ""
    confidence: Literal["low", "medium", "high"] = "high"


class StorageResource(BaseModel):
    """Remote storage bucket/resource evidenced in source."""

    name: str
    service: str
    operations: list[str] = []
    provenance: Literal["repository", "runtime", "both"] = "repository"
    source: str = ""
    confidence: Literal["low", "medium", "high"] = "high"


class APIReference(BaseModel):
    """One API interaction referenced in client source.

    kind: "external" (absolute URL), "relative" (same-origin path), or
    "supabase_table" (client-side Supabase .from(...) reference). These are
    DISCOVERY SIGNALS - external/backend references are never attacked
    automatically.
    """

    url: str
    kind: Literal["external", "relative", "supabase_table"] = "relative"
    method: str = ""
    source: Literal["repository", "runtime", "both"] = "repository"


class StorageSignal(BaseModel):
    """One client-side storage interaction (localStorage/sessionStorage).
    DISCOVERY SIGNAL only."""

    storage_type: Literal["localStorage", "sessionStorage"]
    key: str
    source: Literal["repository", "runtime", "both"] = "repository"


class ApplicationContext(BaseModel):
    """Structured context about an INDEPENDENT application under test, built
    by discovery (repository inspection + bounded runtime probing of the
    sandbox-local instance). The AI reasons from this instead of a hardcoded
    app description.

    runtime_origin is the sandbox-local origin (e.g. http://127.0.0.1:3000)
    - never an external host. Tests are constrained to the discovered routes.

    Milestone 10: frontend-heavy targets additionally expose DISCOVERY
    SIGNALS (frontend_routes, api_references, storage_signals,
    environment_references, external_services). These describe the client
    surface - they are never treated as vulnerabilities by themselves.
    """

    target_id: str
    name: str
    framework: str = ""
    runtime_origin: str
    routes: list[DiscoveredRoute] = []
    auth_signals: list[str] = []
    models: list[str] = []
    security_relevant_components: list[str] = []
    discovery_summary: str = ""
    frontend_routes: list[FrontendRoute] = []
    api_references: list[APIReference] = []
    storage_signals: list[StorageSignal] = []
    environment_references: list[str] = []
    external_services: list[str] = []
    # Generic frontend/repository understanding fields. Existing fields above
    # remain compatible with M8-M10 clients and tests.
    frameworks: list[str] = []
    dependencies: list[str] = []
    capabilities: list[ApplicationCapability] = []
    external_service_sdks: list[ExternalService] = []
    data_resources: list[DataResource] = []
    storage_resources: list[StorageResource] = []
    authentication_provider: list[str] = []
    authentication_usage: list[str] = []
    runtime_routes: list[DiscoveredRoute] = []
    spa_fallback_detected: bool = False
    # Milestone 11 - query parameter names actually evidenced in source
    # (searchParams.get(...)/URLSearchParams/location.search/router usage).
    # NEVER invented: only parameters present in discovered code are listed,
    # and executable experiments may only use parameters in this list.
    query_parameters: list[str] = []
    # Milestone 12 - request header names the target permits on executable
    # experiments (from the adapter, never arbitrary). BreakTrace only ever
    # sends allowlisted headers with bounded values.
    allowed_request_headers: list[str] = []
    # Milestone 12 - generic, conservative authorization semantics inferred
    # from repository source so the AI can reason about cross-user object
    # authorization instead of only missing authentication:
    #   identity_inputs        - request headers consumed as identity
    #   resource_relationships - resource ownership metadata (owner_field,
    #                            resource/principal ids, owners map)
    #   seed_entities          - clearly fictional static seed fixtures
    identity_inputs: list[IdentityInput] = []
    resource_relationships: list[ResourceOwnership] = []
    seed_entities: list[SeedEntity] = []
    discovery_diagnostics: dict = {}


# ---------------------------------------------------------------------------
# Milestone 9 - Security Twin: unified finding model + assessment result
# ---------------------------------------------------------------------------


class ApplicationVersion(BaseModel):
    """Version identity of the application running inside the Security Twin.

    Captured from the sandbox clone where available. NEVER invented: any
    component that cannot be determined stays None, and if nothing can be
    determined the whole object is omitted (null).
    """

    repository: str | None = None
    ref: str | None = None
    commit_sha: str | None = None


class ExecutableExperimentInput(BaseModel):
    """One executable_experiment proposed by the AI (Milestone 11).

    Same strict grid as SecurityTestProposal but the actor is optional at the
    LLM layer (defaulted to the anonymous actor during validation) and the
    output is identified by type="executable_experiment". INTENT only -
    nothing is executed until validate_executable_experiment() approves it
    and the Daytona layer runs it.
    """

    type: Literal["executable_experiment"] = "executable_experiment"
    title: str
    category: str
    hypothesis: str
    invariant: str
    actor: BreakTraceActor | None = None
    request: BreakTraceRequest
    expected_status: int
    reason: str


class SecurityObservation(BaseModel):
    """Application-specific security reasoning that BreakTrace CANNOT verify
    inside the current Security Twin (Milestone 11).

    A security observation is NOT a vulnerability and is NOT a finding. It
    describes a meaningful security question or trust boundary that depends
    on something outside the twin (e.g. an external Supabase backend's RLS
    or storage policies) or that cannot be safely verified here.

    It must never:
      - contain an executable request / payload / shell / code
      - be marked verified
      - increment vulnerability or verified-finding counts
      - enter Security Memory as a regression test
    """

    type: Literal["security_observation"] = "security_observation"
    title: str
    category: str
    reason: str
    evidence: list[str] = []
    # Always not_verifiable_in_twin - enforced by the Literal below.
    verification: Literal["not_verifiable_in_twin"] = "not_verifiable_in_twin"
    verification_requirement: str = ""


class SecurityFinding(BaseModel):
    """Normalized security finding across ALL assessment layers.

    source distinguishes where the finding came from:
      deterministic - a bounded known-check (no AI)
      regression    - a previously verified BreakTrace replayed
      ai            - a runtime-verified AI hypothesis

    status distinguishes the outcome:
      passed    - the condition was tested and held
      verified  - a real, runtime-proven security failure
      regression- a previously fixed condition has returned
      error     - the check could not be executed (never counts as regression)

    AI hypotheses are NOT findings. Only runtime-verified AI failures become
    status = "verified".
    """

    id: str
    target_id: str
    source: Literal["deterministic", "regression", "ai"]
    category: str
    title: str
    severity: str
    status: Literal["passed", "verified", "regression", "error"]
    description: str
    evidence: dict = {}
    remediation: str = ""
    test_definition: dict | None = None
    assessment_id: str = ""
    application_version: ApplicationVersion | None = None


class RegressionReplayResult(BaseModel):
    """Outcome of replaying ONE stored BreakTrace against the Security Twin.

    status: passed (condition holds), regression (previously verified failure
    reproduced), or error (could not be replayed). ERROR never counts as a
    regression.

    Milestone 12 - Security Memory display fields are carried on the replay
    result so the frontend can render the full memory from backend-derived
    data (never faked): category, invariant, and the first/last-replayed
    version labels (e.g. demo-v1-vulnerable / demo-v2-fixed).
    """

    entry_id: str
    title: str
    status: Literal["passed", "regression", "error"]
    expected_status: int
    observed_status: int | None = None
    error: str | None = None
    severity: str = "high"
    category: str = ""
    invariant: str = ""
    # Milestone 12 - the stored request that is replayed (method/path), so
    # the UI can show exactly what test came from Security Memory.
    method: str = ""
    path: str = ""
    first_detected_version: str | None = None
    last_replayed_version: str | None = None


class RegressionSection(BaseModel):
    """Layer 1 - Security Regression summary derived from real replay data."""

    tests_replayed: int
    passed: int
    regressions: int
    errors: int
    results: list[RegressionReplayResult] = []


class DeterministicSection(BaseModel):
    """Layer 2 - Deterministic security check summary derived from real
    execution results."""

    checks_executed: int
    passed: int
    issues: int
    results: list[SecurityFinding] = []


class AiExplorationItem(BaseModel):
    """One AI security analysis and, for executable experiments, its runtime
    verification outcome.

    Milestone 11 - the AI may produce two distinct analysis kinds:

      kind="experiment" -> an executable_experiment that BreakTrace validated
          and (unless rejected/not_verifiable) runtime-verified. It is NEVER a
          finding by itself: only verification="verified" items represent
          runtime-proven failures. verification="rejected" items never
          executed and are recorded with a reason. verification
          ="not_verifiable_in_twin" items executed but did not exercise any
          server-side security logic.

      kind="observation" -> a security_observation. It is NOT a finding and is
          NEVER verified; verification is always "not_verifiable_in_twin".
          These carry evidence references + a verification_requirement instead
          of an executable experiment.
    """

    hypothesis: str
    reason: str
    title: str
    category: str
    experiment: dict
    expected_status: int | None = None
    observed_status: int | None = None
    verification: Literal[
        "verified", "passed", "error", "not_verifiable_in_twin", "rejected"
    ]
    rejection_reason: str | None = None
    # Milestone 11 - analysis kind (default "experiment" keeps older clients
    # working).
    kind: Literal["experiment", "observation"] = "experiment"
    evidence: list[str] = []
    verification_requirement: str = ""


class AiExplorationSection(BaseModel):
    """Layer 3 - AI Security Exploration summary.

    Milestone 11 - the AI is no longer forced to produce executable tests. It
    produces "analyses", each of which is an executable_experiment or a
    security_observation. Counts:
      hypotheses_generated     = total analyses (experiments + observations
                                 + rejected)
      executable_experiments   = analyses accepted as executable experiments
      observations             = security observations (never findings)
      tests_executed           = experiments actually runtime-verified
      verified_findings        = runtime-proven experiment failures
      hypotheses_rejected      = analyses that failed validation
    """

    provider: str
    model: str
    hypotheses_generated: int
    tests_executed: int
    verified_findings: int
    hypotheses_rejected: int = 0
    observations: int = 0
    executable_experiments: int = 0
    results: list[AiExplorationItem] = []
    # Milestone 12 - whether fresh AI exploration ran. A remote AI failure
    # (status="unavailable"/"error") must NOT invalidate the regression /,
    # deterministic / discovery / findings layers - the frontend renders this
    # as "AI Exploration unavailable", not as a failed assessment.
    status: Literal["ok", "unavailable", "error"] = "ok"
    error_message: str = ""


class SecurityTwinInfo(BaseModel):
    """The Security Twin runtime representation inside an assessment result."""

    sandbox_provider: str = "daytona"
    application_version: ApplicationVersion | None = None


class SecurityTwinSummary(BaseModel):
    """High-level M9 summary - EVERY value derived from result arrays, never
    hardcoded."""

    security_regressions: int
    new_verified_findings: int
    deterministic_issues: int
    controls_passed: int


class SecurityTwinAssessment(BaseModel):
    """Unified Security Twin assessment result (Milestone 9).

    One Security Twin (one Daytona sandbox) serves every layer:
    regression replay FIRST -> deterministic checks -> discovery -> AI
    exploration -> validation -> runtime verification -> unified findings.
    """

    assessment_id: str
    target: dict
    security_twin: SecurityTwinInfo
    regression: RegressionSection
    deterministic: DeterministicSection
    discovery: ApplicationContext | None = None
    ai_exploration: AiExplorationSection
    findings: list[SecurityFinding] = []
    summary: SecurityTwinSummary
    timings: dict = {}
