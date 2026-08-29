"""Security Twin orchestrator (Milestone 9).

The Security Twin is an isolated, runnable instance of the developer's
application inside a Daytona sandbox. Security testing happens against this
disposable instance - never against a live production origin.

Lifecycle per assessment (ONE sandbox per assessment):

    SecurityTwin.create()                          # Daytona sandbox (TTL net)
    SecurityTwin.prepare()                         # clone / install / start / ready
    LAYER 1  replay stored BreakTraces FIRST       # no AI, uses stored experiments
    LAYER 2  deterministic checks                  # no AI, bounded known checks
             application discovery -> ApplicationContext
    LAYER 3  AI security exploration               # hypotheses from discovered context
             BreakTrace validation                 # shared allowlist gate
             runtime verification                  # execute against the twin
             unified findings + Security Memory bookkeeping
    finally: SecurityTwin.destroy()                # sandbox NEVER leaks

SecurityTwin orchestrates the existing targets.py / target_runner.py /
daytona_runner.py infrastructure - it does NOT duplicate Daytona
functionality. Cleanup is protected by finally behavior.
"""

import time

from ai_provider import (
    get_provider_metadata,
    get_provider_name,
    propose_security_analysis_for_twin_split,
)
from checks.base import TwinRuntime
from checks.registry import (
    get_check_registry,
    get_source_check_registry,
)
from checks.source import (
    SourceSecurityCheck,
    scan_repository_source,
)
from daytona_runner import get_daytona_client
from discovery import (
    build_application_context,
    build_probe_candidates,
    inspect_frontend_source,
    inspect_repository,
    probe_runtime,
)
from library import load_regression_entries, mark_entries_replayed
from models import (
    AiExplorationItem,
    AiExplorationSection,
    AssessmentRunResult,
    AssessmentSummary,
    DeterministicSection,
    RegressionReplayResult,
    RegressionSection,
    SecurityFinding,
    SecurityObservation,
    SecurityTestProposal,
    SecurityTwinAssessment,
    SecurityTwinInfo,
    SecurityTwinSummary,
)
from target_runner import (
    CLIENT_PATH,
    capture_application_version,
    execute_proposals,
    prepare_target,
    replay_entries_in_twin,
)

_twin_number = 0


def _next_twin_id() -> str:
    """Return the next sequential Security Twin assessment id."""
    global _twin_number
    _twin_number += 1
    return f"TWIN-{_twin_number:03d}"


class SecurityTwin:
    """Runtime representation of the isolated application instance.

    Conceptually: SecurityTwin -> Daytona Sandbox -> Application Instance.
    """

    def __init__(self, adapter, target_id: str):
        self.adapter = adapter
        self.target_id = target_id
        self.client = None
        self.sandbox = None
        self.runtime_origin: str | None = None
        self.application_version = None
        self.repository = adapter.repository_url
        self.status = "pending"

    def create(self) -> "SecurityTwin":
        """Create the Daytona sandbox with a TTL safety net."""
        try:
            self.client = get_daytona_client()
            self.sandbox = self.client.create()
        except Exception as exc:
            raise RuntimeError(f"Failed to create Daytona sandbox: {exc}") from exc
        try:
            self.sandbox.set_ttl(10)
        except Exception:
            pass  # best-effort safety net
        self.status = "created"
        return self

    def prepare(self) -> "SecurityTwin":
        """Clone / install / start the target and wait until it is ready.

        Also captures the application version identity where available.
        """
        self.runtime_origin = prepare_target(self.sandbox, self.adapter)
        self.application_version = capture_application_version(
            self.sandbox, self.adapter
        )
        self.status = "ready"
        return self

    def destroy(self) -> None:
        """Always destroy the sandbox; a cleanup failure must not mask the
        real result or error."""
        if self.sandbox is not None and self.client is not None:
            try:
                self.client.delete(self.sandbox)
            except Exception:
                pass
            self.sandbox = None
        self.status = "destroyed"


def _twin_runtime(twin: SecurityTwin) -> TwinRuntime:
    """Bounded HTTP access to the running twin for deterministic checks."""
    return TwinRuntime(
        twin.sandbox, twin.adapter, twin.runtime_origin, CLIENT_PATH
    )


# ---------------------------------------------------------------------------
# Layer 2 - deterministic checks (no AI)
# ---------------------------------------------------------------------------


def run_deterministic_checks(
    runtime: TwinRuntime,
    target_id: str,
    assessment_id: str,
    version,
) -> list[SecurityFinding]:
    """Execute every registered deterministic check against the twin.

    HTTP checks probe the sandbox-local instance; source checks scan the
    cloned repository inside the sandbox. Returns one SecurityFinding per
    check: status \"verified\" for issues, \"passed\" when the check
    completed cleanly, or \"error\" when the check itself could not be
    executed (never counted as an issue).
    """
    findings: list[SecurityFinding] = []

    def _record(check, issues: list[SecurityFinding]) -> None:
        if issues:
            findings.extend(
                issue.model_copy(
                    update={
                        "target_id": target_id,
                        "assessment_id": assessment_id,
                        "application_version": version,
                    }
                )
                for issue in issues
            )
        else:
            findings.append(
                SecurityFinding(
                    id=f"{check.id}-passed",
                    target_id=target_id,
                    source="deterministic",
                    category=check.category,
                    title=check.title,
                    severity=check.severity,
                    status="passed",
                    description="Check executed; no issue detected.",
                    evidence={},
                    assessment_id=assessment_id,
                    application_version=version,
                )
            )

    def _error(check, exc: Exception) -> None:
        findings.append(
            SecurityFinding(
                id=f"{check.id}-error",
                target_id=target_id,
                source="deterministic",
                category=check.category,
                title=check.title,
                severity=check.severity,
                status="error",
                description=f"Check could not be executed: {exc}",
                evidence={},
                assessment_id=assessment_id,
                application_version=version,
            )
        )

    for check in get_check_registry():
        try:
            issues = check.run(runtime)
        except Exception as exc:
            _error(check, exc)
            continue
        _record(check, issues)

    # Milestone 10 - source-based checks (bounded repository scan).
    source_checks = [
        c for c in get_source_check_registry()
        if isinstance(c, SourceSecurityCheck)
    ]
    if source_checks:
        try:
            scan = scan_repository_source(
                runtime.sandbox, runtime.adapter, source_checks
            )
        except Exception as exc:
            for check in source_checks:
                _error(check, exc)
        else:
            for check in source_checks:
                try:
                    issues = check.run_source(scan.get(check.id, []))
                except Exception as exc:
                    _error(check, exc)
                    continue
                _record(check, issues)
    return findings


# ---------------------------------------------------------------------------
# Layer 1 - security regression (replay stored BreakTraces FIRST, no AI)
# ---------------------------------------------------------------------------


def _regression_section(items: list[RegressionReplayResult]) -> RegressionSection:
    return RegressionSection(
        tests_replayed=len(items),
        passed=sum(1 for i in items if i.status == "passed"),
        regressions=sum(1 for i in items if i.status == "regression"),
        errors=sum(1 for i in items if i.status == "error"),
        results=items,
    )


def _regression_findings(
    items: list[RegressionReplayResult],
    target_id: str,
    assessment_id: str,
    version,
) -> list[SecurityFinding]:
    descriptions = {
        "passed": "Stored experiment replayed; the security condition holds.",
        "regression": (
            "Previously verified security condition has returned: the stored "
            "experiment reproduced the failure again."
        ),
        "error": "The stored experiment could not be replayed (not a regression).",
    }
    return [
        SecurityFinding(
            id=f"REG-{item.entry_id}",
            target_id=target_id,
            source="regression",
            category="regression",
            title=item.title,
            severity=item.severity,
            status=item.status,
            description=descriptions[item.status],
            evidence={
                "entry_id": item.entry_id,
                "expected_status": item.expected_status,
                "observed_status": item.observed_status,
                "error": item.error,
            },
            assessment_id=assessment_id,
            application_version=version,
        )
        for item in items
    ]


# ---------------------------------------------------------------------------
# Layer 3 - AI security exploration (validated, then runtime verified)
# ---------------------------------------------------------------------------


def _is_spa_shell(body) -> bool:
    """True when the response body is the SPA shell (index.html fallback)."""
    if isinstance(body, str):
        head = body[:600].upper()
        return (
            "<!DOCTYPE HTML>" in head
            or "<HTML" in head
            or '<div id="root">' in body
        )
    return False


def _is_secure_denial(expected_status: int, observed_status: int) -> bool:
    """True when a status mismatch is NOT a security failure because BOTH the
    expected and observed results are denials (401/403).

    Conservatively applied only to the denial-vs-denial case (e.g. expected
    401 / observed 403, or expected 403 / observed 401). A denial expected
    but a successful (200/201/204...) response observed is still a security
    failure. This never weakens exact-status verification for unrelated tests.
    """
    denials = {401, 403}
    return (
        expected_status in denials
        and observed_status in denials
        and expected_status != observed_status
    )


def _cross_user_evidence(result, context) -> dict:
    """Enrich a verified AI finding with cross-user (IDOR) context derived from
    discovered evidence - never from hardcoded apps.

    Returns a bounded dict only when ALL of the following hold for the executed
    experiment:
      - a discovered user_identity header was supplied,
      - the path targets a discovered parameterized resource route,
      - that resource has a discovered owner for the requested id,
      - the supplied principal differs from the resource owner (cross-principal).
    Only allowlisted header values (bounded, non-secret) are ever recorded.
    """
    headers = getattr(result.request, "headers", None) or {}
    principal_id = None
    for ii in getattr(context, "identity_inputs", []) or []:
        name = getattr(ii, "name", "") or ""
        if not name or name not in headers:
            continue
        if getattr(ii, "purpose", "") != "user_identity":
            continue
        try:
            candidate = int(str(headers.get(name)))
        except (TypeError, ValueError):
            continue
        principal_id = candidate
        break
    if principal_id is None:
        return {}

    base = result.request.path.split("?")[0].rstrip("/")
    resource_name = ""
    resource_id = None
    for route in getattr(context, "routes", []) or []:
        template = route.path.split("?")[0].rstrip("/")
        if ":" not in template:
            continue
        tsegs = template.split("/")
        bsegs = base.split("/")
        if len(tsegs) != len(bsegs):
            continue
        pidxs = [i for i, s in enumerate(tsegs) if s.startswith(":")]
        if not pidxs:
            continue
        # every non-param segment must match; the param becomes the id.
        ok = True
        for i, (t, b) in enumerate(zip(tsegs, bsegs)):
            if i in pidxs:
                try:
                    resource_id = int(b)
                except (TypeError, ValueError):
                    ok = False
                    break
                continue
            if t != b:
                ok = False
                break
        if not ok:
            continue
        j = pidxs[0]
        resource_name = tsegs[j - 1] if j > 0 else ""
        break
    if not resource_name or resource_id is None:
        return {}

    owner_id = None
    for rel in getattr(context, "resource_relationships", []) or []:
        if (getattr(rel, "resource", "") or "").lower() == resource_name.lower():
            owner_id = (getattr(rel, "owners", None) or {}).get(resource_id)
            break
    if owner_id is None or owner_id == principal_id:
        return {}

    user_labels = {}
    for se in getattr(context, "seed_entities", []) or []:
        if (getattr(se, "entity_type", "") or "").lower() in ("users", "user", "accounts"):
            user_labels = getattr(se, "labels", None) or {}
            break

    def _label(pid):
        lbl = user_labels.get(pid)
        return f"user {pid}" if lbl is None else f"user {pid} / {lbl}"

    return {
        "cross_user_access": True,
        "principal": principal_id,
        "principal_label": _label(principal_id),
        "resource": resource_name,
        "resource_identifier": resource_id,
        "resource_owner": owner_id,
        "resource_owner_label": _label(owner_id),
        "request": {"method": result.request.method, "path": result.request.path},
        "request_headers": dict(headers),
        "expected_status": result.expected.status,
        "observed_status": result.observed.status,
    }


def _build_ai_extra_context(
    deterministic_findings: list[SecurityFinding],
    regression_items: list[RegressionReplayResult],
) -> str:
    """Summarize what Layers 1-2 already covered so the AI does not propose
    duplicate tests."""
    issues = [f for f in deterministic_findings if f.status == "verified"]
    passed = [f for f in deterministic_findings if f.status == "passed"]
    issues_text = ", ".join(f.title for f in issues) or "none"
    replayed_titles = ", ".join(i.title for i in regression_items) or "none"
    return (
        "- Deterministic checks completed: "
        f"{len(deterministic_findings)} check(s) "
        f"({len(issues)} issue(s) found, {len(passed)} passed). "
        f"Issues found: {issues_text}.\n"
        "- Security regression replay completed: "
        f"{len(regression_items)} stored BreakTrace(s) replayed "
        f"({sum(1 for i in regression_items if i.status == 'passed')} passed, "
        f"{sum(1 for i in regression_items if i.status == 'regression')} "
        f"regression, "
        f"{sum(1 for i in regression_items if i.status == 'error')} error). "
        f"Replayed titles: {replayed_titles}."
    )


def run_ai_exploration(
    twin: SecurityTwin,
    context,
    target_id: str,
    assessment_id: str,
    version,
    deterministic_findings: list[SecurityFinding],
    regression_items: list[RegressionReplayResult],
) -> tuple[AiExplorationSection, AssessmentRunResult, list[SecurityFinding]]:
    """Layer 3 (Milestone 11): the AI returns up to 3 security analyses -
    each independently an executable_experiment or a security_observation -
    derived from the DISCOVERED context.

    Executable experiments pass BreakTrace validation one at a time (split
    validation) and are runtime-verified against the SAME twin. Only
    runtime-verified experiment failures become verified AI findings.
    Security observations are application-specific reasoning with NO
    executable surface: they are never verified, never count as findings,
    never increment vulnerability/finding counts, and never enter Security
    Memory (they are not present in the executed run at all). A rejected
    analysis never aborts the assessment.
    """
    extra = _build_ai_extra_context(
        deterministic_findings, regression_items
    )
    valid_proposals, observations, rejected = propose_security_analysis_for_twin_split(
        context, extra_context=extra
    )
    # Robust to providers that return validated SecurityTestProposal objects
    # (the normal path) or raw executable_experiment dicts.
    valid_proposals = [
        p
        if isinstance(p, SecurityTestProposal)
        else SecurityTestProposal.model_validate(
            {
                **{k: v for k, v in (p or {}).items() if k != "type"},
                "actor": (p or {}).get("actor")
                          or {"name": "anonymous", "user_id": 0},
            }
        )
        for p in valid_proposals
    ]
    results = execute_proposals(
        twin.sandbox, twin.adapter, twin.runtime_origin, valid_proposals
    )

    by_pair = {
        (p.request.method, p.request.path): p for p in valid_proposals
    }
    metadata = get_provider_metadata()
    provider_name = get_provider_name()

    def _classify(result) -> str:
        """Honest verification classification for one executed experiment.

        For frontend-only twins the server only serves the SPA shell, so an
        experiment against a client-side route does not exercise any
        server-side security logic - it is classified not_verifiable_in_twin
        instead of being claimed as a pass or a verified finding. The ready
        path itself (the app loading) is a real, passed control.

        Milestone 12 secure-denial rule: when the experiment EXPECTS a denial
        (401/403) and the target ALSO returns a denial (401/403) - i.e.
        cross-denial (expected 401/observed 403 or vice versa) - access was
        still denied, so this is NOT a verified security vulnerability, even
        though the exact status differs. A denial-versus-200 remains a
        verified security failure. Exact-status verification for unrelated
        tests is unchanged.
        """
        if not result.test_executed:
            return "error"
        if twin.adapter.frontend_only and _is_spa_shell(result.observed.body):
            if (
                result.request.path == twin.adapter.ready_path
                and result.observed.status == result.expected.status
            ):
                return "passed"
            return "not_verifiable_in_twin"
        violated = result.invariant_violated and not _is_secure_denial(
            result.expected.status, result.observed.status
        )
        return "verified" if violated else "passed"

    items: list[AiExplorationItem] = []
    findings: list[SecurityFinding] = []
    projected: list = []
    vulnerable_count = 0
    control_count = 0
    for result in results:
        proposal = by_pair.get((result.request.method, result.request.path))
        verification = _classify(result)
        if verification == "not_verifiable_in_twin":
            # Projected copy for the M8-compat cached run: must never be
            # saved as a verified vulnerability or counted as a passed
            # control.
            projected.append(
                result.model_copy(
                    update={"invariant_violated": False, "status": "not_verifiable"}
                )
            )
        elif verification == "passed" and result.invariant_violated:
            # Secure denial (expected 401/403, observed the other denial):
            # passage, never a saved vulnerability in the cached run.
            projected.append(
                result.model_copy(
                    update={"invariant_violated": False, "status": "safe"}
                )
            )
            control_count += 1
        else:
            projected.append(result)
            if verification == "verified":
                vulnerable_count += 1
            elif verification == "passed":
                control_count += 1

        if verification == "not_verifiable_in_twin":
            items.append(
                AiExplorationItem(
                    hypothesis=result.hypothesis or "",
                    reason=proposal.reason if proposal else "",
                    title=result.title,
                    category=result.category,
                    experiment={
                        "method": result.request.method,
                        "path": result.request.path,
                    },
                    expected_status=result.expected.status,
                    observed_status=(
                        result.observed.status if result.test_executed else None
                    ),
                    verification="not_verifiable_in_twin",
                    kind="experiment",
                )
            )
            # Not a finding: the property was never exercised server-side.
            continue

        status = verification
        if result.test_executed:
            evidence = {
                "expected_status": result.expected.status,
                "observed_status": result.observed.status,
                "observed_body": result.observed.body,
            }
            if status == "verified":
                xu = _cross_user_evidence(result, context)
                if xu:
                    evidence = {**evidence, **xu}
        else:
            evidence = {}
        items.append(
            AiExplorationItem(
                hypothesis=result.hypothesis or "",
                reason=proposal.reason if proposal else "",
                title=result.title,
                category=result.category,
                experiment={
                    "method": result.request.method,
                    "path": result.request.path,
                },
                expected_status=result.expected.status,
                observed_status=(
                    result.observed.status if result.test_executed else None
                ),
                verification=verification,
                kind="experiment",
            )
        )
        findings.append(
            SecurityFinding(
                id=f"AI-{result.id}",
                target_id=target_id,
                source="ai",
                category=result.category,
                title=result.title,
                severity=result.severity,
                status=status,
                description=(
                    "AI hypothesis runtime-verified as a security failure."
                    if status == "verified"
                    else (
                        "AI hypothesis executed; the expected secure behavior "
                        "held."
                        if status == "passed"
                        else "AI hypothesis could not be executed."
                    )
                ),
                evidence=evidence,
                remediation="",
                test_definition={
                    **{
                        "kind": "http_experiment",
                        "method": result.request.method,
                        "path": result.request.path,
                        "expected_status": result.expected.status,
                    },
                    **(
                        {"headers": result.request.headers}
                        if getattr(result.request, "headers", None)
                        else {}
                    ),
                },
                assessment_id=assessment_id,
                application_version=version,
            )
        )

    # Security observations: application-specific reasoning, no executable
    # surface. They are represented in the exploration results so the UI can
    # show them, but they NEVER become findings and are absent from the
    # executed run (so they can never enter Security Memory).
    for obs_raw in observations:
        obs = obs_raw if isinstance(obs_raw, SecurityObservation) else (
            SecurityObservation.model_validate(obs_raw)
        )
        items.append(
            AiExplorationItem(
                hypothesis="",
                reason=obs.reason,
                title=obs.title,
                category=obs.category,
                experiment={},
                expected_status=None,
                observed_status=None,
                verification="not_verifiable_in_twin",
                kind="observation",
                evidence=list(obs.evidence),
                verification_requirement=obs.verification_requirement,
            )
        )

    # Rejected analyses: recorded with a reason, never executed, never
    # findings, and they must NOT abort the assessment.
    for rejected_entry in rejected:
        items.append(
            AiExplorationItem(
                hypothesis=rejected_entry.get("hypothesis", ""),
                reason="",
                title="Rejected analysis",
                category="",
                experiment={},
                expected_status=None,
                observed_status=None,
                verification="rejected",
                rejection_reason=rejected_entry.get("reason", ""),
            )
        )

    hypotheses_generated = len(valid_proposals) + len(observations) + len(rejected)
    ai_run = AssessmentRunResult(
        assessment_id=assessment_id,
        source=f"{provider_name}_ai",
        summary=AssessmentSummary(
            tests_generated=hypotheses_generated,
            tests_executed=len(results),
            vulnerabilities_found=vulnerable_count,
            controls_passed=control_count,
        ),
        results=projected,
        target_adapter=twin.adapter.target_type,
        provider=metadata.get("provider", provider_name),
        model=metadata.get("model", ""),
    )
    verified_count = sum(1 for f in findings if f.status == "verified")
    section = AiExplorationSection(
        provider=metadata.get("provider", provider_name),
        model=metadata.get("model", ""),
        hypotheses_generated=hypotheses_generated,
        tests_executed=len(results),
        verified_findings=verified_count,
        hypotheses_rejected=len(rejected),
        observations=len(observations),
        executable_experiments=len(valid_proposals),
        results=items,
    )
    return section, ai_run, findings


# ---------------------------------------------------------------------------
# Unified assessment assembly
# ---------------------------------------------------------------------------


def _build_assessment(
    adapter,
    target_id: str,
    assessment_id: str,
    version,
    regression_items: list[RegressionReplayResult],
    deterministic_findings: list[SecurityFinding],
    ai_section: AiExplorationSection,
    context,
    findings: list[SecurityFinding],
    timings: dict,
) -> SecurityTwinAssessment:
    regression = _regression_section(regression_items)
    det_passed = sum(1 for f in deterministic_findings if f.status == "passed")
    det_issues = sum(1 for f in deterministic_findings if f.status == "verified")
    deterministic = DeterministicSection(
        checks_executed=len(deterministic_findings),
        passed=det_passed,
        issues=det_issues,
        results=deterministic_findings,
    )
    summary = SecurityTwinSummary(
        security_regressions=regression.regressions,
        new_verified_findings=ai_section.verified_findings,
        deterministic_issues=det_issues,
        controls_passed=sum(1 for f in findings if f.status == "passed"),
    )
    return SecurityTwinAssessment(
        assessment_id=assessment_id,
        target={
            "target_type": adapter.target_type,
            "name": adapter.name,
            "repository": adapter.repository_url,
            "port": adapter.port,
            "application_identity": adapter.application_identity,
        },
        security_twin=SecurityTwinInfo(application_version=version),
        regression=regression,
        deterministic=deterministic,
        discovery=context,
        ai_exploration=ai_section,
        findings=findings,
        summary=summary,
        timings=timings,
    )


def run_security_twin_discovery(adapter, target_id: str):
    """Run repository and bounded runtime discovery only.

    Reuses the SecurityTwin lifecycle and intentionally makes no AI call and
    runs no deterministic security checks. The sandbox is always destroyed.
    """
    twin = SecurityTwin(adapter, target_id)
    twin.create()
    try:
        twin.prepare()
        inspection = inspect_repository(twin.sandbox, adapter)
        frontend = inspect_frontend_source(twin.sandbox, adapter, inspection)
        candidates = build_probe_candidates(inspection)
        probed, runtime_diagnostics = probe_runtime(
            twin.sandbox, adapter, twin.runtime_origin, candidates
        )
        return build_application_context(
            target_id,
            adapter,
            inspection,
            probed,
            twin.runtime_origin,
            frontend_inspection=frontend,
            runtime_diagnostics=runtime_diagnostics,
        )
    finally:
        twin.destroy()


def run_security_twin_assessment(adapter, target_id: str):
    """Run the full M9 Security Twin assessment lifecycle.

    Flow: resolve application (caller) -> create twin -> prepare -> replay
    Security Memory FIRST -> deterministic checks -> discovery -> AI
    exploration -> validation -> runtime verification -> unified findings ->
    Security Memory bookkeeping -> destroy twin (ALWAYS, via finally).

    Returns:
        (ApplicationContext, SecurityTwinAssessment, AssessmentRunResult)
        where the AssessmentRunResult is the executed AI layer (cached so the
        existing M6/M7 save + chain-analysis endpoints keep working).

    Raises:
        RuntimeError: Setup/discovery/execution failure.
        Provider errors: AI hypothesis generation or validation failure.
        LibraryError: Corrupted Security Memory.
    """
    twin = SecurityTwin(adapter, target_id)
    timings: dict = {}
    _t0 = time.monotonic()
    twin.create()
    timings["sandbox_create_s"] = round(time.monotonic() - _t0, 2)
    assessment_id = _next_twin_id()
    try:
        _t0 = time.monotonic()
        twin.prepare()
        timings["prepare_s"] = round(time.monotonic() - _t0, 2)
        version = twin.application_version

        # LAYER 1 - Security Regression replay FIRST (stored experiments, no AI).
        _t0 = time.monotonic()
        regression_items: list[RegressionReplayResult] = []
        entries = load_regression_entries(target_id, adapter.target_type)
        if entries:
            regression_items = replay_entries_in_twin(
                twin.sandbox, adapter, twin.runtime_origin, entries
            )
            mark_entries_replayed(regression_items, version)
        timings["replay_s"] = round(time.monotonic() - _t0, 2)

        # LAYER 2 - Deterministic checks (bounded, no AI).
        _t0 = time.monotonic()
        deterministic_findings = run_deterministic_checks(
            _twin_runtime(twin), target_id, assessment_id, version
        )
        timings["deterministic_s"] = round(time.monotonic() - _t0, 2)

        # DISCOVERY - ApplicationContext from repository + bounded runtime probes.
        _t0 = time.monotonic()
        inspection = inspect_repository(twin.sandbox, adapter)
        frontend = inspect_frontend_source(twin.sandbox, adapter, inspection)
        candidates = build_probe_candidates(inspection)
        probed, runtime_diagnostics = probe_runtime(
            twin.sandbox, adapter, twin.runtime_origin, candidates
        )
        context = build_application_context(
            target_id,
            adapter,
            inspection,
            probed,
            twin.runtime_origin,
            frontend_inspection=frontend,
            runtime_diagnostics=runtime_diagnostics,
        )
        timings["discovery_s"] = round(time.monotonic() - _t0, 2)

        # LAYER 3 - AI Security Exploration (validated + runtime verified).
        # A remote AI failure MUST NOT destroy the layers that already ran - we
        # preserve and return the regression/deterministic/discovery/evidence
        # results and represent AI exploration as unavailable instead of
        # failing the whole assessment.
        _t0 = time.monotonic()
        provider_name = get_provider_name()
        try:
            ai_section, ai_run, ai_findings = run_ai_exploration(
                twin,
                context,
                target_id,
                assessment_id,
                version,
                deterministic_findings,
                regression_items,
            )
        except Exception as exc:  # noqa: BLE001 - AI layer failure is non-fatal
            ai_findings = []
            ai_section = AiExplorationSection(
                provider=provider_name,
                model="",
                hypotheses_generated=0,
                tests_executed=0,
                verified_findings=0,
                observations=0,
                executable_experiments=0,
                results=[],
                status="unavailable",
                error_message=str(exc)[:400],
            )
            ai_run = AssessmentRunResult(
                assessment_id=assessment_id,
                source=f"{provider_name}_ai",
                summary=AssessmentSummary(
                    tests_generated=0,
                    tests_executed=0,
                    vulnerabilities_found=0,
                    controls_passed=0,
                ),
                results=[],
                target_adapter=adapter.target_type,
                provider=provider_name,
            )
        timings["ai_exploration_s"] = round(time.monotonic() - _t0, 2)

        regression_findings = _regression_findings(
            regression_items, target_id, assessment_id, version
        )
        findings = (
            deterministic_findings + regression_findings + ai_findings
        )
        timings["total_s"] = round(
            sum(v for v in timings.values() if isinstance(v, (int, float))), 2
        )
        assessment = _build_assessment(
            adapter,
            target_id,
            assessment_id,
            version,
            regression_items,
            deterministic_findings,
            ai_section,
            context,
            findings,
            timings,
        )
        return context, assessment, ai_run
    finally:
        # A failed assessment must never leak a sandbox.
        twin.destroy()
