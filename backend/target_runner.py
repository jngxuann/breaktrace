"""Daytona lifecycle runner for INDEPENDENT target adapters (Milestone 8).

Full per-assessment lifecycle for an authorized training target (e.g. OWASP
Juice Shop) inside ONE disposable Daytona sandbox:

    create sandbox (TTL safety net)
    -> clone pinned repository
    -> install dependencies (trusted adapter commands)
    -> start the application
    -> wait until it is actually ready
    -> repository + bounded runtime discovery -> ApplicationContext
    -> AI generates hypotheses from the DISCOVERED context
    -> BreakTrace validates them against discovered routes
    -> execute tests against the sandbox-local instance only
    -> capture evidence, build results
    -> destroy sandbox in finally cleanup (deterministic)

Performance choice: one sandbox per assessment (clone once, install once,
run discovery + all tests, then destroy). No prepared-image caching: the
current Daytona SDK surface creates default-image sandboxes, and a stale
snapshot would drift from the official repository. Deterministic cleanup and
the TTL mechanism are preserved.

Security: every request stays on the adapter's hardcoded sandbox-local
origin. Proposals carry only method+path (validated to discovered routes) -
there is no URL field, no shell command, no code path from the AI.
"""

import json
import re
import shlex

from daytona_runner import get_daytona_client
from discovery import (
    TARGET_TEST_CLIENT_SOURCE,
    build_application_context,
    build_probe_candidates,
    exec_in_sandbox,
    inspect_frontend_source,
    inspect_repository,
    probe_runtime,
)
from models import (
    ApplicationContext,
    ApplicationVersion,
    AssessmentRunResult,
    AssessmentSummary,
    BreakTraceExpected,
    BreakTraceObserved,
    BreakTraceResult,
    RegressionReplayResult,
    ReplayItem,
    SecurityTestProposal,
)
from targets import (
    TargetAdapter,
    get_target_adapter,
    resolve_ref,
)

CLIENT_PATH = "/tmp/breaktrace/target_client.py"
REMOTE_DIR = "/tmp/breaktrace"

# Trusted, adapter-defined timeouts for each lifecycle step.
_CLONE_TIMEOUT = 600
_INSTALL_TIMEOUT = 1800
_START_TIMEOUT = 60
_READY_TIMEOUT = 240
_TEST_TIMEOUT = 60


def _node_major(version_output: str) -> int:
    """Parse the major node version from `node --version` output."""
    match = re.search(r"v?(\d+)", version_output.splitlines()[0] if version_output else "")
    return int(match.group(1)) if match else 0


def prepare_target(sandbox, adapter: TargetAdapter) -> str:
    """Clone/install/start the target and wait until it is ready.

    Returns the sandbox-local origin (e.g. http://127.0.0.1:3000). All shell
    fragments come from the trusted adapter definition.

    Raises:
        RuntimeError: If any setup step fails or the app never becomes ready.
    """
    origin = f"http://127.0.0.1:{adapter.port}"

    # 1. Prerequisites. Node + npm are required for node-based adapters;
    #    python-only adapters (requires_node=False, e.g. the regression demo)
    #    skip them but still need git to clone the repository.
    node_major = 0
    if adapter.requires_node:
        version_out = exec_in_sandbox(
            sandbox, "node --version && npm --version && git --version", timeout=60
        )
        node_major = _node_major(version_out)
        if not node_major:
            raise RuntimeError(
                "Sandbox image has no usable node/npm. Target setup requires "
                "git, node and npm (see README for the required sandbox image)."
            )
    else:
        exec_in_sandbox(sandbox, "git --version", timeout=30)

    # 2. Clone the pinned repository (shallow). A full 40-hex ref is treated
    #    as a pinned commit SHA: shallow-clone the default branch, fetch the
    #    exact commit, and detach HEAD at it (GitHub serves arbitrary SHAs).
    if adapter.repository_url:
        exec_in_sandbox(sandbox, f"mkdir -p {REMOTE_DIR}", timeout=30)
        ref = resolve_ref(adapter, node_major)
        if ref and re.fullmatch(r"[0-9a-fA-F]{40}", ref):
            clone = (
                f"git clone --depth 1 {adapter.repository_url} {adapter.repo_dir}"
            )
            exec_in_sandbox(sandbox, clone, timeout=_CLONE_TIMEOUT)
            exec_in_sandbox(
                sandbox,
                f"git -C {adapter.repo_dir} fetch --depth 1 origin {ref}",
                timeout=_CLONE_TIMEOUT,
            )
            exec_in_sandbox(
                sandbox,
                f"git -C {adapter.repo_dir} checkout --detach {ref}",
                timeout=_CLONE_TIMEOUT,
            )
        elif ref:
            clone = (
                f"git clone --depth 1 --branch {ref} "
                f"{adapter.repository_url} {adapter.repo_dir}"
            )
            exec_in_sandbox(sandbox, clone, timeout=_CLONE_TIMEOUT)
        else:
            clone = f"git clone --depth 1 {adapter.repository_url} {adapter.repo_dir}"
            exec_in_sandbox(sandbox, clone, timeout=_CLONE_TIMEOUT)

    # 3. Install dependencies using the project's documented setup.
    if adapter.install_command:
        exec_in_sandbox(
            sandbox,
            f"cd {adapter.repo_dir} && {adapter.install_command}",
            timeout=_INSTALL_TIMEOUT,
        )

    # 4. Start the application in the background with trusted adapter env
    #    (e.g. placeholder VITE_* values so an SPA can boot in the twin).
    if adapter.start_command:
        exec_in_sandbox(
            sandbox,
            f"cd {adapter.repo_dir} && {adapter.start_command}",
            timeout=_START_TIMEOUT,
            env=adapter.env or None,
        )

    # 5. Upload the bounded HTTP client and wait until the app is ready.
    sandbox.fs.upload_file(TARGET_TEST_CLIENT_SOURCE.encode(), CLIENT_PATH)
    out = exec_in_sandbox(
        sandbox,
        f"python {CLIENT_PATH} --wait",
        timeout=_READY_TIMEOUT,
        env={"BREAKTRACE_TARGET_ORIGIN": origin},
    )
    if out != "ready":
        tail = ""
        try:
            tail = exec_in_sandbox(
                sandbox,
                f"tail -40 {adapter.repo_dir}/app.log 2>/dev/null || true",
                timeout=30,
            )
        except Exception:
            pass
        detail = f" App log tail: {tail}" if tail else ""
        raise RuntimeError(f"Target did not become ready in time.{detail}")
    return origin


def capture_application_version(
    sandbox, adapter: TargetAdapter
) -> ApplicationVersion | None:
    """Capture the application's version identity from the sandbox clone.

    Best-effort: runs git inside the sandbox against the freshly cloned repo
    and records the HEAD commit sha and the ref it was checked out at. If
    nothing can be determined, returns None - version information is NEVER
    invented.

    Returns:
        An ApplicationVersion with only the fields that were actually
        observed, or None when no version information is available.
    """
    if not adapter.repository_url:
        return None
    commit_sha = None
    ref = None
    try:
        commit_sha = exec_in_sandbox(
            sandbox,
            f"git -C {adapter.repo_dir} rev-parse HEAD",
            timeout=30,
        ).strip() or None
    except Exception:
        commit_sha = None
    try:
        # Best-effort ref label: tag if HEAD is tagged, else branch name.
        ref = exec_in_sandbox(
            sandbox,
            f"git -C {adapter.repo_dir} describe --tags --exact-match "
            "2>/dev/null || git -C "
            f"{adapter.repo_dir} rev-parse --abbrev-ref HEAD",
            timeout=30,
        ).strip() or None
    except Exception:
        ref = None
    # Detached HEAD (pinned commit) reports ref "HEAD" - report the pinned
    # adapter ref instead, which is the ref actually checked out.
    if ref == "HEAD" and adapter.ref:
        ref = adapter.ref
    if not commit_sha and not ref:
        return None
    return ApplicationVersion(
        repository=adapter.repository_url,
        ref=ref,
        commit_sha=commit_sha,
    )


def execute_proposals(
    sandbox,
    adapter: TargetAdapter,
    origin: str,
    proposals: list[SecurityTestProposal],
    prefix: str = "BT",
) -> list[BreakTraceResult]:
    """Execute validated proposals against the sandbox-local instance.

    GET tests run first, DELETE last (stable relative order preserved), so
    state-changing tests cannot corrupt other tests' assumptions. Every
    request targets ONLY the adapter's local origin.

    Raises:
        RuntimeError: If a test execution or its output parsing fails.
    """
    ordered = sorted(
        proposals, key=lambda p: 0 if p.request.method == "GET" else 1
    )
    results: list[BreakTraceResult] = []
    for index, proposal in enumerate(ordered, start=1):
        expected_status = proposal.expected_status
        path_arg = shlex.quote(proposal.request.path)
        env = {"BREAKTRACE_TARGET_ORIGIN": origin}
        request_headers = getattr(proposal.request, "headers", None) or {}
        if request_headers:
            env["BREAKTRACE_TARGET_HEADERS"] = "\n".join(
                f"{k}: {v}" for k, v in request_headers.items()
            )
        output = exec_in_sandbox(
            sandbox,
            f"python {CLIENT_PATH} {proposal.request.method} {path_arg}",
            timeout=_TEST_TIMEOUT,
            env=env,
        )
        try:
            parsed = json.loads(output)
            observed_status = int(parsed["status"])
            observed_body = parsed["body"]
        except (ValueError, KeyError, TypeError) as exc:
            raise RuntimeError(
                f"Malformed test output from sandbox: {output or '(empty)'}"
            ) from exc

        invariant_violated = observed_status != expected_status
        results.append(
            BreakTraceResult(
                id=f"{prefix}-{index:03d}",
                title=proposal.title,
                category=proposal.category,
                severity="high",
                invariant=proposal.invariant,
                actor=proposal.actor,
                request=proposal.request,
                expected=BreakTraceExpected(status=expected_status),
                observed=BreakTraceObserved(
                    status=observed_status, body=observed_body
                ),
                test_executed=True,
                invariant_violated=invariant_violated,
                status="vulnerable" if invariant_violated else "safe",
                mode="independent",
                source="",
                hypothesis=proposal.hypothesis,
            )
        )
    return results


def run_target_assessment(
    adapter: TargetAdapter, target_id: str
) -> tuple[ApplicationContext, AssessmentRunResult]:
    """Run the full M8 lifecycle for one independent target.

    Returns (ApplicationContext, AssessmentRunResult). The sandbox is ALWAYS
    destroyed in the finally block, including on setup/discovery/test failure.

    Raises:
        RuntimeError: Setup/discovery/execution failure.
        ProposalValidationError / ProviderUnavailableError / ProviderConfigError:
            AI hypothesis generation or validation failure.
    """
    from ai_provider import (
        get_provider_metadata,
        get_provider_name,
        propose_security_assessment_for_context,
    )

    client = get_daytona_client()
    sandbox = None
    try:
        # 1. Fresh disposable sandbox with a TTL safety net.
        try:
            sandbox = client.create()
        except Exception as exc:
            raise RuntimeError(f"Failed to create Daytona sandbox: {exc}") from exc
        try:
            sandbox.set_ttl(10)
        except Exception:
            pass  # best-effort

        # 2-5. Prepare the target (clone/install/start/ready).
        local_origin = prepare_target(sandbox, adapter)

        # 6. Discovery: repository + frontend inspection + bounded runtime
        #    probing.
        inspection = inspect_repository(sandbox, adapter)
        frontend = inspect_frontend_source(sandbox, adapter, inspection)
        candidates = build_probe_candidates(inspection)
        probed, runtime_diagnostics = probe_runtime(sandbox, adapter, local_origin, candidates)
        context = build_application_context(
            target_id,
            adapter,
            inspection,
            probed,
            local_origin,
            frontend_inspection=frontend,
            runtime_diagnostics=runtime_diagnostics,
        )

        # 7-8. AI hypotheses from DISCOVERED context, validated, then
        #      executed against the sandbox-local instance.
        assessment = propose_security_assessment_for_context(context)
        results = execute_proposals(sandbox, adapter, local_origin, assessment.proposals)

        violations = [r for r in results if r.invariant_violated]
        summary = AssessmentSummary(
            tests_generated=len(assessment.proposals),
            tests_executed=len(results),
            vulnerabilities_found=len(violations),
            controls_passed=len(results) - len(violations),
        )
        provider_name = get_provider_name()
        metadata = get_provider_metadata()
        run_result = AssessmentRunResult(
            assessment_id=f"{adapter.target_type[:3].upper()}-{target_id[:8]}",
            source=f"{provider_name}_ai",
            summary=summary,
            results=results,
            target_adapter=adapter.target_type,
            provider=metadata.get("provider", provider_name),
            model=metadata.get("model", ""),
        )
        return context, run_result
    finally:
        # 9. Always destroy the sandbox; a cleanup failure must not mask the
        #    real result or error.
        if sandbox is not None:
            try:
                client.delete(sandbox)
            except Exception:
                pass


def replay_entries_in_twin(
    sandbox,
    adapter: TargetAdapter,
    origin: str,
    entries,
) -> list[RegressionReplayResult]:
    """Replay stored BreakTrace entries against an ALREADY-RUNNING Security
    Twin instance (no new sandbox, no AI involvement).

    Replay uses the stored experiment exactly as saved (method, path,
    expected status) - it never asks an AI provider what the vulnerability
    was.

    Statuses per entry:
      passed     -> the stored expected condition held (not reproduced)
      regression -> the previously verified condition has returned
      error      -> the experiment could not be replayed (never a regression)

    Original evidence in the library is never touched.
    """
    items: list[RegressionReplayResult] = []
    replay_version = getattr(adapter, "ref", None) or ""
    for entry in entries:
        try:
            path_arg = shlex.quote(entry.request.path)
            env = {"BREAKTRACE_TARGET_ORIGIN": origin}
            request_headers = getattr(entry.request, "headers", None) or {}
            if request_headers:
                env["BREAKTRACE_TARGET_HEADERS"] = "\n".join(
                    f"{k}: {v}" for k, v in request_headers.items()
                )
            output = exec_in_sandbox(
                sandbox,
                f"python {CLIENT_PATH} {entry.request.method} {path_arg}",
                timeout=_TEST_TIMEOUT,
                env=env,
            )
            parsed = json.loads(output)
            observed_status = int(parsed["status"])
            invariant_violated = observed_status != entry.expected.status
            items.append(
                RegressionReplayResult(
                    entry_id=entry.id,
                    title=entry.title,
                    status=(
                        "regression" if invariant_violated else "passed"
                    ),
                    expected_status=entry.expected.status,
                    observed_status=observed_status,
                    severity=entry.severity,
                    category=entry.category,
                    invariant=entry.invariant,
                    method=entry.request.method,
                    path=entry.request.path,
                    first_detected_version=(
                        (entry.application_version or {}).get("ref")
                        if entry.application_version
                        else entry.first_detected_at or None
                    ),
                    last_replayed_version=replay_version,
                )
            )
        except Exception as exc:
            items.append(
                RegressionReplayResult(
                    entry_id=entry.id,
                    title=entry.title,
                    status="error",
                    expected_status=entry.expected.status,
                    error=str(exc),
                    severity=entry.severity,
                    category=entry.category,
                    invariant=entry.invariant,
                    method=entry.request.method,
                    path=entry.request.path,
                    first_detected_version=(
                        (entry.application_version or {}).get("ref")
                        if entry.application_version
                        else entry.first_detected_at or None
                    ),
                    last_replayed_version=replay_version,
                )
            )
    return items


def replay_juice_shop_entries(entries) -> list[ReplayItem]:
    """Re-execute stored Juice Shop BreakTraces against a fresh sandbox
    instance (honest re-execution - never claims a fix).

    Statuses per entry (backward-compatible vocabulary used by the M6/M7
    library replay flow):
      passed  -> invariant held (attack no longer reproducible)
      failed  -> invariant violated (STILL VULNERABLE)
      error   -> execution error (test could not be re-run)

    The sandbox is always destroyed in finally.

    Raises:
        RuntimeError: If the Juice Shop target cannot be prepared.
    """
    adapter = get_target_adapter("juice_shop")
    client = get_daytona_client()
    sandbox = None
    try:
        try:
            sandbox = client.create()
        except Exception as exc:
            raise RuntimeError(f"Failed to create Daytona sandbox: {exc}") from exc
        try:
            sandbox.set_ttl(10)
        except Exception:
            pass
        origin = prepare_target(sandbox, adapter)

        replayed = replay_entries_in_twin(sandbox, adapter, origin, entries)
        return [
            ReplayItem(
                id=item.entry_id,
                status="failed" if item.status == "regression" else item.status,
            )
            for item in replayed
        ]
    finally:
        if sandbox is not None:
            try:
                client.delete(sandbox)
            except Exception:
                pass
