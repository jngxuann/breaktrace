"""BreakTrace Milestone 2 + 3 + 5 - reproduce, fix, replay in Daytona.

Everything for this milestone runs INSIDE a disposable Daytona sandbox:

    1. create a fresh sandbox
    2. upload the invoice API (stdlib http.server) + test client
    3. start the app in the background with the requested BREAKTRACE_MODE
    4. wait until the app is ready
    5. run the adversarial test client inside the sandbox
       (Alice -> GET /api/invoices/2)
    6. capture status + body and evaluate the security invariant
    7. delete the sandbox (always, in a finally block)

The SAME shared test definition (BREAKTRACE_BT_001) is executed against
whichever application mode is requested:

    run_breaktrace("vulnerable")  -> expected 403, observed 200 (vulnerable)
    run_breaktrace("fixed")       -> expected 403, observed 403 (passed)

The attack never changes - only the application behavior changes.

Milestone 5 adds the AI SECURITY ASSESSMENT: up to three validated AI
proposals are executed against ONE fresh sandbox (GET tests first, DELETE
last, so state-changing tests cannot corrupt other tests' assumptions):

    run_assessment(proposals, "vulnerable") -> AssessmentRunResult
    run_assessment(proposals, "fixed")      -> same shape, replayed

Security: the vulnerable application and the test client are HARDCODED string
constants below. The frontend can never influence what runs inside the
sandbox - no shell commands, URLs, Python, or scripts are accepted from it.
The target is always the app we just started on 127.0.0.1 inside the sandbox.
"""

import json 

from daytona_runner import get_daytona_client
from models import (
    AssessmentReplayResult,
    AssessmentRunResult,
    AssessmentSummary,
    BreakTraceActor,
    BreakTraceExpected,
    BreakTraceObserved,
    BreakTraceRequest,
    BreakTraceResult,
    ReplayItem,
    ReplaySummary,
    SecurityTestProposal,
)

# ---------------------------------------------------------------------------
# Hardcoded payloads executed inside the sandbox
# ---------------------------------------------------------------------------

APP_PORT = 8080
REMOTE_DIR = "/tmp/breaktrace"
APP_PATH = f"{REMOTE_DIR}/app.py"
TEST_CLIENT_PATH = f"{REMOTE_DIR}/test_client.py"
LOG_PATH = f"{REMOTE_DIR}/app.log"

# The deliberately vulnerable invoice API. Runs on 127.0.0.1 inside the
# sandbox only. Milestone 5 expands the demo with a third user (Admin), an
# admin-only endpoint and a protected state-changing operation:
#
#   GET    /api/invoices/{id}   ownership check only when BREAKTRACE_MODE=fixed
#   GET    /api/admin/users     admin-role check only when BREAKTRACE_MODE=fixed
#   DELETE /api/invoices/{id}   ownership check ALWAYS enforced (secure control)
#
# The AI proposes hypotheses; this hardcoded app is what Daytona actually runs.
VULNERABLE_APP_SOURCE = r'''
import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

INVOICES = {
    1: {"id": 1, "owner_id": 1, "owner": "Alice", "amount": 120},
    2: {"id": 2, "owner_id": 2, "owner": "Bob", "amount": 450},
}

USERS = [
    {"id": 1, "name": "Alice", "role": "user"},
    {"id": 2, "name": "Bob", "role": "user"},
    {"id": 99, "name": "Admin", "role": "admin"},
]

# For this controlled demo every request is treated as Alice (user_id=1, role=user).
CURRENT_USER_ID = 1
CURRENT_USER_ROLE = "user"

MODE = os.getenv("BREAKTRACE_MODE", "vulnerable")
ENFORCE_OWNERSHIP = MODE == "fixed"
ENFORCE_ADMIN_ROLE = MODE == "fixed"


class Handler(BaseHTTPRequestHandler):
    def _send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            self._send(200, {"status": "ok"})
            return
        if path == "/api/admin/users":
            if ENFORCE_ADMIN_ROLE and CURRENT_USER_ROLE != "admin":
                self._send(403, {"detail": "Forbidden"})
                return
            # VULNERABLE MODE (default): any caller can list users.
            self._send(200, {"users": USERS})
            return
        prefix = "/api/invoices/"
        if path.startswith(prefix):
            try:
                invoice_id = int(path[len(prefix):])
            except ValueError:
                self._send(400, {"error": "invalid invoice id"})
                return
            invoice = INVOICES.get(invoice_id)
            if invoice is None:
                self._send(404, {"error": "invoice not found"})
                return
            if ENFORCE_OWNERSHIP and invoice["owner_id"] != CURRENT_USER_ID:
                self._send(403, {"detail": "Forbidden"})
                return
            # VULNERABLE MODE (default): no ownership check - any invoice is
            # returned to any caller.
            self._send(200, invoice)
            return
        self._send(404, {"error": "not found"})

    def do_DELETE(self):
        path = urlparse(self.path).path
        prefix = "/api/invoices/"
        if not path.startswith(prefix):
            self._send(404, {"error": "not found"})
            return
        try:
            invoice_id = int(path[len(prefix):])
        except ValueError:
            self._send(400, {"error": "invalid invoice id"})
            return
        invoice = INVOICES.get(invoice_id)
        if invoice is None:
            self._send(404, {"error": "invoice not found"})
            return
        # This control is ALWAYS enforced (vulnerable and fixed mode): a user
        # may only delete their own invoices.
        if invoice["owner_id"] != CURRENT_USER_ID:
            self._send(403, {"detail": "Forbidden"})
            return
        del INVOICES[invoice_id]
        self._send(200, {"status": "deleted", "id": invoice_id})

    def log_message(self, *args):
        pass  # keep the log quiet


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
'''

# The adversarial test client. Also runs inside the sandbox. In --wait mode it
# polls /health until the app is ready; otherwise it performs the adversarial
# request and prints a single JSON line {"status": ..., "body": ...}.
#
# Usage: test_client.py [METHOD] [PATH]   (default GET /api/invoices/2)
# Legacy: test_client.py /api/invoices/2  (bare path means GET)
TEST_CLIENT_SOURCE = r'''
import json
import sys
import time
import urllib.error
import urllib.request

BASE = "http://127.0.0.1:8080"
DEFAULT_TARGET_PATH = "/api/invoices/2"
ALLOWED_METHODS = ("GET", "DELETE")


def http_request(method, path):
    req = urllib.request.Request(BASE + path, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            raw = resp.read().decode()
            try:
                body = json.loads(raw)
            except ValueError:
                body = raw
            return resp.status, body
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            body = json.loads(raw)
        except ValueError:
            body = raw
        return exc.code, body


def wait_ready(seconds=30):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            status, _ = http_request("GET", "/health")
            if status == 200:
                return
        except Exception:
            pass
        time.sleep(0.5)
    raise SystemExit("app did not become ready in time")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--wait":
        wait_ready()
        print("ready")
    else:
        # METHOD PATH, or a bare PATH (legacy GET), or defaults.
        method = "GET"
        target = DEFAULT_TARGET_PATH
        if len(sys.argv) > 1 and sys.argv[1] in ALLOWED_METHODS:
            method = sys.argv[1]
            if len(sys.argv) > 2:
                target = sys.argv[2]
        elif len(sys.argv) > 1:
            target = sys.argv[1]
        status, body = http_request(method, target)
        print(json.dumps({"status": status, "body": body}))
'''

# ---------------------------------------------------------------------------
# The shared BreakTrace definition.
#
# One reusable security test. The actor, request and expectation NEVER change
# between the vulnerable run and the fixed-version replay - only the
# application behavior changes (via BREAKTRACE_MODE).
# ---------------------------------------------------------------------------

BREAKTRACE_BT_001 = {
    "id": "BT-001",
    "title": "Cross-user invoice access",
    "category": "broken_access_control",
    "severity": "high",
    "invariant": "A user must never be able to access another user's invoice.",
    "actor": BreakTraceActor(name="Alice", user_id=1),
    "request": BreakTraceRequest(method="GET", path="/api/invoices/2"),
    "expected": BreakTraceExpected(status=403),
}

# Application modes the runner can deploy. The attack stays identical.
MODE_VULNERABLE = "vulnerable"
MODE_FIXED = "fixed"


def _status_for(mode: str, invariant_violated: bool) -> str:
    """Map (mode, outcome) to a human-meaningful result status.

    A PASS means the previously successful attack is no longer reproducible -
    it is not an execution failure.
    """
    if mode == MODE_FIXED:
        return "failed" if invariant_violated else "passed"
    return "vulnerable" if invariant_violated else "safe"


def _exec(sandbox, command, timeout=30, env=None) -> str:
    """Run a command inside the sandbox and return trimmed stdout.

    Raises:
        RuntimeError: If the command exits non-zero.
    """
    result = sandbox.process.exec(command, timeout=timeout, env=env)
    output = (result.result or "").strip()
    if result.exit_code != 0:
        raise RuntimeError(
            f"Command failed with exit code {result.exit_code}: "
            f"{output or '(no output)'}"
        )
    return output


def execute_breaktrace(
    definition: dict,
    mode: str,
    source: str = "breaktrace",
    hypothesis: str | None = None,
) -> BreakTraceResult:
    """Execute a validated BreakTrace test definition against an app running
    in the given mode, inside a fresh disposable Daytona sandbox.

    The definition is the internal test representation (id, title, category,
    severity, invariant, actor, request, expected). It is always converted
    from a validated allowlisted source - never taken from raw user input.

    Args:
        definition: Internal test definition dict.
        mode: Application behavior - MODE_VULNERABLE or MODE_FIXED.
        source: Origin of the test definition ("breaktrace", "nosana_ai").
        hypothesis: Optional AI reasoning attached to the result.

    Returns:
        A structured BreakTraceResult describing the attack run against
        that mode of the application.

    Raises:
        ValueError: If mode is not a known application mode.
        RuntimeError: If any step fails (sandbox creation, app setup,
            startup, adversarial test, or malformed test output).
    """
    if mode not in (MODE_VULNERABLE, MODE_FIXED):
        raise ValueError(f"Unknown application mode: {mode!r}")

    client = get_daytona_client()
    sandbox = None
    try:
        # 1. Fresh disposable sandbox.
        try:
            sandbox = client.create()
        except Exception as exc:
            raise RuntimeError(f"Failed to create Daytona sandbox: {exc}") from exc

        # Safety net: if cleanup below ever fails, the sandbox still dies.
        try:
            sandbox.set_ttl(10)
        except Exception:
            pass  # best-effort

        # 2. Set up the deliberately vulnerable application inside the sandbox.
        try:
            _exec(sandbox, f"mkdir -p {REMOTE_DIR}")
            sandbox.fs.upload_file(VULNERABLE_APP_SOURCE.encode(), APP_PATH)
            sandbox.fs.upload_file(TEST_CLIENT_SOURCE.encode(), TEST_CLIENT_PATH)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to set up the test app inside the sandbox: {exc}"
            ) from exc

        # 3. Start the app in the background with the requested mode. The
        #    application reads BREAKTRACE_MODE: vulnerable (no ownership
        #    check) or fixed (enforces invoice ownership).
        try:
            _exec(
                sandbox,
                f"nohup python {APP_PATH} > {LOG_PATH} 2>&1 & echo started",
                timeout=30,
                env={"BREAKTRACE_MODE": mode},
            )
        except Exception as exc:
            raise RuntimeError(f"Failed to start the test app: {exc}") from exc

        # 4. Wait until the app is ready.
        try:
            _exec(sandbox, f"python {TEST_CLIENT_PATH} --wait", timeout=90)
        except Exception as exc:
            tail = ""
            try:
                tail = _exec(sandbox, f"cat {LOG_PATH} 2>/dev/null || true")
            except Exception:
                pass
            detail = f" {tail}" if tail else ""
            raise RuntimeError(f"Test app did not become ready.{detail}") from exc

        # 5-6. Execute the adversarial test inside the sandbox, capture
        #      status + body and evaluate the invariant.
        return _run_test_in_sandbox(sandbox, definition, mode, source, hypothesis)
    finally:
        # 7. Always delete the sandbox; a cleanup failure must not mask the
        #    run's real result or error.
        if sandbox is not None:
            try:
                client.delete(sandbox)
            except Exception:
                pass


def _run_test_in_sandbox(
    sandbox,
    definition: dict,
    mode: str,
    source: str,
    hypothesis: str | None,
) -> BreakTraceResult:
    """Run ONE validated test definition against an already-running app inside
    an existing sandbox, and evaluate the invariant.

    Used by both execute_breaktrace (one sandbox per test) and run_assessment
    (many tests share one sandbox). The method + path always come from a
    validated allowlisted definition.

    Raises:
        RuntimeError: If the adversarial test or its output parsing fails.
    """
    try:
        method = definition["request"].method
        target_path = definition["request"].path
        output = _exec(
            sandbox,
            f"python {TEST_CLIENT_PATH} {method} {target_path}",
            timeout=30,
        )
    except Exception as exc:
        raise RuntimeError(
            f"Adversarial test failed inside the sandbox: {exc}"
        ) from exc

    try:
        parsed = json.loads(output)
        observed_status = int(parsed["status"])
        observed_body = parsed["body"]
    except (ValueError, KeyError, TypeError) as exc:
        raise RuntimeError(
            f"Malformed test output from sandbox: {output or '(empty)'}"
        ) from exc

    expected_status = definition["expected"].status
    invariant_violated = observed_status != expected_status

    observed = BreakTraceObserved(status=observed_status, body=observed_body)
    return BreakTraceResult(
        **definition,
        observed=observed,
        test_executed=True,
        invariant_violated=invariant_violated,
        status=_status_for(mode, invariant_violated),
        mode=mode,
        source=source,
        hypothesis=hypothesis,
    )


def run_breaktrace(mode: str) -> BreakTraceResult:
    """Convenience wrapper: execute the built-in BT-001 definition."""
    return execute_breaktrace(BREAKTRACE_BT_001, mode)


def proposal_to_definition(
    proposal: SecurityTestProposal, test_id: str = "BT-AI-001"
) -> dict:
    """Convert a validated AI proposal into the internal test definition.

    The proposal only describes INTENT. This conversion decides exactly how
    that intent maps onto the safe execution layer (same app, same sandbox,
    allowlisted endpoints). The result carries the AI hypothesis and source.
    """
    return {
        "id": test_id,
        "title": proposal.title,
        "category": proposal.category,
        "severity": "high",
        "invariant": proposal.invariant,
        "actor": proposal.actor,
        "request": proposal.request,
        "expected": BreakTraceExpected(status=proposal.expected_status),
    }


def run_assessment(
    proposals: list[SecurityTestProposal],
    mode: str,
    source: str = "ai",
    assessment_id: str = "ASSESS-001",
) -> AssessmentRunResult:
    """Execute a validated AI assessment (up to 3 proposals) against ONE fresh
    disposable Daytona sandbox running the app in the given mode.

    State safety: non-mutating GET tests run first, state-changing DELETE
    tests run last, so one test can never corrupt another test's assumptions.
    The sandbox is always deleted afterwards (finally) with a TTL safety net.

    Args:
        proposals: The validated, allowlisted AI proposals (intent only).
        mode: MODE_VULNERABLE or MODE_FIXED.
        source: Origin of the test definitions.
        assessment_id: Stable id shared by run and replay.

    Returns:
        An AssessmentRunResult with a computed summary (never hardcoded) and
        one BreakTraceResult per executed test, id BT-AI-001..BT-AI-00n.

    Raises:
        ValueError: If mode is not a known application mode.
        RuntimeError: If any step fails (sandbox, app setup, startup, test).
    """
    if mode not in (MODE_VULNERABLE, MODE_FIXED):
        raise ValueError(f"Unknown application mode: {mode!r}")

    client = get_daytona_client()
    sandbox = None
    try:
        # 1. ONE fresh disposable sandbox for the whole assessment.
        try:
            sandbox = client.create()
        except Exception as exc:
            raise RuntimeError(f"Failed to create Daytona sandbox: {exc}") from exc

        # Safety net: if cleanup below ever fails, the sandbox still dies.
        try:
            sandbox.set_ttl(10)
        except Exception:
            pass  # best-effort

        # 2. Set up the app + test client inside the sandbox.
        try:
            _exec(sandbox, f"mkdir -p {REMOTE_DIR}")
            sandbox.fs.upload_file(VULNERABLE_APP_SOURCE.encode(), APP_PATH)
            sandbox.fs.upload_file(TEST_CLIENT_SOURCE.encode(), TEST_CLIENT_PATH)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to set up the test app inside the sandbox: {exc}"
            ) from exc

        # 3. Start the app in the background with the requested mode.
        try:
            _exec(
                sandbox,
                f"nohup python {APP_PATH} > {LOG_PATH} 2>&1 & echo started",
                timeout=30,
                env={"BREAKTRACE_MODE": mode},
            )
        except Exception as exc:
            raise RuntimeError(f"Failed to start the test app: {exc}") from exc

        # 4. Wait until the app is ready.
        try:
            _exec(sandbox, f"python {TEST_CLIENT_PATH} --wait", timeout=90)
        except Exception as exc:
            tail = ""
            try:
                tail = _exec(sandbox, f"cat {LOG_PATH} 2>/dev/null || true")
            except Exception:
                pass
            detail = f" {tail}" if tail else ""
            raise RuntimeError(f"Test app did not become ready.{detail}") from exc

        # 5. Order tests: GET (non-mutating) first, DELETE last. The relative
        #    order of same-method tests is preserved (stable sort).
        ordered = sorted(
            proposals, key=lambda p: 0 if p.request.method == "GET" else 1
        )

        # 6. Execute every validated test against the SAME running app.
        results: list[BreakTraceResult] = []
        for index, proposal in enumerate(ordered, start=1):
            definition = proposal_to_definition(
                proposal, test_id=f"BT-AI-{index:03d}"
            )
            results.append(
                _run_test_in_sandbox(
                    sandbox, definition, mode, source, proposal.hypothesis
                )
            )

        # 7. Summarize from ACTUAL results - never hardcoded.
        violations = [r for r in results if r.invariant_violated]
        summary = AssessmentSummary(
            tests_generated=len(proposals),
            tests_executed=len(results),
            vulnerabilities_found=len(violations),
            controls_passed=len(results) - len(violations),
        )
        return AssessmentRunResult(
            assessment_id=assessment_id,
            source=source,
            summary=summary,
            results=results,
        )
    finally:
        # 8. Always delete the sandbox; a cleanup failure must not mask the
        #    assessment's real result or error.
        if sandbox is not None:
            try:
                client.delete(sandbox)
            except Exception:
                pass


def build_replay_result(
    assessment_id: str, results: list[BreakTraceResult]
) -> AssessmentReplayResult:
    """Derive the compact replay verdict from fixed-mode execution results.

    In fixed mode _status_for maps: invariant held -> "passed", violated ->
    "failed". The summary counts come from the actual results.
    """
    passed = sum(1 for r in results if r.status == "passed")
    return AssessmentReplayResult(
        assessment_id=assessment_id,
        mode=MODE_FIXED,
        summary=ReplaySummary(
            tests_replayed=len(results),
            passed=passed,
            failed=len(results) - passed,
        ),
        results=[ReplayItem(id=r.id, status=r.status) for r in results],
    )
