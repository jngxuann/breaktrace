"""BreakTrace target adapters (Milestone 8).

A TargetAdapter encapsulates ALL knowledge about how to run a specific
AUTHORIZED training target inside a Daytona sandbox: which repository to
clone, how to install and start it, how to determine readiness, and which
HTTP capabilities the sandbox-local execution layer supports.

Only explicitly supported, authorized educational/demo targets exist here.
There is NO adapter for arbitrary public websites - the M7 application URL
remains an identity/history key only and is never probed.

Target-specific setup knowledge (install/start/readiness) is allowed and
lives HERE. Known-vulnerability answers are NOT embedded anywhere.

The embedded BreakTrace demo app keeps its existing mechanism in
breaktrace_demo.py; a "demo" adapter is registered so the target list stays
complete, but the demo execution path is untouched.
"""

import os
from dataclasses import dataclass, field, replace

from models import TargetInfo


class TargetError(RuntimeError):
    """The requested target adapter does not exist or is unsupported."""


@dataclass(frozen=True)
class TargetAdapter:
    """Immutable description of one authorized training target.

    All shell fragments are TRUSTED adapter definitions - never user input.
    """

    target_type: str
    name: str
    description: str
    repository_url: str
    # Pinned git ref (tag/branch). `ref_legacy` is used on sandboxes whose
    # node major version is below the primary ref's engine requirement.
    ref: str | None
    ref_legacy: str | None = None
    min_node_major: int = 0
    port: int = 3000
    repo_dir: str = "/tmp/breaktrace/target"
    install_command: str = "npm install --no-audit --no-fund --loglevel=error"
    start_command: str = "nohup npm start > app.log 2>&1 & echo started"
    ready_path: str = "/"
    supported_methods: tuple[str, ...] = ("GET", "DELETE")
    # Milestone 10 - application identity is the M7 URL origin used as the
    # stable history key (never scanned). env carries trusted, adapter-defined
    # environment variables the application needs to boot in the twin (never
    # real secrets). frontend_only marks targets whose twin serves a client
    # SPA rather than server-side APIs.
    application_identity: str = ""
    env: dict | None = None
    frontend_only: bool = False
    # Milestone 11 - whether the target needs a node runtime in the sandbox.
    # Python-only demo targets set this to False so prepare_target does not
    # require node.
    requires_node: bool = True
    # Milestone 11 - request header NAMES the target permits on executable
    # experiments. Values are bounded and headers are strictly allowlisted.
    allowed_request_headers: list[str] = field(default_factory=list)
    # Milestone 12 - ordered, allowlisted versions for switching a target's
    # checked-out ref (each is {"key", "label", "ref"}). Used by the
    # regression demo (V1/V2/V3). Never accepts arbitrary user-controlled refs.
    canonical_versions: list[dict] = field(default_factory=list)
    # Milestone 12 - the allowlisted version key currently selected (e.g.
    # "v1"). Empty when the target has no selectable versions. Only ever set
    # by resolve_target_version from the adapter's canonical_versions.
    version: str = ""


JUICE_SHOP_ADAPTER = TargetAdapter(
    target_type="juice_shop",
    name="OWASP Juice Shop",
    description=(
        "OWASP Juice Shop is a modern, intentionally vulnerable web "
        "application used for security training. Official repository, "
        "pinned release tag."
    ),
    repository_url="https://github.com/juice-shop/juice-shop.git",
    ref="v20.2.0",          # latest stable; requires node >= 22
    ref_legacy="v17.1.1",   # fallback for sandboxes with node 20/21
    min_node_major=22,
    port=3000,
    repo_dir="/tmp/breaktrace/juice-shop",
    install_command="npm install --no-audit --no-fund --loglevel=error",
    start_command="nohup npm start > app.log 2>&1 & echo started",
    ready_path="/",
    supported_methods=("GET", "DELETE"),
)

DEMO_ADAPTER = TargetAdapter(
    target_type="demo",
    name="BreakTrace Demo App",
    description=(
        "The built-in controlled demo application (vulnerable -> fixed "
        "regression demonstration). Executed through the existing embedded "
        "mechanism in breaktrace_demo.py."
    ),
    repository_url="",
    ref=None,
    port=8080,
    repo_dir="/tmp/breaktrace",
    install_command="",
    start_command="",
    ready_path="/health",
    supported_methods=("GET", "DELETE"),
)

# ---------------------------------------------------------------------------
# Milestone 10 - CyberSafe JARSS User App (primary hackathon Security Twin)
#
# A REAL, lighter Vite/React application built by the project team. The
# adapter knows ONLY how to prepare the application (repository, pinned ref,
# install/start, port, readiness, identity, boot env) - it contains NO
# vulnerability knowledge. BreakTrace discovers the application itself.
#
# Notes:
# - ref is pinned to the current commit SHA so the twin does not blindly
#   track moving main during the demo (prepare_target clones by SHA).
# - The repo's src/app/supabase.ts throws at import when VITE_SUPABASE_URL /
#   VITE_SUPABASE_ANON_KEY are missing, so the adapter provides trusted
#   LOCAL placeholder values purely so the SPA can boot. The real Supabase
#   backend is NOT part of the twin; placeholder 127.0.0.1 values mean zero
#   external traffic. Backend-dependent behavior is classified
#   not_verifiable_in_twin by the orchestrator.
# ---------------------------------------------------------------------------

CYBERSAFE_JARSS_USER_ADAPTER = TargetAdapter(
    target_type="cybersafe_jarss_user",
    name="CyberSafe JARSS User App",
    description=(
        "Real Vite/React web application (CyberSafe JARSS User App) - the "
        "primary Security Twin target for the hackathon."
    ),
    repository_url="https://github.com/jngxuann/cybersafe-jarss-user-app.git",
    ref="d1f6e0d4e869eed83f14078690e27d5de1a05d6f",  # pinned commit
    port=5173,
    repo_dir="/tmp/breaktrace/cybersafe-jarss",
    install_command="npm ci --no-audit --no-fund --loglevel=error",
    start_command=(
        "nohup npm run dev -- --host 0.0.0.0 > app.log 2>&1 & echo started"
    ),
    ready_path="/",
    supported_methods=("GET", "DELETE"),
    application_identity="https://cybersafe-jarss-user-app.vercel.app",
    env={
        "VITE_SUPABASE_URL": "http://127.0.0.1:54321",
        "VITE_SUPABASE_ANON_KEY": "breaktrace-placeholder-anon-key",
    },
    frontend_only=True,
)

# ---------------------------------------------------------------------------
# Milestone 12 - BreakTrace Regression Demo (controlled Security Regression)
#
# A deliberately vulnerable, educational micro-app (https://.../demo_app) that
# runs ONLY inside BreakTrace's isolated Daytona Security Twin. It exists to
# demonstrate SECURITY MEMORY + SECURITY REGRESSION across three versions:
#
#   V1 (demo-v1-vulnerable)   - GET /api/reports/:id returns any report (IDOR)
#   V2 (demo-v2-fixed)        - ownership enforced, foreign report -> 403
#   V3 (demo-v3-regression)   - vibe-coded "sharing" change re-introduces the bug
#
# The adapter contains ONLY preparation facts (repo / ref / install / start /
# port / readiness / allowed version labels). It contains NO vulnerability
# knowledge - BreakTrace discovers and verifies the behavior through the same
# general Security Twin mechanisms (never a hardcoded "demo == vulnerable").
#
# The application is a zero-dependency Python stdlib server, so it needs no
# node runtime and no package install - it starts in a couple of seconds.
# ---------------------------------------------------------------------------

# Repository URL for the regression demo. It reads from the environment so the
# adapter never ships a fabricated GitHub URL. Set BREAKTRACE_DEMO_REPO_URL to
# the real repo after it is created/pushed (see README / report).
DEMO_REPOSITORY_URL = os.getenv("BREAKTRACE_DEMO_REPO_URL", "").strip()

# Allowlisted versions (fixed addressable set - arbitrary refs never execute).
DEMO_VERSIONS = [
    {"key": "v1", "label": "V1 — Vulnerable", "ref": "demo-v1-vulnerable"},
    {"key": "v2", "label": "V2 — Fixed", "ref": "demo-v2-fixed"},
    {"key": "v3", "label": "V3 — Regression", "ref": "demo-v3-regression"},
]

SECURITY_REGRESSION_DEMO_ADAPTER = TargetAdapter(
    target_type="security_regression_demo",
    name="BreakTrace Regression Demo",
    description=(
        "Deliberately vulnerable educational micro-app that demonstrates "
        "Security Memory + Security Regression Testing across V1 (vulnerable) "
        "-> V2 (fixed) -> V3 (regression)."
    ),
    repository_url=DEMO_REPOSITORY_URL,
    ref=DEMO_VERSIONS[0]["ref"],      # default = V1 vulnerable
    port=8001,
    repo_dir="/tmp/breaktrace/breaktrace-regression-demo",
    install_command="",                # zero-dependency stdlib app
    start_command=(
        "nohup sh -c 'command -v python3 >/dev/null 2>&1 && python3 app.py "
        "|| python app.py' > app.log 2>&1 & echo started"
    ),
    ready_path="/",
    supported_methods=("GET",),
    application_identity="https://breaktrace-regression-demo.example",
    requires_node=False,
    allowed_request_headers=["X-Demo-User"],
    canonical_versions=DEMO_VERSIONS,
)

_TARGETS: dict[str, TargetAdapter] = {
    CYBERSAFE_JARSS_USER_ADAPTER.target_type: CYBERSAFE_JARSS_USER_ADAPTER,
    SECURITY_REGRESSION_DEMO_ADAPTER.target_type: SECURITY_REGRESSION_DEMO_ADAPTER,
    JUICE_SHOP_ADAPTER.target_type: JUICE_SHOP_ADAPTER,
    DEMO_ADAPTER.target_type: DEMO_ADAPTER,
}


def get_target_adapter(target_type: str) -> TargetAdapter:
    """Return the adapter for a target type, rejecting unknown targets.

    Raises:
        TargetError: If the target type is not a supported adapter.
    """
    adapter = _TARGETS.get((target_type or "").strip().lower())
    if adapter is None:
        known = ", ".join(sorted(_TARGETS))
        raise TargetError(
            f"Unsupported target {target_type!r}. Supported targets: {known}."
        )
    return adapter


def list_targets() -> list[TargetInfo]:
    """Public, sanitized list of supported targets for the frontend."""
    return [
        TargetInfo(
            target_type=a.target_type,
            name=a.name,
            description=a.description,
            repository=a.repository_url,
            port=a.port,
            local_origin=f"http://127.0.0.1:{a.port}",
            supported_methods=list(a.supported_methods),
            application_identity=a.application_identity,
            versions=[dict(v) for v in a.canonical_versions],
        )
        for a in _TARGETS.values()
    ]


def resolve_target_version(target_type: str, version_key: str) -> TargetAdapter:
    """Resolve an ALLOWLISTED version for a target with selectable versions.

    Only the versions defined in the adapter's canonical_versions may be
    selected. Arbitrary user-controlled git refs are NEVER accepted.

    Returns a derived TargetAdapter whose ref/version are set to the selected
    allowlisted value.

    Raises:
        TargetError: If the target has no versions, or version_key is not in
            the allowlist.
    """
    adapter = get_target_adapter(target_type)
    key = (version_key or "").strip()
    if not adapter.canonical_versions:
        # Targets without selectable versions ignore the field.
        return adapter
    matched = next(
        (v for v in adapter.canonical_versions if v.get("key") == key), None
    )
    if matched is None:
        allowed = ", ".join(
            v.get("key") for v in adapter.canonical_versions
        )
        raise TargetError(
            f"Unknown version {version_key!r} for target {target_type!r}. "
            f"Allowed versions: {allowed}."
        )
    return replace(adapter, ref=matched["ref"], version=key)


def resolve_ref(adapter: TargetAdapter, node_major: int) -> str:
    """Pick the pinned ref for the sandbox's node version.

    Target-specific setup knowledge: recent Juice Shop releases require
    node >= 22; older releases cover node 20/21. If no ref is configured the
    adapter has no repository to clone.
    """
    if not adapter.repository_url or not adapter.ref:
        return adapter.ref or ""
    if node_major < adapter.min_node_major and adapter.ref_legacy:
        return adapter.ref_legacy
    return adapter.ref
