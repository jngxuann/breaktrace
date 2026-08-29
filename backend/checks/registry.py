"""Deterministic check registry (Milestone 9, Layer 2).

The orchestrator iterates CHECK_REGISTRY generically - it contains NO
check-specific logic. New checks are added here without touching the
Security Twin orchestrator.
"""

from checks.cookies import CookieSecurityCheck
from checks.cors import CorsSecurityCheck
from checks.exposure import ExposureSecurityCheck
from checks.headers import HeaderSecurityCheck
from checks.source import (
    ClientStorageAuthCheck,
    HardcodedSecretCheck,
)

CHECK_REGISTRY = [
    HeaderSecurityCheck(),
    CookieSecurityCheck(),
    CorsSecurityCheck(),
    ExposureSecurityCheck(),
]

# Milestone 10 - source-based deterministic checks (scan the cloned
# repository inside the sandbox; generic, not target-specific).
SOURCE_CHECK_REGISTRY = [
    HardcodedSecretCheck(),
    ClientStorageAuthCheck(),
]


def get_check_registry() -> list:
    """Return the HTTP deterministic checks to execute (copy-safe list)."""
    return list(CHECK_REGISTRY)


def get_source_check_registry() -> list:
    """Return the repository-source deterministic checks (copy-safe list)."""
    return list(SOURCE_CHECK_REGISTRY)
