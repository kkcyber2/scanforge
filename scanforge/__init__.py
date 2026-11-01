"""scanforge — the orchestration layer ForgeGuard's engine is missing.

What it does
------------
A job plan, a check registry, per-check timeouts, isolation and bounded
retries, and one aggregated result document. Checks are plain callables, so a
third-party check is an entry point rather than a fork.

What it does not do
-------------------
It does not decide whether a target may be scanned. That is scopeguard's job
and it must run first. An orchestrator that both authorizes and executes is an
orchestrator nobody can audit.
"""

from .orchestrator import CheckResult, CheckStatus, Orchestrator, RunResult, RunStatus
from .registry import (
    CheckContext,
    CheckFailed,
    CheckSkipped,
    CheckSpec,
    Registry,
    load_module_checks,
    registry,
)

__version__ = "1.0.0"

__all__ = [
    "CheckContext",
    "CheckFailed",
    "CheckResult",
    "CheckSkipped",
    "CheckSpec",
    "CheckStatus",
    "Orchestrator",
    "Registry",
    "RunResult",
    "RunStatus",
    "load_module_checks",
    "registry",
]
