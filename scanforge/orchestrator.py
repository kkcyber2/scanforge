"""The orchestration layer.

ForgeGuard's engine exposes 18 routes; 8 are wired. What is missing is not
another route but the thing that decides *what runs, in what order, with what
timeout, and what happens when one check hangs*. That is this module.

Design decisions worth defending:

**Timeouts are real.** A check runs in a worker thread and is abandoned when
the deadline passes. Python cannot kill a thread, so the abandoned worker keeps
its slot until it exits — the pool is sized to absorb that, and any check still
running is reported as ``timed_out`` rather than quietly dropped. Pretending a
hung check "passed" is the failure mode this exists to prevent.

**A failing check does not fail the scan.** Each check is isolated; its
exception is captured with the exception type and message, and the run
continues. But the run's final status records that checks failed, so a report
can never claim a clean sweep when three checks blew up.

**Retries are bounded and only for transient failures.** A check that raises
``CheckFailed`` gets retried up to ``max_retries``; a ``CheckSkipped`` is not
retried (the precondition will not change); a timeout is not retried by default
because a check that hung once will usually hang again and the retry spends the
whole budget twice.

**The result is one document.** Every check's findings are normalised, merged
and counted, with per-check accounting that says exactly which checks ran, how
long each took, and which produced nothing. "No findings" and "did not run" are
different outcomes and are never conflated.
"""

from __future__ import annotations

import datetime as _dt
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence

from sentinel_findings.schema import Finding, FindingCollection

from .registry import CheckContext, CheckFailed, CheckSkipped, CheckSpec, Registry, registry


class CheckStatus(str, Enum):
    PASSED = "passed"        # ran, produced findings or none
    FAILED = "failed"        # raised; captured
    TIMED_OUT = "timed_out"  # exceeded its deadline
    SKIPPED = "skipped"      # declined; not an error


class RunStatus(str, Enum):
    COMPLETE = "complete"        # every check passed
    PARTIAL = "partial"          # some checks failed/timed out
    ABORTED = "aborted"          # the run stopped early


@dataclass
class CheckResult:
    name: str
    status: CheckStatus
    duration_ms: int
    finding_count: int = 0
    attempts: int = 1
    error: str = ""
    error_type: str = ""
    skipped_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "duration_ms": self.duration_ms,
            "finding_count": self.finding_count,
            "attempts": self.attempts,
            "error": self.error,
            "error_type": self.error_type,
            "skipped_reason": self.skipped_reason,
        }


@dataclass
class RunResult:
    """One scan's complete outcome."""

    run_id: str
    target: str
    started_at: str
    finished_at: str
    duration_s: float
    status: RunStatus
    findings: FindingCollection
    checks: List[CheckResult] = field(default_factory=list)

    # ------------------------------------------------------------------ #
    # Accounting                                                         #
    # ------------------------------------------------------------------ #

    @property
    def ran(self) -> int:
        return sum(
            1 for c in self.checks if c.status in (CheckStatus.PASSED, CheckStatus.FAILED,
                                                   CheckStatus.TIMED_OUT)
        )

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if c.status is CheckStatus.FAILED)

    @property
    def timed_out(self) -> int:
        return sum(1 for c in self.checks if c.status is CheckStatus.TIMED_OUT)

    @property
    def skipped(self) -> int:
        return sum(1 for c in self.checks if c.status is CheckStatus.SKIPPED)

    @property
    def incomplete(self) -> bool:
        """True when the scan did not execute everything it planned."""
        return self.failed > 0 or self.timed_out > 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_s": round(self.duration_s, 3),
            "status": self.status.value,
            "coverage": {
                "planned": len(self.checks),
                "ran": self.ran,
                "failed": self.failed,
                "timed_out": self.timed_out,
                "skipped": self.skipped,
                "complete": not self.incomplete,
            },
            "counts": self.findings.counts,
            "total_findings": self.findings.total,
            "checks": [c.to_dict() for c in self.checks],
            "findings": [f.to_dict() for f in self.findings.sorted()],
        }


class Orchestrator:
    """Runs a plan of checks and aggregates the result."""

    def __init__(
        self,
        *,
        reg: Optional[Registry] = None,
        max_workers: int = 4,
        check_timeout_s: float = 30.0,
        max_retries: int = 1,
        retry_timeout_s: float = 5.0,
    ) -> None:
        self.registry = reg or registry
        self.max_workers = max(1, max_workers)
        self.check_timeout_s = check_timeout_s
        self.max_retries = max(0, max_retries)
        self.retry_timeout_s = retry_timeout_s

    def run(
        self,
        target: str,
        *,
        checks: Optional[Sequence[str]] = None,
        options: Optional[Dict[str, Any]] = None,
        scan_id: str = "",
        on_event: Optional[Any] = None,
    ) -> RunResult:
        """Execute the plan.

        ``on_event`` is an optional callable receiving ``(kind, payload)`` so a
        caller can stream progress without the orchestrator knowing about
        transports.
        """
        plan = self.registry.plan(checks)
        run_id = scan_id or uuid.uuid4().hex
        started_wall = _now()
        started = time.monotonic()

        results: List[CheckResult] = []
        collection = FindingCollection()

        if on_event:
            on_event(
                "start",
                {"run_id": run_id, "target": target, "planned": len(plan)},
            )

        # The pool is created explicitly and deliberately NOT used as a context
        # manager: ``with`` calls ``shutdown(wait=True)`` on exit, which would
        # block until a hung check's thread finishes and defeat the timeout
        # entirely. Abandoned workers are left to exit on their own; they cannot
        # be killed, and pretending otherwise is what makes timeout handling
        # look correct while it silently waits.
        pool = ThreadPoolExecutor(max_workers=self.max_workers)
        try:
            for spec in plan:
                if on_event:
                    on_event("check_start", {"name": spec.name, "category": spec.category})

                result, found = self._run_one(pool, spec, target, options or {}, run_id)
                results.append(result)
                collection.extend(found)

                if on_event:
                    on_event(
                        "check_done",
                        {
                            "name": spec.name,
                            "status": result.status.value,
                            "duration_ms": result.duration_ms,
                            "findings": result.finding_count,
                        },
                    )
        finally:
            pool.shutdown(wait=False)

        duration = time.monotonic() - started
        status = RunStatus.PARTIAL if any(
            r.status in (CheckStatus.FAILED, CheckStatus.TIMED_OUT) for r in results
        ) else RunStatus.COMPLETE

        out = RunResult(
            run_id=run_id,
            target=target,
            started_at=started_wall,
            finished_at=_now(),
            duration_s=duration,
            status=status,
            findings=collection,
            checks=results,
        )
        if on_event:
            on_event("finish", out.to_dict()["coverage"])
        return out

    # ------------------------------------------------------------------ #
    # One check                                                          #
    # ------------------------------------------------------------------ #

    def _run_one(
        self,
        pool: ThreadPoolExecutor,
        spec: CheckSpec,
        target: str,
        options: Dict[str, Any],
        run_id: str,
    ) -> tuple[CheckResult, List[Finding]]:
        ctx = CheckContext(
            target=target,
            timeout_s=self.check_timeout_s,
            options=options,
            scan_id=run_id,
            tool_name=spec.name,
        )

        attempts = 0
        last_error: Optional[BaseException] = None
        budget = self.check_timeout_s

        while attempts <= self.max_retries:
            attempts += 1
            # Reset per attempt. Without this a successful retry still exits via
            # the failure branch, because last_error is never cleared.
            last_error = None
            found: List[Finding] = []
            t0 = time.monotonic()
            future = pool.submit(self._invoke, spec, ctx)
            try:
                found = future.result(timeout=budget)
            except FutureTimeout:
                return (
                    CheckResult(
                        name=spec.name,
                        status=CheckStatus.TIMED_OUT,
                        duration_ms=int((time.monotonic() - t0) * 1000),
                        attempts=attempts,
                        error=f"exceeded {budget:.0f}s deadline",
                        error_type="Timeout",
                    ),
                    [],
                )
            except CheckSkipped as exc:
                return (
                    CheckResult(
                        name=spec.name,
                        status=CheckStatus.SKIPPED,
                        duration_ms=int((time.monotonic() - t0) * 1000),
                        attempts=attempts,
                        skipped_reason=str(exc),
                    ),
                    [],
                )
            except CheckFailed as exc:
                last_error = exc
            except Exception as exc:  # noqa: BLE001 - isolation is the point
                last_error = exc

            if last_error is None:
                return (
                    CheckResult(
                        name=spec.name,
                        status=CheckStatus.PASSED,
                        duration_ms=int((time.monotonic() - t0) * 1000),
                        finding_count=len(found),
                        attempts=attempts,
                    ),
                    found,
                )

            # Back off briefly before a retry, then shrink the budget so a
            # check that hangs does not spend the full timeout twice.
            if attempts <= self.max_retries:
                time.sleep(min(self.retry_timeout_s, 1.0))
                budget = max(1.0, budget / 2)

        assert last_error is not None
        return (
            CheckResult(
                name=spec.name,
                status=CheckStatus.FAILED,
                duration_ms=0,
                attempts=attempts,
                error=f"{type(last_error).__name__}: {last_error}",
                error_type=type(last_error).__name__,
            ),
            [],
        )

    @staticmethod
    def _invoke(spec: CheckSpec, ctx: CheckContext) -> List[Finding]:
        """Called inside the worker thread.

        The return value is normalised here rather than trusted: a check that
        returns ``None`` or a bare dict is a bug, but it should not corrupt the
        run.
        """
        raw = spec.fn(ctx)
        if raw is None:
            return []
        if isinstance(raw, Finding):
            return [raw]
        if isinstance(raw, dict):
            payload = dict(raw)
            payload.setdefault("id", "")
            payload.setdefault("provenance", "observed")
            return [Finding.from_dict(payload)]
        out: List[Finding] = []
        for item in raw:
            if isinstance(item, Finding):
                out.append(item)
            elif isinstance(item, dict):
                out.append(Finding.from_dict(item))
            else:
                raise TypeError(
                    f"check {spec.name!r} returned {type(item).__name__}; "
                    "expected Finding or dict"
                )
        return out


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()
