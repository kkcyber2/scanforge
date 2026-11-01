"""Check registry and the contract a check must satisfy.

A check is a callable that receives a ``CheckContext`` and returns findings or
raises ``CheckSkipped``. The registry is what makes the engine pluggable: the
orchestrator never imports a specific check, it looks one up by name.

Deliberate omissions:

* no network helpers are provided here, because a check that reaches out is a
  check that can reach the wrong place. Scope enforcement lives in scopeguard
  and must have run before the orchestrator is allowed to start.
* a check cannot see another check's output. Cross-check correlation happens in
  the aggregator, on the canonical schema, so checks stay independently
  testable.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional

from sentinel_findings.schema import Finding


class CheckSkipped(Exception):
    """Raised when a check declines to run (missing precondition).

    Distinct from failure: a skipped check is not an error, and must not be
    counted as one. Confusing the two is how a pipeline reports "healthy" while
    half its checks never ran.
    """


class CheckFailed(Exception):
    """Raised when a check cannot complete. Captured and recorded, not fatal."""


@dataclass
class CheckContext:
    """Everything a check is allowed to know about the run."""

    target: str
    timeout_s: float = 30.0
    options: Dict[str, Any] = field(default_factory=dict)
    scan_id: str = ""
    # Populated by the orchestrator so a check can tag its findings.
    tool_name: str = ""

    def option(self, key: str, default: Any = None) -> Any:  # noqa: ANN401
        return self.options.get(key, default)


CheckFn = Callable[[CheckContext], List[Finding]]


@dataclass
class CheckSpec:
    """Metadata plus the callable, so the orchestrator can plan without running."""

    name: str
    fn: CheckFn
    category: str = "general"
    # Rough cost, used to order checks so cheap ones land first and a slow
    # check does not delay every fast one.
    weight: int = 1
    description: str = ""
    # Checks that must not run without a specific capability. Reserved for
    # future gating (e.g. a check that needs a credential).
    requires: List[str] = field(default_factory=list)


class Registry:
    """Name -> CheckSpec, with no import side effects until first use."""

    def __init__(self) -> None:
        self._specs: Dict[str, CheckSpec] = {}

    def register(
        self,
        name: str,
        *,
        category: str = "general",
        weight: int = 1,
        description: str = "",
        requires: Optional[Iterable[str]] = None,
    ) -> Callable[[CheckFn], CheckFn]:
        """Decorator form, used by the built-in checks."""

        def deco(fn: CheckFn) -> CheckFn:
            self.add(
                CheckSpec(
                    name=name,
                    fn=fn,
                    category=category,
                    weight=weight,
                    description=description or (fn.__doc__ or "").strip().split("\n")[0],
                    requires=list(requires or []),
                )
            )
            return fn

        return deco

    def add(self, spec: CheckSpec) -> None:
        if spec.name in self._specs:
            raise ValueError(f"check {spec.name!r} already registered")
        self._specs[spec.name] = spec

    def get(self, name: str) -> CheckSpec:
        try:
            return self._specs[name]
        except KeyError:
            raise KeyError(
                f"no check named {name!r}; available: {sorted(self._specs)}"
            ) from None

    def names(self) -> List[str]:
        return sorted(self._specs)

    def specs(self) -> List[CheckSpec]:
        return [self._specs[n] for n in self.names()]

    def plan(self, requested: Optional[Iterable[str]] = None) -> List[CheckSpec]:
        """Resolve names to specs, ordered cheapest-first.

        ``requested`` may name checks, or be None for all of them. Unknown
        names raise — a typo in a scan profile should fail loudly, not silently
        run nothing.
        """
        if requested is None:
            chosen = list(self._specs.values())
        else:
            chosen = [self.get(n) for n in requested]
        return sorted(chosen, key=lambda s: (s.weight, s.name))

    def load_entry_points(self, group: str = "scanforge.checks") -> int:
        """Discover third-party checks declared as package entry points.

        Returns how many were added. Silent when a package declares nothing,
        which is the normal case for a plain install.
        """
        try:
            from importlib.metadata import entry_points
        except ImportError:  # pragma: no cover - py<3.8
            return 0

        added = 0
        try:
            eps = entry_points(group=group)
        except TypeError:  # pragma: no cover - older API shape
            eps = entry_points().get(group, [])  # type: ignore[attr-defined]
        for ep in eps:
            try:
                loaded = ep.load()
            except Exception:  # noqa: BLE001 - a broken plugin must not kill the run
                continue
            if isinstance(loaded, CheckSpec):
                self.add(loaded)
                added += 1
            elif callable(loaded):
                self.add(
                    CheckSpec(
                        name=ep.name,
                        fn=loaded,
                        description=(loaded.__doc__ or "").strip().split("\n")[0],
                    )
                )
                added += 1
        return added


registry = Registry()


def load_module_checks(module_path: str) -> int:
    """Import a module for its registration side effects.

    Returns the number of checks the registry gained, so a caller can tell a
    typo (0) from a working plugin.
    """
    before = len(registry.names())
    importlib.import_module(module_path)
    return len(registry.names()) - before
