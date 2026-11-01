# scanforge

The orchestration layer ForgeGuard's engine is missing.

ForgeGuard exposes 18 routes on its Python engine and the Next.js app calls
seven of them. Nothing in the codebase knows that, so the gap was found by a
human reading two files side by side. This is the machinery that finds it
mechanically: a plan, a check registry, real timeouts, failure isolation, and
one aggregated result.

```
$ scanforge list
engine_contract        integration     w=1  ForgeGuard's expected engine surface vs what the engine exposes
scope_declaration      authorization   w=1  Target must carry a verifiable authorization record before any check runs
simulation_exposure    honesty         w=1  Detect a codebase that can silently return simulated results
unfinished_markers     code-quality    w=2  Count TODO/FIXME/HACK markers in a source tree
```

## What it does

- **Plans before it runs.** Checks are registered with a cost weight; the plan
  is ordered cheapest-first so a slow check does not delay every fast one.
- **Enforces a real timeout.** A hung check is abandoned, recorded as
  `timed_out`, and the run continues. It is not killed silently and it is not
  allowed to block the whole scan.
- **Isolates failure.** One check raising does not end the run. Its exception
  type and message are recorded per check, and the run is marked `partial`.
- **Distinguishes skipped from failed.** A check that declines for a missing
  precondition is `skipped`, which is a legitimate outcome and does not make a
  run partial. Treating those as the same is how a pipeline reports "healthy"
  while half its checks never ran.
- **Bounds retries.** `CheckFailed` is retried up to `max_retries`; timeouts and
  skips never are.
- **Aggregates on one schema.** Deduplication is by fingerprint, worst severity
  wins, so two checks that notice the same problem produce one finding.

## What it does not do

It does not decide whether a target may be scanned. That is
[scopeguard](https://github.com/kkcyber2/scopeguard)'s job and it must run
before an orchestrator is allowed to start. An orchestrator that both
authorizes and executes is an orchestrator nobody can audit.

## Install

```bash
pip install "sentinel-findings @ git+https://github.com/kkcyber2/sentinel-findings@main"
pip install "scanforge @ git+https://github.com/kkcyber2/scanforge@main"
```

`scanforge` depends on `sentinel-findings` for the canonical schema and the
report renderer. That dependency is deliberate: an orchestrator with its own
private finding shape is the reason ForgeGuard's scans could not be correlated.

## Usage

```bash
scanforge list
scanforge run --target example.com
scanforge run --target example.com --checks unfinished_markers --option root=./src --out run.json
scanforge report run.json --out report.html
```

Exit codes: `0` complete, `1` usage error, `3` partial (a check failed or timed
out). The partial code exists so CI can tell "ran and found nothing" from
"did not finish" — the two look identical in a report otherwise.

## The engine-contract check

This is the one that earns the project. It compares the routes ForgeGuard's
engine exposes to the routes the app actually calls, and reports both gaps.

Real output, run against ForgeGuard's engine surface at HEAD and the app's call
set:

```bash
$ scanforge run --target forgeguard.local --checks engine_contract \
    --option 'engine_routes=["/scan/start","/scan/cancel/{scan_id}", ...]' \
    --option 'app_calls=["/scan/start","/forge/execute", ...]'
complete: 1/1 checks ran, 5 findings
  MEDIUM | Engine route unreachable from the app: GET /scan/{scan_id}/state
  MEDIUM | Engine route unreachable from the app: GET /war-machine/leads
  MEDIUM | Engine route unreachable from the app: POST /developer/test-probe
  MEDIUM | Engine route unreachable from the app: POST /scan/cancel/{scan_id}
  MEDIUM | Engine route unreachable from the app: POST /scan/{scan_id}/escalation
```

Five routes, which is the "11 paths, 8 wired" finding from the audit — derived
rather than read off two files by hand. `POST /scan/cancel/{scan_id}` and
`GET /scan/{scan_id}/state` are the two that matter: they are how a user cancels
a scan and how the UI polls it. Both are implemented engine-side and unreachable
app-side, which is why a hung scan has no exit.

Two real bugs were found and fixed while building this matcher, both of which
produced findings that looked plausible and were wrong:

1. **A bare path was normalised to GET.** ForgeGuard's route listing is a bare
   path list, so `POST /scan/start` was compared as `GET /scan/start` and
   reported missing. The matcher now treats an unstated method as a wildcard and
   only requires a method match when both sides declare one.
2. **Infrastructure routes counted as undelivered capability.** `/health`,
   `/robots.txt` and `/favicon.ico` are not features; reporting them as
   "implemented but unused" is noise that buries the real findings. They are
   excluded by name.

Both are covered by tests that assert against the real 18-route surface.

## The other checks

**`scope_declaration`** — refuses a scan on a target with no authorization
record, flags a partial record (missing signer or timestamp) as CRITICAL, and
flags a record naming a different target as CRITICAL. It verifies presence and
shape, not truth: authorization is a legal act, not something a program
confirms.

**`unfinished_markers`** — counts TODO/FIXME/HACK markers. A **zero result is
emitted as a MEDIUM finding**, not a clean bill of health. This is not
theoretical: ForgeGuard has zero markers in 77,131 lines, which means its
incomplete flows are unmarked and a marker search will never find them. A check
that reports "0 problems found" there would be actively misleading.

**`simulation_exposure`** — finds a code path that can emit results without
measuring the target. It matches both filenames (`synthetic`, `simulat`) and
content markers (`REVENUE_SIMULATION_MODE`, `generateSynthetic`), because a
filename-only scan reports "clean" for a codebase whose runner returns
fabricated results behind an env flag in a normally-named module. A module
marked `@deprecated` that still references the flag is downgraded to LOW rather
than dropped — dead code one import away from running is a trap, not a non-issue.

## Writing a check

A check is a callable taking a `CheckContext` and returning findings:

```python
from scanforge.registry import CheckContext, CheckSkipped, registry
from sentinel_findings.schema import Finding, Severity, Provenance

@registry.register("my_check", category="tls", weight=3)
def my_check(ctx: CheckContext):
    """One line that becomes the description."""
    if not ctx.option("endpoint"):
        raise CheckSkipped("no endpoint supplied")
    ...
    return [Finding(id="", title="...", severity=Severity.HIGH,
                    provenance=Provenance.OBSERVED, tool="my_check",
                    target=ctx.target)]
```

Return `None`, a single `Finding`, a list of `Finding`, or a dict — all are
normalised. Anything else is recorded as a `TypeError` check failure rather than
crashing the run.

Third-party packages can declare checks as entry points under the
`scanforge.checks` group; `Registry.load_entry_points()` picks them up.

## The honesty rule this project follows

`unfinished_markers` returns a finding when it finds nothing, because on this
codebase nothing is the dangerous answer. If a check cannot see something, its
docstring says so and the output does not imply otherwise. Every check here
declares what it cannot see.

## Tests

```bash
pip install -e ".[dev]"
python -m pytest
```

57 tests, verified from a fresh clone. The timeout tests use a real `sleep` and
assert the orchestrator returns in under two seconds — a timeout that is only
tested with a mock is a timeout nobody has verified works.

## Limitations

- **Timeouts abandon, they do not kill.** A timed-out check runs in a worker
  thread that keeps running until its own work finishes. Threads cannot be
  killed in Python. The orchestrator stops *waiting*, which is what protects the
  scan, but a check that never returns leaves a thread behind. Run untrusted
  checks in a process pool if that matters to you.
- **No suspension of execution.** The design records a timeout and moves on. If
  a check has already sent packets, abandoning it does not un-send them.
- **`engine_contract` is surface-shaped.** A route that exists and returns 500
  still counts as present. It cannot tell you a route is broken, only that it is
  missing or unused.
- **The expected route list is hard-coded.** Reading it from the engine at run
  time would make the check compare the engine to itself. It needs updating when
  the engine's surface changes — that is the intended cost.
- **In-process, single-machine.** `max_workers` is threads in one process. No
  distributed execution, no persistence, no resume.

## License

MIT.
