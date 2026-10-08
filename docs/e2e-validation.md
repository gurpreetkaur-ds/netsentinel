# End-to-end validation (2026-10-07)

`netsentinel e2e --flows 400 --seed 123` against the **live, hardened** services (systemd sandbox
applied, Let's Encrypt dashboard). Run `38d00008`, report in `artifacts/e2e/`. Result: **PASSED, 19/19**.

| Step | Check | Result |
|---|---|---|
| 1 Ingest | 400 held-out flows (ephemeral key, revoked after) | 400/400 accepted |
| 2 Validate | malformed flows rejected with a stored reason | `non_numeric_feature:Protocol`, `out_of_range:Dst Port`, `too_many_missing_features:82/83` |
| 2 Auth | no key → 401; ingest-only key reading events → 403 | both |
| 6 Inference | every valid flow scored | 400; detection p50 0.29 s |
| 6 Accuracy | recall ≥ 0.99, FPR ≤ 0.5% | 96/96 attacks (recall 1.0); 1 false alert in 304 benign (0.33%) |
| 7 Correlation | every attack flow in exactly one case | 6 cases, none unassigned |
| 8 Investigation | every case investigated by Claude **under the sandbox**, no guard rejections | 6/6 `ok`, 0 guard findings; 49–91 s per case |
| 9 Risk | every case scored | 45–62 (2 high, 4 medium) |
| 10 Response | proposals exist, all reversible, none decided by a machine | 18 proposals (8 disruptive), 0 irreversible, 0 auto-decided |
| 11 Tickets | every case ticketed with all five sections | NS-000028 … NS-000033 |
| Ops | no errors / permission denials in any service log during the run | 0 |

**Observed limitation:** case → ticket took 7.7–13 min here, because Claude investigates one case at
a time (~1 min each) and these cases queued behind an earlier run's. Detection itself stays sub-second;
only the explanation is delayed. A second Investigation worker would halve the queue (agents are safe
to run in parallel: work is claimed atomically).

An earlier attempt, run `b874a15a`, "passed" its case checks vacuously: the validator looked before the
orchestrator had correlated anything. The validator now waits stage by stage and treats zero cases as a
failure.

## Re-run with model v2 active (2026-10-07)

Run `32287ef0` (`netsentinel e2e --flows 400 --seed 31337`): **PASSED, 19/19**. 83/83 attacks, 1 false
alert in 317 benign flows, 6 cases, 6/6 Claude investigations `ok` (50-85 s each, two in parallel),
6 tickets (NS-000090 … NS-000095), 0 log errors. These sampled flows carry no timestamps, so they
exercise v2's per-flow fallback. The window path is validated by the slice replays in `docs/model-v2.md`.

Between runs, two other outcomes were recorded honestly:
* Run `c8c53ae1`: 18/19. The single failure was a log error from deliberately restarting the
  Investigation Agent mid-run (Claude process killed, exit 143), which `ops/systemd/finalize.sh` prevents.
* Run `ce0dc9ce`: 18/19. The server's Claude login hit its session limit. Every flow was still scored
  and every case ticketed within 38 s with rule-based steps (`llm_status = unavailable`); the
  orchestrator now retries such cases after 15 min (max 3 investigations per case).
