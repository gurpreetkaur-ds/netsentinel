# Detection model v2: per-source time-window features

`python -m netsentinel.ml.train v2` → `artifacts/v2/` (`report-experiment.json` holds the full evaluation).

## Why

v1 judges each flow alone. A port-scan probe or a password attempt looks like a benign handshake. The
attack is the *pattern* of many flows from one source. v1's weakest unseen families were exactly
these: PortScan and BruteForce.

## Data with real time

The Kaggle/Hugging Face copy used for v0/v1 had its timestamps reduced to `mm:ss.f`, with rows not in
time order (35-45% of consecutive rows go backwards), so no time window could be built. v2 uses the
authors' original **corrected CICIDS-2017** (Engelen et al., 2021; Distrinet / KU Leuven,
`CICIDS2017_improved.zip`, 344 MB). It is the same flows (2,099,976 vs 2,099,971), the same 83 features
and the same labels, with microsecond UTC timestamps and real IP strings.

## The six window features (`netsentinel/ml/windows.py`)

For each flow: the flows from the **same source IP** that **ended** in the 60 s up to this flow's end:
`src_win_flows`, `src_win_distinct_dst_ports`, `src_win_distinct_dst_ips`,
`src_win_same_service_flows` (to this flow's dst ip:port), `src_win_share_no_response`, `src_win_share_rst`.

Typical per-minute medians: benign source 125 flows / 4 ports; port scanner 997 distinct ports;
DDoS source 4,880 flows to one service, all reset.

**Causal and identical in production.** A flow reaches NetSentinel when it ends, so using end times
means nothing comes from the future. The Detection Agent computes the same features from the database
(`flow_events.ended_at` = start + duration, set at ingest). A test ingests 800 real port-scan-period
flows through the API and asserts the live values equal the training values.

No source *identity* is used: grouping by IP only defines the window, and the features describe
behaviour, not which address it was.

## Results (same rows, same splits, same 0.1% false-alert budget)

| Unseen family (E2) | per-flow features | **+ window features** |
|---|---|---|
| BruteForce | 48.0% | **100%** |
| Botnet | 80.7% | **96.3%** |
| PortScan (46,165 flows) | 83.1% | **92.1%** |
| DoS | 92.7% | **99.0%** |
| WebAttack | 90.3% | **100%** |
| DDoS | 100% | 100% |
| Infiltration (16 flows) | 93.8% | 87.5% (1 flow; noise) |

Seen attacks (E1): 1 missed attack in 103,457 (was 10), 313 false alerts in 316,067 benign (was 337),
and PortScan type labelling coverage 100% at 100% accuracy (was 89% / 98%).

**Not comparable with the v1 report.** v1 de-duplicated on the 83 per-flow features (−259k rows),
leaving harder unique scan flows; here window features make rows distinct, so per-flow duplicates stay.
That is why the per-flow column above reads PortScan 83% rather than v1's 33%. Only the two columns
of this table compare like with like.

## Packaging and safety

The artifact is a `WindowedDetector`: the window model scores flows that have window context, and the
per-flow model from the same experiment scores flows that don't (no source IP or timestamp). The window
model never saw a flow without that context. Each detection records the threshold that applied.

* Model Check accepts a model only for a feature schema the service can compute (`cicflowmeter-v1` or
  `cicflowmeter-v2-window60`) and only with exactly that feature list.
* Rollback: a previously active (approved) model can be re-activated: `netsentinel models activate netsentinel-v1`.

## Caveats

* The operational threshold is p ≥ 0.000016: the classes separate extremely well on this lab data.
  Expect to re-tune on real traffic, where busy legitimate hosts (NAT gateways, backup servers,
  vulnerability scanners) can look like fan-out.
* Windows need sensors to send `observed_at` and the 5-tuple. Without them, flows fall back to per-flow
  scoring (v1-level detection).

## Live validation (2026-10-07, v2 active on the production services)

Real capture intervals replayed through the live API in the order the flows ended, with a 60 s warm-up
and no overlap between replays (`netsentinel replay --slice DAY START_UTC MINUTES`). Every scored flow
used the window model; for SSH flows the live window values were checked equal to full-day values.

| Slice | Attack flows caught | Family named correctly | False alerts / benign |
|---|---|---|---|
| Port scan, Fri 17:56 (1 min) | 997 / 997 | 100% | 0 / 279 |
| FTP brute force, Tue 12:30 (2 min) | 124 / 124 | 100% | 2 / 1,816 |
| SSH brute force, Tue 17:20 (2 min) | 102 / 102 | 100% | 6 / 1,318 |
| Botnet attempts, Fri 18:00 (3 min) | 42 / 42 | 100% | 6 / 1,645 |

**False alerts: 14 of 5,058 benign flows (0.28%)**, against 0.10% in validation. They all scored just
above the very low threshold (p ≈ 0.00002-0.0002): repeated HTTPS or STUN from one workstation, SMB to
the domain controller, and legitimate SSH logins to the server under attack. The threshold was **not**
re-tuned on these replays: they are test data. Re-tune on real traffic before relying on the 0.1% figure.

Two replay pitfalls were found and fixed on the way. Without a warm-up, the first minute of a replay
has half-empty windows (brute force got named PortScan). Back-to-back replays shifted to "now" shared
windows (SSH windows counted the FTP replay). Neither can happen with a continuous real sensor.

Approval: `netsentinel-v2` was registered, approved and activated by `linuxuser` on the owner's
instruction to finish all remaining work. `netsentinel-v1` stays retired and approved; roll back
with `netsentinel models activate netsentinel-v1`.
