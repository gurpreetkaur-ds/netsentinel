# Detection model v1

`python -m netsentinel.ml.train v1` → `artifacts/v1/detector.joblib` + `artifacts/v1/report.json`
(about 9 minutes on 2 cores).

## Binary vs multi-class, and why NetSentinel uses both

| | Binary (notebook, v0) | Hierarchical multi-class (v1) |
|---|---|---|
| Question answered | "Is this flow an attack?" | "Is it an attack? Which family? Which type?" |
| Output | 0 / 1 | `is_attack`, `p_attack`, `family` (+ confidence), `attack_type` (+ confidence) |
| Novel attacks | caught only if they look "attack-like" | same stage-1 behaviour; stages 2-3 can't name what they never saw |
| Analyst value | an alert | an alert with a triage starting point (DoS vs scan vs brute force need different responses) |

v1 is a three-stage cascade:

1. **Stage 1, binary (the decision maker).** HistGradientBoosting on all traffic. Its threshold is
   tuned on a validation set so that ≤ 0.1% of benign flows alert.
2. **Stage 2, family.** Runs only on flows stage 1 flagged. Trained on families with ≥ 50 training
   examples. Answers only at ≥ 0.6 confidence, otherwise `family = null`.
3. **Stage 3, attack type.** One model per family with ≥ 2 learnable types (≥ 100 examples each).
   Answers only at ≥ 0.8 confidence. Single-type families (DDoS → LOIC, Botnet → Ares) report that type.

Stages 2-3 never change stage 1's decision. A flow the family model can't name is still an attack.

## Changes from v0

- Fixed 83-feature schema (`netsentinel/ml/schema.py`). It removes `Attempted Category` (label
  leakage), source/destination IP and source port (identity, not behaviour), and Timestamp.
- Infinite/missing values become NaN instead of the row being dropped, because a live detector
  can't drop flows.
- Exact duplicates are removed **after** dropping the identity columns: 258,992 rows (v0 removed
  only 3,167, because IPs/ports made copies look distinct). 8,750 rows share identical features
  but carry different labels, which caps achievable accuracy.
- Taxonomy (`netsentinel/ml/taxonomy.py`): every dataset label maps to Normal or to a family/type.
  "- Attempted" rows keep their family and type but are flagged `attempted`, which the model never
  predicts.
- Correct metrics: ROC-AUC/PR-AUC come from scores, never from hard labels.

## Results

### E1: attack types seen in training (stratified 60/20/20, test = 368,196 flows)

| Threshold | p_attack ≥ | False alerts | Missed attacks | Precision | Recall | FPR |
|---|---|---|---|---|---|---|
| **operational (FPR ≤ 0.1% on validation)** | 0.0004 | 265 | 1 | 0.9968 | 0.99999 | 0.093% |
| max-F1 | 0.611 | 31 | 15 | 0.9996 | 0.99982 | 0.011% |

ROC-AUC 0.999999. CICIDS-2017 is known to be easy when the same attack tools appear in training
and test, so **treat E1 as a ceiling, not a forecast**. E2 is the realistic number.

Family stage (on caught attacks): 100% coverage, 99.98% accuracy for the six trained families.
Infiltration (15 test flows) and Exploit/Heartbleed (2) are below training support: they are
still flagged as attacks, but the family model labels them as a *wrong* known family rather than
"unknown". Closed-set classifiers can't say "none of the above". That's a known limitation,
tracked for the investigation agent to flag.

Type stage: DoS 99.98% accurate (100% coverage), PortScan 99.0% (81% coverage), BruteForce,
Botnet and DDoS 100%. WebAttack: the model answers for only 27% of flows, at 78% accuracy. Web
Brute Force and XSS are near-identical at flow level, and SQL Injection (18 rows) is too rare to
learn. This is the "type only when support and confidence allow" rule working as intended.

### E2: attack families never seen in training (leave-one-family-out, same 0.1% FPR budget)

| Held-out family | Test flows | Recall, supervised | Isolation Forest (benign-only) |
|---|---|---|---|
| DDoS | 19,029 | **1.00** | 0.00 |
| WebAttack | 412 | 0.92 | 0.00 |
| Botnet | 387 | 0.91 | 0.00 |
| DoS | 35,502 | 0.81 | 0.00 |
| Infiltration | 16 | 0.75 (small sample) | 0.00 |
| BruteForce | 1,393 | 0.48 | 0.00 |
| PortScan | 26,360 | **0.33** | 0.00 |

For comparison, v0's notebook split was effectively "DoS unseen". There the Random Forest
caught 0.48–0.87 of DoS depending on library version; v1 catches 0.81 under a controlled test.

- **Novel-attack detection is the real weak point:** port scans and brute force look like small
  benign handshakes unless the model has seen them. Per-flow models can't see the pattern
  (*many* small flows from one source). Planned fix: a host/time-window aggregation layer in the
  agent stage, e.g. distinct destination ports per source per minute.
- **Isolation Forest adds nothing at a 0.1% false-alert budget** (0 recall in every held-out
  family, 0.007% FPR). It is not used in the alert path.

## Threshold choice

The operational threshold (0.0004) is kept as the default, even though max-F1 gives 8× fewer false
alerts in E1. E2 was measured at the 0.1%-FPR budget, and the lower threshold is what lets stage 1
catch unfamiliar attacks. Both thresholds are stored in the model's metadata; switching is a
configuration change reviewed through the model registry (next phase).
