# v0: the original notebook, reproduced

`python -m netsentinel.ml.train v0` replays the notebook's pipeline from the raw CSVs, without
Jupyter, and writes `artifacts/v0/report.json`. It deliberately keeps the notebook's flaws, so the
reference stays honest.

## What reproduces exactly

| | Notebook | v0 |
|---|---|---|
| Duplicates removed | 3,167 | 3,167 |
| Correlated features dropped | 27 | 27 |
| Train / test rows | 1,467,762 / 629,042 | 1,467,762 / 629,042 |
| Model features | 60 | 60 |
| Isolation Forest confusion matrix | [[346254, 100939], [1851, 179998]] | identical |

## What does not reproduce, and why that matters

| Model | Notebook: attacks caught | scikit-learn 1.6.1 | scikit-learn 1.9.1 |
|---|---|---|---|
| Random Forest (same seed, same data) | 157,352 (recall 0.865) | 105,439 (0.580) | 87,189 (0.479) |
| Logistic Regression | 108,172 (0.595) | not run | 102,128 (0.562) |

False positives stay near 35 for Random Forest and near 1,070 for Logistic Regression in every
run. Only the attack side swings.

**Cause:** the split isn't time-based. Hugging Face orders the files alphabetically (fri, mon,
thu, tue, wed), so the "future" 30% is Tuesday and Wednesday. Those days are almost entirely DoS
Hulk / GoldenEye / Slowloris / Slowhttptest, plus Heartbleed, and **none of those appear in the
training data**. Whether a model flags an attack family it has never seen depends on incidental
tree splits. RF recall by label in v0 is FTP/SSH-Patator ~1.0 (seen in training), DoS Hulk 0.51,
GoldenEye 0.29, Slowloris 0.004, Slowhttptest 0.003 and Heartbleed 0.

So the notebook's 0.87 RF recall is not a property of the model. It's one draw from an unstable
process, and the same code gives 0.48–0.87 depending on library version.

## Metric corrections recorded alongside

| Model | Notebook "ROC-AUC" | Actual ROC-AUC (continuous scores) | PR-AUC |
|---|---|---|---|
| Isolation Forest | 0.8821 (from 0/1 predictions) | 0.8657 | 0.5653 |
| Random Forest | 0.9999 | 0.9999 | 0.9995 |
| Logistic Regression | 0.7962 (from 0/1 predictions) | 0.9638 | 0.9620 |

Random Forest's ~1.0 ranking AUC next to 0.48 recall means the default 0.5 threshold is badly
placed for unseen attacks. That motivates the threshold-tuning step in v1.

## Other known v0 flaws (fixed in v1)

- `Attempted Category` is a model feature and leaks the label ("… - Attempted" rows).
- `Src IP dec` / `Dst IP dec` rank #4 and #7 in importance. That's lab-network topology memorised,
  which won't carry over to other networks.
- Binary-only output.
