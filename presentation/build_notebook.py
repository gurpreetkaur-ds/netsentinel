"""Builds presentation/NetSentinel.ipynb (the cleaned presentation copy).

    .venv/bin/python presentation/build_notebook.py && .venv/bin/python presentation/build_notebook.py --execute

The notebook reads the saved evaluation artifacts and the raw CSV cache. It does not retrain, and
production code never imports it.
"""

import sys
from pathlib import Path

import nbformat as nbf

HERE = Path(__file__).parent
ROOT = HERE.parent
OUT = HERE / "NetSentinel.ipynb"
md, code = nbf.v4.new_markdown_cell, nbf.v4.new_code_cell

cells = [
md("""# NetSentinel: from anomaly-detection notebook to threat-detection platform

This notebook tells the story of the project from the original `Anomaly_detection.ipynb`
(preserved unchanged in `original/`) to the deployed platform. It **reads saved results**:

* `artifacts/v0/report.json`: the original notebook, reproduced as a script
* `artifacts/v1/report.json`: the production model and its evaluations
* `artifacts/e2e/*.json`: end-to-end validation runs of the live platform

Production code lives in the `netsentinel` package. This notebook imports it; nothing imports the notebook."""),
code("""import json
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

from netsentinel.ml import data, schema, taxonomy

ROOT = data.ROOT
v0 = json.loads((ROOT / "artifacts/v0/report.json").read_text())
v1 = json.loads((ROOT / "artifacts/v1/report.json").read_text())

# Chart style: one hue for single-series charts, recessive grid, text in ink colours.
BLUE, INK2, GRID = "#2a78d6", "#52514e", "#e1e0d9"
plt.rcParams.update({"font.family": "sans-serif", "axes.edgecolor": "#c3c2b7", "axes.labelcolor": INK2,
                     "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False,
                     "axes.grid": True, "axes.axisbelow": True, "grid.color": GRID, "grid.linewidth": 0.6,
                     "figure.dpi": 110})
pd.set_option("display.max_colwidth", 90)"""),

md("""## 1. The data: CICIDS-2017

Five days of CICFlowMeter flows from the Canadian Institute for Cybersecurity testbed. Each day
contains different attacks, which matters for how the data is split."""),
code("""labels = pd.concat({d: pd.read_parquet(data.CACHE / f"{d}.parquet", columns=["Label", "Attempted Category"])
                    for d in data.DAYS_CHRONOLOGICAL}, names=["day"]).reset_index(level=0).reset_index(drop=True)
pd.crosstab(labels["Label"], labels["day"])[list(data.DAYS_CHRONOLOGICAL)]"""),

md("""## 2. What the original notebook got wrong

| Issue | Evidence | Consequence |
|---|---|---|
| **Target leakage** | `Attempted Category` is a model feature, and is ≠ −1 *exactly* on `… - Attempted` labels (next cell) | the model can read part of the answer |
| **Not a time split** | Hugging Face loads files alphabetically (fri, mon, thu, tue, wed), so the "future" 30% is Tuesday + Wednesday | test attacks (all DoS, Heartbleed) never appear in training |
| **Identity features** | `Src IP dec` / `Dst IP dec` rank #4 and #7 in importance | memorises the lab's addresses, not attack behaviour |
| **ROC-AUC from hard labels** | `roc_auc_score(y, y_pred)` for two models | reports balanced accuracy and calls it AUC |
| **Binary only** | 0 / 1 output | no triage information |"""),
code("""attempted_flag = labels["Attempted Category"] != -1
attempted_label = labels["Label"].str.endswith("- Attempted")
pd.crosstab(attempted_flag.rename("Attempted Category != -1"), attempted_label.rename("label ends with '- Attempted'"))"""),
code("""print("Notebook's test split comes from:", v0["data"]["test_days"])
test_labels = pd.Series(v0["data"]["test_labels"]).drop("BENIGN").sort_values(ascending=False)
test_labels.rename("flows in the notebook's test split").to_frame()"""),

md("""## 3. v0: the notebook, reproduced exactly

`python -m netsentinel.ml.train v0` replays the notebook from the raw CSVs, keeping its flaws on
purpose. The data pipeline reproduces **exactly**. Random Forest does **not**: with the same data, the
same seed and the same settings, the number of attacks it catches depends on the scikit-learn version."""),
code("""ref = v0["notebook_reference"]
pd.DataFrame({
    "notebook": [ref["duplicates"], ref["correlated_dropped"], ref["train_rows"], ref["test_rows"],
                 str(ref["confusion_matrix"]["isolation_forest"])],
    "v0": [v0["data"]["duplicates_removed"], len(v0["data"]["correlated_dropped"]), v0["data"]["train_rows"],
           v0["data"]["test_rows"], str(v0["models"]["isolation_forest"]["confusion_matrix"])],
}, index=["duplicates removed", "correlated features dropped", "train rows", "test rows",
          "Isolation Forest confusion matrix"])"""),
code("""support = v0["data"]["test_attacks"]
runs = {"notebook (Colab)": ref["confusion_matrix"]["random_forest"][1][1],
        "scikit-learn 1.6.1": 105_439,          # measured, see docs/model-baseline.md
        "scikit-learn 1.9.1": v0["models"]["random_forest"]["confusion_matrix"][1][1]}
recall = {k: v / support for k, v in runs.items()}
fig, ax = plt.subplots(figsize=(7, 2.4))
bars = ax.barh(list(recall), list(recall.values()), color=BLUE, height=0.5)
ax.bar_label(bars, labels=[f"{v:.0%}" for v in recall.values()], padding=4, color=INK2)
ax.set_xlim(0, 1); ax.xaxis.set_major_formatter("{x:.0%}"); ax.set_xlabel("attack recall, same code and seed"); ax.invert_yaxis(); ax.grid(axis="y", visible=False)
ax.set_title("Random Forest recall on the notebook's split is not reproducible", loc="left", fontsize=11)
plt.show()"""),
md("""Why: the test attacks (DoS variants, Heartbleed) are absent from training, so whether a model flags
them depends on incidental tree splits. Per-label recall from the v0 run:"""),
code("""pd.Series(v0["rf_recall_by_attack_label"]).rename("RF recall (v0)").sort_values().to_frame().style.format("{:.1%}")"""),
code("""pd.DataFrame({m: {"notebook 'ROC-AUC'": ref["roc_auc_as_printed"][m], "ROC-AUC (scores)": r["roc_auc"],
                   "PR-AUC": r["pr_auc"]} for m, r in v0["models"].items()}).T.style.format("{:.4f}")"""),

md("""## 4. v1: fixed schema and a hierarchical detector

**Binary vs multi-class.** The notebook answers one question, *is this flow an attack?* v1 keeps that
as stage 1, the only stage that decides anything, and adds two descriptive stages that answer only when
confident enough:

```
Network event ─► Stage 1: Normal vs Attack         (decides; threshold tuned to ≤ 0.1% false alerts)
                     └─► Stage 2: attack family      (answers at ≥ 0.6 confidence, else "unknown")
                             └─► Stage 3: attack type (answers at ≥ 0.8 confidence, else none)
```

A flow the family model can't name is still an attack. Families and types are only learned once
they have enough training examples (`netsentinel/ml/taxonomy.py`)."""),
code("""print(len(schema.FEATURES), "model features; removed:")
pd.Series(schema.EXCLUDED, name="reason").to_frame()"""),
code("""pd.DataFrame([{"dataset label": k, "family": v.family or "Normal", "type": v.attack_type or "", "attempted": v.attempted}
              for k, v in taxonomy.LABELS.items()]).sort_values(["family", "type", "attempted"]).set_index("dataset label")"""),
code("""e1 = v1["e1"]
pd.DataFrame({name: {"threshold": m["threshold"], "false alerts": m["confusion_matrix"][0][1],
                     "missed attacks": m["confusion_matrix"][1][0], "precision": m["attack"]["precision"],
                     "recall": m["attack"]["recall"], "false-positive rate": m["false_positive_rate"]}
              for name, m in [("operational (≤0.1% FPR)", e1["fpr_0.1pct"]), ("max F1", e1["max_f1"])]}).T"""),
code("""fam = pd.DataFrame(e1["family"]["per_family"]).T
typ = pd.DataFrame(e1["attack_type"]).T.add_prefix("type ")
fam.join(typ[["type coverage", "type accuracy_when_answered"]])"""),
md("""E1 (attack types seen in training) is near perfect. CICIDS-2017 is known to be easy when the same tools
appear in training and test, so treat it as a ceiling. The honest test is E2."""),

md("""## 5. E2: attacks the model has never seen

For each family, the stage-1 detector is retrained **without** it and tested on whether it still flags
that family, at the same ≤ 0.1% false-alert budget."""),
code("""e2 = pd.DataFrame(v1["e2"]["families"]).T.sort_values("supervised_recall")
fig, ax = plt.subplots(figsize=(7, 3.2))
bars = ax.barh(e2.index, e2["supervised_recall"], color=BLUE, height=0.55)
ax.bar_label(bars, labels=[f"{r:.0%}  (n={int(n):,})" for r, n in zip(e2["supervised_recall"], e2["test_support"])],
             padding=4, color=INK2, fontsize=9)
ax.set_xlim(0, 1.25); ax.set_xticks([0, .25, .5, .75, 1]); ax.set_xticklabels(["0%", "25%", "50%", "75%", "100%"])
ax.set_xlabel("recall on the held-out family (0.1% false-alert budget)"); ax.grid(axis="y", visible=False)
ax.set_title("Unseen port scans and brute force are the weak spots", loc="left", fontsize=11)
plt.show()
e2[["test_support", "supervised_recall", "supervised_fpr", "isolation_forest_recall"]]"""),
md("""* A single scan or login attempt looks like a benign handshake. The attack is the *pattern* across many
  flows, which is why the platform correlates flows by source (the Orchestrator) and scores the source's
  port fan-out (the Risk Agent).
* An Isolation Forest trained on benign traffic catches **nothing** at this false-alert budget, so it is
  not in the alert path."""),

md("""## 6. v2: per-source time windows

The weak spots above are attacks that only show up as a pattern across flows. v2 adds six features
that describe the **source's last 60 seconds**: flow count, distinct destination ports and hosts,
flows to the same service, and share of unanswered or reset flows. They are causal (computed from
flows that had already *ended*) and computed identically in training and in the live Detection Agent.

This needs real timestamps, which the Kaggle copy lost, so v2 uses the authors' corrected
CICIDS-2017 (Engelen et al., 2021). Both detectors below train on the same rows with the same splits."""),
code("""v2r = json.loads((ROOT / "artifacts/v2/report-experiment.json").read_text())["results"]
cmp = pd.DataFrame({"per-flow features": {f: v["supervised_recall"] for f, v in v2r["v1-features"]["e2"]["families"].items()},
                    "+ window features (v2)": {f: v["supervised_recall"] for f, v in v2r["v2-features"]["e2"]["families"].items()}})
cmp = cmp.sort_values("per-flow features")
ORANGE = "#eb6834"
fig, ax = plt.subplots(figsize=(7.5, 3.6))
y = range(len(cmp))
b1 = ax.barh([i + 0.2 for i in y], cmp["per-flow features"], height=0.38, color=BLUE, label="per-flow features",
             edgecolor="white", linewidth=1)
b2 = ax.barh([i - 0.2 for i in y], cmp["+ window features (v2)"], height=0.38, color=ORANGE, label="+ window features (v2)",
             edgecolor="white", linewidth=1)
ax.set_yticks(list(y)); ax.set_yticklabels(cmp.index); ax.set_xlim(0, 1.12)
ax.xaxis.set_major_formatter("{x:.0%}"); ax.grid(axis="y", visible=False)
ax.bar_label(b2, labels=[f"{v:.0%}" for v in cmp["+ window features (v2)"]], padding=3, color=INK2, fontsize=8)
ax.legend(loc="lower left", bbox_to_anchor=(0, 1.0), ncol=2, frameon=False, fontsize=9)
ax.set_xlabel("recall on the held-out family (0.1% false-alert budget)")
ax.set_title("Window features close the brute-force and scan gaps", loc="left", fontsize=11, pad=24)
plt.show()
cmp.style.format("{:.1%}")"""),
md("""Live check with v2 active: real capture intervals replayed through the production API, in the order
the flows ended. Port scan 997/997, FTP brute force 124/124, SSH brute force 102/102, botnet attempts
42/42, all named with the correct family. False alerts were 14 of 5,058 benign flows (0.28%, against
0.10% in validation), all just above a very low threshold. Re-tune the threshold on real traffic.
Details in `docs/model-v2.md`."""),

md("""## 7. The platform

```
 sensors / replay ──► FastAPI ingest (API key, step 1) ──► Detection Agent (steps 2-7)
                                                              validate · normalise · extract
                                                              MODEL CHECK (hash + human approval)
                                                              inference ─► detection.attack (event bus)
                                                                              │
 Security Orchestrator ◄──────────────────────────────────────────────────────┘
   correlates flows by source + family into cases (step 7)
     └─► Investigation Agent: Claude, keyless, guarded (step 8)
           └─► Risk Assessment Agent: deterministic, explainable (step 9)
                 └─► Response Agent: reversible proposals only, human approval (step 10)
                       └─► Ticket Agent: NS-000123, SLA, timeline (step 11)
 Dashboard: read-only, HTTPS, signed sessions (step 12)
```

Every investigation and ticket keeps four labelled sections: **VERIFIED TELEMETRY**, **MODEL OUTPUT**,
**LLM ANALYSIS** and **RECOMMENDATION**. Claude never changes a detection or a risk score, and a guard
rejects any analysis that mentions an IP address absent from the evidence."""),
code("""runs = sorted((ROOT / "artifacts/e2e").glob("*.json"), key=lambda p: p.stat().st_mtime)
if not runs:
    print("No end-to-end run yet: `netsentinel e2e`")
else:
    r = json.loads(runs[-1].read_text())
    print(f"Latest end-to-end validation ({r['run_started'][:16]} UTC): {'PASSED' if r['passed'] else 'FAILED'}")
    display(pd.Series(r["checks"], name="passed").to_frame())
    display(pd.DataFrame(r["tickets"]))"""),

md("""## 8. Limitations and next steps

* **Threshold on real traffic:** v2 separates the lab data so well that its alert threshold is tiny
  (p ≥ 0.000016). Live replays gave 0.28% false alerts, not 0.10%. Re-tune on the target network, where
  busy legitimate hosts (NAT gateways, backup servers, scanners) produce fan-out too.
* **Sensors must send timestamps and the 5-tuple** for window features. Without them, flows fall back to
  per-flow scoring.
* **Lab data:** CICIDS-2017 is one network in 2017. Validate on live traffic (Zeek/NetFlow adapters are
  designed in) before trusting the numbers.
* **Closed-set families:** rare families (Infiltration, Heartbleed) get named as a wrong family instead
  of "unknown". An open-set check or more examples are needed.
* **Replay timestamps:** replayed flows are timestamped on arrival. Real sensors should send `observed_at`."""),
]

nb = nbf.v4.new_notebook(cells=cells, metadata={
    "kernelspec": {"name": "netsentinel", "display_name": "NetSentinel (.venv)", "language": "python"},
    "language_info": {"name": "python"}})

if "--execute" in sys.argv:
    from nbclient import NotebookClient
    NotebookClient(nb, timeout=600, kernel_name="netsentinel", resources={"metadata": {"path": str(ROOT)}}).execute()
    print("executed OK")
nbf.write(nb, OUT)
print("wrote", OUT)
