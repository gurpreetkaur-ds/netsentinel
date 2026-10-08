"""v0: a faithful, runnable reproduction of the original notebook (original/Anomaly_detection.ipynb).

It keeps the notebook's known flaws on purpose (Attempted Category leakage, IPs as features,
alphabetical-day "time" split, hard-label AUC), so later versions have an honest reference.
The notebook's cells are replayed in their effective execution order (counts 3, 71-74, 109-115).
"""

import json
import logging
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from . import data
from .metrics import binary_report

log = logging.getLogger(__name__)

# Numbers printed in the notebook's saved outputs.
NOTEBOOK = {
    "duplicates": 3167, "correlated_dropped": 27, "train_rows": 1_467_762, "test_rows": 629_042,
    "confusion_matrix": {
        "isolation_forest": [[346254, 100939], [1851, 179998]],
        "random_forest": [[447157, 36], [24497, 157352]],
        "logistic_regression": [[446129, 1064], [73677, 108172]],
    },
    "roc_auc_as_printed": {"isolation_forest": 0.8820521823984458, "random_forest": 0.9999374952778974,
                           "logistic_regression": 0.7962329439209423},
}


def prepare(df: pd.DataFrame) -> dict:
    """Cells 71-74 and 109: cleaning, pruning, binary label, positional 70/30 split."""
    day = df.pop("day")
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    duplicates = int(df.duplicated().sum())
    df = df.drop_duplicates()

    nunique = df.nunique()
    constant = list(nunique[nunique <= 1].index)
    df = df.drop(columns=constant)

    corr = df.select_dtypes(include=[np.number]).corr().abs()
    upper = corr.where(np.triu(np.ones(corr.shape), k=1).astype(bool))
    correlated = [c for c in upper.columns if any(upper[c] > 0.95)]
    df = df.drop(columns=correlated, errors="ignore")

    original_label = df["Label"].copy()
    df["Label"] = (df["Label"] != "BENIGN").astype(int)
    day = day.loc[df.index].reset_index(drop=True)
    original_label = original_label.reset_index(drop=True)
    df = df.reset_index(drop=True)

    y = df["Label"]
    X = df.drop("Label", axis=1).select_dtypes(include=[np.number])
    split = int(len(df) * 0.7)
    return {
        "X_train": X.iloc[:split], "X_test": X.iloc[split:], "y_train": y.iloc[:split], "y_test": y.iloc[split:],
        "label_test": original_label.iloc[split:], "day": day, "split": split,
        "duplicates": duplicates, "constant": constant, "correlated": correlated, "features": list(X.columns),
    }


def run(out_dir: Path, *, n_jobs: int = -1) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    p = prepare(data.load_raw(data.DAYS_HF_ORDER))
    log.info("prepared: train=%d test=%d features=%d (%.0fs)", len(p["X_train"]), len(p["X_test"]),
             len(p["features"]), time.time() - t0)

    scaler = StandardScaler()
    Xtr = scaler.fit_transform(p["X_train"])
    Xte = scaler.transform(p["X_test"])
    ytr, yte = p["y_train"].to_numpy(), p["y_test"].to_numpy()
    results, timings = {}, {}

    t = time.time()
    iso = IsolationForest(contamination=ytr.mean(), random_state=42).fit(Xtr[ytr == 0])
    iso_pred = np.where(iso.predict(Xte) == -1, 1, 0)
    results["isolation_forest"] = binary_report(yte, iso_pred, scores=-iso.score_samples(Xte))
    timings["isolation_forest"] = time.time() - t
    log.info("isolation forest done (%.0fs)", timings["isolation_forest"])

    t = time.time()
    rf = RandomForestClassifier(n_estimators=100, max_depth=10, min_samples_leaf=10, class_weight="balanced",
                                random_state=42, n_jobs=n_jobs).fit(Xtr, ytr)
    rf_prob = rf.predict_proba(Xte)[:, 1]
    rf_pred = rf.predict(Xte)
    results["random_forest"] = binary_report(yte, rf_pred, scores=rf_prob)
    timings["random_forest"] = time.time() - t
    log.info("random forest done (%.0fs)", timings["random_forest"])

    t = time.time()
    lr = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42).fit(Xtr, ytr)
    results["logistic_regression"] = binary_report(yte, lr.predict(Xte), scores=lr.predict_proba(Xte)[:, 1])
    timings["logistic_regression"] = time.time() - t
    log.info("logistic regression done (%.0fs)", timings["logistic_regression"])

    importance = sorted(zip(p["features"], rf.feature_importances_.tolist()), key=lambda x: -x[1])
    labels = p["label_test"].reset_index(drop=True)
    test_labels = labels.value_counts().to_dict()
    per_class_recall = {label: float(rf_pred[(labels == label).to_numpy()].mean())
                        for label in sorted(test_labels) if label != "BENIGN"}

    report = {
        "version": "v0-notebook-reproduction",
        "data": {"order": list(data.DAYS_HF_ORDER), "duplicates_removed": p["duplicates"],
                 "constant_dropped": p["constant"], "correlated_dropped": p["correlated"],
                 "train_rows": len(p["X_train"]), "test_rows": len(p["X_test"]),
                 "test_attacks": int(yte.sum()), "test_benign": int((yte == 0).sum()),
                 "test_days": p["day"].iloc[p["split"]:].value_counts().to_dict(),
                 "test_labels": test_labels},
        "features": p["features"],
        "models": results,
        "rf_recall_by_attack_label": per_class_recall,
        "rf_top_features": importance[:15],
        "seconds": timings,
        "notebook_reference": NOTEBOOK,
    }
    (out_dir / "report.json").write_text(json.dumps(report, indent=2, default=str))
    joblib.dump({"scaler": scaler, "model": rf, "features": p["features"]}, out_dir / "random_forest.joblib")
    return report
