"""v1: fixed schema, hierarchical detector, threshold tuning, and two evaluations.

E1 (in-distribution): stratified 60/20/20 train/validation/test split by fine label. The
    validation part picks the thresholds; the test part is touched once, for reporting.
E2 (novel attacks): leave-one-family-out. For each family, the binary detector is retrained
    without it and tested on whether it still flags that family, alongside an Isolation Forest
    trained only on benign traffic.
"""

import hashlib
import json
import logging
import platform
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, f1_score, precision_recall_curve, roc_curve
from sklearn.model_selection import train_test_split

from . import data, schema, taxonomy
from .detector import HierarchicalDetector, Thresholds, make_classifier
from .metrics import binary_report

log = logging.getLogger(__name__)

MIN_FAMILY_SUPPORT = 50   # training rows needed before a family is learned
MIN_TYPE_SUPPORT = 100    # training rows needed before an attack type is learned
TARGET_FPR = 0.001        # operational threshold: at most 1 false alert per 1,000 benign flows
SEED = 42
CONTEXT_COLUMNS = ("Src IP dec", "Dst IP dec", "Src Port", "Dst Port", "Protocol")


def prepare() -> dict:
    df = data.load_raw(data.DAYS_CHRONOLOGICAL)
    info = pd.DataFrame([taxonomy.lookup(l).__dict__ for l in df["Label"].unique()],
                        index=df["Label"].unique())
    X = df[list(schema.FEATURES)].to_numpy(dtype=np.float32, copy=True)
    X[~np.isfinite(X)] = np.nan
    labels = df["Label"].to_numpy()
    rows_raw = len(X)

    # Exact duplicates (same features and label) would straddle the split and inflate test scores.
    key = pd.DataFrame(X).assign(_l=labels)
    keep = ~key.duplicated().to_numpy()
    conflicting = int(key[keep].drop(columns="_l").duplicated(keep=False).sum())
    del key
    X, labels = X[keep], labels[keep]
    # Not model inputs: the 5-tuple, kept so the replay tool can send realistic telemetry.
    context = df[list(CONTEXT_COLUMNS)].to_numpy(dtype=np.int64)[keep]
    meta = info.loc[labels].reset_index(drop=True)
    fingerprint = hashlib.sha256()
    for day in data.DAYS_CHRONOLOGICAL:
        fingerprint.update((data.RAW / f"{day}.csv").stat().st_size.to_bytes(8, "big"))
    return {"X": X, "label": labels, "is_attack": meta["is_attack"].to_numpy(bool),
            "family": meta["family"].to_numpy(object), "attack_type": meta["attack_type"].to_numpy(object),
            "attempted": meta["attempted"].to_numpy(bool), "context": context,
            "stats": {"rows_raw": rows_raw, "duplicates_removed": rows_raw - len(X),
                      "rows_with_conflicting_label": conflicting, "rows": len(X),
                      "data_fingerprint": fingerprint.hexdigest()[:16]}}


def threshold_for_fpr(y, p, target_fpr: float) -> float:
    fpr, tpr, thr = roc_curve(y, p)
    ok = np.flatnonzero(fpr <= target_fpr)
    return float(thr[ok[-1]]) if len(ok) else 1.0


def threshold_max_f1(y, p) -> float:
    prec, rec, thr = precision_recall_curve(y, p)
    f1 = 2 * prec[:-1] * rec[:-1] / np.maximum(prec[:-1] + rec[:-1], 1e-12)
    return float(thr[f1.argmax()])


def fit_detector(D: dict, tr: np.ndarray, va: np.ndarray) -> tuple[HierarchicalDetector, dict]:
    X, y = D["X"], D["is_attack"]
    t = time.time()
    binary = make_classifier().fit(X[tr], y[tr])
    p_va = binary.predict_proba(X[va])[:, 1]
    thr = {"fpr_0.1pct": threshold_for_fpr(y[va], p_va, TARGET_FPR), "max_f1": threshold_max_f1(y[va], p_va)}
    log.info("binary stage trained (%.0fs) thresholds=%s", time.time() - t, thr)

    attack_tr = tr[y[tr]]
    fam_counts = pd.Series(D["family"][attack_tr]).value_counts()
    trained_families = sorted(fam_counts[fam_counts >= MIN_FAMILY_SUPPORT].index)
    fam_rows = attack_tr[np.isin(D["family"][attack_tr], trained_families)]
    t = time.time()
    family_model = make_classifier(class_weight="balanced").fit(X[fam_rows], D["family"][fam_rows])
    log.info("family stage trained on %s (%.0fs)", trained_families, time.time() - t)

    type_models, single_type, type_support = {}, {}, {}
    for family in trained_families:
        rows = fam_rows[D["family"][fam_rows] == family]
        counts = pd.Series(D["attack_type"][rows]).value_counts()
        type_support[family] = counts.to_dict()
        learnable = sorted(counts[counts >= MIN_TYPE_SUPPORT].index)
        if len(counts) == 1:
            single_type[family] = counts.index[0]
        elif len(learnable) >= 2:
            r = rows[np.isin(D["attack_type"][rows], learnable)]
            type_models[family] = make_classifier(class_weight="balanced").fit(X[r], D["attack_type"][r])
    log.info("type stage: models for %s, single-type %s", sorted(type_models), single_type)

    det = HierarchicalDetector(binary, family_model, type_models, single_type, Thresholds(attack=thr["fpr_0.1pct"]))
    return det, {"thresholds": thr, "trained_families": trained_families, "type_support_train": type_support,
                 "type_models": {f: list(m.classes_) for f, m in type_models.items()}, "single_type": single_type}


def evaluate_e1(D: dict, det: HierarchicalDetector, te: np.ndarray, thresholds: dict) -> dict:
    X, y = D["X"][te], D["is_attack"][te]
    p = det.p_attack(X)
    res = {name: binary_report(y, (p >= t).astype(int), scores=p) | {"threshold": t}
           for name, t in thresholds.items()}

    pred = det.predict(X)
    labels = pd.Series(D["label"][te])
    flagged = pred["is_attack"].to_numpy()
    res["recall_by_label"] = {l: {"support": int((labels == l).sum()), "recall": float(flagged[(labels == l).to_numpy()].mean())}
                              for l in sorted(labels.unique()) if l != "BENIGN"}
    res["recall_attempted_vs_completed"] = {
        "attempted": float(flagged[D["attempted"][te]].mean()),
        "completed": float(flagged[y & ~D["attempted"][te]].mean())}

    # Family stage, measured on attacks the binary stage caught.
    caught = y & flagged
    true_fam = D["family"][te][caught]
    fam_pred = pred["family"].to_numpy()[caught]
    answered = pd.notna(fam_pred)
    fams = sorted(set(true_fam))
    res["family"] = {
        "coverage": float(answered.mean()),
        "accuracy_when_answered": float((fam_pred[answered] == true_fam[answered]).mean()),
        "macro_f1_when_answered": float(f1_score(true_fam[answered], fam_pred[answered].astype(str), average="macro",
                                                 labels=fams, zero_division=0)),
        "labels": fams,
        "confusion_when_answered": confusion_matrix(true_fam[answered], fam_pred[answered].astype(str), labels=fams).tolist(),
        "per_family": {f: {"support": int((true_fam == f).sum()),
                           "coverage": float(answered[true_fam == f].mean()),
                           "accuracy_when_answered": float((fam_pred[answered & (true_fam == f)] == f).mean())
                           if (answered & (true_fam == f)).any() else None}
                       for f in fams},
    }
    true_type = D["attack_type"][te][caught]
    type_pred = pred["attack_type"].to_numpy()[caught]
    res["attack_type"] = {}
    for f in fams:
        m = true_fam == f
        a = m & pd.notna(type_pred)
        res["attack_type"][f] = {"support": int(m.sum()), "coverage": float(a.sum() / m.sum()),
                                 "accuracy_when_answered": float((type_pred[a] == true_type[a]).mean()) if a.any() else None}
    return res


def evaluate_e2(D: dict, tr: np.ndarray, va: np.ndarray, te: np.ndarray) -> dict:
    X, y, fam = D["X"], D["is_attack"], D["family"]
    benign_tr = tr[~y[tr]]
    iso = IsolationForest(n_estimators=200, random_state=SEED, n_jobs=-1).fit(np.nan_to_num(X[benign_tr]))
    iso_va = -iso.score_samples(np.nan_to_num(X[va]))
    iso_thr = threshold_for_fpr(y[va], iso_va, TARGET_FPR)
    iso_te = -iso.score_samples(np.nan_to_num(X[te]))
    out = {"isolation_forest_threshold": iso_thr, "families": {}}
    for family in sorted(pd.Series(fam[te][y[te]]).value_counts().loc[lambda s: s >= 10].index):
        t = time.time()
        held = fam == family
        tr_f, va_f = tr[~held[tr]], va[~held[va]]
        clf = make_classifier().fit(X[tr_f], y[tr_f])
        thr = threshold_for_fpr(y[va_f], clf.predict_proba(X[va_f])[:, 1], TARGET_FPR)
        p_te = clf.predict_proba(X[te])[:, 1]
        target, benign = held[te], ~y[te]
        out["families"][family] = {
            "test_support": int(target.sum()),
            "supervised_recall": float((p_te[target] >= thr).mean()),
            "supervised_fpr": float((p_te[benign] >= thr).mean()),
            "isolation_forest_recall": float((iso_te[target] >= iso_thr).mean()),
            "either_recall": float(((p_te[target] >= thr) | (iso_te[target] >= iso_thr)).mean()),
        }
        log.info("E2 held out %s: %s (%.0fs)", family, out["families"][family], time.time() - t)
    out["isolation_forest_fpr"] = float((iso_te[~y[te]] >= iso_thr).mean())
    return out


def run(out_dir: Path, *, skip_e2: bool = False) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    D = prepare()
    log.info("prepared %s (%.0fs)", D["stats"], time.time() - t0)
    idx = np.arange(len(D["X"]))
    rest, te = train_test_split(idx, test_size=0.2, stratify=D["label"], random_state=SEED)
    tr, va = train_test_split(rest, test_size=0.25, stratify=D["label"][rest], random_state=SEED)

    det, fit_info = fit_detector(D, tr, va)
    e1 = evaluate_e1(D, det, te, fit_info["thresholds"])
    log.info("E1 done: %s", {k: e1[k]["attack"] for k in fit_info["thresholds"]})
    e2 = None if skip_e2 else evaluate_e2(D, tr, va, te)

    det.metadata = {"version": "v1", "trained_at": datetime.now(timezone.utc).isoformat(),
                    "sklearn": sklearn.__version__, "python": platform.python_version(),
                    "data": D["stats"], "split": {"train": len(tr), "validation": len(va), "test": len(te)},
                    "target_fpr": TARGET_FPR, **fit_info}
    report = {**det.metadata, "features": list(schema.FEATURES), "excluded_features": schema.EXCLUDED,
              "e1": e1, "e2": e2, "seconds": round(time.time() - t0)}
    (out_dir / "report.json").write_text(json.dumps(report, indent=2, default=str))
    joblib.dump(det, out_dir / "detector.joblib", compress=3)
    return report
