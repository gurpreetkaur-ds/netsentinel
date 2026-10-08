"""v2 experiment: do per-source time-window features help, especially on unseen attacks?

Data: Engelen et al.'s corrected CICIDS-2017 (data/raw/distrinet), which keeps full timestamps.
Two detectors are trained on the same rows with the same splits and the same E1/E2 protocol as v1:
  "v1-features"  83 per-flow features
  "v2-features"  83 per-flow + 6 per-source 60 s window features (netsentinel/ml/windows.py)
"""

import json
import logging
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from . import data, schema, taxonomy, train_v1, windows
from .detector import WindowedDetector

log = logging.getLogger(__name__)
DISTRINET = data.ROOT / "data" / "interim" / "distrinet"
SCHEMA_V2 = "cicflowmeter-v2-window60"
FEATURES_V2 = schema.FEATURES + windows.WINDOW_FEATURES


def prepare() -> dict:
    cols = list(dict.fromkeys(list(schema.FEATURES) + ["Src IP", "Dst IP", "Timestamp", "Label"]))
    df = pd.concat([pd.read_parquet(DISTRINET / f"{d}.parquet", columns=cols) for d in data.DAYS_CHRONOLOGICAL],
                   ignore_index=True)
    t = time.time()
    W = windows.from_frame(df)   # computed on every flow before de-duplication, as production would see them
    log.info("window features for %d flows in %.0fs", len(df), time.time() - t)
    X = np.hstack([df[list(schema.FEATURES)].to_numpy(dtype=np.float32), W])
    X[~np.isfinite(X)] = np.nan
    labels = df["Label"].to_numpy()
    rows_raw = len(X)
    keep = ~pd.DataFrame(X).assign(_l=labels).duplicated().to_numpy()
    X, labels = X[keep], labels[keep]
    info = pd.DataFrame([taxonomy.lookup(l).__dict__ for l in np.unique(labels)], index=np.unique(labels))
    meta = info.loc[labels].reset_index(drop=True)
    return {"X": X, "label": labels, "is_attack": meta["is_attack"].to_numpy(bool),
            "family": meta["family"].to_numpy(object), "attack_type": meta["attack_type"].to_numpy(object),
            "attempted": meta["attempted"].to_numpy(bool),
            "stats": {"rows_raw": rows_raw, "rows": len(X), "duplicates_removed": rows_raw - len(X),
                      "source": "Engelen et al. corrected CICIDS-2017 (distrinet CNS2022)"}}


def _variant(D: dict, cols: slice) -> dict:
    return {**D, "X": D["X"][:, cols]}


def run(out_dir: Path, *, skip_e2: bool = False) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    D = prepare()
    log.info("prepared %s (%.0fs)", D["stats"], time.time() - t0)
    idx = np.arange(len(D["X"]))
    rest, te = train_test_split(idx, test_size=0.2, stratify=D["label"], random_state=train_v1.SEED)
    tr, va = train_test_split(rest, test_size=0.25, stratify=D["label"][rest], random_state=train_v1.SEED)

    results, detectors = {}, {}
    for name, cols, feats, schema_version in (
            ("v1-features", slice(0, len(schema.FEATURES)), schema.FEATURES, schema.SCHEMA_VERSION),
            ("v2-features", slice(0, len(FEATURES_V2)), FEATURES_V2, SCHEMA_V2)):
        Dv = _variant(D, cols)
        log.info("=== %s (%d features)", name, len(feats))
        det, fit_info = train_v1.fit_detector(Dv, tr, va)
        det.features, det.schema_version = tuple(feats), schema_version
        e1 = train_v1.evaluate_e1(Dv, det, te, fit_info["thresholds"])
        e2 = None if skip_e2 else train_v1.evaluate_e2(Dv, tr, va, te)
        results[name] = {"features": len(feats), "fit": fit_info, "e1": e1, "e2": e2}
        detectors[name] = det
        log.info("%s E1 op: %s; E2: %s", name, e1["fpr_0.1pct"]["attack"],
                 {f: round(v["supervised_recall"], 3) for f, v in (e2 or {}).get("families", {}).items()})

    det = WindowedDetector(primary=detectors["v2-features"], fallback=detectors["v1-features"],
                           features=FEATURES_V2, schema_version=SCHEMA_V2)
    det.metadata = {"version": "v2", "data": D["stats"], "split": {"train": len(tr), "validation": len(va), "test": len(te)},
                    "target_fpr": train_v1.TARGET_FPR, "window_seconds": windows.WINDOW_SECONDS,
                    "thresholds": results["v2-features"]["fit"]["thresholds"],
                    "fallback_thresholds": results["v1-features"]["fit"]["thresholds"]}
    report = {"data": D["stats"], "window_features": list(windows.WINDOW_FEATURES), "results": results,
              "seconds": round(time.time() - t0)}
    # --skip-e2 repackages the (deterministic) detectors without overwriting the full evaluation report
    (out_dir / ("report-package.json" if skip_e2 else "report.json")).write_text(json.dumps(report, indent=2, default=str))
    joblib.dump(det, out_dir / "detector.joblib", compress=3)
    return report
