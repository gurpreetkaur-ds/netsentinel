import json

import joblib
import numpy as np
import pandas as pd
import pytest

from netsentinel.ml import data, schema, taxonomy
from netsentinel.ml.detector import HierarchicalDetector, Thresholds, make_classifier
from netsentinel.ml.train_v1 import threshold_for_fpr

DATASET_LABELS = [
    "BENIGN", "Botnet", "Botnet - Attempted", "DDoS", "DoS GoldenEye", "DoS GoldenEye - Attempted", "DoS Hulk",
    "DoS Hulk - Attempted", "DoS Slowhttptest", "DoS Slowhttptest - Attempted", "DoS Slowloris",
    "DoS Slowloris - Attempted", "FTP-Patator", "FTP-Patator - Attempted", "Heartbleed", "Infiltration",
    "Infiltration - Attempted", "Infiltration - Portscan", "Portscan", "SSH-Patator", "SSH-Patator - Attempted",
    "Web Attack - Brute Force", "Web Attack - Brute Force - Attempted", "Web Attack - SQL Injection",
    "Web Attack - SQL Injection - Attempted", "Web Attack - XSS", "Web Attack - XSS - Attempted",
]


def test_every_dataset_label_is_mapped_to_a_known_family():
    for label in DATASET_LABELS:
        info = taxonomy.lookup(label)
        assert info.is_attack == (label != "BENIGN")
        assert info.family is None or info.family in taxonomy.FAMILIES
        assert info.attempted == label.endswith("- Attempted")
    with pytest.raises(ValueError):
        taxonomy.lookup("Something New")


def test_requested_families_present():
    assert {"DoS", "DDoS", "PortScan", "BruteForce", "WebAttack", "Botnet", "Infiltration"} <= set(taxonomy.FAMILIES)


def test_schema_excludes_leaky_and_identity_columns():
    assert len(schema.FEATURES) == len(set(schema.FEATURES)) == 83
    for col in ("Attempted Category", "Src IP dec", "Dst IP dec", "Src Port", "Timestamp", "Label"):
        assert col not in schema.FEATURES


def test_threshold_for_fpr_respects_target():
    rng = np.random.default_rng(0)
    y = np.r_[np.zeros(10_000, bool), np.ones(1_000, bool)]
    p = np.r_[rng.uniform(0, 0.8, 10_000), rng.uniform(0.5, 1, 1_000)]
    t = threshold_for_fpr(y, p, 0.001)
    assert (p[~y] >= t).mean() <= 0.001


def _toy_detector():
    rng = np.random.default_rng(1)
    n = 600
    X = rng.normal(size=(n, 2)).astype(np.float32)
    fam = np.array(["A"] * 300 + ["B"] * 300, dtype=object)
    X[fam == "B", 0] += 6
    typ = np.where(X[:, 1] > 0, "t1", "t2").astype(object)
    y = np.r_[np.zeros(n, bool), np.ones(n, bool)]
    Xb = np.r_[rng.normal(size=(n, 2)).astype(np.float32) - 10, X]
    binary = make_classifier().fit(Xb, y)
    family = make_classifier().fit(X, fam)
    types = {"A": make_classifier().fit(X[fam == "A"], typ[fam == "A"])}
    return HierarchicalDetector(binary, family, types, {"B": "only-b"}, Thresholds(attack=0.5), features=("x", "y"))


def test_hierarchy_only_describes_flagged_flows_and_respects_confidence():
    det = _toy_detector()
    X = np.array([[-10, -10], [0, 2], [6, 0]], dtype=np.float32)
    out = det.predict(X)
    assert out["is_attack"].tolist() == [False, True, True]
    assert pd.isna(out.loc[0, "family"]) and pd.isna(out.loc[0, "attack_type"])
    assert out.loc[1, "family"] == "A" and out.loc[1, "attack_type"] == "t1"
    assert out.loc[2, "family"] == "B" and out.loc[2, "attack_type"] == "only-b"

    det.thresholds = Thresholds(attack=0.5, family_confidence=1.01)  # never confident enough
    out = det.predict(X)
    assert out["family"].isna().all() and out["attack_type"].isna().all()
    assert out["is_attack"].tolist() == [False, True, True]       # stage 1 is unaffected


V1 = data.ROOT / "artifacts" / "v1"


@pytest.mark.skipif(not (V1 / "report.json").exists(), reason="run `python -m netsentinel.ml.train v1` first")
def test_v1_quality_gates():
    r = json.loads((V1 / "report.json").read_text())
    op = r["e1"]["fpr_0.1pct"]
    assert op["false_positive_rate"] <= 0.0015 and op["attack"]["recall"] >= 0.99
    assert r["e1"]["family"]["per_family"]["DoS"]["accuracy_when_answered"] >= 0.99
    assert r["features"] == list(schema.FEATURES)
    # novel-attack recall regressions should be noticed, not silently accepted
    e2 = {f: v["supervised_recall"] for f, v in r["e2"]["families"].items()}
    assert e2["DDoS"] >= 0.95 and e2["DoS"] >= 0.7 and e2["PortScan"] >= 0.25


@pytest.mark.skipif(not (V1 / "detector.joblib").exists(), reason="run `python -m netsentinel.ml.train v1` first")
def test_saved_detector_scores_missing_values():
    det = joblib.load(V1 / "detector.joblib")
    assert det.schema_version == schema.SCHEMA_VERSION and det.metadata["version"] == "v1"
    X = np.full((2, len(schema.FEATURES)), np.nan, dtype=np.float32)
    out = det.predict(X)
    assert len(out) == 2 and out["p_attack"].between(0, 1).all()


def test_windowed_detector_uses_fallback_without_window_context():
    from netsentinel.ml.detector import WindowedDetector
    rng = np.random.default_rng(3)
    Xf = rng.normal(size=(400, 2)).astype(np.float32)
    y = Xf[:, 0] > 0
    Xw = np.hstack([Xf, (y * 10 + rng.normal(size=400)).reshape(-1, 1).astype(np.float32)])
    prim = HierarchicalDetector(make_classifier().fit(Xw, y), None, {}, {}, Thresholds(attack=0.5), features=("a", "b", "w"))
    fb = HierarchicalDetector(make_classifier().fit(Xf, y), None, {}, {}, Thresholds(attack=0.6), features=("a", "b"))
    det = WindowedDetector(prim, fb, features=("a", "b", "w"), schema_version="test")
    X = np.array([[2, 0, 10], [2, 0, np.nan], [-2, 0, np.nan]], dtype=np.float32)
    out = det.predict(X)
    assert out["used_window"].tolist() == [True, False, False]
    assert out["threshold"].tolist() == [0.5, 0.6, 0.6]
    assert out["is_attack"].tolist() == [True, True, False]


V2 = data.ROOT / "artifacts" / "v2"


@pytest.mark.skipif(not (V2 / "report-experiment.json").exists(), reason="run `python -m netsentinel.ml.train v2` first")
def test_v2_quality_gates_and_improvement_over_per_flow():
    r = json.loads((V2 / "report-experiment.json").read_text())["results"]
    base, win = r["v1-features"], r["v2-features"]
    assert win["e1"]["fpr_0.1pct"]["false_positive_rate"] <= 0.0015
    assert win["e1"]["fpr_0.1pct"]["attack"]["recall"] >= 0.999
    e2b = {f: v["supervised_recall"] for f, v in base["e2"]["families"].items()}
    e2w = {f: v["supervised_recall"] for f, v in win["e2"]["families"].items()}
    for fam in ("BruteForce", "PortScan", "Botnet", "DoS"):      # the point of v2
        assert e2w[fam] > e2b[fam], fam
    assert e2w["BruteForce"] >= 0.95 and e2w["PortScan"] >= 0.85


@pytest.mark.skipif(not (V2 / "detector.joblib").exists(), reason="package v2 first")
def test_v2_artifact_is_registered_schema_with_fallback():
    from netsentinel import registry
    det = joblib.load(V2 / "detector.joblib")
    assert registry.KNOWN_SCHEMAS[det.schema_version] == det.features
    X = np.full((1, len(det.features)), np.nan, dtype=np.float32)
    assert det.predict(X)["used_window"].tolist() == [False]
