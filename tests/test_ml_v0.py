import json

import numpy as np
import pandas as pd
import pytest

from netsentinel.ml import baseline_v0, data
from netsentinel.ml.metrics import binary_report

REPORT = data.ROOT / "artifacts" / "v0" / "report.json"


def test_prepare_mirrors_notebook_steps():
    rng = np.random.default_rng(0)
    n = 100
    a = rng.normal(size=n)
    df = pd.DataFrame({
        "a": a, "a_copy": a * 2 + 1,          # correlated -> dropped
        "const": 1.0,                          # constant -> dropped
        "b": rng.normal(size=n), "Timestamp": [f"00:{i:02d}.0" for i in range(n)],
        "Label": ["BENIGN"] * 70 + ["DoS Hulk"] * 30, "day": ["x"] * n,
    })
    df.loc[3, "b"] = np.inf                   # -> row dropped
    df.loc[5] = df.loc[4]                     # duplicate -> dropped
    p = baseline_v0.prepare(df)
    assert p["constant"] == ["const"]
    assert p["correlated"] == ["a_copy"]
    assert p["duplicates"] == 1
    assert p["features"] == ["a", "b"]         # non-numeric Timestamp is excluded
    assert len(p["X_train"]) + len(p["X_test"]) == 98
    assert len(p["X_train"]) == int(98 * 0.7)
    assert set(p["y_train"].unique()) <= {0, 1}


def test_hard_label_auc_is_balanced_accuracy():
    y = np.array([0, 0, 0, 1, 1])
    pred = np.array([0, 1, 0, 1, 0])
    r = binary_report(y, pred)
    assert r["auc_on_hard_predictions"] == pytest.approx((2 / 3 + 1 / 2) / 2)
    assert "roc_auc" not in r


@pytest.mark.skipif(not REPORT.exists(), reason="run `python -m netsentinel.ml.train v0` first")
def test_v0_reproduces_notebook():
    r = json.loads(REPORT.read_text())
    ref = r["notebook_reference"]
    assert r["data"]["duplicates_removed"] == ref["duplicates"]
    assert len(r["data"]["correlated_dropped"]) == ref["correlated_dropped"]
    assert r["data"]["train_rows"] == ref["train_rows"] and r["data"]["test_rows"] == ref["test_rows"]
    assert len(r["features"]) == 60
    # Isolation Forest reproduces cell-for-cell.
    assert r["models"]["isolation_forest"]["confusion_matrix"] == ref["confusion_matrix"]["isolation_forest"]
    # Random Forest and Logistic Regression do NOT reproduce across scikit-learn versions on this split:
    # the test part is ~all Tuesday/Wednesday DoS traffic absent from training, so whether a model
    # flags it is incidental (RF attack recall: notebook 0.865, sklearn 1.6.1 0.580, 1.9.1 0.479).
    # See docs/model-baseline.md. Only the benign side is stable, and that is what we assert.
    for model in ("random_forest", "logistic_regression"):
        (tn, fp), _ = r["models"][model]["confusion_matrix"]
        (ref_tn, ref_fp), _ = ref["confusion_matrix"][model]
        assert abs(fp - ref_fp) <= 100, (model, fp, ref_fp)
        assert tn + fp == ref_tn + ref_fp == r["data"]["test_benign"]
