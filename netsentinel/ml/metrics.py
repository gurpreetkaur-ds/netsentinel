"""Binary detection metrics, computed the same way for every model version."""

import numpy as np
from sklearn.metrics import (average_precision_score, confusion_matrix, precision_recall_fscore_support,
                             roc_auc_score)


def binary_report(y_true, y_pred, scores=None) -> dict:
    """`scores` are continuous attack scores. ROC-AUC/PR-AUC are only reported when they exist:
    AUC computed on hard 0/1 predictions (as the notebook did for two models) is balanced accuracy,
    not a ranking metric."""
    y_true, y_pred = np.asarray(y_true), np.asarray(y_pred)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    p, r, f, s = precision_recall_fscore_support(y_true, y_pred, labels=[0, 1], zero_division=0)
    out = {
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        "attack": {"precision": float(p[1]), "recall": float(r[1]), "f1": float(f[1]), "support": int(s[1])},
        "normal": {"precision": float(p[0]), "recall": float(r[0]), "f1": float(f[0]), "support": int(s[0])},
        "accuracy": float((tp + tn) / len(y_true)),
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
        "auc_on_hard_predictions": float(roc_auc_score(y_true, y_pred)),
    }
    if scores is not None:
        out["roc_auc"] = float(roc_auc_score(y_true, scores))
        out["pr_auc"] = float(average_precision_score(y_true, scores))
    return out
