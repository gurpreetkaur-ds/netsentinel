"""Hierarchical detector: Normal vs Attack -> attack family -> attack type.

Stage 1 (binary) is the decision maker. Stages 2-3 only describe flows that stage 1 already called
attacks, and each answers only when it is confident enough. Otherwise it reports None ("unknown").
"""

from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier

from . import schema


def make_classifier(class_weight=None, seed: int = 42) -> HistGradientBoostingClassifier:
    return HistGradientBoostingClassifier(max_iter=300, learning_rate=0.1, max_leaf_nodes=63,
                                          early_stopping=True, validation_fraction=0.1, n_iter_no_change=15,
                                          class_weight=class_weight, random_state=seed)


@dataclass
class Thresholds:
    attack: float              # p(attack) at or above this -> Attack
    family_confidence: float = 0.6
    type_confidence: float = 0.8


@dataclass
class HierarchicalDetector:
    binary: HistGradientBoostingClassifier
    family_model: HistGradientBoostingClassifier | None
    type_models: dict[str, HistGradientBoostingClassifier]
    single_type: dict[str, str]          # families with exactly one known type
    thresholds: Thresholds
    features: tuple[str, ...] = schema.FEATURES
    schema_version: str = schema.SCHEMA_VERSION
    metadata: dict = field(default_factory=dict)

    def p_attack(self, X: np.ndarray) -> np.ndarray:
        return self.binary.predict_proba(X)[:, 1]

    def predict(self, X: np.ndarray) -> pd.DataFrame:
        p = self.p_attack(X)
        out = pd.DataFrame({"p_attack": p, "is_attack": p >= self.thresholds.attack, "threshold": self.thresholds.attack,
                            "family": None, "family_confidence": np.nan,
                            "attack_type": None, "type_confidence": np.nan})
        idx = np.flatnonzero(out["is_attack"].to_numpy())
        if len(idx) == 0 or self.family_model is None:
            return out
        fp = self.family_model.predict_proba(X[idx])
        fam = self.family_model.classes_[fp.argmax(1)]
        fconf = fp.max(1)
        out.loc[idx, "family_confidence"] = fconf
        confident = fconf >= self.thresholds.family_confidence
        out.loc[idx[confident], "family"] = fam[confident]

        for family in np.unique(fam[confident]):
            rows = idx[confident & (fam == family)]
            if family in self.single_type:
                out.loc[rows, "attack_type"] = self.single_type[family]
                out.loc[rows, "type_confidence"] = out.loc[rows, "family_confidence"]
            elif family in self.type_models:
                m = self.type_models[family]
                tp = m.predict_proba(X[rows])
                tconf = tp.max(1)
                types = m.classes_[tp.argmax(1)]
                out.loc[rows, "type_confidence"] = tconf
                ok = tconf >= self.thresholds.type_confidence
                out.loc[rows[ok], "attack_type"] = types[ok]
        return out


@dataclass
class WindowedDetector:
    """Model v2: per-flow + per-source window features. Flows whose window features are unknown (no
    source IP or timestamp) are scored by `fallback`, a per-flow detector trained on the same data,
    because `primary` never saw a flow without window context."""
    primary: HierarchicalDetector       # features = per-flow + window
    fallback: HierarchicalDetector      # features = per-flow only
    features: tuple[str, ...]
    schema_version: str
    metadata: dict = field(default_factory=dict)

    @property
    def thresholds(self) -> Thresholds:
        return self.primary.thresholds

    def p_attack(self, X: np.ndarray) -> np.ndarray:
        return self.predict(X)["p_attack"].to_numpy()

    def predict(self, X: np.ndarray) -> pd.DataFrame:
        n_flow = len(self.fallback.features)
        has_window = ~np.isnan(X[:, n_flow:]).any(axis=1)
        parts = []
        if has_window.any():
            parts.append(self.primary.predict(X[has_window]).set_index(np.flatnonzero(has_window)))
        if (~has_window).any():
            parts.append(self.fallback.predict(X[~has_window, :n_flow]).set_index(np.flatnonzero(~has_window)))
        out = pd.concat(parts).sort_index()
        out["used_window"] = has_window
        return out.reset_index(drop=True)
