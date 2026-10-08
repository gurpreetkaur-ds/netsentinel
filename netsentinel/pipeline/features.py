"""Pipeline steps 2-4: VALIDATE, NORMALIZE, EXTRACT FEATURES for CICFlowMeter-style flow records.

Input is the untrusted `features` object a client sent. Output is the model's float32 vector in
schema order (NaN = missing), or a rejection reason. Fields outside the schema, including any
`Label`, are ignored: client-supplied ground truth can never influence a detection.
"""

import math
import re
from dataclasses import dataclass

import numpy as np

from ..ml import schema

MIN_PRESENT_FRACTION = 0.8

# Original CICFlowMeter / CICIDS-2017 "MachineLearningCSV" names -> schema names.
ALIASES = {
    "Destination Port": "Dst Port", "Total Fwd Packets": "Total Fwd Packet",
    "Total Backward Packets": "Total Bwd packets", "Total Length of Fwd Packets": "Total Length of Fwd Packet",
    "Total Length of Bwd Packets": "Total Length of Bwd Packet", "Min Packet Length": "Packet Length Min",
    "Max Packet Length": "Packet Length Max", "Avg Fwd Segment Size": "Fwd Segment Size Avg",
    "Avg Bwd Segment Size": "Bwd Segment Size Avg", "Fwd Avg Bytes/Bulk": "Fwd Bytes/Bulk Avg",
    "Fwd Avg Packets/Bulk": "Fwd Packet/Bulk Avg", "Fwd Avg Bulk Rate": "Fwd Bulk Rate Avg",
    "Bwd Avg Bytes/Bulk": "Bwd Bytes/Bulk Avg", "Bwd Avg Packets/Bulk": "Bwd Packet/Bulk Avg",
    "Bwd Avg Bulk Rate": "Bwd Bulk Rate Avg", "Init_Win_bytes_forward": "FWD Init Win Bytes",
    "Init_Win_bytes_backward": "Bwd Init Win Bytes", "act_data_pkt_fwd": "Fwd Act Data Pkts",
    "min_seg_size_forward": "Fwd Seg Size Min",
}
RANGES = {"Dst Port": (0, 65535), "Protocol": (0, 255)}


def _canon(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


_LOOKUP: dict[str, int] = {}
for _i, _f in enumerate(schema.FEATURES):
    _LOOKUP[_canon(_f)] = _i
for _alias, _target in ALIASES.items():
    _LOOKUP.setdefault(_canon(_alias), schema.FEATURES.index(_target))


@dataclass(frozen=True)
class Extracted:
    vector: np.ndarray | None
    missing: int
    ignored_fields: int
    reject_reason: str | None = None


def extract(features: dict) -> Extracted:
    vec = np.full(len(schema.FEATURES), np.nan, dtype=np.float32)
    seen: set[int] = set()
    ignored = 0
    for key, value in features.items():
        i = _LOOKUP.get(_canon(key))
        if i is None:
            ignored += 1
            continue
        name = schema.FEATURES[i]
        if i in seen:
            return Extracted(None, 0, ignored, f"ambiguous_feature:{name}")
        seen.add(i)
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return Extracted(None, 0, ignored, f"non_numeric_feature:{name}")
        if not math.isfinite(value):
            continue  # treated as missing, like CICFlowMeter's Infinity
        lo, hi = RANGES.get(name, (-math.inf, math.inf))
        if not lo <= value <= hi:
            return Extracted(None, 0, ignored, f"out_of_range:{name}")
        vec[i] = value
    missing = int(np.isnan(vec).sum())
    if len(schema.FEATURES) - missing < MIN_PRESENT_FRACTION * len(schema.FEATURES):
        return Extracted(None, missing, ignored, f"too_many_missing_features:{missing}/{len(schema.FEATURES)}")
    return Extracted(vec, missing, ignored)


_DURATION = _canon("Flow Duration")


def flow_duration_us(features: dict) -> float | None:
    """The flow's duration in microseconds under any accepted spelling, if numeric and finite."""
    for key, value in features.items():
        if _canon(key) == _DURATION and isinstance(value, (int, float)) and not isinstance(value, bool) \
                and math.isfinite(value) and value >= 0:
            return float(value)
    return None
