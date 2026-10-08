"""CICIDS-2017 loading. The pipeline reads the raw day CSVs directly; it never depends on the notebook."""

from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
RAW = ROOT / "data" / "raw"
CACHE = ROOT / "data" / "interim"

DAYS_CHRONOLOGICAL = ("monday", "tuesday", "wednesday", "thursday", "friday")
# Hugging Face `load_dataset("bvk/CICIDS-2017")` concatenates the files alphabetically. The notebook's
# "time-based" split therefore runs over fri, mon, thu, tue, wed, not over time.
DAYS_HF_ORDER = tuple(sorted(DAYS_CHRONOLOGICAL))


def load_raw(order: tuple[str, ...] = DAYS_HF_ORDER) -> pd.DataFrame:
    """All five days concatenated in `order`, with a `day` column. Cached as parquet after the first read."""
    CACHE.mkdir(parents=True, exist_ok=True)
    parts = []
    for day in order:
        cached = CACHE / f"{day}.parquet"
        if cached.exists():
            part = pd.read_parquet(cached)
        else:
            part = pd.read_csv(RAW / f"{day}.csv", low_memory=False)
            part.to_parquet(cached, index=False)
        parts.append(part.assign(day=day))
    return pd.concat(parts, ignore_index=True)
