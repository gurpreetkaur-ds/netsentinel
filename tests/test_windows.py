import numpy as np
import pandas as pd

from netsentinel.ml import windows


def _df(rows):
    return pd.DataFrame(rows, columns=["Src IP", "Dst IP", "Dst Port", "Timestamp", "Flow Duration",
                                       "Total Bwd packets", "RST Flag Count"])


def test_scan_fanout_and_window_expiry():
    t0 = pd.Timestamp("2017-07-07 12:00:00")
    rows = [("1.1.1.1", "10.0.0.5", 20 + i, t0 + pd.Timedelta(seconds=i), 1000, 0, 1) for i in range(5)]
    rows.append(("1.1.1.1", "10.0.0.5", 80, t0 + pd.Timedelta(seconds=200), 1000, 3, 0))   # after the window
    rows.append(("2.2.2.2", "10.0.0.5", 22, t0 + pd.Timedelta(seconds=2), 1000, 3, 0))     # other source
    f = pd.DataFrame(windows.from_frame(_df(rows)), columns=windows.WINDOW_FEATURES)
    assert f.loc[4].tolist() == [5, 5, 1, 1, 1.0, 1.0]       # 5th probe sees all 5 probes
    assert f.loc[5].tolist() == [1, 1, 1, 1, 0.0, 0.0]       # 200 s later the window has emptied
    assert f.loc[6, "src_win_flows"] == 1                    # sources never mix


def test_window_is_causal_by_end_time():
    t0 = pd.Timestamp("2017-07-07 12:00:00")
    # flow A starts first but ends last; flow B must not see A (A had not ended yet)
    rows = [("1.1.1.1", "10.0.0.5", 22, t0, 30_000_000, 1, 0),
            ("1.1.1.1", "10.0.0.5", 22, t0 + pd.Timedelta(seconds=1), 1_000_000, 1, 0)]
    f = windows.from_frame(_df(rows))
    assert f[1, 0] == 1 and f[0, 0] == 2


def test_brute_force_same_service_count():
    t0 = pd.Timestamp("2017-07-07 12:00:00")
    rows = [("1.1.1.1", "10.0.0.5", 22, t0 + pd.Timedelta(seconds=i), 10, 2, 0) for i in range(10)]
    f = windows.from_frame(_df(rows))
    assert f[-1, windows.WINDOW_FEATURES.index("src_win_same_service_flows")] == 10


def test_time_slice_is_end_ordered_and_shifted_to_now():
    import pytest
    from netsentinel import replay
    from netsentinel.ml import data
    if not (data.ROOT / "data/interim/distrinet/tuesday.parquet").exists():
        pytest.skip("distrinet data not prepared")
    flows, truth = replay.time_slice("tuesday", "12:30", 1)
    starts = pd.to_datetime([f["observed_at"] for f in flows])
    ends = starts + pd.to_timedelta([f["features"]["Flow Duration"] or 0 for f in flows], unit="us")
    assert ends.is_monotonic_increasing
    assert abs((pd.Timestamp.now(tz="UTC") - ends.max()).total_seconds()) < 120
    assert any(t[0] == "FTP-Patator" for t in truth.values()) and len(flows) > len(truth)   # warm-up sent, not measured
