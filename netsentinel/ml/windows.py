"""Per-source time-window features (model v2).

A single scan probe or login attempt looks like a benign handshake. The attack is the pattern across
flows from one source. For each flow these features describe its source's recent behaviour.

Causal by construction: a flow reaches NetSentinel when it *ends*, so a flow's window holds the flows
from the same source IP whose end time lies in (end - W, end], itself included. Production can compute
exactly the same values from flows already received; nothing comes from the future.
"""

from collections import Counter, deque

import numpy as np
import pandas as pd

WINDOW_SECONDS = 60
WINDOW_FEATURES: tuple[str, ...] = (
    "src_win_flows",                # flows from this source in the window
    "src_win_distinct_dst_ports",   # port fan-out (scans)
    "src_win_distinct_dst_ips",     # host fan-out (sweeps, worms)
    "src_win_same_service_flows",   # flows to this flow's dst ip:port (brute force, floods)
    "src_win_share_no_response",    # share of window flows with no backward packets
    "src_win_share_rst",            # share of window flows with a RST
)


def compute(src: np.ndarray, dst: np.ndarray, dport: np.ndarray, end_s: np.ndarray, bwd_pkts: np.ndarray,
            rst: np.ndarray, window_s: float = WINDOW_SECONDS) -> np.ndarray:
    """Returns an (n, 6) float32 array aligned with the inputs. `end_s` is flow end time in seconds."""
    n = len(src)
    out = np.zeros((n, len(WINDOW_FEATURES)), dtype=np.float32)
    order = np.lexsort((end_s, src))           # by source, then by end time
    no_resp = (np.nan_to_num(bwd_pkts) == 0)
    has_rst = (np.nan_to_num(rst) > 0)
    i = 0
    while i < n:
        j = i
        s = src[order[i]]
        while j < n and src[order[j]] == s:
            j += 1
        # sliding window over this source's flows, in end-time order
        win: deque = deque()
        ports, ips, services = Counter(), Counter(), Counter()
        n_noresp = n_rst = 0
        for k in order[i:j]:
            t = end_s[k]
            while win and win[0][0] <= t - window_s:
                _, kk = win.popleft()
                ports[dport[kk]] -= 1
                if not ports[dport[kk]]:
                    del ports[dport[kk]]
                ips[dst[kk]] -= 1
                if not ips[dst[kk]]:
                    del ips[dst[kk]]
                services[(dst[kk], dport[kk])] -= 1
                n_noresp -= no_resp[kk]
                n_rst -= has_rst[kk]
            win.append((t, k))
            ports[dport[k]] += 1
            ips[dst[k]] += 1
            services[(dst[k], dport[k])] += 1
            n_noresp += no_resp[k]
            n_rst += has_rst[k]
            m = len(win)
            out[k] = (m, len(ports), len(ips), services[(dst[k], dport[k])], n_noresp / m, n_rst / m)
        i = j
    return out


def from_frame(df: pd.DataFrame, window_s: float = WINDOW_SECONDS) -> np.ndarray:
    """CICFlowMeter frame with Src IP, Dst IP, Dst Port, Timestamp (flow start) and Flow Duration (µs)."""
    # Seconds since the epoch, independent of pandas' internal resolution (ns vs µs in pandas 3).
    start = (pd.to_datetime(df["Timestamp"]) - pd.Timestamp("1970-01-01")).dt.total_seconds().to_numpy()
    end = start + np.nan_to_num(df["Flow Duration"].to_numpy(dtype=np.float64)) / 1e6
    return compute(df["Src IP"].to_numpy(), df["Dst IP"].to_numpy(), df["Dst Port"].to_numpy(), end,
                   df["Total Bwd packets"].to_numpy(dtype=np.float64), df["RST Flag Count"].to_numpy(dtype=np.float64),
                   window_s)
