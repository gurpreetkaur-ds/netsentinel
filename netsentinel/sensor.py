"""Live sensor: this server's own traffic → CICFlowMeter-style flows → NetSentinel ingest API.

Capture uses the Python port of CICFlowMeter (`cicflowmeter` 0.5.0, scapy). It records flow metadata
(addresses, ports, sizes, timings, flags), never payloads. Its output differs from the Java CICFlowMeter
that produced the training data, and every difference is handled explicitly in TO_SCHEMA below:

* times are in **seconds** here and **microseconds** in training → durations, IATs, active/idle × 1e6
* its timestamp is rounded to whole seconds in local time → the exact epoch start time of each flow is used
* per-direction RST flags, ICMP code/type and total TCP flow time don't exist → sent as missing
* its CWR count is a copy of the forward-URG count (a library bug) → sent as missing
* it exports a flow only after 240 s of silence, even when the TCP connection already closed → flows that
  saw FIN or RST are exported 2 s after their last packet, like the Java CICFlowMeter ends TCP flows
* a new flow's first packet was counted twice (Flow.__init__ stores it and FlowSession.process adds it
  again; a 0.5.0 bug) → patched so each packet is counted once

The API key is created at start (ingest:write, 24 h expiry), rotated every 20 h, kept in memory only and
revoked on shutdown. Nothing secret is stored on disk.
"""

import getpass
import logging
import queue
import signal
import threading
import time
from datetime import datetime, timedelta, timezone

import httpx

from . import db
from .security import api_keys

log = logging.getLogger(__name__)

US = 1e6  # seconds → microseconds
# cicflowmeter field → (NetSentinel schema feature, multiplier)
TO_SCHEMA: dict[str, tuple[str, float]] = {
    "dst_port": ("Dst Port", 1), "protocol": ("Protocol", 1),
    "flow_duration": ("Flow Duration", US),
    "flow_byts_s": ("Flow Bytes/s", 1), "flow_pkts_s": ("Flow Packets/s", 1),
    "fwd_pkts_s": ("Fwd Packets/s", 1), "bwd_pkts_s": ("Bwd Packets/s", 1),
    "tot_fwd_pkts": ("Total Fwd Packet", 1), "tot_bwd_pkts": ("Total Bwd packets", 1),
    "totlen_fwd_pkts": ("Total Length of Fwd Packet", 1), "totlen_bwd_pkts": ("Total Length of Bwd Packet", 1),
    "fwd_pkt_len_max": ("Fwd Packet Length Max", 1), "fwd_pkt_len_min": ("Fwd Packet Length Min", 1),
    "fwd_pkt_len_mean": ("Fwd Packet Length Mean", 1), "fwd_pkt_len_std": ("Fwd Packet Length Std", 1),
    "bwd_pkt_len_max": ("Bwd Packet Length Max", 1), "bwd_pkt_len_min": ("Bwd Packet Length Min", 1),
    "bwd_pkt_len_mean": ("Bwd Packet Length Mean", 1), "bwd_pkt_len_std": ("Bwd Packet Length Std", 1),
    "pkt_len_max": ("Packet Length Max", 1), "pkt_len_min": ("Packet Length Min", 1),
    "pkt_len_mean": ("Packet Length Mean", 1), "pkt_len_std": ("Packet Length Std", 1),
    "pkt_len_var": ("Packet Length Variance", 1),
    "fwd_header_len": ("Fwd Header Length", 1), "bwd_header_len": ("Bwd Header Length", 1),
    "fwd_seg_size_min": ("Fwd Seg Size Min", 1), "fwd_act_data_pkts": ("Fwd Act Data Pkts", 1),
    "flow_iat_mean": ("Flow IAT Mean", US), "flow_iat_max": ("Flow IAT Max", US),
    "flow_iat_min": ("Flow IAT Min", US), "flow_iat_std": ("Flow IAT Std", US),
    "fwd_iat_tot": ("Fwd IAT Total", US), "fwd_iat_max": ("Fwd IAT Max", US), "fwd_iat_min": ("Fwd IAT Min", US),
    "fwd_iat_mean": ("Fwd IAT Mean", US), "fwd_iat_std": ("Fwd IAT Std", US),
    "bwd_iat_tot": ("Bwd IAT Total", US), "bwd_iat_max": ("Bwd IAT Max", US), "bwd_iat_min": ("Bwd IAT Min", US),
    "bwd_iat_mean": ("Bwd IAT Mean", US), "bwd_iat_std": ("Bwd IAT Std", US),
    "fwd_psh_flags": ("Fwd PSH Flags", 1), "bwd_psh_flags": ("Bwd PSH Flags", 1),
    "fwd_urg_flags": ("Fwd URG Flags", 1), "bwd_urg_flags": ("Bwd URG Flags", 1),
    "fin_flag_cnt": ("FIN Flag Count", 1), "syn_flag_cnt": ("SYN Flag Count", 1), "rst_flag_cnt": ("RST Flag Count", 1),
    "psh_flag_cnt": ("PSH Flag Count", 1), "ack_flag_cnt": ("ACK Flag Count", 1), "urg_flag_cnt": ("URG Flag Count", 1),
    "ece_flag_cnt": ("ECE Flag Count", 1),
    "down_up_ratio": ("Down/Up Ratio", 1), "pkt_size_avg": ("Average Packet Size", 1),
    "init_fwd_win_byts": ("FWD Init Win Bytes", 1), "init_bwd_win_byts": ("Bwd Init Win Bytes", 1),
    "active_max": ("Active Max", US), "active_min": ("Active Min", US), "active_mean": ("Active Mean", US),
    "active_std": ("Active Std", US), "idle_max": ("Idle Max", US), "idle_min": ("Idle Min", US),
    "idle_mean": ("Idle Mean", US), "idle_std": ("Idle Std", US),
    "fwd_byts_b_avg": ("Fwd Bytes/Bulk Avg", 1), "fwd_pkts_b_avg": ("Fwd Packet/Bulk Avg", 1),
    "bwd_byts_b_avg": ("Bwd Bytes/Bulk Avg", 1), "bwd_pkts_b_avg": ("Bwd Packet/Bulk Avg", 1),
    "fwd_blk_rate_avg": ("Fwd Bulk Rate Avg", 1), "bwd_blk_rate_avg": ("Bwd Bulk Rate Avg", 1),
    "fwd_seg_size_avg": ("Fwd Segment Size Avg", 1), "bwd_seg_size_avg": ("Bwd Segment Size Avg", 1),
    "subflow_fwd_pkts": ("Subflow Fwd Packets", 1), "subflow_bwd_pkts": ("Subflow Bwd Packets", 1),
    "subflow_fwd_byts": ("Subflow Fwd Bytes", 1), "subflow_bwd_byts": ("Subflow Bwd Bytes", 1),
}
NOT_PROVIDED = ("Fwd RST Flags", "Bwd RST Flags", "ICMP Code", "ICMP Type", "Total TCP Flow Time", "CWR Flag Count")


def _num(v):
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if f == f and f not in (float("inf"), float("-inf")) else None


def to_flow(data: dict) -> dict:
    """One cicflowmeter record (with the exact `_start_epoch` added by the sensor) → API flow."""
    feats = {}
    for src, (dst, mult) in TO_SCHEMA.items():
        v = _num(data.get(src))
        feats[dst] = None if v is None else v * mult
    for name in NOT_PROVIDED:
        feats[name] = None
    start = datetime.fromtimestamp(float(data["_start_epoch"]), tz=timezone.utc)
    proto = int(data.get("protocol") or 0)
    ctx = {"src_ip": data.get("src_ip"), "dst_ip": data.get("dst_ip"), "protocol": proto}
    for k in ("src_port", "dst_port"):
        if data.get(k) is not None and 0 <= int(data[k]) <= 65535:
            ctx[k] = int(data[k])
    return {"observed_at": start.isoformat(), "context": ctx, "features": feats}


class ApiWriter:
    """cicflowmeter OutputWriter: queues flows; a background thread posts them in batches."""

    def __init__(self, base_url: str, key_source, batch: int = 200, flush_s: float = 2.0, mode: str = "shadow"):
        self.base_url, self.key_source, self.batch, self.flush_s, self.mode = base_url, key_source, batch, flush_s, mode
        self.q: queue.Queue = queue.Queue(maxsize=50_000)
        self.sent = self.dropped = self.failed = 0
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._loop, name="sensor-sender", daemon=True)
        self.thread.start()

    def write(self, data: dict) -> None:
        try:
            self.q.put_nowait(to_flow(data))
        except queue.Full:
            self.dropped += 1
        except Exception:
            log.exception("could not convert a flow record")

    def _loop(self) -> None:
        with httpx.Client(base_url=self.base_url, timeout=30) as client:
            while not (self.stop.is_set() and self.q.empty()):
                flows, deadline = [], time.monotonic() + self.flush_s
                while len(flows) < self.batch and time.monotonic() < deadline:
                    try:
                        flows.append(self.q.get(timeout=0.2))
                    except queue.Empty:
                        if self.stop.is_set():
                            break
                if not flows:
                    continue
                try:
                    r = client.post("/v1/flows", json={"source": "cicflowmeter", "mode": self.mode, "flows": flows},
                                    headers={"Authorization": f"Bearer {self.key_source()}"})
                    r.raise_for_status()
                    self.sent += len(flows)
                except Exception as e:
                    self.failed += len(flows)
                    log.warning("could not deliver %d flows: %s", len(flows), type(e).__name__)


class EphemeralKey:
    """An ingest-only API key held in memory; rotated before expiry, revoked on close."""

    def __init__(self, pool, rotate_after_s: float = 20 * 3600):
        self.pool, self.rotate_after_s = pool, rotate_after_s
        self._lock = threading.Lock()
        self._key, self._issued = None, 0.0

    def __call__(self) -> str:
        with self._lock:
            if self._key is None or time.monotonic() - self._issued > self.rotate_after_s:
                old = self._key
                key = api_keys.generate()
                with self.pool.connection() as c:
                    api_keys.register(c, key_id=api_keys.parse_key_id(key), sha256_hex=api_keys.digest(key).hex(),
                                      name="live sensor (ephemeral)", scopes=["ingest:write"],
                                      created_by=f"sensor:{getpass.getuser()}",
                                      expires_at=datetime.now(timezone.utc) + timedelta(hours=24))
                self._key, self._issued = key, time.monotonic()
                if old:
                    self._revoke(old, "rotated")
            return self._key

    def _revoke(self, key: str, reason: str) -> None:
        with self.pool.connection() as c:
            api_keys.revoke(c, api_keys.parse_key_id(key), reason=reason, actor="sensor")

    def close(self) -> None:
        with self._lock:
            if self._key:
                self._revoke(self._key, "sensor stopped")
                self._key = None


def _patch_library() -> None:
    """Fixes for cicflowmeter 0.5.0, applied once: exact epoch start/end for the writer (the library
    only gives a rounded string), and no double count of a flow's first packet."""
    from cicflowmeter.flow import Flow
    if getattr(Flow.get_data, "_netsentinel", False):
        return
    original_init = Flow.__init__

    def __init__(self, packet, direction):
        original_init(self, packet, direction)
        self.packets = []     # FlowSession.process adds the first packet right after construction

    Flow.__init__ = __init__
    original = Flow.get_data

    def get_data(self, include_fields=None):
        d = original(self, include_fields)
        d["_start_epoch"] = float(self.start_timestamp)
        d["_end_epoch"] = float(self.latest_timestamp)
        return d
    get_data._netsentinel = True
    Flow.get_data = get_data


def _closed(flow) -> bool:
    for pkt, _ in flow.packets[-4:]:
        if "TCP" in pkt and ("F" in pkt["TCP"].flags or "R" in pkt["TCP"].flags):
            return True
    return False


def export_closed(session, now: float, quiet_s: float = 2.0) -> int:
    """Exports TCP flows that ended (FIN/RST seen) and have been quiet for `quiet_s` seconds."""
    with session._lock:
        done = [(k, f) for k, f in session.flows.items() if now - f.latest_timestamp >= quiet_s and _closed(f)]
        for k, _ in done:
            del session.flows[k]
    for _, f in done:
        session.output_writer.write(f.get_data(session.fields))
    return len(done)


def make_session(writer):
    from cicflowmeter.flow_session import FlowSession
    _patch_library()
    session = FlowSession(output_mode="csv", output="/dev/null", fields=None, verbose=False)
    session.output_writer = writer
    return session


def run(*, interface: str, base_url: str, bpf: str = "ip and (tcp or udp or icmp)", alert: bool = False) -> None:
    """`alert=False` (default) sends in shadow mode: scored and stored, no cases or tickets. The model
    is trained on CICIDS-2017 flows from the Java CICFlowMeter; until it is calibrated on this host's
    traffic, live alerts would be mostly false (observed: 55% of flows flagged in a first test)."""
    from scapy.config import conf
    from scapy.sendrecv import AsyncSniffer
    from cicflowmeter.sniffer import _start_periodic_gc
    conf.sniff_promisc = False                      # only this host's own traffic
    pool = db.make_pool(max_size=1)
    key = EphemeralKey(pool)
    key()                                           # fail fast if the database/Wall is unreachable
    writer = ApiWriter(base_url, key, mode="live" if alert else "shadow")
    session = make_session(writer)
    _start_periodic_gc(session)
    closer_stop = threading.Event()

    def _closer():
        while not closer_stop.wait(1.0):
            try:
                export_closed(session, time.time())
            except Exception:
                log.exception("exporting closed flows failed")
    threading.Thread(target=_closer, name="sensor-closer", daemon=True).start()
    sniffer = AsyncSniffer(iface=interface, filter=bpf, prn=session.process, store=False)
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    sniffer.start()
    log.info("sensor capturing on %s (%s), sending to %s in %s mode", interface, bpf, base_url,
             "ALERT" if alert else "shadow")
    try:
        while not stop.wait(60):
            log.info("sensor: sent %d flows, queue %d, failed %d, dropped %d",
                     writer.sent, writer.q.qsize(), writer.failed, writer.dropped)
    finally:
        sniffer.stop()
        closer_stop.set()
        session._gc_stop.set()
        session.flush_flows()
        writer.stop.set()
        writer.thread.join(timeout=30)
        key.close()
        pool.close()
        log.info("sensor stopped: sent %d flows", writer.sent)
