import pytest
from scapy.all import IP, TCP, Raw, wrpcap

from netsentinel import sensor
from netsentinel.ml import schema
from netsentinel.pipeline.features import extract


class Capture:
    def __init__(self):
        self.flows = []

    def write(self, data):
        self.flows.append(sensor.to_flow(data))


def _pcap(path, t0=1_700_000_000.0):
    c, s = "203.0.113.7", "192.0.2.10"
    pkts = [IP(src=c, dst=s) / TCP(sport=40000, dport=22, flags="S", window=64240),
            IP(src=s, dst=c) / TCP(sport=22, dport=40000, flags="SA", window=65160),
            IP(src=c, dst=s) / TCP(sport=40000, dport=22, flags="A") / Raw(b"x" * 100),
            IP(src=s, dst=c) / TCP(sport=22, dport=40000, flags="FA") / Raw(b"y" * 40)]
    for p, dt in zip(pkts, (0.0, 0.1, 0.3, 0.5)):
        p.time = t0 + dt
    wrpcap(str(path), pkts)
    return t0


def _run(path):
    from scapy.sendrecv import sniff
    cap = Capture()
    session = sensor.make_session(cap)
    sniff(offline=str(path), prn=session.process, store=False)
    session.flush_flows()
    return cap.flows


def test_units_converted_to_training_scale(tmp_path):
    t0 = _pcap(tmp_path / "a.pcap")
    flows = _run(tmp_path / "a.pcap")
    assert len(flows) == 1
    f = flows[0]["features"]
    assert f["Flow Duration"] == pytest.approx(500_000, rel=1e-6)   # 0.5 s → µs, as in CICFlowMeter-Java
    assert f["Flow IAT Max"] == pytest.approx(200_000, rel=1e-6)
    assert f["Total Fwd Packet"] == 2 and f["Total Bwd packets"] == 2          # first packet counted once
    assert f["FWD Init Win Bytes"] == 64240 and f["Bwd Init Win Bytes"] == 65160
    assert f["Total Length of Fwd Packet"] > 0 and f["Total Length of Bwd Packet"] > 0
    assert f["Dst Port"] == 22 and f["SYN Flag Count"] >= 1
    assert f["CWR Flag Count"] is None and f["Total TCP Flow Time"] is None   # not provided / library bug


def test_exact_start_time_and_context(tmp_path):
    t0 = _pcap(tmp_path / "a.pcap")
    fl = _run(tmp_path / "a.pcap")[0]
    from datetime import datetime
    assert datetime.fromisoformat(fl["observed_at"]).timestamp() == pytest.approx(t0, abs=1e-3)
    assert fl["context"] == {"src_ip": "203.0.113.7", "dst_ip": "192.0.2.10", "protocol": 6,
                             "src_port": 40000, "dst_port": 22}


def test_sensor_flow_passes_validation(tmp_path):
    _pcap(tmp_path / "a.pcap")
    x = extract(_run(tmp_path / "a.pcap")[0]["features"])
    assert x.reject_reason is None and x.missing == 6 and x.vector.shape == (len(schema.FEATURES),)


def test_closed_tcp_flow_is_exported_promptly(tmp_path):
    from scapy.sendrecv import sniff
    t0 = _pcap(tmp_path / "a.pcap")
    cap = Capture()
    session = sensor.make_session(cap)
    sniff(offline=str(tmp_path / "a.pcap"), prn=session.process, store=False)
    assert cap.flows == [] and len(session.flows) == 1           # library alone would wait 240 s
    assert sensor.export_closed(session, now=t0 + 0.5 + 1.0) == 0  # still within the 2 s quiet period
    assert sensor.export_closed(session, now=t0 + 0.5 + 2.5) == 1
    assert len(cap.flows) == 1 and session.flows == {}
    assert cap.flows[0]["features"]["Total Fwd Packet"] == 2
