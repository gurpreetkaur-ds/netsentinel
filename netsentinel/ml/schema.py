"""Feature schema v1: the exact model inputs, shared by training and the API's VALIDATE step.

Changes from the notebook (v0):
- removed identity/leaky columns (EXCLUDED below)
- no data-driven correlation pruning. The feature set is fixed, so it can't change silently when
  the data does, and tree models are unaffected by correlated inputs.
- missing and infinite values are kept as NaN instead of dropping the flow. CICFlowMeter emits
  Infinity for rates over zero-duration flows, and a live detector can't drop those.
"""

SCHEMA_VERSION = "cicflowmeter-v1"

EXCLUDED = {
    "Attempted Category": "target leakage: non-(-1) exactly on '- Attempted' labels",
    "Src IP dec": "host identity: memorises lab topology, not behaviour",
    "Dst IP dec": "host identity: memorises lab topology, not behaviour",
    "Src Port": "ephemeral client port: noise that encodes the capture's OS/port allocator",
    "Timestamp": "only mm:ss.f in this dataset; not a behavioural feature",
}

FEATURES: tuple[str, ...] = (
    "Dst Port", "Protocol", "Flow Duration",
    "Total Fwd Packet", "Total Bwd packets", "Total Length of Fwd Packet", "Total Length of Bwd Packet",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags", "Fwd RST Flags", "Bwd RST Flags",
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Packet Length Min", "Packet Length Max", "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
    "CWR Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Average Packet Size", "Fwd Segment Size Avg", "Bwd Segment Size Avg",
    "Fwd Bytes/Bulk Avg", "Fwd Packet/Bulk Avg", "Fwd Bulk Rate Avg",
    "Bwd Bytes/Bulk Avg", "Bwd Packet/Bulk Avg", "Bwd Bulk Rate Avg",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "FWD Init Win Bytes", "Bwd Init Win Bytes", "Fwd Act Data Pkts", "Fwd Seg Size Min",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
    "ICMP Code", "ICMP Type", "Total TCP Flow Time",
)
