"""Label taxonomy: Network Event -> Normal | Attack -> family -> type.

Extending: add a family to FAMILIES and map its dataset labels in LABELS. A family or type is
only learned once training has at least MIN_SUPPORT examples. Until then its flows still count
as attacks, and the family/type prediction is reported as unknown.
"""

from dataclasses import dataclass

NORMAL = "Normal"
FAMILIES = ("DoS", "DDoS", "PortScan", "BruteForce", "WebAttack", "Botnet", "Infiltration", "Exploit")


@dataclass(frozen=True)
class LabelInfo:
    is_attack: bool
    family: str | None
    attack_type: str | None
    attempted: bool = False  # attack traffic that carried no effective payload (Engelen et al., 2021)


_BASE = {
    "BENIGN": LabelInfo(False, None, None),
    "DoS Hulk": LabelInfo(True, "DoS", "Hulk"),
    "DoS GoldenEye": LabelInfo(True, "DoS", "GoldenEye"),
    "DoS Slowloris": LabelInfo(True, "DoS", "Slowloris"),
    "DoS Slowhttptest": LabelInfo(True, "DoS", "Slowhttptest"),
    "DDoS": LabelInfo(True, "DDoS", "LOIC"),
    "Portscan": LabelInfo(True, "PortScan", "External PortScan"),
    "Infiltration - Portscan": LabelInfo(True, "PortScan", "Internal PortScan"),
    "FTP-Patator": LabelInfo(True, "BruteForce", "FTP-Patator"),
    "SSH-Patator": LabelInfo(True, "BruteForce", "SSH-Patator"),
    "Web Attack - Brute Force": LabelInfo(True, "WebAttack", "Web Brute Force"),
    "Web Attack - SQL Injection": LabelInfo(True, "WebAttack", "SQL Injection"),
    "Web Attack - XSS": LabelInfo(True, "WebAttack", "XSS"),
    "Botnet": LabelInfo(True, "Botnet", "Ares"),
    "Infiltration": LabelInfo(True, "Infiltration", "Infiltration"),
    "Heartbleed": LabelInfo(True, "Exploit", "Heartbleed"),
}

LABELS: dict[str, LabelInfo] = dict(_BASE)
for _name, _info in _BASE.items():
    if _info.is_attack and _name != "Infiltration - Portscan":
        LABELS[f"{_name} - Attempted"] = LabelInfo(True, _info.family, _info.attack_type, attempted=True)


def lookup(label: str) -> LabelInfo:
    try:
        return LABELS[label]
    except KeyError:
        raise ValueError(f"unmapped dataset label {label!r}: add it to netsentinel/ml/taxonomy.py") from None
