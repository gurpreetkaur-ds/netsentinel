"""Calibrate the live sensor against weak labels from this host's own logs.

Live traffic has no ground truth, but the host records two kinds of attack independently:
  * the firewall log ([UFW BLOCK]): sources sending packets to closed ports    → scanners
  * the SSH log (invalid user / failed password): sources guessing passwords  → brute force (to port 22)
and two kinds of benign traffic are known:
  * flows this host initiates (source = the host itself)
  * flows from the owner's own addresses (--owner-ip, default: owner_ips in config/site.json)
Everything else stays unlabelled and is reported only as a volume.

    netsentinel calibrate [--hours 24] [--owner-ip IP ...] [--target-fpr 0.001]
"""

import ipaddress
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score

from . import db, site
from .ml.data import ROOT

UFW_RE = re.compile(r"^(\S+) .*\[UFW BLOCK\].* SRC=(\S+) .*DPT=(\d+)")
SSH_RE = re.compile(r"^(\S+) .*sshd\[\d+\]: (?:Invalid user \S* from|Failed password for (?:invalid user )?\S+ from"
                    r"|Connection closed by invalid user \S*|Disconnected from invalid user \S*) (\d+\.\d+\.\d+\.\d+)")


def _log_sources(path: Path, regex: re.Pattern, since: datetime) -> set[str]:
    out = set()
    try:
        with path.open(errors="replace") as f:
            for line in f:
                m = regex.match(line)
                if m and datetime.fromisoformat(m.group(1)) >= since:
                    out.add(m.group(2))
    except FileNotFoundError:
        pass
    return out


def label(src: str, dst_port: int | None, host_ips: set[str], owner_ips: set[str],
          scanners: set[str], ssh_guessers: set[str]) -> str | None:
    if src in host_ips or src in owner_ips:
        return "benign"
    if src in ssh_guessers and dst_port == 22:
        return "bruteforce"
    if src in scanners:
        return "scan"
    return None


def run(*, hours: float, owner_ips: tuple[str, ...], host_ips: tuple[str, ...], target_fpr: float,
        log_dir: Path = Path("/var/log")) -> dict:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    scanners = _log_sources(log_dir / "ufw.log", UFW_RE, since)
    guessers = _log_sources(log_dir / "auth.log", SSH_RE, since)
    with db.connect() as c:
        rows = c.execute(
            "SELECT host(f.src_ip), f.dst_port, d.p_attack, d.is_attack, d.threshold FROM flow_events f "
            "JOIN detections d USING (event_id) JOIN api_keys k ON k.key_id = f.key_id "
            "WHERE k.name = 'live sensor (ephemeral)' AND f.received_at >= %s", (since,)).fetchall()
    labels = [label(r[0], r[1], set(host_ips), set(owner_ips), scanners, guessers) for r in rows]
    p = np.array([r[2] for r in rows], dtype=float)
    flagged = np.array([r[3] for r in rows], dtype=bool)
    lab = np.array([l or "unlabelled" for l in labels])
    benign, attack = lab == "benign", np.isin(lab, ["scan", "bruteforce"])
    report = {
        "window_hours": hours, "flows": len(rows),
        "labels": {k: int((lab == k).sum()) for k in ("benign", "scan", "bruteforce", "unlabelled")},
        "log_sources": {"firewall_scanners": len(scanners), "ssh_guessers": len(guessers)},
        "current_threshold": float(np.median([r[4] for r in rows])) if rows else None,
        "flagged_share_all": float(flagged.mean()) if rows else None,
        "flagged_share_unlabelled": float(flagged[lab == "unlabelled"].mean()) if (lab == "unlabelled").any() else None,
    }
    if benign.any():
        report["current_fpr_on_benign"] = float(flagged[benign].mean())
    for k in ("scan", "bruteforce"):
        if (lab == k).any():
            report[f"current_recall_{k}"] = float(flagged[lab == k].mean())
    if benign.any() and attack.any():
        report["roc_auc_attack_vs_benign"] = float(roc_auc_score(attack[benign | attack], p[benign | attack]))
        # smallest threshold keeping benign false alarms within target (needs enough benign flows to mean much)
        thr = float(np.quantile(p[benign], 1 - target_fpr, method="higher")) if benign.sum() else None
        report["suggested"] = {"target_fpr": target_fpr, "threshold": thr, "benign_flows_used": int(benign.sum()),
                               "recall_scan": float((p[lab == "scan"] > thr).mean()) if (lab == "scan").any() else None,
                               "recall_bruteforce": float((p[lab == "bruteforce"] > thr).mean())
                               if (lab == "bruteforce").any() else None,
                               "flagged_share_unlabelled": float((p[lab == "unlabelled"] > thr).mean())
                               if (lab == "unlabelled").any() else None}
    if benign.sum() >= 20 and attack.any():
        curve = []
        for fpr in (0.005, 0.01, 0.02, 0.05, 0.10):
            t = float(np.quantile(p[benign], 1 - fpr, method="higher"))
            curve.append({"benign_fpr_budget": fpr, "threshold": t,
                          "recall_scan": float((p[lab == "scan"] > t).mean()) if (lab == "scan").any() else None,
                          "recall_bruteforce": float((p[lab == "bruteforce"] > t).mean()) if (lab == "bruteforce").any() else None,
                          "flagged_share_unlabelled": float((p[lab == "unlabelled"] > t).mean())
                          if (lab == "unlabelled").any() else None})
        report["operating_curve"] = curve
        report["note"] = (f"{int(benign.sum())} benign flows: an FPR budget below ~{1 / benign.sum():.2%} "
                          "cannot be measured yet; let the sensor collect longer.")
    out = ROOT / "artifacts" / "calibration"
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{datetime.now(timezone.utc):%Y%m%dT%H%M%S}.json").write_text(json.dumps(report, indent=2))
    return report


def host_addresses() -> tuple[str, ...]:
    import socket
    addrs = {a[4][0] for a in socket.getaddrinfo(socket.gethostname(), None)}
    found = tuple(a for a in addrs if not ipaddress.ip_address(a).is_loopback)
    return found or ((site.load()["server_ip"],) if site.load()["server_ip"] else ())
