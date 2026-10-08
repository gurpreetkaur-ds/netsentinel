"""Experiment: a detector trained on the live sensor's own traffic with weak labels from host logs.

    python -m netsentinel.ml.local_sensor [--since 2026-10-07]

Inbound flows only (this host's own outbound connections would teach "outbound means benign").
Labels: scan / SSH brute force from the firewall and SSH logs (see netsentinel/calibrate.py), benign =
the owner's addresses. Evaluated across sources: the owner's addresses are put in different folds and
attackers are split by IP, so every test uses a benign source and attackers the model never saw.
Writes artifacts/local_sensor/report.json; nothing is registered or deployed.
"""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score

from .. import calibrate, db, site
from ..pipeline.features import extract
from . import schema, windows
from .data import ROOT
from .detector import make_classifier


def load(since: datetime):
    s = site.load()
    host, owners = {s["server_ip"]}, set(s["owner_ips"])
    scanners = calibrate._log_sources(Path("/var/log/ufw.log"), calibrate.UFW_RE, since)
    guessers = calibrate._log_sources(Path("/var/log/auth.log"), calibrate.SSH_RE, since)
    with db.connect() as c:
        rows = c.execute(
            "SELECT host(f.src_ip), host(f.dst_ip), f.dst_port, extract(epoch FROM coalesce(f.ended_at, f.received_at)), "
            "f.flow, d.p_attack FROM flow_events f JOIN api_keys k ON k.key_id = f.key_id "
            "LEFT JOIN detections d USING (event_id) "
            "WHERE k.name = 'live sensor (ephemeral)' AND f.received_at >= %s AND f.status = 'scored'", (since,)).fetchall()
    vecs = [extract(r[4]).vector for r in rows]
    keep = [i for i, v in enumerate(vecs) if v is not None]
    rows, vecs = [rows[i] for i in keep], [vecs[i] for i in keep]
    X = np.vstack(vecs)
    col = lambda name: X[:, schema.FEATURES.index(name)]
    W = windows.compute(np.array([r[0] for r in rows], dtype=object), np.array([r[1] for r in rows], dtype=object),
                        np.array([r[2] if r[2] is not None else -1 for r in rows]), np.array([float(r[3]) for r in rows]),
                        col("Total Bwd packets"), col("RST Flag Count"))   # over all flows, as live
    src = np.array([r[0] for r in rows], dtype=object)
    inbound = np.array([r[1] in host and r[0] not in host for r in rows])
    lab = np.array([calibrate.label(r[0], r[2], host, owners, scanners, guessers) or "unlabelled" for r in rows])
    v2_p = np.array([r[5] if r[5] is not None else np.nan for r in rows], dtype=float)
    return np.hstack([X, W])[inbound], src[inbound], lab[inbound], v2_p[inbound]


def _fold(ip: str) -> int:
    return int(hashlib.sha256(ip.encode()).hexdigest(), 16) % 2


def run(since: datetime) -> dict:
    X, src, lab, v2_p = load(since)
    X = X[:, ~np.isnan(X).all(axis=0)]      # features this flow meter never provides (always missing)
    owners = sorted(set(src[lab == "benign"]))
    attack = np.isin(lab, ["scan", "bruteforce"])
    benign = lab == "benign"
    fold = np.array([_fold(s) for s in src])
    for i, o in enumerate(owners[:2]):          # the owner's addresses go to different folds
        fold[src == o] = i
    results = []
    for test_fold in (0, 1):
        tr = (fold != test_fold) & (attack | benign)
        te = fold == test_fold
        clf = make_classifier(class_weight="balanced").fit(X[tr], attack[tr])
        p = clf.predict_proba(X[te])[:, 1]
        a, b, u = attack[te], benign[te], lab[te] == "unlabelled"
        res = {"test_fold": test_fold, "benign_sources_test": len(set(src[te][b])),
               "train": {"attack": int((attack & tr).sum()), "benign": int((benign & tr).sum())},
               "test": {"attack": int(a.sum()), "benign": int(b.sum()), "unlabelled": int(u.sum())}}
        if a.any() and b.any():
            res["roc_auc"] = float(roc_auc_score(np.r_[np.ones(a.sum()), np.zeros(b.sum())], np.r_[p[a], p[b]]))
            for budget in (0.01, 0.05):
                t = float(np.quantile(p[b], 1 - budget, method="higher"))
                res[f"at_{budget:.0%}_benign_fpr"] = {
                    "threshold": t,
                    "recall_scan": float((p[lab[te] == "scan"] > t).mean()),
                    "recall_bruteforce": float((p[lab[te] == "bruteforce"] > t).mean()) if (lab[te] == "bruteforce").any() else None,
                    "flagged_unlabelled": float((p[u] > t).mean()) if u.any() else None}
            v2a, v2b = v2_p[te][a], v2_p[te][b]
            ok = ~np.isnan(np.r_[v2a, v2b])
            res["v2_roc_auc_same_test"] = float(roc_auc_score(np.r_[np.ones(len(v2a)), np.zeros(len(v2b))][ok],
                                                              np.r_[v2a, v2b][ok]))
        results.append(res)
    report = {"since": since.isoformat(), "inbound_flows": int(len(lab)),
              "labels": {k: int((lab == k).sum()) for k in ("scan", "bruteforce", "benign", "unlabelled")},
              "benign_sources": len(owners), "folds": results}
    out = ROOT / "artifacts" / "local_sensor"
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--since", default="2026-10-07")
    a = ap.parse_args()
    print(json.dumps(run(datetime.fromisoformat(a.since).replace(tzinfo=timezone.utc)), indent=2))
