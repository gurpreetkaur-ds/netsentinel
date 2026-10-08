# Live sensor (2026-10-07)

`netsentinel-sensor` captures this server's own traffic on `enp1s0` as flow metadata (never payloads)
with the Python CICFlowMeter port (`cicflowmeter` 0.5.0) and sends it to the local API. It runs as
`linuxuser` with one privilege, `CAP_NET_RAW` (systemd exposure 3.4 OK). Its API key is ingest-only,
held in memory, expires in 24 h and is revoked when the sensor stops.

## Making the flow meter match the training data

The training flows came from the Java CICFlowMeter (Engelen et al.'s fixed version). Differences found
and handled in `netsentinel/sensor.py`, each covered by a test on a synthetic capture with known timings:

| Difference | Handling |
|---|---|
| Times in seconds (training: microseconds) | duration, all IATs, active/idle × 10⁶ |
| Timestamp rounded to whole seconds, local time | exact epoch start/end from the flow object |
| First packet of every flow counted twice (library bug) | patched |
| Flows exported only after 240 s of silence, even after FIN | TCP flows exported 2 s after FIN/RST, as the Java tool ends them |
| CWR count copied from forward-URG (library bug) | sent as missing |
| No per-direction RST flags, ICMP code/type, total TCP flow time | sent as missing (6 of 83) |

## What happened when alerts were on

A first run in alert mode flagged **55% of 114 live flows** and opened **75 cases** in a few minutes,
including this server's own HTTPS, its calls to the Claude API, and the owner's phone. The sensor was
stopped, the 75 cases and 4 tickets were closed with an audit note (detections kept as data; no
non-sensor case was touched), and **shadow mode** was added: flows are scored and stored but raise no
cases. The sensor now always starts in shadow mode (`--alert` to change that).

## Calibration against the host's own logs (`netsentinel calibrate`)

There are no labels for live traffic, but the host records attacks independently:
firewall blocks (`/var/log/ufw.log`) → **scanners**; failed/invalid SSH logins (`/var/log/auth.log`) →
**brute force** (their flows to port 22). Flows this host starts and flows from the owner's IPs → **benign**.

First 2 hours (193 flows; 84 benign, 41 scan, 21 brute force):

* The model **ranks** live traffic well: ROC-AUC 0.95 between logged attackers and benign flows.
* The **thresholds don't transfer**. At the validated threshold, benign false alarms are 16%.

| Benign false-alarm budget | Scan flows caught | SSH-guessing flows caught |
|---|---|---|
| 10% | 90% | 100% |
| 5% | 85% | 100% |
| 2% | 2% | 29% |

**Decision: alerting stays off.** 5% false alarms on a server's normal traffic would open a stream of
false cases and Claude investigations. The sensor keeps collecting in shadow mode.

## Path to live alerting

1. Let the sensor collect for ≥ 24 h, then `netsentinel calibrate --hours 24`. With ~1,000+ benign
   flows the curve is measurable down to ~0.1%.
2. If the curve is still poor (likely), **retrain on matched features**: either on this sensor's own
   flows with the weak labels above (an honest, local model, though the labels cover only scans and SSH
   guessing), or on the CICIDS-2017 PCAPs re-processed with this same flow meter, so training and live
   features come from one tool.
3. Then add a per-source alert threshold (human-approved, like model activation) and start the sensor
   with `--alert`.

## 24-hour calibration (2026-10-08)

`netsentinel calibrate --hours 24`: 29,764 flows (2,918 benign, 19,253 scan, 2,350 SSH brute force,
5,243 unlabelled). ROC-AUC attack vs benign **0.92** (0.95 on the first 2 h).

| Benign false-alarm budget | Scan flows caught | SSH-guessing flows caught |
|---|---|---|
| validated threshold (p ≥ 0.000016) | 97% (at 32% false alarms) | 100% |
| 10% | 60% | 97% |
| 5% | 40% | 56% |
| 1% | 20% | 7% |

**Conclusion: the CICIDS-2017-trained model is not fit for alerting on this server**, at any threshold.
It was trained on 2017 lab traffic measured by the Java flow meter; this is an internet-facing host
measured by the Python port. The sensor stays in shadow mode. Live alerting needs a model trained on
features from this sensor (see "Path to live alerting").

Caveat on the labels: "scan" means *any* flow from an address the firewall blocked at some point, so it
includes that address's probes of open ports. Some of those look like ordinary handshakes. Benign
labels cover only this host's own connections and the owner's IPs.

## Local model experiment (2026-10-08)

`python -m netsentinel.ml.local_sensor`: a detector trained on the sensor's own inbound flows (per-flow
+ window features, same flow meter as live) with the weak labels above. Evaluated across sources: the
owner's two addresses go to different folds and attackers are split by IP, so each test uses a benign
source and attackers the model never saw. Nothing was registered or deployed.

Data: 26,343 inbound flows: 19,932 scan (2,111 sources), 2,359 SSH brute force (305 sources),
**473 benign from only 2 sources (the owner)**, 4,577 unlabelled.

| Held-out benign source | ROC-AUC (local) | ROC-AUC (v2 lab model, same test) | At 1% false alarms: scans / SSH guessing caught |
|---|---|---|---|
| owner address A (trained on B, 75 benign flows) | 0.99 | 0.59 | 92% / 73% |
| owner address B (trained on A, 398 benign flows) | 0.94 | 0.87 | 46% / 37% |

* Training on the sensor's own features ranks this host's traffic far better than the lab model.
* It is **not deployable**: results swing widely with which owner address is held out, because benign
  traffic comes from two sources. The model largely learns "looks like the owner", and no threshold
  can be trusted.
* What would fix it is **benign diversity**, not more attacks. Candidate weak labels: web visitors
  whose sessions look like real use in the web servers' access logs (Apache, Resumate, the esports
  site), e.g. successful page loads followed by static assets, from sources never firewall-blocked
  and never failing SSH logins. With tens of benign sources, the cross-source test above becomes
  meaningful.

## Benign labels from web access logs: not enough visitors (2026-10-08)

Checked whether web access logs could supply the missing benign diversity (aggregates only):

* Apache (`/var/log/apache2/access.log`, since 2026-10-07 18:00): 107 distinct IPs, 1,361 requests.
  26 IPs requested scanner-style paths (`/.env`, `/wp-*`, `/phpmyadmin`, …), 25 used bot or tool user
  agents. Only **1** IP behaved like a real browser (page plus its assets, browser UA, never
  firewall-blocked, never failing SSH, not the owner).
* Esports site (`storage/logs/serve.log`): request lines carry no client IP, and the current server's
  output isn't written there. Not usable. Resumate logs errors only.

With the owner's two addresses that makes 3 benign sources against ~2,400 attacking ones. **This host
has almost no legitimate inbound visitors**: unsolicited inbound traffic is nearly all hostile, and the
firewall already blocks most of it. A local supervised model can't be validated here, so no labelling
feature was built.

Where the approach would work: a network with real users, e.g. a sensor in front of an application
that has traffic, or a corporate segment. There, access logs or authenticated sessions give hundreds
of benign sources, and `netsentinel.ml.local_sensor`'s cross-source test applies unchanged.
