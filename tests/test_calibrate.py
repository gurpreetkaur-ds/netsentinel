from datetime import datetime, timedelta, timezone

from netsentinel import calibrate


def test_weak_labels():
    host, owner = {"203.0.113.10"}, {"198.51.100.7"}
    scan, ssh = {"85.217.140.13", "45.148.10.183"}, {"45.148.10.183"}
    lab = lambda src, port: calibrate.label(src, port, host, owner, scan, ssh)
    assert lab("203.0.113.10", 443) == "benign"            # flows this host starts
    assert lab("198.51.100.7", 8443) == "benign"            # the owner
    assert lab("45.148.10.183", 22) == "bruteforce"           # failed SSH logins, to SSH
    assert lab("45.148.10.183", 443) == "scan"                # same source elsewhere: blocked by firewall
    assert lab("85.217.140.13", 465) == "scan"
    assert lab("8.8.8.8", 53) is None


def test_log_parsing(tmp_path):
    now = datetime.now(timezone.utc)
    t = now.isoformat()
    (tmp_path / "ufw.log").write_text(
        f"{t} vultr kernel: [UFW BLOCK] IN=enp1s0 OUT= SRC=85.217.140.13 DST=203.0.113.10 LEN=44 PROTO=TCP SPT=1 DPT=465 SYN\n"
        f"{(now - timedelta(days=3)).isoformat()} vultr kernel: [UFW BLOCK] IN=enp1s0 SRC=1.2.3.4 DST=x PROTO=TCP SPT=1 DPT=2\n")
    (tmp_path / "auth.log").write_text(
        f"{t} vultr sshd[1]: Invalid user admin from 2.57.121.25 port 37398\n"
        f"{t} vultr sshd[2]: Failed password for root from 45.148.10.183 port 22 ssh2\n"
        f"{t} vultr sshd[3]: Accepted publickey for linuxuser from 198.51.100.7 port 1 ssh2\n")
    since = now - timedelta(hours=1)
    assert calibrate._log_sources(tmp_path / "ufw.log", calibrate.UFW_RE, since) == {"85.217.140.13"}
    assert calibrate._log_sources(tmp_path / "auth.log", calibrate.SSH_RE, since) == {"2.57.121.25", "45.148.10.183"}
