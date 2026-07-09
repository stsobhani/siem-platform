"""
Generates realistic, multi-source sample logs with deliberately embedded
attack scenarios so every detection rule and the ML pipeline has something
to find out of the box.

Run:
    python scripts/generate_sample_logs.py

Writes to data/sample_logs/{windows_security,linux_auth,firewall,web_access}.log

Embedded scenarios (all anchored to BASE_DATE, 2026-07-01):
  1. Normal daytime logins for a handful of employees (corporate IP range)   -> baseline / negative examples
  2. Brute-force SSH + Windows RDP attempts from 203.0.113.55 (threat intel) -> Rule: brute_force_login
  3. Impossible travel for user 'jsmith' (Baltimore -> Beijing in 6 minutes) -> Rule: impossible_travel
  4. Tor-exit-node + scanner traffic hitting the firewall/web tier           -> Rule: suspicious_ip_threat_intel
  5. sudo-to-root privilege escalation + Windows 4672/4728 events           -> Rule: privilege_escalation
  6. A 3 AM login for a normally 9-5 employee                               -> Rule: unusual_login_hours
  7. Credential-stuffing style failures spread across SSH + web login form -> Rule: multiple_failed_auth
"""
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(42)

BASE_DATE = datetime(2026, 7, 1, tzinfo=timezone.utc)
OUT_DIR = Path(__file__).resolve().parent.parent / "data" / "sample_logs"
OUT_DIR.mkdir(parents=True, exist_ok=True)

EMPLOYEES = ["jsmith", "agarcia", "mchen", "rpatel", "kbrown"]
CORP_IPS = ["10.0.0.5", "10.0.0.12", "10.0.0.31", "192.168.1.44", "172.16.0.9"]
ATTACKER_BRUTE_IP = "203.0.113.55"          # in threat_intel_ips.csv
ATTACKER_TOR_IP = "185.220.101.13"           # in threat_intel_ips.csv
ATTACKER_SCANNER_IP = "45.155.204.9"         # in threat_intel_ips.csv
ATTACKER_BEIJING_IP = "198.51.100.23"        # in threat_intel_ips.csv (malware_c2, also used for geo)
CRED_STUFF_IP = "103.21.244.101"             # in threat_intel_ips.csv

windows_lines, linux_lines, firewall_lines, web_lines = [], [], [], []


def w_ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def l_ts(dt):
    # Linux syslog format has no year and single-digit days are space-padded
    return dt.strftime("%b %e %H:%M:%S").replace("  ", " ")


def f_ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def web_ts(dt):
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


# ---------------------------------------------------------------------------
# 1. Baseline normal activity: each employee logs in during business hours
# ---------------------------------------------------------------------------
for day_offset in range(5):  # 5 business days
    day = BASE_DATE + timedelta(days=day_offset)
    for user, ip in zip(EMPLOYEES, CORP_IPS):
        login_time = day.replace(hour=random.randint(8, 9), minute=random.randint(0, 59))
        windows_lines.append(
            f"{w_ts(login_time)} EventID=4624 Account={user} LogonType=3 "
            f"SourceIP={ip} Workstation=WIN-DC01 Status=success"
        )
        linux_lines.append(
            f"{l_ts(login_time)} web01 sshd[{random.randint(1000,9999)}]: "
            f"Accepted password for {user} from {ip} port {random.randint(40000,60000)} ssh2"
        )
        firewall_lines.append(f"{f_ts(login_time)},fw01,ALLOW,TCP,{ip},10.0.0.10,22")

        logout_time = login_time + timedelta(hours=random.randint(6, 9))
        firewall_lines.append(f"{f_ts(logout_time)},fw01,ALLOW,TCP,{ip},10.0.0.10,443")
        web_lines.append(
            f'{ip} - {user} [{web_ts(login_time + timedelta(minutes=5))}] '
            f'"GET /dashboard HTTP/1.1" 200 4521 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
        )

# ---------------------------------------------------------------------------
# 2. Brute-force: 8 failed SSH + 8 failed Windows logons in under 5 minutes
# ---------------------------------------------------------------------------
brute_start = BASE_DATE.replace(hour=3, minute=10)
for i in range(8):
    t = brute_start + timedelta(seconds=i * 25)
    linux_lines.append(
        f"{l_ts(t)} web01 sshd[{2000+i}]: Failed password for invalid user admin "
        f"from {ATTACKER_BRUTE_IP} port {50000+i} ssh2"
    )
    windows_lines.append(
        f"{w_ts(t + timedelta(seconds=10))} EventID=4625 Account=administrator LogonType=3 "
        f"SourceIP={ATTACKER_BRUTE_IP} Workstation=WIN-DC01 Status=failure"
    )
    firewall_lines.append(f"{f_ts(t)},fw01,BLOCK,TCP,{ATTACKER_BRUTE_IP},10.0.0.10,22")

# ---------------------------------------------------------------------------
# 3. Impossible travel: jsmith logs in from Baltimore, then "Beijing" 6 min later
# ---------------------------------------------------------------------------
travel_t1 = BASE_DATE.replace(hour=14, minute=0)
travel_t2 = travel_t1 + timedelta(minutes=6)
windows_lines.append(
    f"{w_ts(travel_t1)} EventID=4624 Account=jsmith LogonType=3 "
    f"SourceIP=10.0.0.5 Workstation=WIN-DC01 Status=success"
)
windows_lines.append(
    f"{w_ts(travel_t2)} EventID=4624 Account=jsmith LogonType=3 "
    f"SourceIP={ATTACKER_BEIJING_IP} Workstation=WIN-DC01 Status=success"
)
linux_lines.append(
    f"{l_ts(travel_t2 + timedelta(minutes=1))} web01 sshd[3100]: Accepted password for jsmith "
    f"from {ATTACKER_BEIJING_IP} port 55321 ssh2"
)

# ---------------------------------------------------------------------------
# 4. Tor exit node + scanner traffic against the web/firewall tier
# ---------------------------------------------------------------------------
scan_start = BASE_DATE.replace(hour=2, minute=0)
suspicious_paths = ["/wp-login.php", "/admin", "/phpmyadmin", "/.env", "/etc/passwd", "/wp-admin"]
for i, path in enumerate(suspicious_paths):
    t = scan_start + timedelta(seconds=i * 15)
    web_lines.append(
        f'{ATTACKER_SCANNER_IP} - - [{web_ts(t)}] "GET {path} HTTP/1.1" 404 210 "-" "curl/7.68.0"'
    )
    firewall_lines.append(f"{f_ts(t)},fw01,BLOCK,TCP,{ATTACKER_SCANNER_IP},10.0.0.10,443")

tor_time = BASE_DATE.replace(hour=2, minute=30)
web_lines.append(
    f'{ATTACKER_TOR_IP} - - [{web_ts(tor_time)}] "POST /wp-login.php HTTP/1.1" 401 512 "-" "python-requests/2.31"'
)
firewall_lines.append(f"{f_ts(tor_time)},fw01,ALLOW,TCP,{ATTACKER_TOR_IP},10.0.0.10,443")

# ---------------------------------------------------------------------------
# 5. Privilege escalation: sudo-to-root + Windows special-privilege events
# ---------------------------------------------------------------------------
priv_time = BASE_DATE.replace(hour=10, minute=15)
linux_lines.append(
    f"{l_ts(priv_time)} web01 sudo: agarcia : TTY=pts/0 ; PWD=/home/agarcia ; "
    f"USER=root ; COMMAND=/bin/bash"
)
linux_lines.append(
    f"{l_ts(priv_time + timedelta(minutes=2))} web01 sudo: agarcia : TTY=pts/0 ; "
    f"PWD=/etc ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
)
windows_lines.append(
    f"{w_ts(priv_time + timedelta(minutes=5))} EventID=4672 Account=agarcia LogonType=2 "
    f"SourceIP=10.0.0.12 Workstation=WIN-DC01 Status=success"
)
windows_lines.append(
    f"{w_ts(priv_time + timedelta(minutes=6))} EventID=4728 Account=agarcia LogonType=2 "
    f"SourceIP=10.0.0.12 Workstation=WIN-DC01 Status=success"
)

# ---------------------------------------------------------------------------
# 6. Unusual login hours: mchen logs in at 3 AM local/UTC
# ---------------------------------------------------------------------------
odd_hour_time = (BASE_DATE + timedelta(days=2)).replace(hour=3, minute=45)
windows_lines.append(
    f"{w_ts(odd_hour_time)} EventID=4624 Account=mchen LogonType=3 "
    f"SourceIP=10.0.0.31 Workstation=WIN-DC01 Status=success"
)
linux_lines.append(
    f"{l_ts(odd_hour_time + timedelta(minutes=1))} web01 sshd[4200]: Accepted password for mchen "
    f"from 10.0.0.31 port 51122 ssh2"
)

# ---------------------------------------------------------------------------
# 7. Multi-source credential stuffing against 'rpatel' (SSH + web login form)
# ---------------------------------------------------------------------------
stuff_start = BASE_DATE.replace(hour=20, minute=0)
for i in range(6):
    t = stuff_start + timedelta(minutes=i * 4)
    linux_lines.append(
        f"{l_ts(t)} web01 sshd[{5000+i}]: Failed password for rpatel "
        f"from {CRED_STUFF_IP} port {52000+i} ssh2"
    )
for i in range(6):
    t = stuff_start + timedelta(minutes=30 + i * 3)
    web_lines.append(
        f'{CRED_STUFF_IP} - rpatel [{web_ts(t)}] "POST /wp-login.php HTTP/1.1" 401 300 "-" "python-requests/2.31"'
    )
    firewall_lines.append(f"{f_ts(t)},fw01,ALLOW,TCP,{CRED_STUFF_IP},10.0.0.10,443")

# ---------------------------------------------------------------------------
# Write everything out, sorted by nothing in particular (real logs interleave)
# ---------------------------------------------------------------------------
(OUT_DIR / "windows_security.log").write_text("\n".join(windows_lines) + "\n")
(OUT_DIR / "linux_auth.log").write_text("\n".join(linux_lines) + "\n")
(OUT_DIR / "firewall.log").write_text("\n".join(firewall_lines) + "\n")
(OUT_DIR / "web_access.log").write_text("\n".join(web_lines) + "\n")

print(f"Wrote {len(windows_lines)} Windows, {len(linux_lines)} Linux, "
      f"{len(firewall_lines)} firewall, {len(web_lines)} web log lines to {OUT_DIR}")
