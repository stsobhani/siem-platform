"""
Live log simulator.

Continuously generates realistic security events using the actual current
time, writes them straight into the database through the same parser
classes the file-based pipeline uses, and periodically re-runs the
detection rules and the ML model. Leave this running in one terminal while
the dashboard is open in another, and the dashboard will show new events,
new alerts, and updated anomaly scores appearing in near real time.

This is a simulator, not a log replay tool: every event uses
datetime.now(timezone.utc) as its timestamp, so it looks like genuinely
live traffic rather than a fixed historical dataset. It mixes mostly normal
background activity with periodic attack scenarios so all six detection
rules and the ML model keep finding new things to flag as it runs.

Usage:
    python scripts/live_log_simulator.py
    python scripts/live_log_simulator.py --interval 5 --duration 600
"""
import argparse
import logging
import random
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from siem.db.models import RawLog, NormalizedEvent as NormalizedEventORM
from siem.db.session import get_engine, get_session_factory, init_db
from siem.detection.rules import run_all_rules, persist_alerts
from siem.detection.threat_intel import load_sample_feed
from siem.ml.anomaly_detection import run_pipeline as run_ml_pipeline
from siem.parsers.firewall_parser import FirewallParser
from siem.parsers.linux_parser import LinuxSSHParser
from siem.parsers.web_parser import WebServerParser
from siem.parsers.windows_parser import WindowsAuthParser

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("live_simulator")

EMPLOYEES = ["jsmith", "agarcia", "mchen", "rpatel", "kbrown"]
CORP_IPS = ["10.0.0.5", "10.0.0.12", "10.0.0.31", "192.168.1.44", "172.16.0.9"]
ATTACKER_IPS = ["203.0.113.55", "198.51.100.23", "185.220.101.13", "45.155.204.9", "103.21.244.101"]

_windows_parser = WindowsAuthParser()
_linux_parser = LinuxSSHParser()
_firewall_parser = FirewallParser()
_web_parser = WebServerParser()


def _w_ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _l_ts(dt):
    return dt.strftime("%b %e %H:%M:%S").replace("  ", " ")


def _f_ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _web_ts(dt):
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def _write_event(session, source_type: str, parser, raw_line: str):
    raw = RawLog(source_type=source_type, raw_message=raw_line)
    session.add(raw)
    session.flush()
    event = parser.parse_line(raw_line)
    if event is not None:
        session.add(NormalizedEventORM(
            raw_log_id=raw.id,
            event_time=event.event_time,
            source_type=event.source_type,
            host=event.host,
            username=event.username,
            src_ip=event.src_ip,
            dst_ip=event.dst_ip,
            dst_port=event.dst_port,
            event_type=event.event_type,
            severity=event.severity,
            status_code=event.status_code,
            additional_data=event.additional_data,
        ))
        raw.processed = True
    return event is not None


def emit_normal_login(session, now):
    user = random.choice(EMPLOYEES)
    ip = random.choice(CORP_IPS)
    line = (f"{_w_ts(now)} EventID=4624 Account={user} LogonType=3 "
            f"SourceIP={ip} Workstation=WIN-DC01 Status=success")
    _write_event(session, "windows_auth", _windows_parser, line)

    line = (f"{_l_ts(now)} web01 sshd[{random.randint(1000,9999)}]: "
            f"Accepted password for {user} from {ip} port {random.randint(40000,60000)} ssh2")
    _write_event(session, "linux_ssh", _linux_parser, line)
    return 2


def emit_background_traffic(session, now):
    ip = random.choice(CORP_IPS)
    line = f"{_f_ts(now)},fw01,ALLOW,TCP,{ip},10.0.0.10,443"
    _write_event(session, "firewall", _firewall_parser, line)

    user = random.choice(EMPLOYEES)
    line = (f'{ip} - {user} [{_web_ts(now)}] "GET /dashboard HTTP/1.1" 200 4521 '
            f'"-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"')
    _write_event(session, "web_server", _web_parser, line)
    return 2


def emit_brute_force_burst(session, now):
    attacker_ip = "203.0.113.55"
    count = 0
    for i in range(random.randint(6, 9)):
        t = now + timedelta(seconds=i * random.randint(10, 25))
        line = (f"{_l_ts(t)} web01 sshd[{random.randint(2000,2999)}]: "
                f"Failed password for invalid user admin from {attacker_ip} "
                f"port {50000+i} ssh2")
        if _write_event(session, "linux_ssh", _linux_parser, line):
            count += 1
    logger.info("Injected brute force burst from %s", attacker_ip)
    return count


def emit_suspicious_ip_hit(session, now):
    ip = random.choice(ATTACKER_IPS)
    line = f"{_f_ts(now)},fw01,BLOCK,TCP,{ip},10.0.0.10,443"
    _write_event(session, "firewall", _firewall_parser, line)
    logger.info("Injected threat-intel IP hit from %s", ip)
    return 1


def emit_privilege_escalation(session, now):
    user = random.choice(EMPLOYEES)
    line = (f"{_l_ts(now)} web01 sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; "
            f"USER=root ; COMMAND=/bin/bash")
    _write_event(session, "linux_ssh", _linux_parser, line)
    logger.info("Injected privilege escalation event for %s", user)
    return 1


def emit_off_hours_login(session, now):
    # Backfill a login timestamped a few hours ago at a genuinely odd hour,
    # simulating a report that just arrived for an earlier off-hours access.
    odd_hour_time = now.replace(hour=random.choice([1, 2, 3, 4]), minute=random.randint(0, 59))
    if odd_hour_time > now:
        odd_hour_time -= timedelta(days=1)
    user = random.choice(EMPLOYEES)
    ip = random.choice(CORP_IPS)
    line = (f"{_w_ts(odd_hour_time)} EventID=4624 Account={user} LogonType=3 "
            f"SourceIP={ip} Workstation=WIN-DC01 Status=success")
    _write_event(session, "windows_auth", _windows_parser, line)
    logger.info("Injected off-hours login for %s at %s", user, odd_hour_time.strftime("%H:%M UTC"))
    return 1


def emit_impossible_travel(session, now):
    user = random.choice(EMPLOYEES)
    corp_ip = random.choice(CORP_IPS)
    remote_ip = random.choice(["198.51.100.23", "203.0.113.77"])
    line1 = (f"{_w_ts(now)} EventID=4624 Account={user} LogonType=3 "
             f"SourceIP={corp_ip} Workstation=WIN-DC01 Status=success")
    _write_event(session, "windows_auth", _windows_parser, line1)
    t2 = now + timedelta(minutes=random.randint(3, 8))
    line2 = (f"{_w_ts(t2)} EventID=4624 Account={user} LogonType=3 "
             f"SourceIP={remote_ip} Workstation=WIN-DC01 Status=success")
    _write_event(session, "windows_auth", _windows_parser, line2)
    logger.info("Injected impossible travel scenario for %s", user)
    return 2


SCENARIOS = [
    (emit_normal_login, 45),
    (emit_background_traffic, 35),
    (emit_brute_force_burst, 6),
    (emit_suspicious_ip_hit, 6),
    (emit_privilege_escalation, 4),
    (emit_off_hours_login, 2),
    (emit_impossible_travel, 2),
]


def _pick_scenario():
    funcs, weights = zip(*SCENARIOS)
    return random.choices(funcs, weights=weights, k=1)[0]


def run(interval_seconds: int, duration_seconds: int, detection_every: int, ml_every: int):
    engine = get_engine()
    init_db(engine)
    session_factory = get_session_factory(engine)

    with session_factory() as session:
        load_sample_feed(session)

    start = time.time()
    tick = 0
    total_events = 0

    logger.info(
        "Starting live simulator: interval=%ds, detection every %d ticks, ML every %d ticks. "
        "Press Ctrl+C to stop.",
        interval_seconds, detection_every, ml_every,
    )

    try:
        while duration_seconds <= 0 or (time.time() - start) < duration_seconds:
            tick += 1
            now = datetime.now(timezone.utc)
            scenario = _pick_scenario()

            with session_factory() as session:
                n = scenario(session, now)
                session.commit()
                total_events += n

            logger.info("Tick %d: %s produced %d event(s). Total events written: %d",
                        tick, scenario.__name__, n, total_events)

            if tick % detection_every == 0:
                with session_factory() as session:
                    alerts = run_all_rules(session)
                    written = persist_alerts(session, alerts)
                    logger.info("Detection pass complete: %d condition(s) evaluated, %d new alert(s) written",
                                len(alerts), written)

            if tick % ml_every == 0:
                with session_factory() as session:
                    scored = run_ml_pipeline(session)
                    n_anom = int(scored["is_anomaly"].sum()) if not scored.empty else 0
                    logger.info("ML pass complete: %d/%d logins flagged anomalous",
                                n_anom, len(scored))

            time.sleep(interval_seconds)
    except KeyboardInterrupt:
        logger.info("Stopped by user after %d ticks, %d events written.", tick, total_events)


def main():
    parser = argparse.ArgumentParser(description="Live SIEM data simulator")
    parser.add_argument("--interval", type=int, default=8,
                        help="Seconds between simulated event batches (default: 8)")
    parser.add_argument("--duration", type=int, default=0,
                        help="Total seconds to run, 0 means run until Ctrl+C (default: 0)")
    parser.add_argument("--detection-every", type=int, default=4,
                        help="Run the detection engine every N ticks (default: 4)")
    parser.add_argument("--ml-every", type=int, default=8,
                        help="Run the ML pipeline every N ticks (default: 8)")
    args = parser.parse_args()

    run(args.interval, args.duration, args.detection_every, args.ml_every)


if __name__ == "__main__":
    main()
