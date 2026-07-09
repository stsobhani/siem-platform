"""
Detection rule engine.

Each `detect_*` function takes a pandas DataFrame of normalized events
(and, where needed, a live DB session for reference-data lookups like threat
intel) and returns a list of alert dicts ready to be persisted as `Alert`
rows. `run_all_rules()` is the orchestrator that ties everything together
and is what the ingestion pipeline / a scheduled job would call.

Design note: pandas is used for the windowed/group analytics because it
keeps the rule logic readable and easy to unit test in isolation (feed in a
DataFrame, assert on the alerts produced) without needing a live database in
every test. In a higher-throughput production deployment, these same rules
would be expressed as streaming/windowed SQL (or a stream processor like
Kafka Streams/Flink) -- the detection *logic* stays identical either way.
"""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import List, Dict, Any

import pandas as pd
from sqlalchemy import text

from siem.config import config
from siem.detection import geoip
from siem.detection.threat_intel import get_known_bad_ips

logger = logging.getLogger("detection")

SEVERITY_WEIGHT = {"low": 1, "medium": 3, "high": 6, "critical": 9}


def _risk_score(severity: str, multiplier: float = 1.0) -> float:
    base = SEVERITY_WEIGHT.get(severity, 1) * 10
    return round(min(base * multiplier, 100), 2)


def load_events(session, since: pd.Timestamp = None) -> pd.DataFrame:
    """Pull normalized events into a DataFrame for rule evaluation."""
    query = "SELECT * FROM normalized_events"
    params = {}
    if since is not None:
        query += " WHERE event_time >= :since"
        params["since"] = since
    query += " ORDER BY event_time"
    df = pd.read_sql(text(query), session.bind, params=params)
    if not df.empty:
        df["event_time"] = pd.to_datetime(df["event_time"], utc=True)
    return df


# ---------------------------------------------------------------------------
# Rule 1: Brute force login detection
# ---------------------------------------------------------------------------
def detect_brute_force(df: pd.DataFrame) -> List[Dict[str, Any]]:
    alerts = []
    failures = df[df["event_type"] == "login_failure"].dropna(subset=["src_ip"])
    window = timedelta(minutes=config.BRUTE_FORCE_WINDOW_MINUTES)
    threshold = config.BRUTE_FORCE_ATTEMPT_THRESHOLD

    for src_ip, group in failures.groupby("src_ip"):
        group = group.sort_values("event_time")
        times = group["event_time"].tolist()
        ids = group["id"].tolist()
        users = group["username"].tolist()

        i = 0
        for j in range(len(times)):
            while times[j] - times[i] > window:
                i += 1
            count = j - i + 1
            if count >= threshold:
                alerts.append({
                    "rule_name": "brute_force_login",
                    "severity": "high",
                    "src_ip": src_ip,
                    "username": users[j],
                    "title": f"Brute-force login attempts from {src_ip}",
                    "description": (
                        f"{count} failed login attempts from {src_ip} within "
                        f"{config.BRUTE_FORCE_WINDOW_MINUTES} minutes "
                        f"(targeting user(s): {sorted(set(users[i:j+1]))})."
                    ),
                    "risk_score": _risk_score("high", multiplier=min(count / threshold, 2.5)),
                    "event_ids": ids[i:j + 1],
                    "detected_at": times[j],
                })
                i = j + 1  # avoid re-alerting on the same overlapping window repeatedly
    return alerts


# ---------------------------------------------------------------------------
# Rule 2: Impossible travel detection
# ---------------------------------------------------------------------------
def detect_impossible_travel(df: pd.DataFrame) -> List[Dict[str, Any]]:
    alerts = []
    successes = df[
        (df["event_type"] == "login_success") & df["src_ip"].notna() & df["username"].notna()
    ]

    for username, group in successes.groupby("username"):
        group = group.sort_values("event_time")
        rows = group.to_dict("records")
        for prev, curr in zip(rows, rows[1:]):
            p1 = geoip.locate(prev["src_ip"])
            p2 = geoip.locate(curr["src_ip"])
            if not p1 or not p2 or p1.city == p2.city:
                continue
            seconds = (curr["event_time"] - prev["event_time"]).total_seconds()
            speed = geoip.implied_speed_kmh(p1, p2, seconds)
            if speed > config.IMPOSSIBLE_TRAVEL_MAX_KMH:
                alerts.append({
                    "rule_name": "impossible_travel",
                    "severity": "critical",
                    "src_ip": curr["src_ip"],
                    "username": username,
                    "title": f"Impossible travel detected for user {username}",
                    "description": (
                        f"{username} logged in from {p1.city}, {p1.country} then "
                        f"{p2.city}, {p2.country} {seconds/60:.1f} minutes later "
                        f"(implied speed ~{speed:,.0f} km/h)."
                    ),
                    "risk_score": _risk_score("critical"),
                    "event_ids": [prev["id"], curr["id"]],
                    "detected_at": curr["event_time"],
                })
    return alerts


# ---------------------------------------------------------------------------
# Rule 3: Suspicious IP detection (threat intel match)
# ---------------------------------------------------------------------------
def detect_suspicious_ip(df: pd.DataFrame, known_bad_ips: set) -> List[Dict[str, Any]]:
    alerts = []
    if not known_bad_ips:
        return alerts

    hits = df[df["src_ip"].isin(known_bad_ips)]
    for src_ip, group in hits.groupby("src_ip"):
        group = group.sort_values("event_time")
        alerts.append({
            "rule_name": "suspicious_ip_threat_intel",
            "severity": "high",
            "src_ip": src_ip,
            "username": group["username"].dropna().iloc[0] if group["username"].notna().any() else None,
            "title": f"Traffic from known-malicious IP {src_ip}",
            "description": (
                f"{len(group)} event(s) observed from {src_ip}, which matches a "
                f"known-bad indicator in the threat intelligence feed."
            ),
            "risk_score": _risk_score("high", multiplier=min(len(group) / 3, 2)),
            "event_ids": group["id"].tolist(),
            "detected_at": group["event_time"].max(),
        })
    return alerts


# ---------------------------------------------------------------------------
# Rule 4: Privilege escalation detection
# ---------------------------------------------------------------------------
def detect_privilege_escalation(df: pd.DataFrame) -> List[Dict[str, Any]]:
    alerts = []
    priv_events = df[df["event_type"] == "privilege_escalation"]
    for (username, host), group in priv_events.groupby(["username", "host"]):
        group = group.sort_values("event_time")
        alerts.append({
            "rule_name": "privilege_escalation",
            "severity": "high",
            "src_ip": group["src_ip"].dropna().iloc[0] if group["src_ip"].notna().any() else None,
            "username": username,
            "title": f"Privilege escalation activity by {username} on {host}",
            "description": (
                f"{len(group)} privilege-escalation event(s) (sudo/admin-token) "
                f"by {username} on {host}."
            ),
            "risk_score": _risk_score("high", multiplier=min(len(group), 3)),
            "event_ids": group["id"].tolist(),
            "detected_at": group["event_time"].max(),
        })
    return alerts


# ---------------------------------------------------------------------------
# Rule 5: Unusual login hours
# ---------------------------------------------------------------------------
def detect_unusual_login_hours(df: pd.DataFrame) -> List[Dict[str, Any]]:
    alerts = []
    logins = df[df["event_type"] == "login_success"].copy()
    if logins.empty:
        return alerts
    logins["hour"] = logins["event_time"].dt.hour
    off_hours = logins[
        (logins["hour"] < config.UNUSUAL_HOUR_START) | (logins["hour"] >= config.UNUSUAL_HOUR_END)
    ]
    for _, row in off_hours.iterrows():
        alerts.append({
            "rule_name": "unusual_login_hours",
            "severity": "medium",
            "src_ip": row["src_ip"],
            "username": row["username"],
            "title": f"Off-hours login by {row['username']}",
            "description": (
                f"{row['username']} logged in at {row['event_time'].strftime('%H:%M UTC')}, "
                f"outside the configured business-hours window "
                f"({config.UNUSUAL_HOUR_START}:00-{config.UNUSUAL_HOUR_END}:00)."
            ),
            "risk_score": _risk_score("medium"),
            "event_ids": [row["id"]],
            "detected_at": row["event_time"],
        })
    return alerts


# ---------------------------------------------------------------------------
# Rule 6: Multiple failed authentication attempts (broader / cross-source)
# ---------------------------------------------------------------------------
def detect_multiple_failed_auth(df: pd.DataFrame) -> List[Dict[str, Any]]:
    alerts = []
    fail_types = {"login_failure", "http_auth_failure"}
    failures = df[df["event_type"].isin(fail_types)].dropna(subset=["username"])
    window = timedelta(minutes=config.MULTI_FAIL_WINDOW_MINUTES)
    threshold = config.MULTI_FAIL_THRESHOLD

    for username, group in failures.groupby("username"):
        group = group.sort_values("event_time")
        times = group["event_time"].tolist()
        ids = group["id"].tolist()
        sources = group["source_type"].tolist()

        i = 0
        for j in range(len(times)):
            while times[j] - times[i] > window:
                i += 1
            count = j - i + 1
            if count >= threshold:
                alerts.append({
                    "rule_name": "multiple_failed_auth",
                    "severity": "high",
                    "src_ip": group["src_ip"].iloc[j],
                    "username": username,
                    "title": f"Repeated failed authentication for {username}",
                    "description": (
                        f"{count} failed authentication events for user {username} "
                        f"across sources {sorted(set(sources[i:j+1]))} within "
                        f"{config.MULTI_FAIL_WINDOW_MINUTES} minutes."
                    ),
                    "risk_score": _risk_score("high", multiplier=min(count / threshold, 2)),
                    "event_ids": ids[i:j + 1],
                    "detected_at": times[j],
                })
                i = j + 1
    return alerts


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
def run_all_rules(session) -> List[Dict[str, Any]]:
    df = load_events(session)
    if df.empty:
        logger.info("No normalized events found -- nothing to evaluate.")
        return []

    known_bad_ips = get_known_bad_ips(session)

    all_alerts: List[Dict[str, Any]] = []
    all_alerts += detect_brute_force(df)
    all_alerts += detect_impossible_travel(df)
    all_alerts += detect_suspicious_ip(df, known_bad_ips)
    all_alerts += detect_privilege_escalation(df)
    all_alerts += detect_unusual_login_hours(df)
    all_alerts += detect_multiple_failed_auth(df)

    logger.info("Detection run produced %d alerts", len(all_alerts))
    return all_alerts


def _existing_alert_keys(session) -> set:
    """Build a set of (rule_name, event_ids-tuple) for alerts already in the
    database, so re-running detection against unchanged events (which
    happens naturally every time the live simulator or a scheduled job
    re-evaluates the full event history) does not write duplicate alerts."""
    from siem.db.models import Alert

    rows = session.query(Alert.rule_name, Alert.event_ids).all()
    keys = set()
    for rule_name, event_ids in rows:
        keys.add((rule_name, tuple(sorted(event_ids or []))))
    return keys


def persist_alerts(session, alerts: List[Dict[str, Any]]) -> int:
    """Insert alerts that represent genuinely new evidence. An alert is
    considered a duplicate of an existing one if it has the same rule and
    the exact same set of underlying event ids -- i.e. the same evidence
    already triggered this rule before."""
    from siem.db.models import Alert

    existing_keys = _existing_alert_keys(session)
    written = 0

    for a in alerts:
        key = (a["rule_name"], tuple(sorted(a["event_ids"] or [])))
        if key in existing_keys:
            continue
        existing_keys.add(key)

        session.add(Alert(
            rule_name=a["rule_name"],
            severity=a["severity"],
            src_ip=a.get("src_ip"),
            username=a.get("username"),
            host=a.get("host"),
            title=a["title"],
            description=a["description"],
            risk_score=a["risk_score"],
            event_ids=a["event_ids"],
            detected_at=a["detected_at"],
        ))
        written += 1

    session.commit()
    return written
