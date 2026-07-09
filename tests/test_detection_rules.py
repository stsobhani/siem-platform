"""
Unit tests for the detection rule engine.

Each rule is tested against a small, hand-built pandas DataFrame so the
tests run fast and don't require a live database.
"""
from datetime import datetime, timedelta, timezone

import pandas as pd
import pytest

from siem.detection import rules


def _events(rows):
    """Helper: build a normalized_events-shaped DataFrame from row dicts."""
    defaults = {
        "id": None, "raw_log_id": None, "host": None, "username": None,
        "src_ip": None, "dst_ip": None, "dst_port": None, "status_code": None,
        "additional_data": None, "created_at": None,
    }
    full_rows = []
    for i, r in enumerate(rows, start=1):
        row = {**defaults, **r}
        row["id"] = row["id"] or i
        full_rows.append(row)
    df = pd.DataFrame(full_rows)
    df["event_time"] = pd.to_datetime(df["event_time"], utc=True)
    return df


BASE = datetime(2026, 7, 1, 3, 0, 0, tzinfo=timezone.utc)


class TestBruteForce:
    def test_flags_rapid_repeated_failures(self):
        rows = [
            {"event_time": BASE + timedelta(seconds=i * 20), "source_type": "linux_ssh",
             "event_type": "login_failure", "src_ip": "203.0.113.55", "username": "admin",
             "severity": "medium"}
            for i in range(6)
        ]
        df = _events(rows)
        alerts = rules.detect_brute_force(df)
        assert len(alerts) == 1
        assert alerts[0]["rule_name"] == "brute_force_login"
        assert alerts[0]["src_ip"] == "203.0.113.55"

    def test_no_alert_below_threshold(self):
        rows = [
            {"event_time": BASE + timedelta(minutes=i * 10), "source_type": "linux_ssh",
             "event_type": "login_failure", "src_ip": "203.0.113.55", "username": "admin",
             "severity": "medium"}
            for i in range(3)
        ]
        df = _events(rows)
        assert rules.detect_brute_force(df) == []


class TestImpossibleTravel:
    def test_flags_geographically_impossible_logins(self):
        rows = [
            {"event_time": BASE, "source_type": "windows_auth", "event_type": "login_success",
             "src_ip": "10.0.0.5", "username": "jsmith", "severity": "low"},
            {"event_time": BASE + timedelta(minutes=6), "source_type": "windows_auth",
             "event_type": "login_success", "src_ip": "198.51.100.23", "username": "jsmith",
             "severity": "low"},
        ]
        df = _events(rows)
        alerts = rules.detect_impossible_travel(df)
        assert len(alerts) == 1
        assert alerts[0]["rule_name"] == "impossible_travel"
        assert alerts[0]["severity"] == "critical"

    def test_no_alert_for_plausible_travel_time(self):
        rows = [
            {"event_time": BASE, "source_type": "windows_auth", "event_type": "login_success",
             "src_ip": "10.0.0.5", "username": "jsmith", "severity": "low"},
            {"event_time": BASE + timedelta(hours=20), "source_type": "windows_auth",
             "event_type": "login_success", "src_ip": "198.51.100.23", "username": "jsmith",
             "severity": "low"},
        ]
        df = _events(rows)
        assert rules.detect_impossible_travel(df) == []


class TestSuspiciousIP:
    def test_flags_known_bad_ip(self):
        rows = [
            {"event_time": BASE, "source_type": "firewall", "event_type": "conn_allowed",
             "src_ip": "185.220.101.13", "username": None, "severity": "low"},
        ]
        df = _events(rows)
        alerts = rules.detect_suspicious_ip(df, known_bad_ips={"185.220.101.13"})
        assert len(alerts) == 1
        assert alerts[0]["rule_name"] == "suspicious_ip_threat_intel"

    def test_no_alert_when_ip_not_in_feed(self):
        rows = [
            {"event_time": BASE, "source_type": "firewall", "event_type": "conn_allowed",
             "src_ip": "10.0.0.5", "username": None, "severity": "low"},
        ]
        df = _events(rows)
        assert rules.detect_suspicious_ip(df, known_bad_ips={"185.220.101.13"}) == []


class TestPrivilegeEscalation:
    def test_flags_sudo_to_root(self):
        rows = [
            {"event_time": BASE, "source_type": "linux_ssh", "event_type": "privilege_escalation",
             "host": "web01", "username": "agarcia", "src_ip": None, "severity": "high"},
        ]
        df = _events(rows)
        alerts = rules.detect_privilege_escalation(df)
        assert len(alerts) == 1
        assert alerts[0]["username"] == "agarcia"


class TestUnusualLoginHours:
    def test_flags_3am_login(self):
        rows = [
            {"event_time": BASE, "source_type": "windows_auth", "event_type": "login_success",
             "src_ip": "10.0.0.31", "username": "mchen", "severity": "low"},
        ]
        df = _events(rows)
        alerts = rules.detect_unusual_login_hours(df)
        assert len(alerts) == 1
        assert alerts[0]["rule_name"] == "unusual_login_hours"

    def test_no_alert_for_business_hours_login(self):
        rows = [
            {"event_time": BASE.replace(hour=10), "source_type": "windows_auth",
             "event_type": "login_success", "src_ip": "10.0.0.31", "username": "mchen",
             "severity": "low"},
        ]
        df = _events(rows)
        assert rules.detect_unusual_login_hours(df) == []


class TestMultipleFailedAuth:
    def test_flags_cross_source_failures(self):
        rows = []
        for i in range(10):
            rows.append({
                "event_time": BASE + timedelta(minutes=i * 3), "source_type": "linux_ssh",
                "event_type": "login_failure", "src_ip": "103.21.244.101",
                "username": "rpatel", "severity": "medium",
            })
        df = _events(rows)
        alerts = rules.detect_multiple_failed_auth(df)
        assert len(alerts) == 1
        assert alerts[0]["username"] == "rpatel"
