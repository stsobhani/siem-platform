"""Unit tests for the Isolation Forest anomaly detection pipeline."""
from datetime import datetime, timedelta, timezone

import pandas as pd

from siem.ml.anomaly_detection import build_features, train_and_score, FEATURE_COLUMNS

BASE = datetime(2026, 7, 1, 9, 0, 0, tzinfo=timezone.utc)


def _normalized_events_df():
    rows = []
    idx = 1
    # 20 normal business-hours logins for 4 users, always from the same IP
    for i in range(20):
        rows.append({
            "id": idx, "event_time": BASE + timedelta(hours=i % 8), "source_type": "windows_auth",
            "event_type": "login_success", "username": f"user{i % 4}", "src_ip": "10.0.0.5",
            "host": "WIN-DC01", "dst_ip": None, "dst_port": None, "severity": "low",
            "status_code": None, "additional_data": None,
        })
        idx += 1
    # One clearly anomalous 3 AM login from a brand-new IP with recent failures
    rows.append({
        "id": idx, "event_time": BASE.replace(hour=3), "source_type": "windows_auth",
        "event_type": "login_failure", "username": "user0", "src_ip": "203.0.113.55",
        "host": "WIN-DC01", "dst_ip": None, "dst_port": None, "severity": "medium",
        "status_code": None, "additional_data": None,
    })
    idx += 1
    rows.append({
        "id": idx, "event_time": BASE.replace(hour=3, minute=5), "source_type": "windows_auth",
        "event_type": "login_success", "username": "user0", "src_ip": "203.0.113.55",
        "host": "WIN-DC01", "dst_ip": None, "dst_port": None, "severity": "low",
        "status_code": None, "additional_data": None,
    })
    df = pd.DataFrame(rows)
    df["event_time"] = pd.to_datetime(df["event_time"], utc=True)
    return df


class TestBuildFeatures:
    def test_returns_expected_columns(self):
        df = _normalized_events_df()
        features = build_features(df)
        for col in FEATURE_COLUMNS:
            assert col in features.columns
        assert len(features) == df[df["event_type"] == "login_success"].shape[0]

    def test_empty_input_returns_empty_frame(self):
        empty = pd.DataFrame(columns=[
            "id", "event_time", "source_type", "event_type", "username", "src_ip",
            "host", "dst_ip", "dst_port", "severity", "status_code", "additional_data",
        ])
        features = build_features(empty)
        assert features.empty

    def test_new_ip_flagged_on_first_sighting(self):
        df = _normalized_events_df()
        features = build_features(df)
        anomalous_row = features[features["src_ip"] == "203.0.113.55"]
        assert anomalous_row["is_new_source_ip"].iloc[0] == 1


class TestTrainAndScore:
    def test_produces_scores_between_0_and_1(self):
        df = _normalized_events_df()
        features = build_features(df)
        scored = train_and_score(features)
        assert "anomaly_score" in scored.columns
        assert "is_anomaly" in scored.columns
        assert scored["anomaly_score"].between(0, 1).all()

    def test_too_few_samples_returns_no_anomalies(self):
        tiny = pd.DataFrame([{
            "id": 1, "username": "user0", "event_time": BASE, "src_ip": "10.0.0.5",
            "hour_of_day": 9, "day_of_week": 2, "is_new_source_ip": 0,
            "failed_attempts_1h": 0, "logins_last_24h": 1, "is_off_hours": 0,
        }])
        scored = train_and_score(tiny)
        assert scored["is_anomaly"].sum() == 0
