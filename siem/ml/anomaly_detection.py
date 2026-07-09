"""
Unsupervised anomaly detection on login behavior using Isolation Forest.

Feature engineering turns each login_success event into a small behavioral
feature vector per user:
    - hour_of_day            : 0-23
    - day_of_week            : 0-6 (Monday=0)
    - is_new_source_ip       : 1 if this is the first time we've seen this
                                (user, src_ip) pair, else 0
    - failed_attempts_1h     : count of that user's failed logins in the
                                hour preceding this login
    - logins_last_24h        : how many times this user has logged in the
                                previous 24 hours (velocity)
    - is_off_hours           : 1 if outside configured business hours

Isolation Forest is well suited here because it doesn't require labeled
"attack" data (which we'd never realistically have for novel behavior) --
it isolates points that are easy to separate from the rest of the
distribution, which tends to correspond to rare/anomalous behavior.
"""
from __future__ import annotations

import logging
from typing import Tuple

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sqlalchemy import text

from siem.config import config

logger = logging.getLogger("ml.anomaly_detection")

FEATURE_COLUMNS = [
    "hour_of_day",
    "day_of_week",
    "is_new_source_ip",
    "failed_attempts_1h",
    "logins_last_24h",
    "is_off_hours",
]


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    """Given the full normalized_events DataFrame, build a per-login feature
    table for every login_success event."""
    df = df.copy()
    df["event_time"] = pd.to_datetime(df["event_time"], utc=True)
    df = df.sort_values("event_time")

    logins = df[df["event_type"] == "login_success"].dropna(subset=["username"]).copy()
    failures = df[df["event_type"] == "login_failure"].dropna(subset=["username"])

    if logins.empty:
        return pd.DataFrame(columns=["id", "username", "event_time", *FEATURE_COLUMNS])

    logins["hour_of_day"] = logins["event_time"].dt.hour
    logins["day_of_week"] = logins["event_time"].dt.dayofweek
    logins["is_off_hours"] = (
        (logins["hour_of_day"] < config.UNUSUAL_HOUR_START)
        | (logins["hour_of_day"] >= config.UNUSUAL_HOUR_END)
    ).astype(int)

    seen_pairs = set()
    is_new_ip = []
    failed_1h = []
    logins_24h = []

    # Pre-index failures per user for fast windowed counting
    failures_by_user = {u: g.sort_values("event_time") for u, g in failures.groupby("username")}
    logins_by_user_running = {}  # username -> list of prior login timestamps

    for row in logins.itertuples():
        user = row.username
        ip = row.src_ip
        t = row.event_time

        pair_key = (user, ip)
        is_new_ip.append(0 if pair_key in seen_pairs else 1)
        seen_pairs.add(pair_key)

        if user in failures_by_user:
            fg = failures_by_user[user]
            count = ((fg["event_time"] <= t) & (fg["event_time"] > t - pd.Timedelta(hours=1))).sum()
        else:
            count = 0
        failed_1h.append(int(count))

        prior = logins_by_user_running.setdefault(user, [])
        count_24h = sum(1 for pt in prior if t - pd.Timedelta(hours=24) < pt <= t)
        logins_24h.append(count_24h)
        prior.append(t)

    logins["is_new_source_ip"] = is_new_ip
    logins["failed_attempts_1h"] = failed_1h
    logins["logins_last_24h"] = logins_24h

    return logins[["id", "username", "event_time", "src_ip", *FEATURE_COLUMNS]]


def train_and_score(features_df: pd.DataFrame) -> pd.DataFrame:
    """Fit an Isolation Forest on the feature table and return scored rows."""
    if features_df.empty or len(features_df) < 10:
        logger.warning("Not enough login events (%d) to train a meaningful model.", len(features_df))
        features_df = features_df.copy()
        features_df["anomaly_score"] = 0.0
        features_df["is_anomaly"] = False
        return features_df

    X = features_df[FEATURE_COLUMNS].values
    model = IsolationForest(
        n_estimators=200,
        contamination=config.ISOLATION_FOREST_CONTAMINATION,
        random_state=42,
    )
    model.fit(X)

    # decision_function: higher = more normal. We invert + min-max scale to
    # 0-1 so "1.0" always means "most anomalous" regardless of model internals.
    raw_scores = -model.decision_function(X)
    scaled = (raw_scores - raw_scores.min()) / (raw_scores.max() - raw_scores.min() + 1e-9)

    result = features_df.copy()
    result["anomaly_score"] = scaled
    result["is_anomaly"] = model.predict(X) == -1
    return result


def run_pipeline(session) -> pd.DataFrame:
    """End-to-end: load events, engineer features, score, persist to
    ml_anomaly_scores, return the scored DataFrame."""
    df = pd.read_sql(text("SELECT * FROM normalized_events"), session.bind)
    if df.empty:
        logger.info("No events available for ML scoring.")
        return pd.DataFrame()

    features = build_features(df)
    scored = train_and_score(features)

    if not scored.empty:
        _persist_scores(session, scored)
    return scored


def _persist_scores(session, scored: pd.DataFrame):
    """Replace the current contents of ml_anomaly_scores with this run's
    results. The model is refit on the full event history every run, so
    scores for the same login can shift slightly as new data arrives --
    a replace-on-refresh table reflects the model's current view rather
    than accumulating duplicate rows for the same logins on every pass."""
    from siem.db.models import MLAnomalyScore

    session.query(MLAnomalyScore).delete()

    for row in scored.itertuples():
        features = {col: getattr(row, col) for col in FEATURE_COLUMNS}
        session.add(MLAnomalyScore(
            username=row.username,
            event_time=row.event_time,
            anomaly_score=float(row.anomaly_score),
            is_anomaly=bool(row.is_anomaly),
            features=features,
        ))
    session.commit()
