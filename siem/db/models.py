"""
SQLAlchemy ORM models for the SIEM platform.
Mirrors the schema defined in sql/init.sql.
"""
from sqlalchemy import (
    Column, BigInteger, Integer, String, Text, Boolean, Numeric,
    DateTime, ForeignKey, ARRAY
)
from sqlalchemy.dialects.postgresql import JSONB, INET
from sqlalchemy.orm import declarative_base
from datetime import datetime, timezone

Base = declarative_base()


def utcnow():
    return datetime.now(timezone.utc)


class RawLog(Base):
    __tablename__ = "raw_logs"

    id = Column(BigInteger, primary_key=True)
    source_type = Column(String(50), nullable=False)
    raw_message = Column(Text, nullable=False)
    ingested_at = Column(DateTime(timezone=True), default=utcnow)
    processed = Column(Boolean, default=False)


class NormalizedEvent(Base):
    __tablename__ = "normalized_events"

    id = Column(BigInteger, primary_key=True)
    raw_log_id = Column(BigInteger, ForeignKey("raw_logs.id", ondelete="SET NULL"))
    event_time = Column(DateTime(timezone=True), nullable=False)
    source_type = Column(String(50), nullable=False)
    host = Column(String(255))
    username = Column(String(255))
    src_ip = Column(INET)
    dst_ip = Column(INET)
    dst_port = Column(Integer)
    event_type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False, default="low")
    status_code = Column(Integer)
    additional_data = Column(JSONB)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(BigInteger, primary_key=True)
    rule_name = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False)
    src_ip = Column(INET)
    username = Column(String(255))
    host = Column(String(255))
    title = Column(String(255), nullable=False)
    description = Column(Text)
    risk_score = Column(Numeric(5, 2), default=0)
    event_ids = Column(ARRAY(BigInteger))
    detected_at = Column(DateTime(timezone=True), default=utcnow)
    status = Column(String(20), default="open")


class ThreatIntelIP(Base):
    __tablename__ = "threat_intel_ips"

    ip = Column(INET, primary_key=True)
    category = Column(String(100))
    confidence = Column(Integer)
    source = Column(String(100))
    added_at = Column(DateTime(timezone=True), default=utcnow)


class MLAnomalyScore(Base):
    __tablename__ = "ml_anomaly_scores"

    id = Column(BigInteger, primary_key=True)
    username = Column(String(255))
    event_time = Column(DateTime(timezone=True), nullable=False)
    anomaly_score = Column(Numeric(6, 4), nullable=False)
    is_anomaly = Column(Boolean, nullable=False)
    features = Column(JSONB)
    created_at = Column(DateTime(timezone=True), default=utcnow)
