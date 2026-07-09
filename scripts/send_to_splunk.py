"""
Forwards normalized events and/or alerts from PostgreSQL to Splunk via the
HTTP Event Collector (HEC).

This is the "single pane of glass" integration: the Python pipeline stays
the system of record and does all the parsing/normalization/detection work,
while Splunk is used as the enterprise-grade search, dashboarding, and
long-term retention layer on top of that same normalized data -- exactly the
role Splunk plays in a real SOC.

Setup:
    1. In Splunk: Settings -> Data Inputs -> HTTP Event Collector -> New Token
    2. Enable the "siem" index (or use one of your own): Settings -> Indexes
    3. Export the token + URL:
         export SPLUNK_HEC_URL="https://<splunk-host>:8088/services/collector"
         export SPLUNK_HEC_TOKEN="<token>"
         export SPLUNK_INDEX="siem"

Usage:
    python scripts/send_to_splunk.py --what events   # forward normalized_events
    python scripts/send_to_splunk.py --what alerts    # forward alerts
    python scripts/send_to_splunk.py --what all       # forward both
"""
import argparse
import json
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests
from sqlalchemy import text

from siem.config import config
from siem.db.session import get_engine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("send_to_splunk")


def _post_batch(events: list) -> None:
    headers = {"Authorization": f"Splunk {config.SPLUNK_HEC_TOKEN}"}
    # HEC accepts back-to-back JSON objects (not a JSON array) in one POST body
    payload = "\n".join(json.dumps(e) for e in events)
    resp = requests.post(
        config.SPLUNK_HEC_URL,
        headers=headers,
        data=payload,
        verify=config.SPLUNK_VERIFY_SSL,
        timeout=10,
    )
    resp.raise_for_status()


def forward_events(engine, batch_size: int = 200) -> int:
    rows = engine.execute(text("SELECT * FROM normalized_events ORDER BY event_time")).mappings().all() \
        if hasattr(engine, "execute") else None
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT * FROM normalized_events ORDER BY event_time")).mappings().all()

    total = 0
    batch = []
    for row in rows:
        d = dict(row)
        event_time = d.pop("event_time")
        hec_event = {
            "time": event_time.timestamp(),
            "sourcetype": f"siem:{d.get('source_type', 'event')}",
            "index": config.SPLUNK_INDEX,
            "event": {k: (str(v) if v is not None else None) for k, v in d.items()},
        }
        batch.append(hec_event)
        if len(batch) >= batch_size:
            _post_batch(batch)
            total += len(batch)
            batch = []
    if batch:
        _post_batch(batch)
        total += len(batch)
    return total


def forward_alerts(engine, batch_size: int = 200) -> int:
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT * FROM alerts ORDER BY detected_at")).mappings().all()

    total = 0
    batch = []
    for row in rows:
        d = dict(row)
        detected_at = d.pop("detected_at")
        hec_event = {
            "time": detected_at.timestamp(),
            "sourcetype": "siem:alert",
            "index": config.SPLUNK_INDEX,
            "event": {k: (str(v) if v is not None else None) for k, v in d.items()},
        }
        batch.append(hec_event)
        if len(batch) >= batch_size:
            _post_batch(batch)
            total += len(batch)
            batch = []
    if batch:
        _post_batch(batch)
        total += len(batch)
    return total


def main():
    parser = argparse.ArgumentParser(description="Forward SIEM data to Splunk via HEC")
    parser.add_argument("--what", choices=["events", "alerts", "all"], default="all")
    args = parser.parse_args()

    if not config.SPLUNK_HEC_TOKEN:
        logger.error("SPLUNK_HEC_TOKEN is not set. Export it before running this script.")
        sys.exit(1)

    engine = get_engine()

    total = 0
    if args.what in ("events", "all"):
        n = forward_events(engine)
        logger.info("Forwarded %d normalized events to Splunk", n)
        total += n
    if args.what in ("alerts", "all"):
        n = forward_alerts(engine)
        logger.info("Forwarded %d alerts to Splunk", n)
        total += n

    logger.info("Done. %d total records forwarded.", total)


if __name__ == "__main__":
    main()
