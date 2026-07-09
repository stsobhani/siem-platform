"""
CLI entrypoint: loads the threat intel feed, runs every detection rule
against the current contents of `normalized_events`, and writes results to
the `alerts` table.

Usage:
    python -m siem.detection.run
"""
import logging

from siem.db.session import get_engine, get_session_factory
from siem.detection.rules import run_all_rules, persist_alerts
from siem.detection.threat_intel import load_sample_feed

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("detection.run")


def main():
    engine = get_engine()
    session_factory = get_session_factory(engine)

    with session_factory() as session:
        n_intel = load_sample_feed(session)
        logger.info("Loaded %d threat intel indicators", n_intel)

        alerts = run_all_rules(session)
        written = persist_alerts(session, alerts)
        logger.info("Evaluated %d alert condition(s), wrote %d new alert(s) to the database",
                    len(alerts), written)


if __name__ == "__main__":
    main()
