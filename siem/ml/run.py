"""
CLI entrypoint: run the Isolation Forest anomaly detection pipeline and
persist scores to `ml_anomaly_scores`.

Usage:
    python -m siem.ml.run
"""
import logging

from siem.db.session import get_engine, get_session_factory
from siem.ml.anomaly_detection import run_pipeline

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ml.run")


def main():
    engine = get_engine()
    session_factory = get_session_factory(engine)
    with session_factory() as session:
        scored = run_pipeline(session)
        n_anom = int(scored["is_anomaly"].sum()) if not scored.empty else 0
        logger.info("ML pipeline complete. %d/%d logins flagged as anomalous.",
                     n_anom, len(scored))


if __name__ == "__main__":
    main()
