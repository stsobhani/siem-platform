"""
Threat intelligence IP reputation feed.

Ships with a small bundled CSV of "known-bad" sample IPs (data/threat_intel_ips.csv)
so the suspicious-IP detection rule works out of the box with zero API keys.

Production upgrade path: replace `load_sample_feed()` with a scheduled job
that pulls from AbuseIPDB, AlienVault OTX, or VirusTotal and upserts into the
`threat_intel_ips` table -- the detection rule itself only ever reads from
that table, so no downstream code changes are required.
"""
import csv
from pathlib import Path
from typing import Set

from sqlalchemy import text

SAMPLE_FEED_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "threat_intel_ips.csv"


def load_sample_feed(session) -> int:
    """Load the bundled sample threat-intel CSV into the threat_intel_ips table."""
    if not SAMPLE_FEED_PATH.exists():
        return 0

    count = 0
    with open(SAMPLE_FEED_PATH, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            session.execute(
                text(
                    """
                    INSERT INTO threat_intel_ips (ip, category, confidence, source)
                    VALUES (:ip, :category, :confidence, :source)
                    ON CONFLICT (ip) DO UPDATE SET
                        category = EXCLUDED.category,
                        confidence = EXCLUDED.confidence,
                        source = EXCLUDED.source
                    """
                ),
                {
                    "ip": row["ip"],
                    "category": row["category"],
                    "confidence": int(row["confidence"]),
                    "source": row["source"],
                },
            )
            count += 1
    session.commit()
    return count


def get_known_bad_ips(session) -> Set[str]:
    """Return the current set of IPs flagged in threat_intel_ips."""
    rows = session.execute(text("SELECT host(ip) AS ip FROM threat_intel_ips")).fetchall()
    return {row.ip for row in rows}
