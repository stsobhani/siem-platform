"""
Log ingestion pipeline.

Reads raw log files for each source type, stores the raw line for audit /
replay purposes, normalizes it via the matching parser, and bulk-loads the
result into `normalized_events`.

Usage:
    python -m siem.ingestion.pipeline --source windows_auth data/sample_logs/windows_security.log
    python -m siem.ingestion.pipeline --all   # ingest every sample log shipped with the repo
"""
import argparse
import logging
from pathlib import Path
from typing import Iterable, List

from siem.db.models import RawLog, NormalizedEvent as NormalizedEventORM
from siem.db.session import get_engine, get_session_factory, init_db
from siem.parsers.base import NormalizedEvent
from siem.parsers.windows_parser import WindowsAuthParser
from siem.parsers.linux_parser import LinuxSSHParser
from siem.parsers.firewall_parser import FirewallParser
from siem.parsers.web_parser import WebServerParser

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ingestion")

PARSER_REGISTRY = {
    "windows_auth": WindowsAuthParser,
    "linux_ssh": LinuxSSHParser,
    "firewall": FirewallParser,
    "web_server": WebServerParser,
}

DEFAULT_SAMPLE_FILES = {
    "windows_auth": "data/sample_logs/windows_security.log",
    "linux_ssh": "data/sample_logs/linux_auth.log",
    "firewall": "data/sample_logs/firewall.log",
    "web_server": "data/sample_logs/web_access.log",
}


def _to_orm(event: NormalizedEvent, raw_log_id: int) -> NormalizedEventORM:
    return NormalizedEventORM(
        raw_log_id=raw_log_id,
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
    )


def ingest_file(source_type: str, path: str, session_factory=None) -> int:
    """Ingest a single raw log file for the given source type.
    Returns the number of normalized events written."""
    if source_type not in PARSER_REGISTRY:
        raise ValueError(f"Unknown source_type '{source_type}'. Options: {list(PARSER_REGISTRY)}")

    parser = PARSER_REGISTRY[source_type]()
    session_factory = session_factory or get_session_factory()
    lines = Path(path).read_text(encoding="utf-8", errors="ignore").splitlines()

    written = 0
    with session_factory() as session:
        for line in lines:
            if not line.strip():
                continue
            raw = RawLog(source_type=source_type, raw_message=line)
            session.add(raw)
            session.flush()  # get raw.id without committing

            try:
                event = parser.parse_line(line)
            except Exception as exc:  # never let one bad line kill the run
                logger.warning("Failed to parse line in %s: %s", path, exc)
                event = None

            if event is not None:
                session.add(_to_orm(event, raw.id))
                raw.processed = True
                written += 1
        session.commit()

    logger.info("Ingested %s: %d/%d lines normalized", path, written, len(lines))
    return written


def ingest_all(session_factory=None) -> int:
    total = 0
    for source_type, path in DEFAULT_SAMPLE_FILES.items():
        if Path(path).exists():
            total += ingest_file(source_type, path, session_factory=session_factory)
        else:
            logger.warning("Sample file missing, skipping: %s", path)
    return total


def main():
    parser = argparse.ArgumentParser(description="SIEM log ingestion pipeline")
    parser.add_argument("path", nargs="?", help="Path to the raw log file")
    parser.add_argument("--source", choices=list(PARSER_REGISTRY), help="Source type of the log file")
    parser.add_argument("--all", action="store_true", help="Ingest all default sample logs")
    parser.add_argument("--init-db", action="store_true", help="Create tables before ingesting")
    args = parser.parse_args()

    engine = get_engine()
    if args.init_db:
        init_db(engine)
    session_factory = get_session_factory(engine)

    if args.all:
        total = ingest_all(session_factory)
    elif args.source and args.path:
        total = ingest_file(args.source, args.path, session_factory)
    else:
        parser.error("Provide --all, or both a path and --source")
        return

    logger.info("Ingestion complete. Total normalized events written: %d", total)


if __name__ == "__main__":
    main()
