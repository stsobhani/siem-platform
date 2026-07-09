"""
Base parser interface. Every source-specific parser implements `parse_line`
and returns a NormalizedEvent (or None if the line should be skipped, e.g.
malformed or irrelevant lines).

Keeping every parser conform to this single output shape is what lets the
downstream detection engine and dashboard stay source-agnostic -- this is
the "normalization" step that a real SIEM lives and dies by.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any


@dataclass
class NormalizedEvent:
    event_time: datetime
    source_type: str
    event_type: str
    host: Optional[str] = None
    username: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    severity: str = "low"
    status_code: Optional[int] = None
    additional_data: Dict[str, Any] = field(default_factory=dict)
    raw_message: str = ""

    def as_dict(self) -> Dict[str, Any]:
        d = self.__dict__.copy()
        d["event_time"] = self.event_time.isoformat()
        return d


class BaseParser(ABC):
    source_type: str = "unknown"

    @abstractmethod
    def parse_line(self, line: str) -> Optional[NormalizedEvent]:
        """Parse a single raw log line into a NormalizedEvent, or return None
        if the line is empty/unparseable and should be discarded."""
        raise NotImplementedError

    def parse_lines(self, lines):
        for line in lines:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            try:
                event = self.parse_line(line)
            except Exception:
                # A malformed line should never crash the pipeline -- in
                # production this would emit to a dead-letter/parse-error queue.
                event = None
            if event is not None:
                yield event
