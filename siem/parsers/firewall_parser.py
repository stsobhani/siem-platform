"""
Parser for firewall logs, modeled on a simplified pfSense/OPNsense CSV export.

Expected format:
    timestamp,firewall_host,action,protocol,src_ip,dst_ip,dst_port

Example:
    2026-07-01T08:15:32Z,fw01,BLOCK,TCP,203.0.113.55,10.0.0.10,443
    2026-07-01T08:15:40Z,fw01,ALLOW,TCP,10.0.0.5,10.0.0.10,22
"""
from datetime import datetime, timezone
from typing import Optional

from siem.parsers.base import BaseParser, NormalizedEvent

_ACTION_MAP = {
    "BLOCK": ("conn_denied", "medium"),
    "ALLOW": ("conn_allowed", "low"),
    "DROP": ("conn_denied", "medium"),
}


class FirewallParser(BaseParser):
    source_type = "firewall"

    def parse_line(self, line: str) -> Optional[NormalizedEvent]:
        parts = [p.strip() for p in line.strip().split(",")]
        if len(parts) != 7:
            return None

        ts, host, action, protocol, src_ip, dst_ip, dst_port = parts

        try:
            event_time = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc
            )
            dst_port_int = int(dst_port)
        except ValueError:
            return None

        event_type, severity = _ACTION_MAP.get(action.upper(), ("unknown_action", "low"))

        return NormalizedEvent(
            event_time=event_time,
            source_type=self.source_type,
            event_type=event_type,
            host=host,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port_int,
            severity=severity,
            additional_data={"protocol": protocol, "action": action.upper()},
            raw_message=line.strip(),
        )
