"""
Parser for Apache/nginx "combined" access log format:

    203.0.113.55 - - [01/Jul/2026:08:15:32 +0000] "GET /wp-login.php HTTP/1.1" 200 512 "-" "curl/7.68.0"
"""
import re
from datetime import datetime, timezone
from typing import Optional

from siem.parsers.base import BaseParser, NormalizedEvent

_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)"'
)

_SUSPICIOUS_PATH_MARKERS = (
    "wp-login.php", "/admin", "phpmyadmin", "../", "etc/passwd",
    "select%20", "union%20select", ".env", "wp-admin",
)


class WebServerParser(BaseParser):
    source_type = "web_server"

    def parse_line(self, line: str) -> Optional[NormalizedEvent]:
        match = _COMBINED_RE.match(line.strip())
        if not match:
            return None

        gd = match.groupdict()
        try:
            event_time = datetime.strptime(gd["ts"], "%d/%b/%Y:%H:%M:%S %z").astimezone(
                timezone.utc
            )
        except ValueError:
            return None

        status = int(gd["status"])
        path_lower = gd["path"].lower()
        is_suspicious = any(marker in path_lower for marker in _SUSPICIOUS_PATH_MARKERS)

        if status == 401 or status == 403:
            event_type = "http_auth_failure"
            severity = "medium"
        elif is_suspicious:
            event_type = "http_suspicious_request"
            severity = "high"
        else:
            event_type = "http_request"
            severity = "low"

        return NormalizedEvent(
            event_time=event_time,
            source_type=self.source_type,
            event_type=event_type,
            username=gd["user"] if gd["user"] != "-" else None,
            src_ip=gd["ip"],
            status_code=status,
            severity=severity,
            additional_data={
                "method": gd["method"],
                "path": gd["path"],
                "user_agent": gd["agent"],
            },
            raw_message=line.strip(),
        )
