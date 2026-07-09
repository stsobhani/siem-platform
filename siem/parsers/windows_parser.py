"""
Parser for Windows Security Event Log exports.

Expected line format (as you'd get exporting `Get-WinEvent` to a flat file,
or forwarding via Windows Event Forwarding / NXLog to a text sink):

    2026-07-01T08:15:32Z EventID=4624 Account=jsmith LogonType=3 \
        SourceIP=203.0.113.55 Workstation=WIN-DC01 Status=success

Key Windows Security Event IDs handled:
    4624 - An account was successfully logged on
    4625 - An account failed to log on
    4672 - Special privileges assigned to new logon (admin-equivalent token)
    4720 - A user account was created
    4728 - A member was added to a security-enabled global group (priv-esc signal)
"""
import re
from datetime import datetime, timezone
from typing import Optional

from siem.parsers.base import BaseParser, NormalizedEvent

_LINE_RE = re.compile(
    r"^(?P<ts>\S+)\s+EventID=(?P<event_id>\d+)\s+Account=(?P<account>\S+)\s+"
    r"LogonType=(?P<logon_type>\d+)\s+SourceIP=(?P<src_ip>\S+)\s+"
    r"Workstation=(?P<workstation>\S+)\s+Status=(?P<status>\S+)"
)

_EVENT_ID_MAP = {
    "4624": ("login_success", "low"),
    "4625": ("login_failure", "medium"),
    "4672": ("privilege_escalation", "high"),
    "4720": ("account_created", "medium"),
    "4728": ("group_membership_change", "high"),
}


class WindowsAuthParser(BaseParser):
    source_type = "windows_auth"

    def parse_line(self, line: str) -> Optional[NormalizedEvent]:
        match = _LINE_RE.match(line.strip())
        if not match:
            return None

        gd = match.groupdict()
        event_id = gd["event_id"]
        event_type, severity = _EVENT_ID_MAP.get(event_id, ("unknown_event", "low"))

        try:
            event_time = datetime.strptime(gd["ts"], "%Y-%m-%dT%H:%M:%SZ").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            return None

        return NormalizedEvent(
            event_time=event_time,
            source_type=self.source_type,
            event_type=event_type,
            host=gd["workstation"],
            username=gd["account"],
            src_ip=gd["src_ip"] if gd["src_ip"] != "-" else None,
            severity=severity,
            additional_data={
                "event_id": event_id,
                "logon_type": gd["logon_type"],
                "status": gd["status"],
            },
            raw_message=line.strip(),
        )
