"""
Parser for Linux /var/log/auth.log style SSH and sudo entries.

Handles the three most security-relevant line shapes:

    Jul  1 08:15:32 web01 sshd[2314]: Failed password for invalid user admin \
        from 203.0.113.55 port 51422 ssh2
    Jul  1 08:16:01 web01 sshd[2315]: Accepted password for jsmith \
        from 10.0.0.5 port 51500 ssh2
    Jul  1 09:00:00 web01 sudo: jsmith : TTY=pts/0 ; PWD=/home/jsmith ; \
        USER=root ; COMMAND=/bin/bash
"""
import re
from datetime import datetime, timezone
from typing import Optional

from siem.parsers.base import BaseParser, NormalizedEvent

_SYSLOG_PREFIX = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>\S+?):\s+(?P<msg>.*)$"
)

_FAILED_RE = re.compile(
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_ACCEPTED_RE = re.compile(
    r"Accepted (password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_SUDO_RE = re.compile(
    r"(?P<user>\S+)\s*:\s*TTY=\S+\s*;\s*PWD=\S+\s*;\s*USER=(?P<target_user>\S+)\s*;\s*COMMAND=(?P<command>.*)"
)

_CURRENT_YEAR = datetime.now(timezone.utc).year


class LinuxSSHParser(BaseParser):
    source_type = "linux_ssh"

    def parse_line(self, line: str) -> Optional[NormalizedEvent]:
        prefix = _SYSLOG_PREFIX.match(line.strip())
        if not prefix:
            return None

        pd = prefix.groupdict()
        try:
            event_time = datetime.strptime(
                f"{_CURRENT_YEAR} {pd['ts']}", "%Y %b %d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            return None

        host, proc, msg = pd["host"], pd["proc"], pd["msg"]

        if proc.startswith("sshd"):
            failed = _FAILED_RE.search(msg)
            if failed:
                return NormalizedEvent(
                    event_time=event_time,
                    source_type=self.source_type,
                    event_type="login_failure",
                    host=host,
                    username=failed.group("user"),
                    src_ip=failed.group("ip"),
                    severity="medium",
                    additional_data={"port": failed.group("port"), "auth_method": "password"},
                    raw_message=line.strip(),
                )
            accepted = _ACCEPTED_RE.search(msg)
            if accepted:
                return NormalizedEvent(
                    event_time=event_time,
                    source_type=self.source_type,
                    event_type="login_success",
                    host=host,
                    username=accepted.group("user"),
                    src_ip=accepted.group("ip"),
                    severity="low",
                    additional_data={"port": accepted.group("port")},
                    raw_message=line.strip(),
                )
            return None

        if proc.startswith("sudo"):
            sudo_match = _SUDO_RE.search(msg)
            if sudo_match:
                target_user = sudo_match.group("target_user")
                severity = "high" if target_user == "root" else "medium"
                return NormalizedEvent(
                    event_time=event_time,
                    source_type=self.source_type,
                    event_type="privilege_escalation",
                    host=host,
                    username=sudo_match.group("user"),
                    severity=severity,
                    additional_data={
                        "target_user": target_user,
                        "command": sudo_match.group("command"),
                    },
                    raw_message=line.strip(),
                )
        return None
