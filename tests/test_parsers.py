"""Unit tests for the source-specific log parsers."""
import pytest

from siem.parsers.windows_parser import WindowsAuthParser
from siem.parsers.linux_parser import LinuxSSHParser
from siem.parsers.firewall_parser import FirewallParser
from siem.parsers.web_parser import WebServerParser


class TestWindowsAuthParser:
    def setup_method(self):
        self.parser = WindowsAuthParser()

    def test_successful_logon(self):
        line = ("2026-07-01T08:15:32Z EventID=4624 Account=jsmith LogonType=3 "
                "SourceIP=10.0.0.5 Workstation=WIN-DC01 Status=success")
        event = self.parser.parse_line(line)
        assert event is not None
        assert event.event_type == "login_success"
        assert event.username == "jsmith"
        assert event.src_ip == "10.0.0.5"
        assert event.severity == "low"

    def test_failed_logon(self):
        line = ("2026-07-01T03:10:00Z EventID=4625 Account=administrator LogonType=3 "
                "SourceIP=203.0.113.55 Workstation=WIN-DC01 Status=failure")
        event = self.parser.parse_line(line)
        assert event.event_type == "login_failure"
        assert event.severity == "medium"

    def test_privilege_escalation_event_id(self):
        line = ("2026-07-01T10:20:00Z EventID=4672 Account=agarcia LogonType=2 "
                "SourceIP=10.0.0.12 Workstation=WIN-DC01 Status=success")
        event = self.parser.parse_line(line)
        assert event.event_type == "privilege_escalation"
        assert event.severity == "high"

    def test_malformed_line_returns_none(self):
        assert self.parser.parse_line("this is not a valid log line") is None

    def test_empty_line_returns_none(self):
        assert self.parser.parse_line("") is None


class TestLinuxSSHParser:
    def setup_method(self):
        self.parser = LinuxSSHParser()

    def test_failed_password(self):
        line = "Jul  1 08:15:32 web01 sshd[2314]: Failed password for invalid user admin from 203.0.113.55 port 51422 ssh2"
        event = self.parser.parse_line(line)
        assert event.event_type == "login_failure"
        assert event.username == "admin"
        assert event.src_ip == "203.0.113.55"
        assert event.host == "web01"

    def test_accepted_password(self):
        line = "Jul  1 08:16:01 web01 sshd[2315]: Accepted password for jsmith from 10.0.0.5 port 51500 ssh2"
        event = self.parser.parse_line(line)
        assert event.event_type == "login_success"
        assert event.username == "jsmith"

    def test_sudo_to_root_is_high_severity(self):
        line = "Jul  1 09:00:00 web01 sudo: agarcia : TTY=pts/0 ; PWD=/home/agarcia ; USER=root ; COMMAND=/bin/bash"
        event = self.parser.parse_line(line)
        assert event.event_type == "privilege_escalation"
        assert event.username == "agarcia"
        assert event.severity == "high"
        assert event.additional_data["target_user"] == "root"

    def test_non_syslog_line_returns_none(self):
        assert self.parser.parse_line("random garbage without syslog prefix") is None


class TestFirewallParser:
    def setup_method(self):
        self.parser = FirewallParser()

    def test_block_action(self):
        line = "2026-07-01T08:15:32Z,fw01,BLOCK,TCP,203.0.113.55,10.0.0.10,443"
        event = self.parser.parse_line(line)
        assert event.event_type == "conn_denied"
        assert event.dst_port == 443
        assert event.severity == "medium"

    def test_allow_action(self):
        line = "2026-07-01T08:15:40Z,fw01,ALLOW,TCP,10.0.0.5,10.0.0.10,22"
        event = self.parser.parse_line(line)
        assert event.event_type == "conn_allowed"
        assert event.severity == "low"

    def test_malformed_csv_returns_none(self):
        assert self.parser.parse_line("not,enough,fields") is None


class TestWebServerParser:
    def setup_method(self):
        self.parser = WebServerParser()

    def test_normal_request(self):
        line = '10.0.0.5 - jsmith [01/Jul/2026:08:06:00 +0000] "GET /dashboard HTTP/1.1" 200 4521 "-" "Mozilla/5.0"'
        event = self.parser.parse_line(line)
        assert event.event_type == "http_request"
        assert event.status_code == 200
        assert event.username == "jsmith"

    def test_auth_failure(self):
        line = '203.0.113.55 - - [01/Jul/2026:08:15:33 +0000] "POST /wp-login.php HTTP/1.1" 401 300 "-" "curl/7.68.0"'
        event = self.parser.parse_line(line)
        assert event.event_type == "http_auth_failure"
        assert event.severity == "medium"

    def test_suspicious_path_flagged(self):
        line = '45.155.204.9 - - [01/Jul/2026:02:00:00 +0000] "GET /etc/passwd HTTP/1.1" 404 210 "-" "curl/7.68.0"'
        event = self.parser.parse_line(line)
        assert event.event_type == "http_suspicious_request"
        assert event.severity == "high"

    def test_malformed_line_returns_none(self):
        assert self.parser.parse_line("not a valid access log line") is None
