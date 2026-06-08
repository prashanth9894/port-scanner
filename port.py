#!/usr/bin/env python3
"""
test_port_scanner.py — Test suite for port_scanner.py

Tests cover:
  - Port range / list parsing
  - Host resolution and target expansion
  - TCP connect scan against a real local listener
  - JSON and CSV output formatting
  - Edge cases and error handling

Run:  python test_port_scanner.py
"""

import json
import socket
import threading
import time
import unittest

# Import the module under test
import port_scanner as ps


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def start_tcp_listener(port: int) -> threading.Thread:
    """Start a minimal TCP server on localhost:port for testing."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(5)
    server.settimeout(3)

    def serve():
        try:
            while True:
                conn, _ = server.accept()
                conn.send(b"TEST-BANNER\r\n")
                conn.close()
        except Exception:
            pass
        finally:
            server.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return t


# ---------------------------------------------------------------------------
# Tests: parse_ports
# ---------------------------------------------------------------------------

class TestParsePorts(unittest.TestCase):

    def test_single_port(self):
        self.assertEqual(ps.parse_ports("80"), [80])

    def test_range(self):
        result = ps.parse_ports("1-5")
        self.assertEqual(result, [1, 2, 3, 4, 5])

    def test_comma_list(self):
        result = ps.parse_ports("22,80,443")
        self.assertEqual(result, [22, 80, 443])

    def test_mixed(self):
        result = ps.parse_ports("22,80-82,443")
        self.assertEqual(result, [22, 80, 81, 82, 443])

    def test_deduplication(self):
        # Overlapping ranges should not duplicate
        result = ps.parse_ports("1-3,2-4")
        self.assertEqual(result, [1, 2, 3, 4])

    def test_invalid_port_number(self):
        with self.assertRaises(ValueError):
            ps.parse_ports("99999")

    def test_invalid_range(self):
        with self.assertRaises(ValueError):
            ps.parse_ports("100-50")   # reversed range

    def test_invalid_format(self):
        with self.assertRaises((ValueError, Exception)):
            ps.parse_ports("abc")


# ---------------------------------------------------------------------------
# Tests: parse_targets
# ---------------------------------------------------------------------------

class TestParseTargets(unittest.TestCase):

    def test_single_ip(self):
        self.assertEqual(ps.parse_targets("127.0.0.1"), ["127.0.0.1"])

    def test_hostname(self):
        result = ps.parse_targets("localhost")
        self.assertIn("localhost", result)

    def test_cidr_24(self):
        result = ps.parse_targets("10.0.0.0/30")
        # /30 has 2 usable hosts
        self.assertEqual(result, ["10.0.0.1", "10.0.0.2"])

    def test_cidr_single_host(self):
        result = ps.parse_targets("192.168.1.5/32")
        self.assertEqual(result, ["192.168.1.5"])


# ---------------------------------------------------------------------------
# Tests: TCP connect scan (against real local listener)
# ---------------------------------------------------------------------------

LISTEN_PORT = 19876   # used by TestScanHost
LISTEN_PORT2 = 19877  # used by TestTcpConnectScan

class TestTcpConnectScan(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Launch a listener before all tests in this class
        cls.listener_thread = start_tcp_listener(LISTEN_PORT2)
        # Wait until the port is actually bound before proceeding
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", LISTEN_PORT2), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)

    def test_open_port(self):
        result = ps.tcp_connect_scan("127.0.0.1", LISTEN_PORT2, timeout=2.0, grab_banners=False)
        self.assertEqual(result.state, "open")
        self.assertEqual(result.port, LISTEN_PORT2)

    def test_closed_port(self):
        # Port 19875 should not be listening
        result = ps.tcp_connect_scan("127.0.0.1", 19875, timeout=1.0, grab_banners=False)
        self.assertEqual(result.state, "closed")

    def test_banner_grab(self):
        result = ps.tcp_connect_scan("127.0.0.1", LISTEN_PORT2, timeout=2.0, grab_banners=True)
        self.assertEqual(result.state, "open")
        self.assertIn("TEST-BANNER", result.banner)

    def test_service_name_known_port(self):
        # Scan port 80 on loopback; it will be closed but service name is http
        # We test get_service_name directly
        self.assertEqual(ps.get_service_name(80), "http")
        self.assertEqual(ps.get_service_name(22), "ssh")
        self.assertEqual(ps.get_service_name(443), "https")

    def test_filtered_or_closed_unreachable_port(self):
        # A port on loopback that nothing is listening on returns closed
        # (ConnectionRefused). This validates the non-open path.
        result = ps.tcp_connect_scan("127.0.0.1", 19874, timeout=1.0, grab_banners=False)
        self.assertIn(result.state, ("closed", "filtered"))


# ---------------------------------------------------------------------------
# Tests: scan_host
# ---------------------------------------------------------------------------

class TestScanHost(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.listener_thread = start_tcp_listener(LISTEN_PORT)
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", LISTEN_PORT), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)

    def test_scan_localhost_single_port(self):
        result = ps.scan_host(
            target="127.0.0.1",
            ports=[LISTEN_PORT],
            timeout=2.0,
            max_workers=1,
            grab_banners=False,
            verbose=False,
        )
        self.assertEqual(result.ip, "127.0.0.1")
        self.assertEqual(result.ports_scanned, 1)
        self.assertEqual(len(result.open_ports), 1)
        self.assertEqual(result.open_ports[0].port, LISTEN_PORT)

    def test_scan_unresolvable_host(self):
        result = ps.scan_host(
            target="this.host.does.not.exist.invalid",
            ports=[80],
            timeout=1.0,
            max_workers=1,
            grab_banners=False,
            verbose=False,
        )
        self.assertEqual(result.ip, "unresolvable")
        self.assertEqual(result.ports_scanned, 0)

    def test_results_sorted_by_port(self):
        result = ps.scan_host(
            target="127.0.0.1",
            ports=[82, 80, 81],
            timeout=1.0,
            max_workers=10,
            grab_banners=False,
            verbose=False,
        )
        ports = [r.port for r in result.all_results]
        self.assertEqual(ports, sorted(ports))

    def test_duration_recorded(self):
        result = ps.scan_host(
            target="127.0.0.1",
            ports=[LISTEN_PORT],
            timeout=2.0,
            max_workers=1,
            grab_banners=False,
            verbose=False,
        )
        self.assertGreaterEqual(result.duration_sec, 0)


# ---------------------------------------------------------------------------
# Tests: Output formatters
# ---------------------------------------------------------------------------

class TestFormatters(unittest.TestCase):

    def _make_result(self) -> ps.ScanResult:
        return ps.ScanResult(
            target="127.0.0.1",
            ip="127.0.0.1",
            scan_start="2025-01-01T00:00:00+00:00",
            scan_end="2025-01-01T00:00:01+00:00",
            duration_sec=1.0,
            ports_scanned=3,
            open_ports=[
                ps.PortResult(port=22, state="open", service="ssh", banner="OpenSSH_9.0"),
                ps.PortResult(port=80, state="open", service="http", banner="Apache/2.4"),
            ],
            all_results=[],
        )

    def test_text_format_contains_open(self):
        text = ps.format_text([self._make_result()])
        self.assertIn("open", text)
        self.assertIn("22", text)
        self.assertIn("80", text)

    def test_json_format_valid(self):
        raw = ps.format_json([self._make_result()])
        parsed = json.loads(raw)
        self.assertIsInstance(parsed, list)
        self.assertEqual(parsed[0]["ip"], "127.0.0.1")
        self.assertEqual(len(parsed[0]["open_ports"]), 2)

    def test_csv_format_header(self):
        raw = ps.format_csv([self._make_result()])
        lines = raw.strip().splitlines()
        self.assertIn("port", lines[0])
        self.assertIn("service", lines[0])
        # Two open ports → header + 2 data rows
        self.assertEqual(len(lines), 3)

    def test_json_no_all_results_key(self):
        # all_results should be stripped from JSON output
        raw = ps.format_json([self._make_result()])
        parsed = json.loads(raw)
        self.assertNotIn("all_results", parsed[0])


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)