"""Tests for the ping / port sweep. No ICMP and no external network required."""

from __future__ import annotations

import contextlib
import ipaddress
import json
import socket
import subprocess
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import sweep as sw

ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------- target parsing


class TestExpandTargets:
    def test_single(self):
        assert [str(a) for a in sw.expand_targets(["192.168.1.10"])] == ["192.168.1.10"]

    def test_cidr_hosts_only(self):
        hosts = [str(a) for a in sw.expand_targets(["192.168.1.0/30"])]
        assert hosts == ["192.168.1.1", "192.168.1.2"]

    def test_slash31_includes_both(self):
        hosts = [str(a) for a in sw.expand_targets(["192.0.2.8/31"])]
        assert hosts == ["192.0.2.8", "192.0.2.9"]

    def test_slash32(self):
        assert [str(a) for a in sw.expand_targets(["10.0.0.5/32"])] == ["10.0.0.5"]

    def test_full_range(self):
        hosts = [str(a) for a in sw.expand_targets(["192.168.1.10-192.168.1.12"])]
        assert hosts == ["192.168.1.10", "192.168.1.11", "192.168.1.12"]

    def test_short_range(self):
        hosts = [str(a) for a in sw.expand_targets(["192.168.1.10-12"])]
        assert hosts == ["192.168.1.10", "192.168.1.11", "192.168.1.12"]

    def test_dedup_preserves_order(self):
        hosts = [str(a) for a in sw.expand_targets(["10.0.0.1", "10.0.0.2", "10.0.0.1"])]
        assert hosts == ["10.0.0.1", "10.0.0.2"]

    def test_file_lines(self, tmp_path):
        f = tmp_path / "t.txt"
        f.write_text("# comment\n192.168.0.1\n\n10.0.0.1/32\n")
        specs = sw.load_target_file(f)
        assert sw.expand_targets(specs) == [
            ipaddress.IPv4Address("192.168.0.1"),
            ipaddress.IPv4Address("10.0.0.1"),
        ]

    def test_hostname_rejected(self):
        with pytest.raises(sw.SweepError, match="hostnames are not resolved"):
            sw.expand_targets(["example.com"])

    def test_bad_cidr(self):
        with pytest.raises(sw.SweepError, match="invalid network"):
            sw.expand_targets(["192.168.1.0/99"])

    def test_reversed_range(self):
        with pytest.raises(sw.SweepError, match="after end"):
            sw.expand_targets(["192.168.1.20-10"])

    def test_sample_targets_file(self):
        specs = sw.load_target_file(ROOT / "sample_targets.txt")
        hosts = sw.expand_targets(specs)
        assert ipaddress.IPv4Address("127.0.0.1") in hosts
        assert all(sw.is_safe_address(h) for h in hosts)


# ---------------------------------------------------------------- safety


class TestSafety:
    def test_private_ok(self):
        sw.validate_targets(
            [ipaddress.IPv4Address("10.1.1.1")], i_own_this=False, allow_large=False
        )

    def test_loopback_ok(self):
        sw.validate_targets(
            [ipaddress.IPv4Address("127.0.0.1")], i_own_this=False, allow_large=False
        )

    def test_documentation_ok(self):
        for a in ("192.0.2.1", "198.51.100.1", "203.0.113.1"):
            assert sw.is_safe_address(ipaddress.IPv4Address(a))

    def test_public_blocked(self):
        with pytest.raises(sw.SweepError, match="--i-own-this-network"):
            sw.validate_targets(
                [ipaddress.IPv4Address("8.8.8.8")], i_own_this=False, allow_large=False
            )

    def test_public_allowed_with_flag(self):
        sw.validate_targets([ipaddress.IPv4Address("8.8.8.8")], i_own_this=True, allow_large=False)

    def test_slash16_allowed(self):
        # A /16 has 65,534 hosts, which is at the default cap (refuse *more* than a /16).
        hosts = list(ipaddress.IPv4Network("10.0.0.0/16").hosts())
        assert len(hosts) <= sw.DEFAULT_MAX_TARGETS
        sw.validate_targets(hosts, i_own_this=False, allow_large=False)

    def test_over_slash16_blocked(self):
        hosts = [ipaddress.IPv4Address("10.0.0.1")] * (sw.DEFAULT_MAX_TARGETS + 1)
        with pytest.raises(sw.SweepError, match="exceeds the limit"):
            sw.validate_targets(hosts, i_own_this=False, allow_large=False)
        sw.validate_targets(hosts, i_own_this=False, allow_large=True)

    def test_hard_cap(self):
        # Avoid allocating a million addresses: stub len() via a tiny list + patched limit.
        hosts = [ipaddress.IPv4Address("10.0.0.1")] * 10
        with (
            patch.object(sw, "HARD_MAX_TARGETS", 5),
            pytest.raises(sw.SweepError, match="exceeds the limit"),
        ):
            sw.validate_targets(hosts, i_own_this=False, allow_large=True)

    def test_empty(self):
        with pytest.raises(sw.SweepError, match="no targets"):
            sw.validate_targets([], i_own_this=False, allow_large=False)

    def test_cli_blocks_public(self, capsys):
        assert sw.main(["discover", "8.8.8.8", "--method", "tcp"]) == 2
        assert "--i-own-this-network" in capsys.readouterr().err

    def test_cli_warns_when_override(self, capsys):
        fake = [sw.HostResult("8.8.8.8", False, "tcp", None, "")]
        with patch("sweep.discover_hosts", return_value=fake):
            rc = sw.main(["discover", "8.8.8.8", "--i-own-this-network", "--method", "tcp", "-q"])
        assert rc == 0
        assert "WARNING" in capsys.readouterr().err


# ---------------------------------------------------------------- ports


class TestPorts:
    def test_common(self):
        ports = sw.parse_ports("common")
        assert 22 in ports and 443 in ports and 3389 in ports
        assert ports == sorted(ports)

    def test_list_and_range(self):
        assert sw.parse_ports("22,80,100-102") == [22, 80, 100, 101, 102]

    def test_bad_port(self):
        with pytest.raises(sw.SweepError):
            sw.parse_ports("70000")

    def test_service_names(self):
        assert sw.service_name(22) == "ssh"
        assert sw.service_name(12345) == ""


# ---------------------------------------------------------------- ping command / parse


class TestPingHelpers:
    def test_linux_flags(self):
        with patch("sweep.platform.system", return_value="Linux"):
            cmd = sw.ping_command("10.0.0.1", 1.2)
        assert cmd == ["ping", "-c", "1", "-W", "2", "10.0.0.1"]

    def test_macos_flags(self):
        with patch("sweep.platform.system", return_value="Darwin"):
            cmd = sw.ping_command("10.0.0.1", 1.2)
        assert cmd[:4] == ["ping", "-c", "1", "-W"]
        assert cmd[4] == "1200"

    def test_windows_flags(self):
        with patch("sweep.platform.system", return_value="Windows"):
            cmd = sw.ping_command("10.0.0.1", 1.2)
        assert cmd == ["ping", "-n", "1", "-w", "1200", "10.0.0.1"]

    def test_parse_rtt_linux(self):
        out = "64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=1.23 ms"
        assert sw.parse_ping_rtt(out) == pytest.approx(1.23)

    def test_parse_rtt_summary(self):
        out = "rtt min/avg/max/mdev = 0.5/1.0/1.5/0.2 ms"
        assert sw.parse_ping_rtt(out) == pytest.approx(0.5)


# ---------------------------------------------------------------- mocked ICMP


class TestIcmpMocked:
    def test_alive(self):
        fake = MagicMock(
            returncode=0,
            stdout="64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=2.5 ms\n",
            stderr="",
        )
        with (
            patch("sweep.shutil.which", return_value="/bin/ping"),
            patch("sweep.subprocess.run", return_value=fake) as run,
        ):
            result = sw.icmp_ping("10.0.0.1", timeout_s=1.0)
        assert result.alive and result.method == "icmp"
        assert result.latency_ms == pytest.approx(2.5)
        assert run.call_args.args[0][0] == "ping"

    def test_down(self):
        fake = MagicMock(returncode=1, stdout="", stderr="Destination Host Unreachable")
        with (
            patch("sweep.shutil.which", return_value="/bin/ping"),
            patch("sweep.subprocess.run", return_value=fake),
        ):
            result = sw.icmp_ping("10.0.0.2", timeout_s=0.5)
        assert not result.alive

    def test_missing_ping_raises(self):
        with (
            patch("sweep.shutil.which", return_value=None),
            pytest.raises(sw.SweepError, match="ping command not found"),
        ):
            sw.icmp_ping("10.0.0.1")

    def test_timeout(self):
        with (
            patch("sweep.shutil.which", return_value="/bin/ping"),
            patch("sweep.subprocess.run", side_effect=subprocess.TimeoutExpired("ping", 1)),
        ):
            result = sw.icmp_ping("10.0.0.1", timeout_s=0.2)
        assert not result.alive and result.detail == "timeout"

    def test_auto_falls_back_when_ping_missing(self):
        with (
            patch("sweep.shutil.which", return_value=None),
            patch(
                "sweep.tcp_probe", return_value=sw.HostResult("10.0.0.1", True, "tcp", 1.0, "p")
            ) as tcp,
        ):
            result = sw.discover_host("10.0.0.1", method="auto")
        assert result.method == "tcp" and result.alive
        tcp.assert_called_once()


# ---------------------------------------------------------------- local TCP port scan


@pytest.fixture
def local_server():
    """Bind a localhost TCP listener that sends a short banner."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def _loop() -> None:
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            with conn, contextlib.suppress(OSError):
                conn.sendall(b"hello-from-test\n")
                conn.settimeout(0.2)
                with contextlib.suppress(OSError):
                    conn.recv(256)

    thread = threading.Thread(target=_loop, daemon=True)
    thread.start()
    yield port
    stop.set()
    srv.close()
    thread.join(timeout=1)


class TestPortScanLocal:
    def test_open_and_closed(self, local_server):
        open_port = local_server
        results = sw.scan_ports(
            ["127.0.0.1"],
            [open_port, 1],
            timeout_s=0.5,
            workers=4,
            banners=False,
            progress=False,
        )
        by_port = {r.port: r for r in results}
        assert by_port[open_port].open is True
        assert by_port[1].open is False

    def test_banner(self, local_server):
        result = sw.scan_port("127.0.0.1", local_server, timeout_s=0.5, banners=True)
        assert result.open
        assert "hello-from-test" in result.banner

    def test_tcp_discovery(self, local_server):
        result = sw.tcp_probe("127.0.0.1", ports=[local_server], timeout_s=0.5)
        assert result.alive and result.method == "tcp"

    def test_tcp_discovery_miss(self):
        result = sw.tcp_probe("127.0.0.1", ports=[1], timeout_s=0.2)
        assert not result.alive


# ---------------------------------------------------------------- reports


class TestReports:
    def _sample_report(self) -> sw.ScanReport:
        return sw.ScanReport(
            command="scan",
            started_at="2026-01-01T00:00:00Z",
            duration_s=1.25,
            hosts=[
                sw.HostResult("192.168.1.1", True, "icmp", 1.0, ""),
                sw.HostResult("192.168.1.2", False, "icmp", None, ""),
            ],
            ports=[
                sw.PortResult("192.168.1.1", 22, True, "ssh", "SSH-2.0", 0.5),
                sw.PortResult("192.168.1.1", 23, False, "telnet", "", None),
            ],
            notes=["unit-test"],
        )

    def test_json_roundtrip(self, tmp_path):
        report = self._sample_report()
        path = tmp_path / "out.json"
        sw.write_json(report, path)
        data = json.loads(path.read_text())
        assert data["hosts_up"] == 1
        assert data["open_ports"] == 1
        assert data["ports"][0]["port"] == 22
        assert len(data["hosts"]) == 2

    def test_csv(self, tmp_path):
        report = self._sample_report()
        path = tmp_path / "out.csv"
        sw.write_csv(report, path)
        text = path.read_text()
        assert "host,192.168.1.1" in text.replace(" ", "")
        assert "port,192.168.1.1,22,open,ssh" in text.replace(" ", "")

    def test_tables(self):
        report = self._sample_report()
        assert "192.168.1.1" in sw.format_host_table(report.hosts)
        assert "ssh" in sw.format_port_table(report.ports)
        assert "Hosts up         : 1" in sw.format_summary(report)


# ---------------------------------------------------------------- concurrency / discover helpers


class TestConcurrency:
    def test_discover_hosts_order(self):
        hosts = [ipaddress.IPv4Address(f"10.0.0.{i}") for i in range(1, 6)]

        def fake(host: str, **kwargs):
            time.sleep(0.01 * (6 - int(host.split(".")[-1])))
            return sw.HostResult(host, True, "tcp", 1.0, "")

        with patch("sweep.discover_host", side_effect=fake):
            results = sw.discover_hosts(hosts, method="tcp", workers=5, progress=False)
        assert [r.host for r in results] == [str(h) for h in hosts]


# ---------------------------------------------------------------- demo + CLI


class TestDemoAndCli:
    def test_demo(self, capsys):
        assert sw.main(["demo"]) == 0
        out = capsys.readouterr().out
        assert "Simulated host sweep" in out
        assert "192.168.10.1" in out
        assert "127.0.0.1" in out
        assert "demo-service" in out or "Open ports" in out or "Port" in out

    def test_demo_library(self):
        report = sw.run_demo(ROOT / "sample_results.json")
        assert any(h.method == "simulated" and h.alive for h in report.hosts)
        assert any(p.open and p.host == "127.0.0.1" for p in report.ports)

    def test_discover_cli_mocked(self, capsys, tmp_path):
        fake_hosts = [
            sw.HostResult("192.168.10.1", True, "icmp", 1.0, ""),
            sw.HostResult("192.168.10.2", False, "icmp", None, ""),
        ]
        json_path = tmp_path / "r.json"
        csv_path = tmp_path / "r.csv"
        with patch("sweep.discover_hosts", return_value=fake_hosts):
            rc = sw.main(
                [
                    "discover",
                    "192.168.10.1-2",
                    "-q",
                    "--json",
                    str(json_path),
                    "--csv",
                    str(csv_path),
                ]
            )
        assert rc == 0
        out = capsys.readouterr().out
        assert "Hosts up         : 1" in out
        data = json.loads(json_path.read_text())
        assert data["hosts_up"] == 1
        assert csv_path.read_text().count("\n") >= 3

    def test_scan_skip_discovery_local(self, local_server, capsys, tmp_path):
        port = local_server
        json_path = tmp_path / "scan.json"
        rc = sw.main(
            [
                "scan",
                "127.0.0.1",
                "--skip-discovery",
                "-p",
                f"{port},1",
                "--banners",
                "-q",
                "--json",
                str(json_path),
            ]
        )
        assert rc == 0
        data = json.loads(json_path.read_text())
        assert data["open_ports"] == 1
        assert data["ports"][0]["port"] == port
        assert "hello-from-test" in data["ports"][0]["banner"]

    def test_bad_input_exit_code(self, capsys):
        assert sw.main(["discover"]) == 2
        assert "error:" in capsys.readouterr().err

    def test_no_traceback_on_bad_ip(self, capsys):
        assert sw.main(["discover", "not-an-ip"]) == 2
        err = capsys.readouterr().err
        assert "error:" in err
        assert "Traceback" not in err

    def test_sample_results_shape(self):
        hosts = sw.load_simulated_hosts(ROOT / "sample_results.json")
        assert len(hosts) == 6
        assert sum(1 for h in hosts if h.alive) == 4
