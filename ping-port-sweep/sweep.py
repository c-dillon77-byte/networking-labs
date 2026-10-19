#!/usr/bin/env python3
"""Ping sweep and TCP port scanner (standard library only, Python 3.10+).

Commands:
    discover TARGETS...   Find live hosts with the system `ping` (or a TCP probe).
    scan     TARGETS...   Discover hosts, then TCP connect-scan their ports.
    demo                  Offline walkthrough: local listeners + simulated sweep.

TARGETS can be a single IP (192.168.1.10), a CIDR (192.168.1.0/24), a range
(192.168.1.10-192.168.1.20 or 192.168.1.10-20), or a file given with --file.

By default only private (RFC 1918), loopback, and documentation (RFC 5737)
addresses may be scanned. Only scan networks you own or are authorized to test.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import contextlib
import csv
import ipaddress
import json
import math
import platform
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

__version__ = "1.0.0"

IPv4 = ipaddress.IPv4Address

SAFE_NETWORKS = tuple(
    ipaddress.IPv4Network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "192.0.2.0/24",
        "198.51.100.0/24",
        "203.0.113.0/24",
    )
)

DEFAULT_MAX_TARGETS = 65_536  # a /16
HARD_MAX_TARGETS = 1_048_576  # a /12, even with --allow-large

COMMON_PORTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    8080: "http-alt",
}

TCP_DISCOVERY_PORTS = (22, 80, 443, 445, 3389)


class SweepError(Exception):
    """User-facing error: printed without a traceback; exit code 2."""


# ---------------------------------------------------------------- targets


def _parse_ip(text: str) -> IPv4:
    try:
        return ipaddress.IPv4Address(text.strip())
    except ValueError:
        raise SweepError(
            f"invalid target {text!r}: use an IPv4 address, CIDR, or range "
            "(hostnames are not resolved)"
        ) from None


def _expand_one(spec: str) -> list[IPv4]:
    """Expand one target spec into a list of IPv4 addresses."""
    spec = spec.strip()
    if not spec or spec.startswith("#"):
        return []
    if "/" in spec:
        try:
            net = ipaddress.IPv4Network(spec, strict=False)
        except ValueError as exc:
            raise SweepError(f"invalid network {spec!r}: {exc}") from None
        if net.prefixlen >= 31:
            return list(net)
        return list(net.hosts())
    if "-" in spec:
        left, right = (part.strip() for part in spec.split("-", 1))
        start = _parse_ip(left)
        if "." in right:
            end = _parse_ip(right)
        else:
            if not right.isdigit():
                raise SweepError(f"invalid range {spec!r}")
            octs = str(start).split(".")
            last = int(right)
            if not 0 <= last <= 255:
                raise SweepError(f"invalid range end {right!r} (must be 0-255)")
            end = ipaddress.IPv4Address(".".join([*octs[:3], str(last)]))
        if int(end) < int(start):
            raise SweepError(f"range start {start} is after end {end}")
        return [ipaddress.IPv4Address(i) for i in range(int(start), int(end) + 1)]
    return [_parse_ip(spec)]


def expand_targets(specs: Iterable[str]) -> list[IPv4]:
    """Expand many specs, drop duplicates, keep first-seen order."""
    seen: set[IPv4] = set()
    out: list[IPv4] = []
    for spec in specs:
        for addr in _expand_one(spec):
            if addr not in seen:
                seen.add(addr)
                out.append(addr)
    return out


def load_target_file(path: Path) -> list[str]:
    """Non-empty, non-comment lines from a targets file."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SweepError(f"cannot read {path}: {exc}") from None
    lines = []
    for ln in text.splitlines():
        line = ln.split("#", 1)[0].strip()
        if line:
            lines.append(line)
    return lines


def is_safe_address(addr: IPv4) -> bool:
    return any(addr in net for net in SAFE_NETWORKS)


def validate_targets(
    hosts: list[IPv4],
    *,
    i_own_this: bool,
    allow_large: bool,
    max_targets: int = DEFAULT_MAX_TARGETS,
) -> None:
    """Refuse unsafe or oversized target sets unless the user overrides."""
    if not hosts:
        raise SweepError("no targets to scan")
    unsafe = [h for h in hosts if not is_safe_address(h)]
    if unsafe and not i_own_this:
        sample = ", ".join(str(h) for h in unsafe[:3])
        more = f" (+{len(unsafe) - 3} more)" if len(unsafe) > 3 else ""
        raise SweepError(
            f"{len(unsafe)} target(s) are outside private/loopback/documentation "
            f"ranges ({sample}{more}). Re-run with --i-own-this-network only if you "
            "own them or have written authorization."
        )
    limit = HARD_MAX_TARGETS if allow_large else max_targets
    if len(hosts) > limit:
        raise SweepError(
            f"{len(hosts):,} targets exceeds the limit of {limit:,}. "
            "Narrow the range, or pass --allow-large (hard cap "
            f"{HARD_MAX_TARGETS:,})."
        )


# ---------------------------------------------------------------- ports


def parse_ports(spec: str) -> list[int]:
    """Parse '22,80,443' or '1-1024' or 'common' into a sorted unique list."""
    spec = spec.strip().lower()
    if not spec:
        raise SweepError("empty port list")
    if spec in {"common", "top", "default"}:
        return sorted(COMMON_PORTS)
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            try:
                start, end = int(a), int(b)
            except ValueError as exc:
                raise SweepError(f"invalid port range {part!r}") from exc
            if not (1 <= start <= end <= 65535):
                raise SweepError(f"port range {part!r} must be within 1-65535")
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(part)
            except ValueError as exc:
                raise SweepError(f"invalid port {part!r}") from exc
            if not 1 <= port <= 65535:
                raise SweepError(f"port {port} must be within 1-65535")
            ports.add(port)
    if not ports:
        raise SweepError("no ports to scan")
    if len(ports) > 10_000:
        raise SweepError(f"{len(ports):,} ports is too many for one run; narrow the range")
    return sorted(ports)


def service_name(port: int) -> str:
    return COMMON_PORTS.get(port, "")


# ---------------------------------------------------------------- ping / TCP probe


@dataclass(frozen=True)
class HostResult:
    host: str
    alive: bool
    method: str  # "icmp", "tcp", "none", "simulated"
    latency_ms: float | None
    detail: str = ""


@dataclass(frozen=True)
class PortResult:
    host: str
    port: int
    open: bool
    service: str
    banner: str = ""
    latency_ms: float | None = None


@dataclass
class ScanReport:
    command: str
    started_at: str
    duration_s: float = 0.0
    hosts: list[HostResult] = field(default_factory=list)
    ports: list[PortResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def hosts_up(self) -> list[HostResult]:
        return [h for h in self.hosts if h.alive]

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.open]


def _ping_wait_seconds(timeout_s: float) -> int:
    return max(1, math.ceil(timeout_s))


def ping_command(host: str, timeout_s: float) -> list[str]:
    """Build a one-packet ping argv for the current OS."""
    system = platform.system().lower()
    timeout_s = max(timeout_s, 0.1)
    if system == "windows":
        ms = max(1, int(timeout_s * 1000))
        return ["ping", "-n", "1", "-w", str(ms), host]
    if system == "darwin":
        ms = max(1, int(timeout_s * 1000))
        return ["ping", "-c", "1", "-W", str(ms), host]
    return ["ping", "-c", "1", "-W", str(_ping_wait_seconds(timeout_s)), host]


_RTT_RE = re.compile(
    r"(?:time[=<]|rtt min/avg/max/(?:mdev|stddev) = )"
    r"(?P<ms>\d+(?:\.\d+)?)\s*(?:ms|/)",
    re.IGNORECASE,
)


def parse_ping_rtt(output: str) -> float | None:
    """Extract RTT in milliseconds from ping stdout, if present."""
    match = _RTT_RE.search(output)
    return float(match.group("ms")) if match else None


def icmp_ping(host: str, timeout_s: float = 1.0) -> HostResult:
    """Run one system ping. Raises SweepError if ping is missing."""
    if shutil.which("ping") is None:
        raise SweepError("ping command not found on PATH")
    cmd = ping_command(host, timeout_s)
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s + 1.5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return HostResult(host, False, "icmp", None, "timeout")
    except OSError as exc:
        raise SweepError(f"failed to run ping: {exc}") from None
    elapsed = (time.perf_counter() - started) * 1000
    alive = proc.returncode == 0
    rtt = parse_ping_rtt(proc.stdout or "") if alive else None
    detail = "" if alive else (proc.stderr or proc.stdout or "").strip().splitlines()
    detail_s = detail[0][:80] if isinstance(detail, list) and detail else ""
    latency = rtt if rtt is not None else (elapsed if alive else None)
    return HostResult(host, alive, "icmp", latency, detail_s)


def tcp_probe(
    host: str,
    ports: Iterable[int] = TCP_DISCOVERY_PORTS,
    timeout_s: float = 0.5,
) -> HostResult:
    """Consider a host alive if any of `ports` accepts a TCP connection."""
    started = time.perf_counter()
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout_s):
                elapsed = (time.perf_counter() - started) * 1000
                return HostResult(host, True, "tcp", elapsed, f"port {port} open")
        except OSError:
            continue
    return HostResult(host, False, "tcp", None, "no open discovery ports")


def discover_host(
    host: str,
    *,
    method: str = "auto",
    timeout_s: float = 1.0,
) -> HostResult:
    """Probe one host. method: auto | icmp | tcp."""
    if method == "tcp":
        return tcp_probe(host, timeout_s=timeout_s)
    if method == "icmp":
        return icmp_ping(host, timeout_s=timeout_s)
    # auto: try ICMP, fall back to TCP if ping is missing or permission denied.
    try:
        result = icmp_ping(host, timeout_s=timeout_s)
        if result.alive:
            return result
        # Host silent on ICMP — still try TCP so firewalled-but-open hosts show up.
        tcp = tcp_probe(host, timeout_s=min(timeout_s, 0.5))
        return tcp if tcp.alive else result
    except SweepError:
        return tcp_probe(host, timeout_s=timeout_s)


def grab_banner(host: str, port: int, timeout_s: float = 1.0) -> str:
    """Best-effort banner: send a short probe for HTTP, otherwise just read."""
    try:
        with socket.create_connection((host, port), timeout=timeout_s) as sock:
            sock.settimeout(timeout_s)
            if port in {80, 8000, 8008, 8080, 8888}:
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            else:
                # Prod a few cleartext services that speak first or after CR.
                sock.sendall(b"\r\n")
            data = sock.recv(256)
    except OSError:
        return ""
    text = data.decode("utf-8", errors="replace").strip()
    text = re.sub(r"[\r\n]+", " | ", text)
    return text[:120]


def scan_port(
    host: str,
    port: int,
    *,
    timeout_s: float = 0.5,
    banners: bool = False,
) -> PortResult:
    """TCP connect scan of one port. No root needed."""
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            elapsed = (time.perf_counter() - started) * 1000
            banner = grab_banner(host, port, timeout_s) if banners else ""
            return PortResult(host, port, True, service_name(port), banner, elapsed)
    except OSError:
        return PortResult(host, port, False, service_name(port), "", None)


# ---------------------------------------------------------------- concurrency


def _run_pool(
    jobs: list[Callable[[], object]],
    workers: int,
    progress_every: int = 50,
) -> list[object]:
    """Run callables concurrently; preserve input order in the result list."""
    if not jobs:
        return []
    workers = max(1, min(workers, len(jobs)))
    results: list[object | None] = [None] * len(jobs)
    done = 0
    lock = threading.Lock()

    def _wrap(idx: int, fn: Callable[[], object]) -> None:
        nonlocal done
        results[idx] = fn()
        with lock:
            done += 1
            if progress_every and done % progress_every == 0:
                print(f"  ... {done}/{len(jobs)} probes", file=sys.stderr, flush=True)

    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_wrap, i, fn) for i, fn in enumerate(jobs)]
        for fut in cf.as_completed(futures):
            fut.result()  # re-raise unexpected errors
    return results  # type: ignore[return-value]


def discover_hosts(
    hosts: list[IPv4],
    *,
    method: str = "auto",
    timeout_s: float = 1.0,
    workers: int = 64,
    progress: bool = True,
) -> list[HostResult]:
    jobs = [(lambda h=str(h): discover_host(h, method=method, timeout_s=timeout_s)) for h in hosts]
    return _run_pool(jobs, workers, progress_every=50 if progress else 0)  # type: ignore[return-value]


def scan_ports(
    hosts: list[str],
    ports: list[int],
    *,
    timeout_s: float = 0.5,
    workers: int = 128,
    banners: bool = False,
    progress: bool = True,
) -> list[PortResult]:
    jobs = [
        (lambda host=host, port=port: scan_port(host, port, timeout_s=timeout_s, banners=banners))
        for host in hosts
        for port in ports
    ]
    return _run_pool(jobs, workers, progress_every=100 if progress else 0)  # type: ignore[return-value]


# ---------------------------------------------------------------- output


def format_host_table(hosts: list[HostResult]) -> str:
    if not hosts:
        return "(no hosts probed)"
    header = f"{'Host':<16} {'Status':<6} {'Method':<10} {'Latency':>10} Detail"
    lines = [header, "-" * len(header)]
    for h in hosts:
        status = "UP" if h.alive else "down"
        lat = f"{h.latency_ms:.1f} ms" if h.latency_ms is not None else "-"
        lines.append(f"{h.host:<16} {status:<6} {h.method:<10} {lat:>10} {h.detail}")
    return "\n".join(lines)


def format_port_table(ports: list[PortResult], *, only_open: bool = True) -> str:
    rows = [p for p in ports if p.open] if only_open else ports
    if not rows:
        return "(no open ports)"
    header = f"{'Host':<16} {'Port':>5} {'Service':<12} {'Latency':>10} Banner"
    lines = [header, "-" * len(header)]
    for p in rows:
        lat = f"{p.latency_ms:.1f} ms" if p.latency_ms is not None else "-"
        lines.append(f"{p.host:<16} {p.port:>5} {p.service:<12} {lat:>10} {p.banner}")
    return "\n".join(lines)


def format_summary(report: ScanReport) -> str:
    lines = [
        f"Command          : {report.command}",
        f"Started (UTC)    : {report.started_at}",
        f"Duration         : {report.duration_s:.2f} s",
        f"Hosts probed     : {len(report.hosts)}",
        f"Hosts up         : {len(report.hosts_up)}",
        f"Open ports       : {len(report.open_ports)}",
    ]
    for note in report.notes:
        lines.append(f"Note             : {note}")
    return "\n".join(lines)


def report_to_dict(report: ScanReport) -> dict:
    return {
        "command": report.command,
        "started_at": report.started_at,
        "duration_s": round(report.duration_s, 3),
        "hosts_probed": len(report.hosts),
        "hosts_up": len(report.hosts_up),
        "open_ports": len(report.open_ports),
        "notes": report.notes,
        "hosts": [asdict(h) for h in report.hosts],
        "ports": [asdict(p) for p in report.open_ports],
    }


def write_json(report: ScanReport, path: Path) -> None:
    path.write_text(json.dumps(report_to_dict(report), indent=2) + "\n", encoding="utf-8")


def write_csv(report: ScanReport, path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            ["type", "host", "port", "status", "method_or_service", "latency_ms", "detail"]
        )
        for h in report.hosts:
            writer.writerow(
                [
                    "host",
                    h.host,
                    "",
                    "up" if h.alive else "down",
                    h.method,
                    "" if h.latency_ms is None else f"{h.latency_ms:.2f}",
                    h.detail,
                ]
            )
        for p in report.open_ports:
            writer.writerow(
                [
                    "port",
                    p.host,
                    p.port,
                    "open",
                    p.service,
                    "" if p.latency_ms is None else f"{p.latency_ms:.2f}",
                    p.banner,
                ]
            )


# ---------------------------------------------------------------- demo (offline)


def _demo_listeners(count: int = 3) -> tuple[list[socket.socket], list[int]]:
    """Bind a few localhost TCP listeners that reply with a short banner."""
    socks: list[socket.socket] = []
    ports: list[int] = []
    for i in range(count):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        socks.append(srv)
        ports.append(srv.getsockname()[1])

        def _accept_loop(s: socket.socket = srv, idx: int = i) -> None:
            s.settimeout(0.2)
            deadline = time.time() + 8
            while time.time() < deadline:
                try:
                    conn, _ = s.accept()
                except OSError:
                    continue
                with conn, contextlib.suppress(OSError):
                    conn.sendall(f"demo-service-{idx + 1}\n".encode())

        threading.Thread(target=_accept_loop, daemon=True).start()
    return socks, ports


def load_simulated_hosts(path: Path) -> list[HostResult]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [HostResult(**row) for row in data["hosts"]]


def run_demo(sample_path: Path | None = None) -> ScanReport:
    """Offline demo: simulated ICMP sweep + real port scan against localhost."""
    started = time.perf_counter()
    report = ScanReport(
        command="demo",
        started_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    if sample_path is None:
        sample_path = Path(__file__).resolve().parent / "sample_results.json"
    simulated = load_simulated_hosts(sample_path)
    report.hosts.extend(simulated)
    report.notes.append(f"host discovery loaded from {sample_path.name} (simulated; no ICMP used)")

    socks, ports = _demo_listeners(3)
    try:
        live = tcp_probe("127.0.0.1", ports=ports, timeout_s=0.5)
        report.hosts.append(live)
        port_results = scan_ports(
            ["127.0.0.1"],
            ports + [1],  # include a closed port for contrast
            timeout_s=0.5,
            workers=8,
            banners=True,
            progress=False,
        )
        report.ports.extend(port_results)
        report.notes.append(f"TCP connect scan of 127.0.0.1 on demo ports {ports} (plus closed :1)")
    finally:
        for s in socks:
            s.close()

    report.duration_s = time.perf_counter() - started
    return report


# ---------------------------------------------------------------- CLI


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sweep",
        description="Ping sweep and TCP port scanner. Only scan networks you own.",
        epilog="See README.md for responsible-use notes.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    safety = argparse.ArgumentParser(add_help=False)
    safety.add_argument(
        "--i-own-this-network",
        action="store_true",
        help="allow targets outside private/loopback/documentation ranges",
    )
    safety.add_argument(
        "--allow-large",
        action="store_true",
        help=f"raise the target cap from {DEFAULT_MAX_TARGETS:,} to {HARD_MAX_TARGETS:,}",
    )
    safety.add_argument(
        "--workers",
        type=int,
        default=None,
        help="concurrent probes (default: 64 for discover, 128 for scan)",
    )
    safety.add_argument("--timeout", type=float, default=1.0, help="per-probe timeout seconds")
    safety.add_argument("--json", type=Path, metavar="FILE", help="write JSON report")
    safety.add_argument("--csv", type=Path, metavar="FILE", help="write CSV report")
    safety.add_argument("-q", "--quiet", action="store_true", help="less progress on stderr")

    targets = argparse.ArgumentParser(add_help=False)
    targets.add_argument(
        "targets",
        nargs="*",
        help="IP, CIDR, or range (192.168.1.10-20). Hostnames are not resolved.",
    )
    targets.add_argument("-f", "--file", type=Path, help="file of targets, one per line")

    sub = p.add_subparsers(dest="command", required=True)

    pd = sub.add_parser("discover", parents=[safety, targets], help="find live hosts")
    pd.add_argument(
        "--method",
        choices=["auto", "icmp", "tcp"],
        default="auto",
        help="discovery method (default: auto = ICMP, then TCP fallback)",
    )

    ps = sub.add_parser("scan", parents=[safety, targets], help="discover + TCP port scan")
    ps.add_argument(
        "--method",
        choices=["auto", "icmp", "tcp"],
        default="auto",
        help="discovery method before the port scan",
    )
    ps.add_argument(
        "-p",
        "--ports",
        default="common",
        help="port list/range or 'common' (default: common)",
    )
    ps.add_argument(
        "--skip-discovery",
        action="store_true",
        help="scan every target; do not ping first",
    )
    ps.add_argument("--banners", action="store_true", help="grab short service banners")

    sub.add_parser("demo", help="offline walkthrough (no network required)")
    return p


def _collect_hosts(args: argparse.Namespace) -> list[IPv4]:
    specs: list[str] = list(args.targets)
    if args.file:
        specs.extend(load_target_file(args.file))
    if not specs:
        raise SweepError("give TARGETS or --file")
    hosts = expand_targets(specs)
    validate_targets(
        hosts,
        i_own_this=args.i_own_this_network,
        allow_large=args.allow_large,
    )
    return hosts


def _emit(report: ScanReport, args: argparse.Namespace) -> None:
    print(format_summary(report))
    print()
    if report.hosts:
        print("=== Hosts ===")
        # For large sweeps, show only the ones that responded unless quiet is off
        # and the set is small.
        show = report.hosts if len(report.hosts) <= 32 else report.hosts_up
        if len(report.hosts) > 32:
            print(f"(showing {len(show)} up hosts of {len(report.hosts)} probed)")
        print(format_host_table(show))
        print()
    if report.ports:
        print("=== Open ports ===")
        print(format_port_table(report.ports, only_open=True))
        print()
    if args.json:
        write_json(report, args.json)
        print(f"Wrote JSON report: {args.json}")
    if args.csv:
        write_csv(report, args.csv)
        print(f"Wrote CSV report: {args.csv}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            report = run_demo()
            # demo has no --json/--csv on the parser; print only.
            print(format_summary(report))
            print()
            print("=== Simulated host sweep (from sample_results.json) ===")
            print(format_host_table([h for h in report.hosts if h.method == "simulated"]))
            print()
            print("=== Live TCP scan of 127.0.0.1 demo listeners ===")
            print(format_host_table([h for h in report.hosts if h.host == "127.0.0.1"]))
            print()
            print(format_port_table(report.ports, only_open=True))
            return 0

        hosts = _collect_hosts(args)
        if getattr(args, "i_own_this_network", False):
            print(
                "WARNING: --i-own-this-network set; scanning outside the default "
                "safe ranges. Make sure you are authorized.",
                file=sys.stderr,
            )
        started = time.perf_counter()
        report = ScanReport(
            command=args.command,
            started_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        progress = not args.quiet

        if args.command == "discover":
            workers = args.workers if args.workers is not None else 64
            report.hosts = discover_hosts(
                hosts,
                method=args.method,
                timeout_s=args.timeout,
                workers=workers,
                progress=progress,
            )
            report.notes.append(f"method={args.method}")
        elif args.command == "scan":
            ports = parse_ports(args.ports)
            disc_workers = args.workers if args.workers is not None else 64
            scan_workers = args.workers if args.workers is not None else 128
            if args.skip_discovery:
                alive_hosts = [str(h) for h in hosts]
                report.hosts = [
                    HostResult(str(h), True, "none", None, "discovery skipped") for h in hosts
                ]
            else:
                report.hosts = discover_hosts(
                    hosts,
                    method=args.method,
                    timeout_s=args.timeout,
                    workers=disc_workers,
                    progress=progress,
                )
                alive_hosts = [h.host for h in report.hosts_up]
            if not alive_hosts:
                report.notes.append("no live hosts; port scan skipped")
            else:
                report.ports = scan_ports(
                    alive_hosts,
                    ports,
                    timeout_s=min(args.timeout, 1.0),
                    workers=scan_workers,
                    banners=args.banners,
                    progress=progress,
                )
                report.notes.append(
                    f"scanned {len(ports)} port(s) on {len(alive_hosts)} host(s); "
                    f"method={args.method}"
                )
        report.duration_s = time.perf_counter() - started
        _emit(report, args)
    except SweepError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
