#!/usr/bin/env python3
"""Subnet calculator and VLSM planner (IPv4, standard library only).

Commands:
    info  ADDR/PREFIX | ADDR MASK ...  Show network details (CIDR or IP + dotted mask).
    split CIDR NEW_PREFIX              Split a network into equal subnets.
    vlsm  BASE_CIDR NAME=HOSTS ...     Allocate variable-length subnets by host need.
    hosts N [NETWORK]                  Smallest subnet that fits N hosts (also: --hosts N).
    batch FILE                         Run `info` on every network listed in a file.
    demo                               Run a walkthrough using synthetic data.

Add --json to info, split, vlsm, hosts, or batch for machine-readable output.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

IPv4Net = ipaddress.IPv4Network


@dataclass(frozen=True)
class SubnetInfo:
    """Computed details for a single IPv4 network."""

    cidr: str
    network: str
    broadcast: str
    netmask: str
    wildcard: str
    prefix: int
    total_addresses: int
    usable_hosts: int
    first_host: str | None
    last_host: str | None
    is_private: bool
    scope: str
    input_address: str
    address_role: str
    binary_mask: str
    ip_class: str


RFC1918 = tuple(ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
RFC5737 = tuple(
    ipaddress.IPv4Network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)


def classify(net: IPv4Net) -> str:
    """Human-readable address scope for a network."""
    if any(net.subnet_of(r) for r in RFC1918):
        return "Private (RFC 1918)"
    if any(net.subnet_of(r) for r in RFC5737):
        return "Documentation (RFC 5737)"
    if net.subnet_of(ipaddress.IPv4Network("100.64.0.0/10")):
        return "Carrier-grade NAT (RFC 6598)"
    if net.is_loopback:
        return "Loopback"
    if net.is_link_local:
        return "Link-local (APIPA)"
    if net.is_multicast:
        return "Multicast"
    if net.is_global:
        return "Public"
    return "Reserved / special-use"


@dataclass(frozen=True)
class Allocation:
    """One VLSM allocation: a named requirement mapped to a subnet."""

    name: str
    hosts_needed: int
    subnet: IPv4Net

    @property
    def usable_hosts(self) -> int:
        return usable_host_count(self.subnet)

    @property
    def wasted(self) -> int:
        return self.usable_hosts - self.hosts_needed


def parse_interface(text: str) -> ipaddress.IPv4Interface:
    """Parse 'addr/prefix', 'addr/mask' or 'addr mask' into address + network.

    Host bits are allowed (e.g. 10.1.2.77/24 lives in 10.1.2.0/24) because that
    is how addresses are usually written on interfaces.
    """
    text = text.strip()
    if " " in text:
        addr, mask = text.split(None, 1)
        text = f"{addr}/{mask.strip().lstrip('/')}"
    if "/" not in text:
        raise ValueError(f"missing prefix length or netmask: {text!r}")
    try:
        return ipaddress.IPv4Interface(text)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as exc:
        raise ValueError(f"invalid IPv4 network {text!r}: {exc}") from exc


def parse_network(text: str) -> IPv4Net:
    """Parse a CIDR or 'address netmask' string into its network."""
    return parse_interface(text).network


def is_mask_token(token: str) -> bool:
    """True for a dotted netmask ('255.255.255.192') or a '/26' prefix token."""
    token = token.strip()
    if token.startswith("/"):
        return token[1:].isdigit() and 0 <= int(token[1:]) <= 32
    if token.count(".") != 3:
        return False
    try:
        ipaddress.IPv4Network(f"0.0.0.0/{token}")
    except ValueError:
        return False
    return True


def join_address_args(tokens: list[str]) -> list[str]:
    """Pair 'IP MASK' given as two CLI arguments into one 'IP MASK' string."""
    out: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        nxt = tokens[i + 1] if i + 1 < len(tokens) else None
        if "/" not in tok and " " not in tok.strip() and nxt is not None and is_mask_token(nxt):
            out.append(f"{tok} {nxt}")
            i += 2
        else:
            out.append(tok)
            i += 1
    return out


def binary_mask(net: IPv4Net) -> str:
    """Netmask as dotted binary octets, e.g. 11111111.11111111.11111111.11000000."""
    return ".".join(f"{octet:08b}" for octet in net.netmask.packed)


def legacy_class(addr: ipaddress.IPv4Address) -> str:
    """Pre-CIDR classful address class from the first octet (historical only)."""
    first = addr.packed[0]
    if first < 128:
        return "A"
    if first < 192:
        return "B"
    if first < 224:
        return "C"
    if first < 240:
        return "D (multicast)"
    return "E (experimental)"


def usable_host_count(net: IPv4Net) -> int:
    """Usable host addresses. /31 (RFC 3021) gives 2, /32 gives 1."""
    if net.prefixlen >= 31:
        return net.num_addresses
    return net.num_addresses - 2


def subnet_info(text: str) -> SubnetInfo:
    """Return a SubnetInfo for a CIDR / 'address mask' string."""
    iface = parse_interface(text)
    net, addr = iface.network, iface.ip
    if net.prefixlen >= 31:
        first, last = net.network_address, net.broadcast_address
    else:
        first, last = net.network_address + 1, net.broadcast_address - 1
    return SubnetInfo(
        cidr=str(net),
        network=str(net.network_address),
        broadcast=str(net.broadcast_address),
        netmask=str(net.netmask),
        wildcard=str(net.hostmask),
        prefix=net.prefixlen,
        total_addresses=net.num_addresses,
        usable_hosts=usable_host_count(net),
        first_host=str(first),
        last_host=str(last),
        is_private=any(net.subnet_of(r) for r in RFC1918),
        scope=classify(net),
        input_address=str(addr),
        address_role=address_role(addr, net),
        binary_mask=binary_mask(net),
        ip_class=legacy_class(addr),
    )


def address_role(addr: ipaddress.IPv4Address, net: IPv4Net) -> str:
    """Whether the input is the network address, broadcast, or a usable host."""
    if net.prefixlen >= 31:
        return "host address"
    if addr == net.network_address:
        return "network address"
    if addr == net.broadcast_address:
        return "broadcast address"
    return "host address"


def split_network(text: str, new_prefix: int) -> list[IPv4Net]:
    """Split a network into equal subnets of the given prefix length."""
    net = parse_network(text)
    if not net.prefixlen <= new_prefix <= 32:
        raise ValueError(f"new prefix /{new_prefix} must be between /{net.prefixlen} and /32")
    return list(net.subnets(new_prefix=new_prefix))


def prefix_for_hosts(hosts: int) -> int:
    """Smallest prefix whose subnet holds `hosts` usable addresses."""
    if hosts < 1:
        raise ValueError("host count must be at least 1")
    if hosts == 1:
        return 32
    if hosts == 2:
        return 31
    bits = math.ceil(math.log2(hosts + 2))
    return 32 - bits


@dataclass(frozen=True)
class HostsFit:
    """Smallest subnet size that holds a requested number of hosts."""

    hosts_requested: int
    prefix: int
    netmask: str
    wildcard: str
    binary_mask: str
    block_size: int
    usable_hosts: int
    spare_hosts: int
    base_network: str | None = None
    first_subnet: str | None = None
    first_subnet_range: str | None = None
    subnets_available: int | None = None


def hosts_fit(hosts: int, network: str | None = None) -> HostsFit:
    """Find the smallest subnet for `hosts`, optionally placed inside `network`."""
    prefix = prefix_for_hosts(hosts)
    size = ipaddress.IPv4Network(("0.0.0.0", prefix))
    usable = usable_host_count(size)
    extra: dict[str, object] = {}
    if network is not None:
        base = parse_network(network)
        if prefix < base.prefixlen:
            raise ValueError(f"{hosts} hosts need a /{prefix}, which is larger than {base}")
        first = ipaddress.IPv4Network((int(base.network_address), prefix))
        info = subnet_info(str(first))
        extra = {
            "base_network": str(base),
            "first_subnet": str(first),
            "first_subnet_range": f"{info.first_host} - {info.last_host}",
            "subnets_available": 2 ** (prefix - base.prefixlen),
        }
    return HostsFit(
        hosts_requested=hosts,
        prefix=prefix,
        netmask=str(size.netmask),
        wildcard=str(size.hostmask),
        binary_mask=binary_mask(size),
        block_size=size.num_addresses,
        usable_hosts=usable,
        spare_hosts=usable - hosts,
        **extra,
    )


def vlsm_allocate(base: str, requirements: dict[str, int]) -> list[Allocation]:
    """Allocate subnets largest-first inside `base`.

    Largest-first keeps every block aligned on its natural boundary, so the
    allocation is contiguous and never overlaps. Raises ValueError if the
    requirements don't fit.
    """
    net = parse_network(base)
    if not requirements:
        raise ValueError("no requirements given")
    ordered = sorted(requirements.items(), key=lambda kv: (-kv[1], kv[0]))
    cursor = int(net.network_address)
    end = int(net.broadcast_address)
    allocations: list[Allocation] = []
    for name, hosts in ordered:
        prefix = prefix_for_hosts(hosts)
        if prefix < net.prefixlen:
            raise ValueError(f"{name} needs {hosts} hosts; larger than {net}")
        size = 2 ** (32 - prefix)
        cursor = (cursor + size - 1) // size * size  # align to block boundary
        if cursor + size - 1 > end:
            raise ValueError(f"out of space in {net} while placing {name} ({hosts} hosts)")
        subnet = ipaddress.IPv4Network((cursor, prefix))
        allocations.append(Allocation(name, hosts, subnet))
        cursor += size
    return allocations


def parse_requirements(items: list[str]) -> dict[str, int]:
    """Parse ['Sales=50', 'IT=20'] into {'Sales': 50, 'IT': 20}."""
    reqs: dict[str, int] = {}
    for item in items:
        name, sep, value = item.partition("=")
        name = name.strip()
        if not sep or not name:
            raise ValueError(f"expected NAME=HOSTS, got {item!r}")
        try:
            hosts = int(value)
        except ValueError:
            raise ValueError(f"host count for {name!r} is not a number") from None
        if name in reqs:
            raise ValueError(f"duplicate requirement name {name!r}")
        reqs[name] = hosts
    return reqs


def read_lines(path: Path) -> list[str]:
    """Non-empty, non-comment lines from a text file."""
    lines = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            lines.append(line)
    return lines


def load_vlsm_file(path: Path) -> tuple[str, dict[str, int]]:
    """First line is the base CIDR; remaining lines are NAME=HOSTS."""
    lines = read_lines(path)
    if not lines:
        raise ValueError(f"{path} is empty")
    return lines[0], parse_requirements(lines[1:])


# ---------------------------------------------------------------- output


def _rows(rows: list[tuple[str, str]]) -> str:
    width = max(len(k) for k, _ in rows)
    return "\n".join(f"{k:<{width}} : {v}" for k, v in rows)


def format_info(info: SubnetInfo) -> str:
    return _rows(
        [
            ("Input address", f"{info.input_address} ({info.address_role})"),
            ("Network", info.cidr),
            ("Prefix length", f"/{info.prefix}"),
            ("Netmask", info.netmask),
            ("Binary mask", info.binary_mask),
            ("Wildcard", info.wildcard),
            ("Broadcast", info.broadcast),
            ("Host range", f"{info.first_host} - {info.last_host}"),
            ("Total addresses", f"{info.total_addresses:,}"),
            ("Usable hosts", f"{info.usable_hosts:,}"),
            ("IP class (legacy)", _class_label(info.ip_class)),
            ("Scope", info.scope),
        ]
    )


_CLASS_DEFAULT_PREFIX = {"A": "/8", "B": "/16", "C": "/24"}


def _class_label(ip_class: str) -> str:
    default = _CLASS_DEFAULT_PREFIX.get(ip_class)
    return f"{ip_class} (classful default {default})" if default else ip_class


def format_hosts(fit: HostsFit) -> str:
    rows = [
        ("Hosts requested", f"{fit.hosts_requested:,}"),
        ("Smallest fit", f"/{fit.prefix}"),
        ("Netmask", fit.netmask),
        ("Binary mask", fit.binary_mask),
        ("Wildcard", fit.wildcard),
        ("Block size", f"{fit.block_size:,} addresses"),
        ("Usable hosts", f"{fit.usable_hosts:,} ({fit.spare_hosts:,} spare)"),
    ]
    if fit.base_network:
        rows += [
            ("Base network", fit.base_network),
            ("First subnet", f"{fit.first_subnet} ({fit.first_subnet_range})"),
            ("Subnets available", f"{fit.subnets_available:,}"),
        ]
    return _rows(rows)


def format_split(subnets: list[IPv4Net]) -> str:
    lines = [f"{'#':>3}  {'Subnet':<20} {'Host range':<33} Usable"]
    for i, net in enumerate(subnets, 1):
        info = subnet_info(str(net))
        rng = f"{info.first_host} - {info.last_host}"
        lines.append(f"{i:>3}  {info.cidr:<20} {rng:<33} {info.usable_hosts}")
    return "\n".join(lines)


def format_vlsm(base: str, allocations: list[Allocation]) -> str:
    net = parse_network(base)
    header = (
        f"{'Name':<14} {'Need':>5} {'Subnet':<20} {'Mask':<16} "
        f"{'Host range':<33} {'Usable':>6} {'Spare':>5}"
    )
    lines = [f"VLSM plan for {net}", header, "-" * len(header)]
    used = 0
    for a in allocations:
        info = subnet_info(str(a.subnet))
        rng = f"{info.first_host} - {info.last_host}"
        lines.append(
            f"{a.name:<14} {a.hosts_needed:>5} {info.cidr:<20} {info.netmask:<16} "
            f"{rng:<33} {a.usable_hosts:>6} {a.wasted:>5}"
        )
        used += a.subnet.num_addresses
    pct = used / net.num_addresses * 100
    lines.append(f"\nAddress space used: {used:,} of {net.num_addresses:,} ({pct:.1f}%)")
    return "\n".join(lines)


def split_to_dict(text: str, new_prefix: int, subnets: list[IPv4Net]) -> dict:
    return {
        "network": str(parse_network(text)),
        "new_prefix": new_prefix,
        "count": len(subnets),
        "subnets": [_subnet_summary(n) for n in subnets],
    }


def vlsm_to_dict(base: str, allocations: list[Allocation]) -> dict:
    net = parse_network(base)
    used = sum(a.subnet.num_addresses for a in allocations)
    return {
        "base": str(net),
        "allocations": [
            {"name": a.name, "hosts_needed": a.hosts_needed, **_subnet_summary(a.subnet)}
            | {"spare_hosts": a.wasted}
            for a in allocations
        ],
        "addresses_used": used,
        "addresses_total": net.num_addresses,
        "percent_used": round(used / net.num_addresses * 100, 1),
    }


def _subnet_summary(net: IPv4Net) -> dict:
    info = subnet_info(str(net))
    return {
        "subnet": info.cidr,
        "netmask": info.netmask,
        "broadcast": info.broadcast,
        "first_host": info.first_host,
        "last_host": info.last_host,
        "usable_hosts": info.usable_hosts,
    }


def to_json(obj: object) -> str:
    return json.dumps(obj, indent=2)


DEMO_BASE = "192.168.10.0/24"
DEMO_REQUIREMENTS = {"Sales": 60, "Engineering": 28, "Guest-WiFi": 25, "Mgmt": 10, "WAN-Link": 2}


def run_demo() -> str:
    parts = [
        "== 1. Subnet info for a host: 192.168.10.77 255.255.255.192 ==",
        format_info(subnet_info("192.168.10.77 255.255.255.192")),
        "",
        "== 2. Smallest subnet for 50 hosts inside 10.20.30.0/24 ==",
        format_hosts(hosts_fit(50, "10.20.30.0/24")),
        "",
        "== 3. Split 172.16.0.0/22 into /24s ==",
        format_split(split_network("172.16.0.0/22", 24)),
        "",
        "== 4. VLSM: small office on 192.168.10.0/24 ==",
        format_vlsm(DEMO_BASE, vlsm_allocate(DEMO_BASE, DEMO_REQUIREMENTS)),
        "",
        "== 5. Documentation range (RFC 5737): 203.0.113.0/24 ==",
        format_info(subnet_info("203.0.113.0/24")),
    ]
    return "\n".join(parts)


# ---------------------------------------------------------------- CLI


def _prefix_arg(text: str) -> int:
    return int(text.lstrip("/"))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="subnet_calc",
        description="IPv4 subnet calculator and VLSM planner.",
        epilog="Shortcut: subnet_calc.py --hosts 50 [--network 192.168.10.0/24] [--json]",
    )
    p.add_argument("--hosts", type=int, metavar="N", help="smallest subnet that fits N hosts")
    p.add_argument("--network", help="with --hosts: place the subnet inside this network")
    p.add_argument("--json", action="store_true", help="machine-readable JSON output")

    # --json is also accepted after the subcommand; SUPPRESS keeps the top-level value.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="JSON")

    sub = p.add_subparsers(dest="command")

    pi = sub.add_parser("info", parents=[common], help="details for one or more networks")
    pi.add_argument(
        "address",
        nargs="+",
        help="10.0.0.5/24, '10.0.0.5 255.255.255.0', or 10.0.0.5 255.255.255.0 (two args)",
    )

    ps = sub.add_parser("split", parents=[common], help="split a network into equal subnets")
    ps.add_argument("cidr")
    ps.add_argument("new_prefix", type=_prefix_arg)

    pv = sub.add_parser("vlsm", parents=[common], help="allocate subnets by host requirement")
    pv.add_argument("base", nargs="?", help="base network, e.g. 192.168.10.0/24")
    pv.add_argument("requirements", nargs="*", metavar="NAME=HOSTS")
    pv.add_argument("-f", "--file", type=Path, help="read base + requirements from file")

    ph = sub.add_parser("hosts", parents=[common], help="smallest subnet that fits N hosts")
    ph.add_argument("count", type=int, metavar="N")
    ph.add_argument("network", nargs="?", help="optional network to place the subnet in")

    pb = sub.add_parser("batch", parents=[common], help="run 'info' on each network in a file")
    pb.add_argument("file", type=Path)

    sub.add_parser("demo", help="run a walkthrough with synthetic data")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    as_json = args.json
    try:
        if args.command is None:
            if args.hosts is None:
                parser.print_usage(sys.stderr)
                raise ValueError("choose a command, or use --hosts N")
            args.command, args.count = "hosts", args.hosts
        elif args.network and args.command != "hosts":
            raise ValueError("--network is only used with --hosts")

        if args.command in ("info", "batch"):
            items = args.address if args.command == "info" else read_lines(args.file)
            infos = [subnet_info(a) for a in join_address_args(items)]
            if as_json:
                print(to_json([asdict(i) for i in infos]))
            else:
                print("\n\n".join(format_info(i) for i in infos))
        elif args.command == "split":
            subnets = split_network(args.cidr, args.new_prefix)
            if as_json:
                print(to_json(split_to_dict(args.cidr, args.new_prefix, subnets)))
            else:
                print(format_split(subnets))
        elif args.command == "vlsm":
            if args.file:
                base, reqs = load_vlsm_file(args.file)
            elif args.base:
                base, reqs = args.base, parse_requirements(args.requirements)
            else:
                raise ValueError("give BASE NAME=HOSTS ... or --file")
            allocations = vlsm_allocate(base, reqs)
            if as_json:
                print(to_json(vlsm_to_dict(base, allocations)))
            else:
                print(format_vlsm(base, allocations))
        elif args.command == "hosts":
            network = getattr(args, "network", None)
            fit = hosts_fit(args.count, network)
            print(to_json(asdict(fit)) if as_json else format_hosts(fit))
        elif args.command == "demo":
            print(run_demo())
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
