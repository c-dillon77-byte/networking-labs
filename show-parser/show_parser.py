#!/usr/bin/env python3
"""Cisco IOS/IOS-XE show-command parser (Python 3.10+, standard library).

Hand-written regex parsers for common `show` outputs. Auto-detects the command
from the text, or accept --command. Reads a file or stdin.

Supported (default engine = regex):
    show ip interface brief
    show vlan brief
    show interfaces status
    show mac address-table
    show cdp neighbors
    show lldp neighbors
    show ip route
    show version

Optional: --engine textfsm if the `textfsm` package and ntc-templates are installed.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


class ParseError(Exception):
    """User-facing parse/CLI error (no traceback; exit code 2)."""


def _clean_lines(text: str) -> list[str]:
    return [ln.rstrip() for ln in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]


def _collapse_ws(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip())


# ---------------------------------------------------------------------------
# Result containers
# ---------------------------------------------------------------------------


@dataclass
class ParseResult:
    command: str
    rows: list[dict] = field(default_factory=list)
    meta: dict = field(default_factory=dict)  # for show version (single record)
    notes: list[str] = field(default_factory=list)

    @property
    def kind(self) -> str:
        return "meta" if self.meta and not self.rows else "table"


# ---------------------------------------------------------------------------
# Auto-detection
# ---------------------------------------------------------------------------

# Ordered: more specific markers first.
DETECT_RULES: list[tuple[str, re.Pattern[str]]] = [
    (
        "show ip interface brief",
        re.compile(
            r"^Interface\s+IP-Address\s+OK\?\s+Method\s+Status\s+Protocol\s*$",
            re.MULTILINE | re.IGNORECASE,
        ),
    ),
    (
        "show vlan brief",
        re.compile(
            r"^VLAN\s+Name\s+Status\s+Ports\s*$",
            re.MULTILINE | re.IGNORECASE,
        ),
    ),
    (
        "show interfaces status",
        re.compile(
            r"^Port\s+Name\s+Status\s+Vlan\s+Duplex\s+Speed\s+Type\s*$",
            re.MULTILINE | re.IGNORECASE,
        ),
    ),
    (
        "show mac address-table",
        re.compile(
            r"Mac Address Table|^\s*Vlan\s+Mac Address\s+Type\s+Ports\s*$",
            re.MULTILINE | re.IGNORECASE,
        ),
    ),
    (
        "show cdp neighbors",
        re.compile(
            r"Device ID\s+Local Intrfce\s+Holdtme\s+Capability",
            re.MULTILINE | re.IGNORECASE,
        ),
    ),
    (
        "show lldp neighbors",
        re.compile(
            r"Device ID\s+Local Intf\s+Hold-time\s+Capability\s+Port ID",
            re.MULTILINE | re.IGNORECASE,
        ),
    ),
    (
        "show ip route",
        re.compile(
            r"Gateway of last resort|^Codes:\s+L - local",
            re.MULTILINE | re.IGNORECASE,
        ),
    ),
    (
        "show version",
        re.compile(
            r"Cisco IOS Software|Technical Support: http://www\.cisco\.com",
            re.MULTILINE | re.IGNORECASE,
        ),
    ),
]

COMMAND_ALIASES: dict[str, str] = {
    "show ip interface brief": "show ip interface brief",
    "show ip int brief": "show ip interface brief",
    "sh ip int br": "show ip interface brief",
    "show vlan brief": "show vlan brief",
    "show vlan": "show vlan brief",
    "sh vlan br": "show vlan brief",
    "show interfaces status": "show interfaces status",
    "show interface status": "show interfaces status",
    "show int status": "show interfaces status",
    "show mac address-table": "show mac address-table",
    "show mac-address-table": "show mac address-table",
    "show mac address table": "show mac address-table",
    "show cdp neighbors": "show cdp neighbors",
    "show cdp neighbour": "show cdp neighbors",
    "show cdp neighbors detail": "show cdp neighbors",
    "sh cdp nei": "show cdp neighbors",
    "show lldp neighbors": "show lldp neighbors",
    "show lldp neighbour": "show lldp neighbors",
    "sh lldp nei": "show lldp neighbors",
    "show ip route": "show ip route",
    "sh ip route": "show ip route",
    "show version": "show version",
    "sh ver": "show version",
}


def normalize_command(name: str) -> str:
    key = _collapse_ws(name).lower()
    if key not in COMMAND_ALIASES:
        supported = ", ".join(sorted({v for v in COMMAND_ALIASES.values()}))
        raise ParseError(f"unknown command {name!r}; supported: {supported}")
    return COMMAND_ALIASES[key]


def detect_command(text: str) -> str:
    for command, pattern in DETECT_RULES:
        if pattern.search(text):
            return command
    raise ParseError("could not auto-detect the show command; pass --command explicitly")


# ---------------------------------------------------------------------------
# Parsers — each pattern is commented so the regex is readable
# ---------------------------------------------------------------------------


def parse_ip_interface_brief(text: str) -> ParseResult:
    """Parse `show ip interface brief`.

    Columns are fixed-ish but interface names vary in length (Gi0/0 vs
    TenGigabitEthernet1/0/1), so we match fields from the right / with flexible gaps.
    """
    # Interface name: letters, digits, / . : -  (covers Gi0/0.10, Serial0/0/0, Tu1, etc.)
    # IP: dotted quad OR the literal "unassigned"
    # OK?: YES/NO
    # Method: NVRAM|manual|DHCP|unset|IPCP|TFTP|...
    # Status: up | down | administratively down  (may contain spaces)
    # Protocol: up | down
    row_re = re.compile(
        r"^(?P<interface>\S+)\s+"
        r"(?P<ip>\d+\.\d+\.\d+\.\d+|unassigned)\s+"
        r"(?P<ok>YES|NO)\s+"
        r"(?P<method>\S+)\s+"
        r"(?P<status>administratively down|up|down)\s+"
        r"(?P<protocol>up|down)\s*$",
        re.IGNORECASE,
    )
    rows: list[dict] = []
    for line in _clean_lines(text):
        if not line or line.lower().startswith("interface"):
            continue
        m = row_re.match(line)
        if not m:
            continue
        rows.append(
            {
                "interface": m.group("interface"),
                "ip_address": m.group("ip"),
                "ok": m.group("ok").upper(),
                "method": m.group("method"),
                "status": m.group("status").lower(),
                "protocol": m.group("protocol").lower(),
            }
        )
    if not rows:
        raise ParseError("no interface rows matched in show ip interface brief")
    return ParseResult("show ip interface brief", rows=rows)


def parse_vlan_brief(text: str) -> ParseResult:
    """Parse `show vlan brief`, including wrapped port-list continuation lines."""
    # Primary row: VLAN id, name, status, optional ports
    #   10   USERS   active   Fa0/1, Fa0/2, Gi0/1
    vlan_re = re.compile(
        r"^(?P<vlan>\d+)\s+"
        r"(?P<name>\S+(?:\s+\S+)*?)\s+"
        r"(?P<status>active|act/lshut|act/unsup|suspend(?:ed)?)\s*"
        r"(?P<ports>.*)$",
        re.IGNORECASE,
    )
    # Continuation: indented list of more ports (no VLAN id at start)
    cont_re = re.compile(r"^\s{2,}(?P<ports>\S.*)$")

    rows: list[dict] = []
    current: dict | None = None
    for line in _clean_lines(text):
        if not line or line.startswith("---") or line.lower().startswith("vlan "):
            continue
        m = vlan_re.match(line)
        if m:
            ports_raw = m.group("ports").strip()
            ports = _split_ports(ports_raw)
            current = {
                "vlan": int(m.group("vlan")),
                "name": m.group("name").strip(),
                "status": m.group("status").lower(),
                "ports": ports,
            }
            rows.append(current)
            continue
        if current is not None:
            c = cont_re.match(line)
            if c:
                current["ports"].extend(_split_ports(c.group("ports")))
    if not rows:
        raise ParseError("no VLAN rows matched in show vlan brief")
    # Normalize ports to a comma-separated string for tabular output.
    for row in rows:
        row["ports"] = ", ".join(row["ports"])
        row["port_count"] = 0 if not row["ports"] else len(row["ports"].split(", "))
    return ParseResult("show vlan brief", rows=rows)


def _split_ports(text: str) -> list[str]:
    if not text.strip():
        return []
    return [p.strip() for p in text.split(",") if p.strip()]


def parse_interfaces_status(text: str) -> ParseResult:
    """Parse `show interfaces status` (switch port table)."""
    # Port names are short (Gi0/1, Fa0/24). Name field may be empty.
    # Status values: connected | notconnect | disabled | err-disabled | inactive | monitoring
    # Vlan: number | trunk | routed
    row_re = re.compile(
        r"^(?P<port>\S+)\s+"
        r"(?P<name>.*?)\s{2,}"  # name padded; require 2+ spaces before Status
        r"(?P<status>connected|notconnect|disabled|err-disabled|inactive|monitoring|faulty)\s+"
        r"(?P<vlan>\S+)\s+"
        r"(?P<duplex>\S+)\s+"
        r"(?P<speed>\S+)\s+"
        r"(?P<type>.+?)\s*$",
        re.IGNORECASE,
    )
    # Some lines have an empty name and only one gap — fallback without the name field.
    row_re_no_name = re.compile(
        r"^(?P<port>\S+)\s+"
        r"(?P<status>connected|notconnect|disabled|err-disabled|inactive|monitoring|faulty)\s+"
        r"(?P<vlan>\S+)\s+"
        r"(?P<duplex>\S+)\s+"
        r"(?P<speed>\S+)\s+"
        r"(?P<type>.+?)\s*$",
        re.IGNORECASE,
    )
    rows: list[dict] = []
    for line in _clean_lines(text):
        if not line or line.lower().startswith("port "):
            continue
        m = row_re.match(line) or row_re_no_name.match(line)
        if not m:
            continue
        groups = m.groupdict()
        rows.append(
            {
                "port": groups["port"],
                "name": groups.get("name", "").strip(),
                "status": groups["status"].lower(),
                "vlan": groups["vlan"],
                "duplex": groups["duplex"],
                "speed": groups["speed"],
                "type": groups["type"].strip(),
            }
        )
    if not rows:
        raise ParseError("no port rows matched in show interfaces status")
    return ParseResult("show interfaces status", rows=rows)


def parse_mac_address_table(text: str) -> ParseResult:
    """Parse `show mac address-table` / `show mac-address-table`."""
    # Vlan may be a number or "All"
    # MAC: xxxx.xxxx.xxxx
    # Type: STATIC | DYNAMIC | STATIC (exclude CPU noise optionally kept)
    row_re = re.compile(
        r"^\s*(?P<vlan>\d+|All)\s+"
        r"(?P<mac>[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s+"
        r"(?P<type>STATIC|DYNAMIC)\s+"
        r"(?P<ports>\S+)\s*$",
        re.IGNORECASE,
    )
    rows: list[dict] = []
    for line in _clean_lines(text):
        m = row_re.match(line)
        if not m:
            continue
        rows.append(
            {
                "vlan": m.group("vlan"),
                "mac": m.group("mac").lower(),
                "type": m.group("type").upper(),
                "ports": m.group("ports"),
            }
        )
    if not rows:
        raise ParseError("no MAC rows matched in show mac address-table")
    return ParseResult("show mac address-table", rows=rows)


def parse_cdp_neighbors(text: str) -> ParseResult:
    """Parse `show cdp neighbors` (non-detail), including wrapped Device ID lines.

    IOS often wraps long Device IDs onto their own line, with the rest of the
    fields indented on the next line:
        R1-CORE.lab.local
                     Gig 0/1   148    R S I   CISCO2911  Gig 0/0
    Short names may stay on a single line.
    """
    header_end = re.compile(r"Port ID\s*$", re.IGNORECASE)
    # Local interface abbreviations used by CDP tables.
    local_re = r"(?P<local>(?:Gig|Fas|Ten|Eth|Wan|Mgmt|Port)\s*\S+|\S+/\S+)"
    # Capability: one or more single-letter codes; 2+ spaces before Platform.
    cap = r"(?P<capability>(?:[A-Za-z](?:\s+[A-Za-z])*))"
    data_only = re.compile(
        rf"^\s*{local_re}\s+"
        r"(?P<holdtime>\d+)\s+"
        rf"{cap}\s{{2,}}"
        r"(?P<platform>\S+)\s+"
        r"(?P<port_id>.+?)\s*$"
    )
    single = re.compile(
        rf"^(?P<device>(?!(?:Gig|Fas|Ten|Eth|Wan|Mgmt)\b)\S+)\s+"
        rf"{local_re}\s+"
        r"(?P<holdtime>\d+)\s+"
        rf"{cap}\s{{2,}}"
        r"(?P<platform>\S+)\s+"
        r"(?P<port_id>.+?)\s*$"
    )

    lines = _clean_lines(text)
    start = 0
    for i, line in enumerate(lines):
        if header_end.search(line):
            start = i + 1
            break

    rows: list[dict] = []
    pending_device: str | None = None
    for line in lines[start:]:
        raw = line.rstrip()
        if not raw.strip():
            continue
        stripped = raw.strip()
        # Device-ID-only wrap line (a single token that is not an interface name).
        if re.fullmatch(r"\S+", stripped) and not re.search(
            r"(?:Gig|Fas|Ten|Eth|Wan|Mgmt)\b|/", stripped
        ):
            pending_device = stripped
            continue
        m = data_only.match(raw) or single.match(stripped)
        if not m:
            continue
        device = (m.groupdict().get("device") or pending_device or "").strip()
        pending_device = None
        if not device:
            continue
        rows.append(
            {
                "device_id": device,
                "local_interface": _collapse_ws(m.group("local")),
                "holdtime": int(m.group("holdtime")),
                "capability": _collapse_ws(m.group("capability")),
                "platform": m.group("platform").strip(),
                "port_id": _collapse_ws(m.group("port_id")),
            }
        )
    if not rows:
        raise ParseError("no CDP neighbor rows matched")
    return ParseResult("show cdp neighbors", rows=rows)


def parse_lldp_neighbors(text: str) -> ParseResult:
    """Parse `show lldp neighbors` (non-detail table)."""
    row_re = re.compile(
        r"^(?P<device>\S+)\s+"
        r"(?P<local>\S+)\s+"
        r"(?P<holdtime>\d+)\s+"
        r"(?P<capability>\S+)\s+"
        r"(?P<port_id>.+?)\s*$"
    )
    rows: list[dict] = []
    for line in _clean_lines(text):
        if (
            not line
            or line.lower().startswith("device id")
            or line.lower().startswith("capability")
            or line.lower().startswith("(")
            or line.lower().startswith("total entries")
        ):
            continue
        m = row_re.match(line)
        if not m:
            continue
        rows.append(
            {
                "device_id": m.group("device"),
                "local_interface": m.group("local"),
                "holdtime": int(m.group("holdtime")),
                "capability": m.group("capability"),
                "port_id": m.group("port_id").strip(),
            }
        )
    if not rows:
        raise ParseError("no LLDP neighbor rows matched")
    return ParseResult("show lldp neighbors", rows=rows)


def parse_ip_route(text: str) -> ParseResult:
    """Parse `show ip route` into prefix / protocol / AD-metric / next-hop / interface."""
    # Route lines look like:
    #   O        10.50.0.0/24 [110/2] via 10.10.10.2, 00:15:32, GigabitEthernet0/0
    #   O IA     10.60.0.0/24 [110/3] via 10.10.10.2, 00:10:01, GigabitEthernet0/0
    #   C        10.10.10.0/30 is directly connected, GigabitEthernet0/0
    #   S*    0.0.0.0/0 [1/0] via 172.16.20.2
    #   S     203.0.113.0/24 [1/0] via 172.16.20.2
    codes = r"L|C|S|R|M|B|D|EX|O|IA|N1|N2|E1|E2|i|su|L1|L2|ia|U|o|P|H|l|a"
    route_re = re.compile(
        rf"^(?P<code>(?:{codes})(?:\s+(?:{codes}))?)\*?\s+"
        rf"(?P<prefix>\d+\.\d+\.\d+\.\d+(?:/\d+)?)\s+"
        rf"(?:"
        rf"\[(?P<ad>\d+)/(?P<metric>\d+)\]\s+via\s+(?P<via>\d+\.\d+\.\d+\.\d+)"
        rf"(?:,\s*(?P<age>\d+:\d+:\d+))?(?:,\s*(?P<iface_via>\S+))?"
        rf"|"
        rf"is directly connected,\s*(?P<iface_conn>\S+)"
        rf")\s*$"
    )
    # Parent "is variably subnetted" lines are skipped (no code + prefix route).
    rows: list[dict] = []
    default_via = None
    m_def = re.search(
        r"Gateway of last resort is (?P<via>\d+\.\d+\.\d+\.\d+)",
        text,
        re.IGNORECASE,
    )
    if m_def:
        default_via = m_def.group("via")

    for line in _clean_lines(text):
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("codes:"):
            continue
        if "is variably subnetted" in stripped or "subnetted," in stripped:
            continue
        if stripped.lower().startswith("gateway of last resort"):
            continue
        m = route_re.match(stripped)
        if not m:
            continue
        code = _collapse_ws(m.group("code"))
        iface = m.group("iface_via") or m.group("iface_conn") or ""
        # Leading codes may end with * for candidate default (S* 0.0.0.0/0 ...)
        is_default = bool(re.match(rf"^{re.escape(code)}\*", stripped))
        rows.append(
            {
                "code": code,
                "prefix": m.group("prefix"),
                "ad": m.group("ad") or "",
                "metric": m.group("metric") or "",
                "next_hop": m.group("via") or ("connected" if m.group("iface_conn") else ""),
                "age": m.group("age") or "",
                "interface": iface,
                "candidate_default": is_default,
            }
        )

    if not rows:
        raise ParseError("no route rows matched in show ip route")
    meta = {}
    if default_via:
        meta["gateway_of_last_resort"] = default_via
    return ParseResult("show ip route", rows=rows, meta=meta)


def parse_version(text: str) -> ParseResult:
    """Parse `show version` into a single metadata record."""
    meta: dict[str, str] = {}

    # Cisco IOS Software, C2900 Software (...), Version 15.7(3)M8, RELEASE SOFTWARE
    m = re.search(
        r"Cisco IOS Software,\s*(?P<img>.+?),\s*Version\s+(?P<version>\S+?),",
        text,
    )
    if m:
        meta["image"] = m.group("img").strip()
        meta["ios_version"] = m.group("version").rstrip(",")

    # Hostname uptime is X days, Y hours, Z minutes
    m = re.search(
        r"^(?P<hostname>\S+)\s+uptime is\s+(?P<uptime>.+)$",
        text,
        re.MULTILINE,
    )
    if m:
        meta["hostname"] = m.group("hostname")
        meta["uptime"] = m.group("uptime").strip()

    # System image file is "flash0:..."
    m = re.search(r'System image file is "([^"]+)"', text)
    if m:
        meta["system_image"] = m.group(1)

    # Cisco CISCO2911/K9 (revision 1.0) with ...
    m = re.search(r"^Cisco\s+(?P<model>\S+)\s+\(revision", text, re.MULTILINE)
    if m:
        meta["model"] = m.group("model")

    # Processor board ID FTX...
    m = re.search(r"Processor board ID\s+(?P<serial>\S+)", text)
    if m:
        meta["serial"] = m.group("serial")

    # License UDI table sometimes repeats serial / PID
    m = re.search(r"^\*?\d+\s+(?P<pid>\S+)\s+(?P<sn>\S+)\s*$", text, re.MULTILINE)
    if m:
        meta.setdefault("model", m.group("pid"))
        meta.setdefault("serial", m.group("sn"))

    m = re.search(r"Configuration register is\s+(?P<cfgreg>\S+)", text)
    if m:
        meta["config_register"] = m.group("cfgreg")

    if not meta:
        raise ParseError("could not parse show version")
    return ParseResult("show version", meta=meta)


PARSERS: dict[str, Callable[[str], ParseResult]] = {
    "show ip interface brief": parse_ip_interface_brief,
    "show vlan brief": parse_vlan_brief,
    "show interfaces status": parse_interfaces_status,
    "show mac address-table": parse_mac_address_table,
    "show cdp neighbors": parse_cdp_neighbors,
    "show lldp neighbors": parse_lldp_neighbors,
    "show ip route": parse_ip_route,
    "show version": parse_version,
}


def parse(text: str, command: str | None = None) -> ParseResult:
    cmd = normalize_command(command) if command else detect_command(text)
    parser = PARSERS[cmd]
    return parser(text)


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------


def filter_down(result: ParseResult) -> ParseResult:
    """Keep only down / admin-down / notconnect / disabled interfaces or ports."""
    if result.command == "show ip interface brief":
        rows = [r for r in result.rows if r["status"] != "up" or r["protocol"] != "up"]
        return ParseResult(result.command, rows=rows, notes=["filtered: down/admin-down"])
    if result.command == "show interfaces status":
        rows = [r for r in result.rows if r["status"] != "connected"]
        return ParseResult(result.command, rows=rows, notes=["filtered: not connected"])
    raise ParseError(f"--down is not supported for {result.command!r}")


def summarize(result: ParseResult) -> ParseResult:
    """Build a summary table for interface / VLAN parsers."""
    if result.command == "show ip interface brief":
        up = sum(1 for r in result.rows if r["status"] == "up" and r["protocol"] == "up")
        admin = sum(1 for r in result.rows if r["status"] == "administratively down")
        down = sum(
            1
            for r in result.rows
            if r["status"] == "down" or (r["status"] == "up" and r["protocol"] == "down")
        )
        unassigned = sum(1 for r in result.rows if r["ip_address"].lower() == "unassigned")
        meta = {
            "total": len(result.rows),
            "up": up,
            "down": down,
            "administratively_down": admin,
            "unassigned_ip": unassigned,
        }
        return ParseResult(result.command, meta=meta, notes=["summary"])
    if result.command == "show vlan brief":
        # Skip the reserved 1002-1005 defaults in "empty" unless they have ports.
        data_vlans = [r for r in result.rows if not (1002 <= r["vlan"] <= 1005)]
        empty = [r for r in data_vlans if r["port_count"] == 0]
        rows = [
            {
                "vlan": r["vlan"],
                "name": r["name"],
                "status": r["status"],
                "port_count": r["port_count"],
                "ports": r["ports"],
                "empty": r["port_count"] == 0,
            }
            for r in data_vlans
        ]
        return ParseResult(
            result.command,
            rows=rows,
            meta={"vlan_count": len(data_vlans), "empty_vlans": len(empty)},
            notes=["summary: empty flag set for VLANs with no ports"],
        )
    if result.command == "show interfaces status":
        connected = sum(1 for r in result.rows if r["status"] == "connected")
        meta = {
            "total": len(result.rows),
            "connected": connected,
            "not_connected": len(result.rows) - connected,
        }
        return ParseResult(result.command, meta=meta, notes=["summary"])
    raise ParseError(f"--summary is not supported for {result.command!r}")


# ---------------------------------------------------------------------------
# Optional TextFSM engine
# ---------------------------------------------------------------------------


def parse_textfsm(text: str, command: str) -> ParseResult:
    """Parse with ntc-templates TextFSM, if installed."""
    try:
        from ntc_templates.parse import parse_output  # type: ignore
    except ImportError as exc:
        raise ParseError(
            "TextFSM engine requires the 'ntc-templates' package (pip install ntc-templates)"
        ) from exc
    platform = "cisco_ios"
    try:
        data = parse_output(platform=platform, command=command, data=text)
    except Exception as exc:  # noqa: BLE001
        raise ParseError(f"TextFSM parse failed: {exc}") from exc
    if not isinstance(data, list):
        raise ParseError("TextFSM returned unexpected data")
    # Lower-case keys for consistency.
    rows = [{str(k).lower(): v for k, v in row.items()} for row in data]
    return ParseResult(command, rows=rows, notes=["engine=textfsm"])


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


def format_table(result: ParseResult) -> str:
    lines: list[str] = [f"Command: {result.command}"]
    for note in result.notes:
        lines.append(f"Note: {note}")
    if result.meta and not result.rows:
        width = max(len(k) for k in result.meta) if result.meta else 0
        for k, v in result.meta.items():
            lines.append(f"  {k:<{width}} : {v}")
        return "\n".join(lines)
    if result.meta:
        lines.append("Meta: " + ", ".join(f"{k}={v}" for k, v in result.meta.items()))
    if not result.rows:
        lines.append("(no rows)")
        return "\n".join(lines)
    keys = list(result.rows[0].keys())
    str_rows = [[_cell(r.get(k, "")) for k in keys] for r in result.rows]
    widths = [len(k) for k in keys]
    for row in str_rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    header = "  ".join(k.upper().replace("_", " ").ljust(widths[i]) for i, k in enumerate(keys))
    rule = "  ".join("-" * widths[i] for i in range(len(keys)))
    lines.append(header)
    lines.append(rule)
    for row in str_rows:
        lines.append("  ".join(row[i].ljust(widths[i]) for i in range(len(keys))))
    lines.append(f"({len(result.rows)} row(s))")
    return "\n".join(lines)


def _cell(value: object) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value)


def to_json(result: ParseResult) -> str:
    payload = {
        "command": result.command,
        "notes": result.notes,
        "meta": result.meta,
        "rows": result.rows,
        "count": len(result.rows),
    }
    return json.dumps(payload, indent=2)


def to_csv(result: ParseResult) -> str:
    if result.meta and not result.rows:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["field", "value"])
        for k, v in result.meta.items():
            writer.writerow([k, v])
        return buf.getvalue()
    if not result.rows:
        return ""
    buf = io.StringIO()
    keys = list(result.rows[0].keys())
    writer = csv.DictWriter(buf, fieldnames=keys)
    writer.writeheader()
    for row in result.rows:
        writer.writerow(row)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------


def sample_dir() -> Path:
    return Path(__file__).resolve().parent / "sample_outputs"


SAMPLE_MAP = {
    "show_ip_interface_brief.txt": "show ip interface brief",
    "show_vlan_brief.txt": "show vlan brief",
    "show_interfaces_status.txt": "show interfaces status",
    "show_mac_address_table.txt": "show mac address-table",
    "show_cdp_neighbors.txt": "show cdp neighbors",
    "show_lldp_neighbors.txt": "show lldp neighbors",
    "show_ip_route.txt": "show ip route",
    "show_version.txt": "show version",
}


def run_demo() -> str:
    parts: list[str] = ["=== Cisco show-command parser demo ===", ""]
    for filename, command in SAMPLE_MAP.items():
        path = sample_dir() / filename
        text = path.read_text(encoding="utf-8")
        result = parse(text, command=command)
        parts.append(f"--- {command} ({filename}) ---")
        if result.command == "show ip interface brief":
            summary = summarize(result)
            parts.append(format_table(summary))
            down = filter_down(result)
            parts.append(f"Down/admin-down interfaces: {len(down.rows)}")
            for row in down.rows:
                parts.append(
                    f"  {row['interface']}: {row['status']}/{row['protocol']} "
                    f"ip={row['ip_address']}"
                )
        elif result.command == "show vlan brief":
            summary = summarize(result)
            parts.append(
                f"VLANs: {summary.meta.get('vlan_count')}, empty: {summary.meta.get('empty_vlans')}"
            )
            for row in summary.rows:
                if row["empty"]:
                    parts.append(f"  empty VLAN {row['vlan']} ({row['name']})")
                else:
                    parts.append(
                        f"  VLAN {row['vlan']} ({row['name']}): {row['port_count']} port(s)"
                    )
        elif result.kind == "meta":
            parts.append(format_table(result))
        else:
            # Show at most 3 rows for brevity in the demo.
            short = ParseResult(
                result.command,
                rows=result.rows[:3],
                meta=result.meta,
                notes=[*result.notes, f"showing 3 of {len(result.rows)}"],
            )
            parts.append(format_table(short))
        parts.append("")
    return "\n".join(parts).rstrip() + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="show_parser",
        description="Parse Cisco IOS/IOS-XE show command output into tables/JSON/CSV.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument(
        "file",
        nargs="?",
        type=Path,
        help="file containing show output (default: stdin)",
    )
    p.add_argument(
        "-c",
        "--command",
        help="force the show command (skip auto-detect)",
    )
    p.add_argument(
        "--engine",
        choices=["regex", "textfsm"],
        default="regex",
        help="parse engine (default: regex; textfsm needs ntc-templates)",
    )
    p.add_argument("--json", action="store_true", help="emit JSON")
    p.add_argument("--csv", action="store_true", help="emit CSV")
    p.add_argument(
        "--down",
        action="store_true",
        help="list down / admin-down / notconnect interfaces (brief & status)",
    )
    p.add_argument(
        "--summary",
        action="store_true",
        help="summary for interface brief / VLAN / interface status",
    )
    p.add_argument(
        "--demo",
        action="store_true",
        help="parse every bundled sample and print a short result",
    )
    return p


def read_input(path: Path | None) -> str:
    if path is not None:
        try:
            return path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ParseError(f"cannot read {path}: {exc}") from None
    if sys.stdin.isatty():
        raise ParseError("no input file and stdin is a TTY; pass a file or pipe data in")
    return sys.stdin.read()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.demo:
            print(run_demo(), end="")
            return 0
        text = read_input(args.file)
        if not text.strip():
            raise ParseError("input is empty")
        command = normalize_command(args.command) if args.command else None
        if args.engine == "textfsm":
            cmd = command or detect_command(text)
            result = parse_textfsm(text, cmd)
        else:
            result = parse(text, command=command)
        if args.down:
            result = filter_down(result)
        if args.summary:
            result = summarize(result)
        if args.json and args.csv:
            raise ParseError("choose only one of --json or --csv")
        if args.json:
            print(to_json(result))
        elif args.csv:
            print(to_csv(result), end="")
        else:
            print(format_table(result))
        return 0
    except ParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
