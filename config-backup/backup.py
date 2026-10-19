#!/usr/bin/env python3
"""Cisco config backup tool (Python 3.10+, netmiko).

Pull running (and optionally startup / version) configs from Cisco devices,
save timestamped backups, and diff against the previous copy.

Credentials never live in the inventory or source code. They come from
environment variables or an interactive getpass prompt.

Commands:
    backup   Pull configs for every device in the inventory.
    demo     Offline walkthrough with fake devices and a simulated change.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import contextlib
import csv
import difflib
import getpass
import json
import os
import re
import sys
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover - declared in requirements.txt
    yaml = None  # type: ignore[assignment]

__version__ = "1.0.0"

DEFAULT_INVENTORY = "inventory.yaml"
DEFAULT_BACKUP_DIR = "backups"
SUPPORTED_TYPES = (
    "cisco_ios",
    "cisco_xe",
    "cisco_nxos",
    "cisco_asa",
    "cisco_xr",
)

# Lines that change on every save / clock tick and should not count as drift.
VOLATILE_PATTERNS = (
    re.compile(r"^! Last configuration change.*$", re.IGNORECASE),
    re.compile(r"^! NVRAM config last updated.*$", re.IGNORECASE),
    re.compile(r"^ntp clock-period\s+\d+\s*$", re.IGNORECASE),
    re.compile(r"^!Time:.*$", re.IGNORECASE),
    re.compile(r"^! No configuration change since last restart.*$", re.IGNORECASE),
    re.compile(r"^Current configuration\s*:.*$", re.IGNORECASE),
)


class BackupError(Exception):
    """User-facing error: printed without a traceback; exit code 2."""


# ---------------------------------------------------------------- inventory


@dataclass(frozen=True)
class Device:
    name: str
    host: str
    device_type: str = "cisco_ios"
    port: int = 22
    username_env: str | None = None  # optional per-device override env var name
    password_env: str | None = None
    secret_env: str | None = None


@dataclass(frozen=True)
class Credentials:
    username: str
    password: str
    secret: str = ""


def _require_yaml() -> None:
    if yaml is None:
        raise BackupError("PyYAML is required for YAML inventories; pip install pyyaml")


def load_inventory(path: Path) -> list[Device]:
    """Load devices from a YAML list or a CSV with header row."""
    if not path.is_file():
        raise BackupError(f"inventory not found: {path}")
    suffix = path.suffix.lower()
    if suffix in {".yaml", ".yml"}:
        return _load_yaml_inventory(path)
    if suffix == ".csv":
        return _load_csv_inventory(path)
    raise BackupError(f"unsupported inventory format {suffix!r} (use .yaml/.yml or .csv)")


def _normalize_device(raw: dict, index: int) -> Device:
    name = str(raw.get("name") or "").strip()
    host = str(raw.get("host") or "").strip()
    if not name or not host:
        raise BackupError(f"inventory entry #{index} needs both 'name' and 'host'")
    dtype = str(raw.get("device_type") or "cisco_ios").strip()
    if dtype not in SUPPORTED_TYPES:
        raise BackupError(
            f"device {name!r}: unsupported device_type {dtype!r}; "
            f"choose one of {', '.join(SUPPORTED_TYPES)}"
        )
    port = int(raw.get("port") or 22)
    if not 1 <= port <= 65535:
        raise BackupError(f"device {name!r}: invalid port {port}")
    return Device(
        name=name,
        host=host,
        device_type=dtype,
        port=port,
        username_env=(str(raw["username_env"]).strip() if raw.get("username_env") else None),
        password_env=(str(raw["password_env"]).strip() if raw.get("password_env") else None),
        secret_env=(str(raw["secret_env"]).strip() if raw.get("secret_env") else None),
    )


def _load_yaml_inventory(path: Path) -> list[Device]:
    _require_yaml()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise BackupError(f"cannot read {path}: {exc}") from None
    if not isinstance(data, list):
        raise BackupError(f"{path}: expected a YAML list of devices")
    devices = [_normalize_device(item, i) for i, item in enumerate(data, 1) if item]
    if not devices:
        raise BackupError(f"{path}: no devices listed")
    _check_unique_names(devices)
    return devices


def _load_csv_inventory(path: Path) -> list[Device]:
    try:
        with path.open(encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            if (
                not reader.fieldnames
                or "name" not in reader.fieldnames
                or "host" not in reader.fieldnames
            ):
                raise BackupError(f"{path}: CSV must have 'name' and 'host' columns")
            rows = list(reader)
    except OSError as exc:
        raise BackupError(f"cannot read {path}: {exc}") from None
    devices = [_normalize_device(row, i) for i, row in enumerate(rows, 1)]
    if not devices:
        raise BackupError(f"{path}: no devices listed")
    _check_unique_names(devices)
    return devices


def _check_unique_names(devices: list[Device]) -> None:
    seen: set[str] = set()
    for d in devices:
        if d.name in seen:
            raise BackupError(f"duplicate device name {d.name!r}")
        seen.add(d.name)


# ---------------------------------------------------------------- credentials


def resolve_credentials(
    device: Device,
    *,
    defaults: Credentials | None = None,
    prompt: bool = True,
) -> Credentials:
    """Resolve username/password/enable secret for one device.

    Order: per-device env override → shared defaults (from NETMIKO_* / CLI) → getpass.
    """
    user = (
        _env(device.username_env)
        or (defaults.username if defaults else "")
        or _env("NETMIKO_USERNAME")
    )
    password = (
        _env(device.password_env)
        or (defaults.password if defaults else "")
        or _env("NETMIKO_PASSWORD")
    )
    secret = (
        _env(device.secret_env)
        or (defaults.secret if defaults else "")
        or _env("NETMIKO_SECRET")
        or ""
    )
    if prompt and not user:
        user = input(f"Username for {device.name}: ").strip()
    if prompt and not password:
        password = getpass.getpass(f"Password for {device.name} ({device.host}): ")
    if not user or not password:
        raise BackupError(
            f"missing credentials for {device.name}: set NETMIKO_USERNAME / "
            "NETMIKO_PASSWORD (or per-device *_env), or run interactively"
        )
    return Credentials(username=user, password=password, secret=secret or "")


def _env(name: str | None) -> str:
    if not name:
        return ""
    return os.environ.get(name, "").strip()


def load_default_credentials(*, prompt: bool = False) -> Credentials | None:
    """Shared credentials from env (no prompt unless asked)."""
    user = _env("NETMIKO_USERNAME")
    password = _env("NETMIKO_PASSWORD")
    secret = _env("NETMIKO_SECRET")
    if user and password:
        return Credentials(user, password, secret)
    if prompt:
        user = user or input("Username: ").strip()
        password = password or getpass.getpass("Password: ")
        if not secret:
            secret = getpass.getpass("Enable secret (blank if none): ")
        if user and password:
            return Credentials(user, password, secret)
    return None


# ---------------------------------------------------------------- normalize / diff


def normalize_config(text: str) -> str:
    """Strip volatile / empty-trailing lines so diffs stay meaningful."""
    lines: list[str] = []
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.rstrip()
        if any(pat.match(line) for pat in VOLATILE_PATTERNS):
            continue
        lines.append(line)
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines) + ("\n" if lines else "")


def configs_equal(a: str, b: str) -> bool:
    return normalize_config(a) == normalize_config(b)


def make_diff(old: str, new: str, *, fromfile: str, tofile: str) -> str:
    old_lines = normalize_config(old).splitlines(keepends=True)
    new_lines = normalize_config(new).splitlines(keepends=True)
    return "".join(
        difflib.unified_diff(old_lines, new_lines, fromfile=fromfile, tofile=tofile, n=3)
    )


def diff_summary(diff_text: str, *, max_lines: int = 12) -> str:
    """Short human summary: counts + a few sample hunk lines."""
    if not diff_text.strip():
        return "no changes"
    added = removed = 0
    samples: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue
        if line.startswith("+"):
            added += 1
            if len(samples) < max_lines:
                samples.append(line)
        elif line.startswith("-"):
            removed += 1
            if len(samples) < max_lines:
                samples.append(line)
    head = f"+{added} / -{removed} lines"
    if not samples:
        return head
    return head + "\n" + "\n".join(samples)


# ---------------------------------------------------------------- backup files


def device_dir(backup_root: Path, device_name: str) -> Path:
    safe = re.sub(r"[^\w.\-]+", "_", device_name)
    return backup_root / safe


def list_backups(folder: Path, suffix: str = ".cfg") -> list[Path]:
    if not folder.is_dir():
        return []
    files = sorted(folder.glob(f"*{suffix}"))
    return [f for f in files if f.is_file()]


def previous_backup(folder: Path, suffix: str = ".cfg") -> Path | None:
    files = list_backups(folder, suffix)
    return files[-1] if files else None


def write_backup(folder: Path, device_name: str, content: str, when: datetime) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    stamp = when.strftime("%Y-%m-%d_%H%M%S")
    safe = re.sub(r"[^\w.\-]+", "_", device_name)
    path = folder / f"{safe}_{stamp}.cfg"
    path.write_text(content, encoding="utf-8")
    return path


def apply_retention(folder: Path, keep: int, suffix: str = ".cfg") -> list[Path]:
    """Delete oldest backups beyond `keep`. Returns deleted paths."""
    if keep < 1:
        raise BackupError("--keep must be at least 1")
    files = list_backups(folder, suffix)
    deleted: list[Path] = []
    for path in files[:-keep] if len(files) > keep else []:
        path.unlink(missing_ok=True)
        deleted.append(path)
        # Also drop a sibling .diff with the same stem if present.
        diff = path.with_suffix(".diff")
        if diff.exists():
            diff.unlink(missing_ok=True)
    return deleted


# ---------------------------------------------------------------- connection


class DeviceSession:
    """Thin wrapper around netmiko ConnectHandler (or a demo fake)."""

    def __init__(self, connection: object):
        self._conn = connection

    def send(self, command: str) -> str:
        return str(self._conn.send_command(command))  # type: ignore[attr-defined]

    def disconnect(self) -> None:
        disconnect = getattr(self._conn, "disconnect", None)
        if callable(disconnect):
            disconnect()


def connect_device(device: Device, creds: Credentials, *, timeout: int = 30) -> DeviceSession:
    """Open a netmiko session. Import is local so tests can mock easily."""
    from netmiko import (
        ConnectHandler,  # local import keeps module importable without netmiko in some tools
    )
    from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

    params = {
        "device_type": device.device_type,
        "host": device.host,
        "username": creds.username,
        "password": creds.password,
        "port": device.port,
        "timeout": timeout,
        "conn_timeout": timeout,
        "auth_timeout": timeout,
        "fast_cli": False,
    }
    if creds.secret:
        params["secret"] = creds.secret
    try:
        conn = ConnectHandler(**params)
        if creds.secret:
            conn.enable()
    except NetmikoAuthenticationException as exc:
        raise BackupError(f"{device.name}: authentication failed") from exc
    except NetmikoTimeoutException as exc:
        raise BackupError(f"{device.name}: connection timed out") from exc
    except OSError as exc:
        raise BackupError(f"{device.name}: connection error: {exc}") from exc
    except Exception as exc:  # netmiko raises several subclasses
        raise BackupError(f"{device.name}: {exc}") from exc
    return DeviceSession(conn)


# ---------------------------------------------------------------- per-device job


@dataclass
class DeviceResult:
    name: str
    host: str
    status: str  # ok | unchanged | error | unsaved
    changed: bool = False
    unsaved: bool = False
    file: str = ""
    diff_file: str = ""
    message: str = ""
    added: int = 0
    removed: int = 0


@dataclass
class RunReport:
    started_at: str
    duration_s: float = 0.0
    results: list[DeviceResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def ok_count(self) -> int:
        return sum(1 for r in self.results if r.status in {"ok", "unchanged", "unsaved"})

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.results if r.status == "error")

    @property
    def changed_count(self) -> int:
        return sum(1 for r in self.results if r.changed)


def _count_diff(diff_text: str) -> tuple[int, int]:
    added = removed = 0
    for line in diff_text.splitlines():
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue
        if line.startswith("+"):
            added += 1
        elif line.startswith("-"):
            removed += 1
    return added, removed


def backup_one(
    device: Device,
    creds: Credentials,
    *,
    backup_root: Path,
    always_save: bool = False,
    save_diff: bool = True,
    pull_startup: bool = False,
    pull_version: bool = False,
    check_startup: bool = False,
    keep: int | None = None,
    timeout: int = 30,
    connect=connect_device,
    now: datetime | None = None,
) -> DeviceResult:
    """Back up one device. `connect` is injectable for demos/tests."""
    when = now or datetime.now()
    folder = device_dir(backup_root, device.name)
    session: DeviceSession | None = None
    try:
        session = connect(device, creds, timeout=timeout)
        running = session.send("show running-config")
        if not running.strip():
            raise BackupError(f"{device.name}: empty running-config")

        startup = ""
        if pull_startup or check_startup:
            startup = session.send("show startup-config")
        if pull_version:
            version = session.send("show version")
            folder.mkdir(parents=True, exist_ok=True)
            stamp = when.strftime("%Y-%m-%d_%H%M%S")
            safe = re.sub(r"[^\w.\-]+", "_", device.name)
            (folder / f"{safe}_{stamp}_version.txt").write_text(version, encoding="utf-8")

        unsaved = False
        if check_startup and startup:
            unsaved = not configs_equal(running, startup)

        prev = previous_backup(folder)
        prev_text = prev.read_text(encoding="utf-8") if prev else ""
        changed = (prev is None) or (not configs_equal(prev_text, running))

        result = DeviceResult(
            name=device.name,
            host=device.host,
            status="ok",
            changed=changed,
            unsaved=unsaved,
        )

        if not changed and not always_save and prev is not None:
            result.status = "unchanged"
            result.file = str(prev)
            result.message = "no changes since last backup"
        else:
            path = write_backup(folder, device.name, running, when)
            result.file = str(path)
            if prev is not None and changed:
                diff_text = make_diff(
                    prev_text,
                    running,
                    fromfile=prev.name,
                    tofile=path.name,
                )
                result.added, result.removed = _count_diff(diff_text)
                result.message = diff_summary(diff_text)
                if save_diff and diff_text.strip():
                    diff_path = path.with_suffix(".diff")
                    diff_path.write_text(diff_text, encoding="utf-8")
                    result.diff_file = str(diff_path)
            elif prev is None:
                result.message = "initial backup"
            else:
                result.message = "saved (--always-save)"

        if pull_startup and startup:
            stamp = when.strftime("%Y-%m-%d_%H%M%S")
            safe = re.sub(r"[^\w.\-]+", "_", device.name)
            folder.mkdir(parents=True, exist_ok=True)
            (folder / f"{safe}_{stamp}_startup.cfg").write_text(startup, encoding="utf-8")

        if unsaved:
            result.status = "unsaved"
            note = "running differs from startup (unsaved changes)"
            result.message = f"{result.message}\n{note}" if result.message else note

        if keep is not None:
            apply_retention(folder, keep)

        return result
    except BackupError as exc:
        return DeviceResult(name=device.name, host=device.host, status="error", message=str(exc))
    except Exception as exc:  # noqa: BLE001 — isolate per-device failures
        return DeviceResult(
            name=device.name,
            host=device.host,
            status="error",
            message=f"{device.name}: unexpected error: {exc}",
        )
    finally:
        if session is not None:
            with contextlib.suppress(Exception):
                session.disconnect()


# ---------------------------------------------------------------- demo fake


class FakeConnection:
    """Offline stand-in for netmiko ConnectHandler."""

    def __init__(self, outputs: dict[str, str]):
        self.outputs = outputs

    def send_command(self, command: str) -> str:
        key = command.strip().lower()
        for cmd, out in self.outputs.items():
            if key == cmd.lower() or key.startswith(cmd.lower()):
                return out
        raise BackupError(f"fake device has no output for {command!r}")

    def enable(self) -> None:
        return None

    def disconnect(self) -> None:
        return None


def _sample_dir() -> Path:
    return Path(__file__).resolve().parent / "sample_configs"


def build_demo_connector(changed: bool = False):
    """Return a connect() callable that serves sample configs."""
    sample = _sample_dir()
    r1_run = (sample / ("r1_running_changed.cfg" if changed else "r1_running.cfg")).read_text(
        encoding="utf-8"
    )
    # After a "change", startup still has the old config → unsaved.
    r1_start = (sample / "r1_running.cfg").read_text(encoding="utf-8")
    sw1_run = (sample / "sw1_running.cfg").read_text(encoding="utf-8")
    r1_ver = (sample / "r1_version.txt").read_text(encoding="utf-8")
    sw1_ver = (sample / "sw1_version.txt").read_text(encoding="utf-8")

    catalog = {
        "R1-CORE": {
            "show running-config": r1_run,
            "show startup-config": r1_start,
            "show version": r1_ver,
        },
        "SW1-ACCESS": {
            "show running-config": sw1_run,
            "show startup-config": sw1_run,
            "show version": sw1_ver,
        },
    }

    def connect(device: Device, creds: Credentials, *, timeout: int = 30) -> DeviceSession:
        outputs = catalog.get(device.name)
        if outputs is None:
            raise BackupError(f"{device.name}: unknown demo device")
        return DeviceSession(FakeConnection(outputs))

    return connect


DEMO_DEVICES = [
    Device("R1-CORE", "192.168.10.1", "cisco_ios"),
    Device("SW1-ACCESS", "192.168.10.2", "cisco_ios"),
]


def run_demo(backup_root: Path | None = None) -> RunReport:
    """Two-pass offline demo: initial backup, then a change + diff."""
    root = backup_root or (Path(__file__).resolve().parent / "backups" / "_demo")
    if root.exists():
        for path in sorted(root.rglob("*"), reverse=True):
            if path.is_file():
                path.unlink()
            elif path.is_dir():
                path.rmdir()
    root.mkdir(parents=True, exist_ok=True)

    creds = Credentials("demo", "demo", "demo")
    started = datetime.now()
    report = RunReport(started_at=started.strftime("%Y-%m-%dT%H:%M:%S"))

    # Pass 1: initial backups (unchanged configs).
    connect_v1 = build_demo_connector(changed=False)
    t0 = datetime(2026, 10, 18, 10, 0, 0)
    for device in DEMO_DEVICES:
        report.results.append(
            backup_one(
                device,
                creds,
                backup_root=root,
                check_startup=True,
                pull_version=True,
                connect=connect_v1,
                now=t0,
            )
        )

    # Pass 2: R1 config drifts; SW1 stays the same.
    connect_v2 = build_demo_connector(changed=True)
    t1 = datetime(2026, 10, 18, 11, 30, 0)
    second_pass: list[DeviceResult] = []
    for device in DEMO_DEVICES:
        second_pass.append(
            backup_one(
                device,
                creds,
                backup_root=root,
                check_startup=True,
                save_diff=True,
                connect=connect_v2,
                now=t1,
            )
        )
    report.notes.append("pass 1: initial backups of R1-CORE and SW1-ACCESS")
    report.notes.append("pass 2: simulated change on R1-CORE (ACL + interface description)")
    report.results = second_pass  # surface the interesting pass in the table
    report.duration_s = 0.0
    # Stash pass-1 info in notes for the printed demo.
    report.notes.append(f"demo backups written under {root}")
    return report


# ---------------------------------------------------------------- runners / output


def run_backups(
    devices: list[Device],
    *,
    backup_root: Path,
    workers: int = 4,
    always_save: bool = False,
    save_diff: bool = True,
    pull_startup: bool = False,
    pull_version: bool = False,
    check_startup: bool = False,
    keep: int | None = None,
    timeout: int = 30,
    prompt: bool = True,
    connect=None,
) -> RunReport:
    if connect is None:
        connect = connect_device
    started = datetime.now()
    report = RunReport(started_at=started.strftime("%Y-%m-%dT%H:%M:%S"))
    defaults = load_default_credentials(prompt=False)
    # Resolve credentials up front (one interactive prompt shared across devices
    # when using NETMIKO_* or a single getpass for defaults).
    if defaults is None and prompt:
        defaults = load_default_credentials(prompt=True)

    cred_map: dict[str, Credentials] = {}
    for device in devices:
        try:
            cred_map[device.name] = resolve_credentials(device, defaults=defaults, prompt=prompt)
        except BackupError as exc:
            report.results.append(
                DeviceResult(name=device.name, host=device.host, status="error", message=str(exc))
            )

    pending = [d for d in devices if d.name in cred_map]
    lock = threading.Lock()

    def _job(device: Device) -> DeviceResult:
        return backup_one(
            device,
            cred_map[device.name],
            backup_root=backup_root,
            always_save=always_save,
            save_diff=save_diff,
            pull_startup=pull_startup,
            pull_version=pull_version,
            check_startup=check_startup,
            keep=keep,
            timeout=timeout,
            connect=connect,
        )

    workers = max(1, min(workers, len(pending) or 1))
    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_job, d): d for d in pending}
        for fut in cf.as_completed(futures):
            result = fut.result()
            with lock:
                report.results.append(result)

    # Stable order matching inventory.
    by_name = {r.name: r for r in report.results}
    report.results = [by_name[d.name] for d in devices if d.name in by_name]
    report.duration_s = (datetime.now() - started).total_seconds()
    return report


def format_table(results: list[DeviceResult]) -> str:
    header = f"{'Device':<14} {'Host':<16} {'Status':<10} {'Changed':<8} File"
    lines = [header, "-" * len(header)]
    for r in results:
        changed = "yes" if r.changed else "no"
        path = r.file or "-"
        if len(path) > 48:
            path = "…" + path[-47:]
        lines.append(f"{r.name:<14} {r.host:<16} {r.status:<10} {changed:<8} {path}")
        if r.message and r.status != "unchanged":
            for msg_line in r.message.splitlines()[:8]:
                lines.append(f"  └ {msg_line}")
        elif r.status == "unchanged" and r.message:
            lines.append(f"  └ {r.message}")
    return "\n".join(lines)


def format_summary(report: RunReport) -> str:
    lines = [
        f"Started          : {report.started_at}",
        f"Duration         : {report.duration_s:.2f} s",
        f"Devices          : {len(report.results)}",
        f"Succeeded        : {report.ok_count}",
        f"Changed          : {report.changed_count}",
        f"Errors           : {report.error_count}",
    ]
    for note in report.notes:
        lines.append(f"Note             : {note}")
    return "\n".join(lines)


def report_to_dict(report: RunReport) -> dict:
    return {
        "started_at": report.started_at,
        "duration_s": round(report.duration_s, 3),
        "devices": len(report.results),
        "succeeded": report.ok_count,
        "changed": report.changed_count,
        "errors": report.error_count,
        "notes": report.notes,
        "results": [asdict(r) for r in report.results],
    }


# ---------------------------------------------------------------- CLI


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="backup",
        description="Back up Cisco running configs with netmiko and diff against the last copy.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "-i",
        "--inventory",
        type=Path,
        default=Path(DEFAULT_INVENTORY),
        help=f"YAML or CSV inventory (default: {DEFAULT_INVENTORY})",
    )
    common.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path(DEFAULT_BACKUP_DIR),
        help=f"backup directory (default: {DEFAULT_BACKUP_DIR})",
    )
    common.add_argument("--workers", type=int, default=4, help="concurrent devices (default: 4)")
    common.add_argument("--timeout", type=int, default=30, help="connect/command timeout seconds")
    common.add_argument("--always-save", action="store_true", help="save even when unchanged")
    common.add_argument("--no-diff", action="store_true", help="do not write .diff files")
    common.add_argument("--startup", action="store_true", help="also save show startup-config")
    common.add_argument("--version-info", action="store_true", help="also save show version")
    common.add_argument(
        "--check-startup",
        action="store_true",
        help="flag devices whose running config differs from startup",
    )
    common.add_argument(
        "--keep", type=int, default=None, metavar="N", help="retain only N backups per device"
    )
    common.add_argument("--json", type=Path, metavar="FILE", help="write JSON summary")
    common.add_argument(
        "--no-prompt",
        action="store_true",
        help="never prompt; fail if credentials env vars are missing",
    )

    sub.add_parser("backup", parents=[common], help="back up every device in the inventory")
    demo = sub.add_parser("demo", help="offline walkthrough with sample configs")
    demo.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="demo backup directory (default: backups/_demo)",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            report = run_demo(args.output)
            print(format_summary(report))
            print()
            print(format_table(report.results))
            # Show the R1 diff body if one was written.
            for r in report.results:
                if r.diff_file and Path(r.diff_file).is_file():
                    print()
                    print(f"=== Diff: {r.name} ===")
                    print(Path(r.diff_file).read_text(encoding="utf-8"))
                    break
            return 0

        devices = load_inventory(args.inventory)
        report = run_backups(
            devices,
            backup_root=args.output,
            workers=args.workers,
            always_save=args.always_save,
            save_diff=not args.no_diff,
            pull_startup=args.startup,
            pull_version=args.version_info,
            check_startup=args.check_startup,
            keep=args.keep,
            timeout=args.timeout,
            prompt=not args.no_prompt,
        )
        print(format_summary(report))
        print()
        print(format_table(report.results))
        if args.json:
            args.json.write_text(
                json.dumps(report_to_dict(report), indent=2) + "\n", encoding="utf-8"
            )
            print(f"\nWrote JSON report: {args.json}")
        return 1 if report.error_count else 0
    except BackupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("error: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
