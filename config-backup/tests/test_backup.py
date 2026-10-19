"""Tests for the Cisco config backup tool. Netmiko is always mocked."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import backup as bk

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "sample_configs"


@pytest.fixture
def r1_cfg() -> str:
    return (SAMPLE / "r1_running.cfg").read_text(encoding="utf-8")


@pytest.fixture
def r1_changed() -> str:
    return (SAMPLE / "r1_running_changed.cfg").read_text(encoding="utf-8")


@pytest.fixture
def sw1_cfg() -> str:
    return (SAMPLE / "sw1_running.cfg").read_text(encoding="utf-8")


# ---------------------------------------------------------------- inventory


class TestInventory:
    def test_yaml(self):
        devices = bk.load_inventory(ROOT / "inventory.yaml")
        assert [d.name for d in devices] == ["R1-CORE", "SW1-ACCESS", "R2-BRANCH"]
        assert devices[0].host == "192.168.10.1"
        assert devices[0].device_type == "cisco_ios"

    def test_csv(self):
        devices = bk.load_inventory(ROOT / "inventory.csv")
        assert len(devices) == 3
        assert devices[1].name == "SW1-ACCESS"

    def test_missing_file(self):
        with pytest.raises(bk.BackupError, match="not found"):
            bk.load_inventory(ROOT / "nope.yaml")

    def test_bad_device_type(self, tmp_path):
        path = tmp_path / "inv.yaml"
        path.write_text("- name: X\n  host: 10.0.0.1\n  device_type: juniper\n")
        with pytest.raises(bk.BackupError, match="unsupported device_type"):
            bk.load_inventory(path)

    def test_duplicate_name(self, tmp_path):
        path = tmp_path / "inv.yaml"
        path.write_text("- name: R1\n  host: 10.0.0.1\n- name: R1\n  host: 10.0.0.2\n")
        with pytest.raises(bk.BackupError, match="duplicate"):
            bk.load_inventory(path)

    def test_csv_requires_columns(self, tmp_path):
        path = tmp_path / "inv.csv"
        path.write_text("hostname,ip\nR1,10.0.0.1\n")
        with pytest.raises(bk.BackupError, match="name"):
            bk.load_inventory(path)


# ---------------------------------------------------------------- credentials


class TestCredentials:
    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("NETMIKO_USERNAME", "admin")
        monkeypatch.setenv("NETMIKO_PASSWORD", "secret")
        monkeypatch.setenv("NETMIKO_SECRET", "enable")
        device = bk.Device("R1", "10.0.0.1")
        creds = bk.resolve_credentials(device, prompt=False)
        assert creds == bk.Credentials("admin", "secret", "enable")

    def test_per_device_override(self, monkeypatch):
        monkeypatch.setenv("NETMIKO_USERNAME", "shared")
        monkeypatch.setenv("NETMIKO_PASSWORD", "sharedpass")
        monkeypatch.setenv("R1_USER", "r1admin")
        monkeypatch.setenv("R1_PASS", "r1pass")
        device = bk.Device(
            "R1",
            "10.0.0.1",
            username_env="R1_USER",
            password_env="R1_PASS",
        )
        creds = bk.resolve_credentials(device, prompt=False)
        assert creds.username == "r1admin"
        assert creds.password == "r1pass"

    def test_missing_no_prompt(self, monkeypatch):
        monkeypatch.delenv("NETMIKO_USERNAME", raising=False)
        monkeypatch.delenv("NETMIKO_PASSWORD", raising=False)
        with pytest.raises(bk.BackupError, match="missing credentials"):
            bk.resolve_credentials(bk.Device("R1", "10.0.0.1"), prompt=False)


# ---------------------------------------------------------------- normalize / diff


class TestNormalizeDiff:
    def test_strips_volatile(self):
        text = (
            "!\n"
            "! Last configuration change at 10:00:00 UTC Sun Oct 18 2026\n"
            "hostname R1\n"
            "ntp clock-period 17179860\n"
            "!\n"
            "end\n"
        )
        norm = bk.normalize_config(text)
        assert "Last configuration change" not in norm
        assert "ntp clock-period" not in norm
        assert "hostname R1" in norm

    def test_equal_ignores_volatile(self):
        a = "! Last configuration change at A\nhostname R1\n"
        b = "! Last configuration change at B\nhostname R1\n"
        assert bk.configs_equal(a, b)

    def test_diff_detects_real_change(self, r1_cfg, r1_changed):
        assert not bk.configs_equal(r1_cfg, r1_changed)
        diff = bk.make_diff(r1_cfg, r1_changed, fromfile="old", tofile="new")
        assert "upgraded link" in diff
        assert "10.66.66.0" in diff
        summary = bk.diff_summary(diff)
        assert "+2" in summary or "+" in summary


# ---------------------------------------------------------------- backup files / retention


class TestFiles:
    def test_write_and_previous(self, tmp_path, r1_cfg):
        folder = tmp_path / "R1-CORE"
        t0 = datetime(2026, 10, 18, 10, 0, 0)
        t1 = datetime(2026, 10, 18, 11, 0, 0)
        p0 = bk.write_backup(folder, "R1-CORE", r1_cfg, t0)
        p1 = bk.write_backup(folder, "R1-CORE", r1_cfg, t1)
        assert bk.previous_backup(folder) == p1
        assert p0.exists() and p1.exists()
        assert "2026-10-18_100000" in p0.name

    def test_retention(self, tmp_path, r1_cfg):
        folder = tmp_path / "R1"
        for hour in range(5):
            bk.write_backup(folder, "R1", r1_cfg, datetime(2026, 10, 18, hour, 0, 0))
        deleted = bk.apply_retention(folder, keep=2)
        assert len(deleted) == 3
        assert len(bk.list_backups(folder)) == 2


# ---------------------------------------------------------------- backup_one with fake connect


def _fake_connect_factory(outputs_by_name: dict[str, dict[str, str]]):
    def connect(device, creds, *, timeout=30):
        return bk.DeviceSession(bk.FakeConnection(outputs_by_name[device.name]))

    return connect


class TestBackupOne:
    def test_initial_and_unchanged(self, tmp_path, r1_cfg):
        device = bk.Device("R1-CORE", "192.168.10.1")
        creds = bk.Credentials("u", "p")
        connect = _fake_connect_factory(
            {"R1-CORE": {"show running-config": r1_cfg, "show startup-config": r1_cfg}}
        )
        r1 = bk.backup_one(
            device,
            creds,
            backup_root=tmp_path,
            connect=connect,
            now=datetime(2026, 10, 18, 10, 0, 0),
        )
        assert r1.status == "ok" and r1.changed and "initial" in r1.message
        r2 = bk.backup_one(
            device,
            creds,
            backup_root=tmp_path,
            connect=connect,
            now=datetime(2026, 10, 18, 11, 0, 0),
        )
        assert r2.status == "unchanged" and not r2.changed
        assert len(bk.list_backups(tmp_path / "R1-CORE")) == 1

    def test_change_writes_diff(self, tmp_path, r1_cfg, r1_changed):
        device = bk.Device("R1-CORE", "192.168.10.1")
        creds = bk.Credentials("u", "p")
        bk.backup_one(
            device,
            creds,
            backup_root=tmp_path,
            connect=_fake_connect_factory({"R1-CORE": {"show running-config": r1_cfg}}),
            now=datetime(2026, 10, 18, 10, 0, 0),
        )
        result = bk.backup_one(
            device,
            creds,
            backup_root=tmp_path,
            connect=_fake_connect_factory({"R1-CORE": {"show running-config": r1_changed}}),
            now=datetime(2026, 10, 18, 12, 0, 0),
        )
        assert result.changed and result.diff_file
        diff = Path(result.diff_file).read_text(encoding="utf-8")
        assert "10.66.66.0" in diff
        assert result.added >= 1 and result.removed >= 0

    def test_always_save(self, tmp_path, r1_cfg):
        device = bk.Device("R1-CORE", "192.168.10.1")
        creds = bk.Credentials("u", "p")
        connect = _fake_connect_factory({"R1-CORE": {"show running-config": r1_cfg}})
        bk.backup_one(
            device,
            creds,
            backup_root=tmp_path,
            connect=connect,
            now=datetime(2026, 10, 18, 10, 0, 0),
        )
        result = bk.backup_one(
            device,
            creds,
            backup_root=tmp_path,
            connect=connect,
            always_save=True,
            now=datetime(2026, 10, 18, 11, 0, 0),
        )
        assert not result.changed
        assert result.status == "ok"
        assert len(bk.list_backups(tmp_path / "R1-CORE")) == 2

    def test_check_startup_unsaved(self, tmp_path, r1_cfg, r1_changed):
        device = bk.Device("R1-CORE", "192.168.10.1")
        result = bk.backup_one(
            device,
            bk.Credentials("u", "p"),
            backup_root=tmp_path,
            check_startup=True,
            connect=_fake_connect_factory(
                {
                    "R1-CORE": {
                        "show running-config": r1_changed,
                        "show startup-config": r1_cfg,
                    }
                }
            ),
            now=datetime(2026, 10, 18, 10, 0, 0),
        )
        assert result.unsaved and result.status == "unsaved"

    def test_auth_failure_isolated(self, tmp_path):
        def bad_connect(device, creds, *, timeout=30):
            raise bk.BackupError(f"{device.name}: authentication failed")

        result = bk.backup_one(
            bk.Device("R1-CORE", "192.168.10.1"),
            bk.Credentials("u", "p"),
            backup_root=tmp_path,
            connect=bad_connect,
        )
        assert result.status == "error"
        assert "authentication failed" in result.message

    def test_keep_retention(self, tmp_path, r1_cfg, r1_changed):
        device = bk.Device("R1-CORE", "192.168.10.1")
        creds = bk.Credentials("u", "p")
        for hour, cfg in enumerate([r1_cfg, r1_changed, r1_cfg, r1_changed]):
            bk.backup_one(
                device,
                creds,
                backup_root=tmp_path,
                always_save=True,
                keep=2,
                connect=_fake_connect_factory({"R1-CORE": {"show running-config": cfg}}),
                now=datetime(2026, 10, 18, hour, 0, 0),
            )
        assert len(bk.list_backups(tmp_path / "R1-CORE")) == 2


# ---------------------------------------------------------------- connect_device mocks netmiko


class TestConnectHandlerMock:
    def test_success_and_enable(self):
        fake_conn = MagicMock()
        with patch("netmiko.ConnectHandler", return_value=fake_conn) as ch:
            session = bk.connect_device(
                bk.Device("R1", "192.168.10.1"),
                bk.Credentials("u", "p", "en"),
            )
        ch.assert_called_once()
        assert ch.call_args.kwargs["host"] == "192.168.10.1"
        fake_conn.enable.assert_called_once()
        fake_conn.send_command.return_value = "hostname R1"
        assert session.send("show run") == "hostname R1"
        session.disconnect()
        fake_conn.disconnect.assert_called_once()

    def test_auth_error(self):
        from netmiko.exceptions import NetmikoAuthenticationException

        with (
            patch(
                "netmiko.ConnectHandler",
                side_effect=NetmikoAuthenticationException("nope"),
            ),
            pytest.raises(bk.BackupError, match="authentication failed"),
        ):
            bk.connect_device(bk.Device("R1", "192.168.10.1"), bk.Credentials("u", "p"))

    def test_timeout_error(self):
        from netmiko.exceptions import NetmikoTimeoutException

        with (
            patch(
                "netmiko.ConnectHandler",
                side_effect=NetmikoTimeoutException("slow"),
            ),
            pytest.raises(bk.BackupError, match="timed out"),
        ):
            bk.connect_device(bk.Device("R1", "192.168.10.1"), bk.Credentials("u", "p"))


# ---------------------------------------------------------------- run_backups concurrency


class TestRunBackups:
    def test_concurrent_mixed_results(self, tmp_path, r1_cfg, sw1_cfg, monkeypatch):
        monkeypatch.setenv("NETMIKO_USERNAME", "admin")
        monkeypatch.setenv("NETMIKO_PASSWORD", "pass")
        devices = [
            bk.Device("R1-CORE", "192.168.10.1"),
            bk.Device("SW1-ACCESS", "192.168.10.2"),
            bk.Device("BAD", "192.168.10.9"),
        ]

        def connect(device, creds, *, timeout=30):
            if device.name == "BAD":
                raise bk.BackupError(f"{device.name}: connection timed out")
            outputs = {
                "R1-CORE": {"show running-config": r1_cfg},
                "SW1-ACCESS": {"show running-config": sw1_cfg},
            }
            return bk.DeviceSession(bk.FakeConnection(outputs[device.name]))

        report = bk.run_backups(
            devices,
            backup_root=tmp_path,
            workers=3,
            prompt=False,
            connect=connect,
        )
        assert report.error_count == 1
        assert report.ok_count == 2
        assert [r.name for r in report.results] == ["R1-CORE", "SW1-ACCESS", "BAD"]


# ---------------------------------------------------------------- demo + CLI


class TestDemoCli:
    def test_demo(self, tmp_path, capsys):
        assert bk.main(["demo", "-o", str(tmp_path / "demo")]) == 0
        out = capsys.readouterr().out
        assert "R1-CORE" in out and "SW1-ACCESS" in out
        assert "Diff:" in out or "10.66.66.0" in out or "upgraded link" in out
        # Second pass should mark R1 changed / possibly unsaved
        assert "changed" in out.lower() or "+" in out

    def test_demo_library(self, tmp_path):
        report = bk.run_demo(tmp_path)
        by_name = {r.name: r for r in report.results}
        assert by_name["R1-CORE"].changed
        assert by_name["R1-CORE"].diff_file
        assert by_name["SW1-ACCESS"].status in {"unchanged", "ok"}
        assert by_name["R1-CORE"].unsaved  # running changed, startup old

    def test_backup_cli_json(self, tmp_path, r1_cfg, monkeypatch, capsys):
        monkeypatch.setenv("NETMIKO_USERNAME", "admin")
        monkeypatch.setenv("NETMIKO_PASSWORD", "pass")
        inv = tmp_path / "inv.yaml"
        inv.write_text("- name: R1-CORE\n  host: 192.168.10.1\n  device_type: cisco_ios\n")
        out_json = tmp_path / "report.json"
        connect = _fake_connect_factory({"R1-CORE": {"show running-config": r1_cfg}})
        with patch("backup.connect_device", connect):
            rc = bk.main(
                [
                    "backup",
                    "-i",
                    str(inv),
                    "-o",
                    str(tmp_path / "bak"),
                    "--json",
                    str(out_json),
                    "--no-prompt",
                    "--workers",
                    "1",
                ]
            )
        assert rc == 0
        data = json.loads(out_json.read_text())
        assert data["succeeded"] == 1
        assert data["results"][0]["name"] == "R1-CORE"

    def test_bad_inventory_exit(self, capsys):
        assert bk.main(["backup", "-i", "missing.yaml", "--no-prompt"]) == 2
        assert "error:" in capsys.readouterr().err

    def test_sample_configs_are_synthetic(self, r1_cfg, sw1_cfg):
        for text in (r1_cfg, sw1_cfg):
            assert "synthetic" in text.lower() or "Synthetic" in text
            assert "10." in text or "192.168." in text
