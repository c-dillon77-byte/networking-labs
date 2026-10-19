"""Tests for the Cisco show-command parser. Offline only — uses bundled samples."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import show_parser as sp

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "sample_outputs"


def _load(name: str) -> str:
    return (SAMPLES / name).read_text(encoding="utf-8")


# ---------------------------------------------------------------- detection


class TestDetect:
    @pytest.mark.parametrize(
        "filename,command",
        list(sp.SAMPLE_MAP.items()),
    )
    def test_auto_detect(self, filename, command):
        assert sp.detect_command(_load(filename)) == command

    def test_unknown(self):
        with pytest.raises(sp.ParseError, match="auto-detect"):
            sp.detect_command("this is not a cisco show command")

    def test_aliases(self):
        assert sp.normalize_command("sh ip int br") == "show ip interface brief"
        assert sp.normalize_command("show mac-address-table") == "show mac address-table"

    def test_bad_alias(self):
        with pytest.raises(sp.ParseError, match="unknown command"):
            sp.normalize_command("show pizza")


# ---------------------------------------------------------------- each parser


class TestIpInterfaceBrief:
    def test_rows_and_admin_down(self):
        result = sp.parse(_load("show_ip_interface_brief.txt"))
        assert result.command == "show ip interface brief"
        assert len(result.rows) == 8
        by_iface = {r["interface"]: r for r in result.rows}
        assert by_iface["GigabitEthernet0/2"]["status"] == "administratively down"
        assert by_iface["GigabitEthernet0/2"]["protocol"] == "down"
        assert by_iface["TenGigabitEthernet1/0/1"]["ip_address"] == "172.16.5.1"
        assert by_iface["GigabitEthernet0/2.10"]["ip_address"] == "192.168.20.1"

    def test_summary_and_down(self):
        result = sp.parse(_load("show_ip_interface_brief.txt"))
        summary = sp.summarize(result)
        assert summary.meta["up"] == 6
        assert summary.meta["administratively_down"] == 1
        assert summary.meta["unassigned_ip"] == 2
        down = sp.filter_down(result)
        assert {r["interface"] for r in down.rows} == {
            "GigabitEthernet0/2",
            "Serial0/0/0",
        }


class TestVlanBrief:
    def test_wrapped_ports_and_empty(self):
        result = sp.parse(_load("show_vlan_brief.txt"))
        by_vlan = {r["vlan"]: r for r in result.rows}
        assert by_vlan[1]["port_count"] == 9  # wrapped continuation
        assert "Fa0/11" in by_vlan[1]["ports"]
        assert by_vlan[30]["name"] == "GUEST"
        assert by_vlan[30]["port_count"] == 0
        summary = sp.summarize(result)
        assert summary.meta["empty_vlans"] == 1
        assert summary.meta["vlan_count"] == 5  # excludes 1002-1005


class TestInterfacesStatus:
    def test_status_values(self):
        result = sp.parse(_load("show_interfaces_status.txt"))
        by_port = {r["port"]: r for r in result.rows}
        assert by_port["Gi0/1"]["vlan"] == "trunk"
        assert by_port["Fa0/3"]["status"] == "notconnect"
        assert by_port["Fa0/4"]["status"] == "disabled"
        assert by_port["Fa0/1"]["name"] == "PC1-Users"
        down = sp.filter_down(result)
        assert {r["port"] for r in down.rows} == {"Fa0/3", "Fa0/4", "Fa0/24"}


class TestMacTable:
    def test_dynamic_and_cpu(self):
        result = sp.parse(_load("show_mac_address_table.txt"))
        assert len(result.rows) == 6
        dyn = [r for r in result.rows if r["type"] == "DYNAMIC"]
        assert len(dyn) == 3
        assert dyn[0]["mac"] == "0050.56ab.1234"


class TestCdp:
    def test_wrapped_device_id(self):
        result = sp.parse(_load("show_cdp_neighbors.txt"))
        assert len(result.rows) == 3
        by_id = {r["device_id"]: r for r in result.rows}
        assert by_id["R1-CORE.lab.local"]["platform"] == "CISCO2911"
        assert by_id["R1-CORE.lab.local"]["capability"] == "R S I"
        assert by_id["R1-CORE.lab.local"]["local_interface"] == "Gig 0/1"
        assert by_id["SW2-ACCESS"]["port_id"] == "Fas 0/24"


class TestLldp:
    def test_rows(self):
        result = sp.parse(_load("show_lldp_neighbors.txt"))
        assert len(result.rows) == 3
        assert result.rows[0]["device_id"] == "R1-CORE.lab.local"
        assert result.rows[2]["capability"] == "T"


class TestIpRoute:
    def test_codes_and_default(self):
        result = sp.parse(_load("show_ip_route.txt"))
        assert result.meta["gateway_of_last_resort"] == "172.16.20.2"
        by_prefix = {r["prefix"]: r for r in result.rows}
        assert by_prefix["0.0.0.0/0"]["candidate_default"] is True
        assert by_prefix["0.0.0.0/0"]["next_hop"] == "172.16.20.2"
        assert by_prefix["10.50.0.0/24"]["code"] == "O"
        assert by_prefix["10.50.0.0/24"]["ad"] == "110"
        assert by_prefix["10.50.0.0/24"]["metric"] == "2"
        assert by_prefix["10.60.0.0/24"]["code"] == "O IA"
        assert by_prefix["10.10.10.0/30"]["next_hop"] == "connected"
        assert by_prefix["198.51.100.0/24"]["code"] == "O E2"


class TestVersion:
    def test_fields(self):
        result = sp.parse(_load("show_version.txt"))
        assert result.meta["hostname"] == "R1-CORE"
        assert result.meta["ios_version"] == "15.7(3)M8"
        assert result.meta["model"] == "CISCO2911/K9"
        assert result.meta["serial"] == "FTX9999Z0AB"
        assert "3 days" in result.meta["uptime"]
        assert result.meta["config_register"] == "0x2102"


# ---------------------------------------------------------------- output / CLI


class TestOutputCli:
    def test_json_and_csv(self):
        result = sp.parse(_load("show_ip_interface_brief.txt"))
        data = json.loads(sp.to_json(result))
        assert data["count"] == 8
        csv_text = sp.to_csv(result)
        assert "interface,ip_address" in csv_text.splitlines()[0]

    def test_cli_file(self, capsys):
        path = SAMPLES / "show_version.txt"
        assert sp.main([str(path)]) == 0
        out = capsys.readouterr().out
        assert "R1-CORE" in out and "15.7(3)M8" in out

    def test_cli_stdin(self, capsys, monkeypatch):
        text = _load("show_mac_address_table.txt")
        monkeypatch.setattr(sp.sys.stdin, "read", lambda: text)
        monkeypatch.setattr(sp.sys.stdin, "isatty", lambda: False)
        assert sp.main([]) == 0
        assert "0050.56ab.1234" in capsys.readouterr().out

    def test_cli_down(self, capsys):
        path = SAMPLES / "show_ip_interface_brief.txt"
        assert sp.main([str(path), "--down"]) == 0
        out = capsys.readouterr().out
        assert "GigabitEthernet0/2" in out
        assert "TenGigabitEthernet1/0/1" not in out

    def test_cli_summary_json(self, capsys):
        path = SAMPLES / "show_vlan_brief.txt"
        assert sp.main([str(path), "--summary", "--json"]) == 0
        data = json.loads(capsys.readouterr().out)
        assert data["meta"]["empty_vlans"] == 1

    def test_cli_force_command(self, capsys):
        # Feed vlan text but force wrong detection path via --command matching content
        path = SAMPLES / "show_vlan_brief.txt"
        assert sp.main([str(path), "-c", "show vlan brief", "--csv"]) == 0
        assert "vlan,name,status" in capsys.readouterr().out

    def test_cli_unknown_input(self, capsys, tmp_path):
        bad = tmp_path / "x.txt"
        bad.write_text("hello world\n")
        assert sp.main([str(bad)]) == 2
        err = capsys.readouterr().err
        assert "error:" in err
        assert "Traceback" not in err

    def test_cli_empty(self, capsys, tmp_path):
        empty = tmp_path / "empty.txt"
        empty.write_text("   \n")
        assert sp.main([str(empty)]) == 2

    def test_cli_down_unsupported(self, capsys):
        path = SAMPLES / "show_version.txt"
        assert sp.main([str(path), "--down"]) == 2

    def test_demo(self, capsys):
        assert sp.main(["--demo"]) == 0
        out = capsys.readouterr().out
        assert "show ip interface brief" in out
        assert "show version" in out
        assert "empty VLAN 30" in out

    def test_textfsm_missing_package(self, capsys):
        path = SAMPLES / "show_ip_interface_brief.txt"
        # Should error cleanly when ntc-templates is not installed.
        rc = sp.main([str(path), "--engine", "textfsm"])
        # If ntc-templates happens to be installed in the env, accept success;
        # otherwise expect a clear error.
        if rc == 2:
            assert "ntc-templates" in capsys.readouterr().err
        else:
            assert rc == 0
