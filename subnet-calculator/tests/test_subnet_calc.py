import ipaddress
import json
from pathlib import Path

import pytest

import subnet_calc as sc

ROOT = Path(__file__).resolve().parent.parent


class TestParse:
    def test_cidr(self):
        assert str(sc.parse_network("192.168.1.0/24")) == "192.168.1.0/24"

    def test_host_bits_are_masked(self):
        assert str(sc.parse_network("10.1.2.77/24")) == "10.1.2.0/24"

    def test_dotted_netmask(self):
        assert str(sc.parse_network("192.168.100.14 255.255.255.252")) == "192.168.100.12/30"

    @pytest.mark.parametrize("bad", ["10.0.0.0", "10.0.0.0/33", "300.1.1.1/24", "abc/24", ""])
    def test_invalid(self, bad):
        with pytest.raises(ValueError):
            sc.parse_network(bad)


class TestInfo:
    def test_slash24(self):
        info = sc.subnet_info("192.168.1.0/24")
        assert info.netmask == "255.255.255.0"
        assert info.wildcard == "0.0.0.255"
        assert info.broadcast == "192.168.1.255"
        assert (info.first_host, info.last_host) == ("192.168.1.1", "192.168.1.254")
        assert info.usable_hosts == 254
        assert info.is_private

    def test_slash26(self):
        info = sc.subnet_info("10.20.30.77/26")
        assert info.network == "10.20.30.64"
        assert info.broadcast == "10.20.30.127"
        assert info.usable_hosts == 62

    def test_slash31_point_to_point(self):
        info = sc.subnet_info("203.0.113.9/31")
        assert info.usable_hosts == 2
        assert (info.first_host, info.last_host) == ("203.0.113.8", "203.0.113.9")

    def test_slash32(self):
        info = sc.subnet_info("198.51.100.5/32")
        assert info.usable_hosts == 1
        assert info.first_host == info.last_host == "198.51.100.5"

    def test_slash8(self):
        assert sc.subnet_info("10.0.0.0/8").usable_hosts == 16_777_214


class TestScope:
    @pytest.mark.parametrize(
        "cidr,scope",
        [
            ("172.16.5.0/24", "Private (RFC 1918)"),
            ("198.51.100.0/26", "Documentation (RFC 5737)"),
            ("100.64.1.0/24", "Carrier-grade NAT (RFC 6598)"),
            ("127.0.0.0/8", "Loopback"),
            ("169.254.0.0/16", "Link-local (APIPA)"),
            ("224.0.0.0/4", "Multicast"),
            ("8.8.8.0/24", "Public"),
        ],
    )
    def test_classify(self, cidr, scope):
        assert sc.subnet_info(cidr).scope == scope

    def test_documentation_range_is_not_rfc1918(self):
        assert not sc.subnet_info("203.0.113.0/24").is_private


class TestSplit:
    def test_split_22_into_24(self):
        nets = sc.split_network("172.16.0.0/22", 24)
        assert [str(n) for n in nets] == [
            "172.16.0.0/24",
            "172.16.1.0/24",
            "172.16.2.0/24",
            "172.16.3.0/24",
        ]

    def test_same_prefix(self):
        assert len(sc.split_network("10.0.0.0/24", 24)) == 1

    @pytest.mark.parametrize("prefix", [23, 33])
    def test_bad_prefix(self, prefix):
        with pytest.raises(ValueError):
            sc.split_network("10.0.0.0/24", prefix)


class TestPrefixForHosts:
    @pytest.mark.parametrize(
        "hosts,prefix",
        [
            (1, 32),
            (2, 31),
            (3, 29),
            (6, 29),
            (7, 28),
            (14, 28),
            (30, 27),
            (62, 26),
            (63, 25),
            (254, 24),
            (255, 23),
        ],
    )
    def test_values(self, hosts, prefix):
        assert sc.prefix_for_hosts(hosts) == prefix

    def test_zero(self):
        with pytest.raises(ValueError):
            sc.prefix_for_hosts(0)


class TestVlsm:
    def test_demo_plan(self):
        allocs = sc.vlsm_allocate(sc.DEMO_BASE, sc.DEMO_REQUIREMENTS)
        got = {a.name: str(a.subnet) for a in allocs}
        assert got == {
            "Sales": "192.168.10.0/26",
            "Engineering": "192.168.10.64/27",
            "Guest-WiFi": "192.168.10.96/27",
            "Mgmt": "192.168.10.128/28",
            "WAN-Link": "192.168.10.144/31",
        }

    def test_every_requirement_fits_and_no_overlap(self):
        base = ipaddress.IPv4Network("10.50.0.0/22")
        reqs = {"A": 200, "B": 100, "C": 50, "D": 40, "E": 12, "F": 6, "G": 2}
        allocs = sc.vlsm_allocate(str(base), reqs)
        for a in allocs:
            assert a.usable_hosts >= a.hosts_needed
            assert a.subnet.subnet_of(base)
        for i, a in enumerate(allocs):
            for b in allocs[i + 1 :]:
                assert not a.subnet.overlaps(b.subnet)

    def test_out_of_space(self):
        with pytest.raises(ValueError, match="out of space"):
            sc.vlsm_allocate("192.168.0.0/24", {"A": 120, "B": 120, "C": 10})

    def test_single_too_big(self):
        with pytest.raises(ValueError):
            sc.vlsm_allocate("192.168.0.0/24", {"Huge": 500})

    def test_empty(self):
        with pytest.raises(ValueError):
            sc.vlsm_allocate("192.168.0.0/24", {})


class TestRequirementsParsing:
    def test_ok(self):
        assert sc.parse_requirements(["Sales=50", " IT = 20"]) == {"Sales": 50, "IT": 20}

    @pytest.mark.parametrize("bad", [["Sales"], ["=5"], ["Sales=x"], ["A=1", "A=2"]])
    def test_bad(self, bad):
        with pytest.raises(ValueError):
            sc.parse_requirements(bad)


class TestSampleFiles:
    def test_sample_inputs_all_parse_and_are_synthetic(self):
        allowed = [
            ipaddress.IPv4Network(n)
            for n in (
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "192.0.2.0/24",
                "198.51.100.0/24",
                "203.0.113.0/24",
            )
        ]
        for line in sc.read_lines(ROOT / "sample_inputs.txt"):
            net = sc.parse_network(line)
            assert any(net.subnet_of(a) for a in allowed), line

    def test_vlsm_example_file(self):
        base, reqs = sc.load_vlsm_file(ROOT / "vlsm_example.txt")
        assert base == "10.50.0.0/22"
        allocs = sc.vlsm_allocate(base, reqs)
        assert len(allocs) == len(reqs) == 7


class TestCli:
    def test_info(self, capsys):
        assert sc.main(["info", "192.168.1.0/24"]) == 0
        assert "192.168.1.254" in capsys.readouterr().out

    def test_split(self, capsys):
        assert sc.main(["split", "172.16.0.0/22", "/24"]) == 0
        assert "172.16.3.0/24" in capsys.readouterr().out

    def test_vlsm_args(self, capsys):
        assert sc.main(["vlsm", "192.168.10.0/24", "Sales=60", "Mgmt=10"]) == 0
        out = capsys.readouterr().out
        assert "192.168.10.0/26" in out and "192.168.10.64/28" in out

    def test_vlsm_file(self, capsys):
        assert sc.main(["vlsm", "--file", str(ROOT / "vlsm_example.txt")]) == 0
        assert "HQ-Users" in capsys.readouterr().out

    def test_batch(self, capsys):
        assert sc.main(["batch", str(ROOT / "sample_inputs.txt")]) == 0
        assert "203.0.113.8" in capsys.readouterr().out

    def test_demo(self, capsys):
        assert sc.main(["demo"]) == 0
        out = capsys.readouterr().out
        assert "VLSM plan for 192.168.10.0/24" in out

    def test_error_exit_code(self, capsys):
        assert sc.main(["info", "not-an-ip/24"]) == 2
        assert "error:" in capsys.readouterr().err


class TestIpAndMaskArgs:
    def test_two_separate_args(self, capsys):
        assert sc.main(["info", "192.168.10.77", "255.255.255.192"]) == 0
        out = capsys.readouterr().out
        assert "192.168.10.77 (host address)" in out
        assert "192.168.10.64/26" in out

    def test_cidr_host_form(self):
        info = sc.subnet_info("192.168.10.77/26")
        assert info.input_address == "192.168.10.77"
        assert info.cidr == "192.168.10.64/26"
        assert info.address_role == "host address"

    def test_mixed_args_pair_correctly(self):
        assert sc.join_address_args(
            ["10.0.0.5", "255.255.255.0", "172.16.1.1/20", "192.0.2.9", "/28"]
        ) == ["10.0.0.5 255.255.255.0", "172.16.1.1/20", "192.0.2.9 /28"]

    def test_prefix_token_with_space(self):
        assert sc.subnet_info("192.0.2.9 /28").cidr == "192.0.2.0/28"

    def test_bare_ip_still_errors(self, capsys):
        assert sc.main(["info", "192.168.10.77"]) == 2
        assert "missing prefix" in capsys.readouterr().err

    def test_two_host_addresses_not_paired(self):
        assert not sc.is_mask_token("10.0.0.1")
        assert sc.is_mask_token("255.255.255.192")
        assert sc.is_mask_token("/26")
        assert not sc.is_mask_token("/33")

    @pytest.mark.parametrize(
        "text,role",
        [
            ("192.168.10.64/26", "network address"),
            ("192.168.10.127/26", "broadcast address"),
            ("192.168.10.100/26", "host address"),
            ("203.0.113.8/31", "host address"),
        ],
    )
    def test_address_role(self, text, role):
        assert sc.subnet_info(text).address_role == role


class TestBinaryMaskAndClass:
    @pytest.mark.parametrize(
        "cidr,binary",
        [
            ("10.0.0.0/8", "11111111.00000000.00000000.00000000"),
            ("192.168.10.64/26", "11111111.11111111.11111111.11000000"),
            ("172.16.0.0/20", "11111111.11111111.11110000.00000000"),
            ("0.0.0.0/0", "00000000.00000000.00000000.00000000"),
        ],
    )
    def test_binary_mask(self, cidr, binary):
        assert sc.subnet_info(cidr).binary_mask == binary

    @pytest.mark.parametrize(
        "addr,cls",
        [
            ("10.1.1.1", "A"),
            ("127.0.0.1", "A"),
            ("172.16.0.1", "B"),
            ("191.255.0.1", "B"),
            ("192.168.1.1", "C"),
            ("223.0.0.1", "C"),
            ("224.0.0.5", "D (multicast)"),
            ("240.0.0.1", "E (experimental)"),
        ],
    )
    def test_legacy_class(self, addr, cls):
        assert sc.legacy_class(ipaddress.IPv4Address(addr)) == cls

    def test_info_output_has_new_rows(self, capsys):
        sc.main(["info", "172.16.5.130/27"])
        out = capsys.readouterr().out
        assert "Prefix length     : /27" in out
        assert "Binary mask       : 11111111.11111111.11111111.11100000" in out
        assert "IP class (legacy) : B (classful default /16)" in out


class TestHosts:
    def test_basic(self):
        fit = sc.hosts_fit(50)
        assert (fit.prefix, fit.netmask, fit.usable_hosts, fit.spare_hosts) == (
            26,
            "255.255.255.192",
            62,
            12,
        )
        assert fit.base_network is None

    def test_exact_power_boundary(self):
        assert sc.hosts_fit(62).prefix == 26
        assert sc.hosts_fit(63).prefix == 25

    def test_with_network(self):
        fit = sc.hosts_fit(50, "192.168.10.0/24")
        assert fit.first_subnet == "192.168.10.0/26"
        assert fit.first_subnet_range == "192.168.10.1 - 192.168.10.62"
        assert fit.subnets_available == 4

    def test_with_host_address_network(self):
        assert sc.hosts_fit(10, "10.20.30.77/24").first_subnet == "10.20.30.0/28"

    def test_too_big_for_network(self):
        with pytest.raises(ValueError, match="larger than"):
            sc.hosts_fit(300, "192.168.10.0/24")

    def test_top_level_flag(self, capsys):
        assert sc.main(["--hosts", "50", "--network", "192.168.10.0/24"]) == 0
        out = capsys.readouterr().out
        assert "Smallest fit      : /26" in out
        assert "Subnets available : 4" in out

    def test_subcommand(self, capsys):
        assert sc.main(["hosts", "500"]) == 0
        assert "/23" in capsys.readouterr().out

    def test_invalid_count(self, capsys):
        assert sc.main(["--hosts", "0"]) == 2
        assert "at least 1" in capsys.readouterr().err

    def test_no_command(self, capsys):
        assert sc.main([]) == 2

    def test_network_without_hosts(self, capsys):
        assert sc.main(["--network", "10.0.0.0/24", "info", "10.0.0.0/24"]) == 2


class TestJson:
    def _run(self, capsys, argv):
        assert sc.main(argv) == 0
        return json.loads(capsys.readouterr().out)

    def test_info(self, capsys):
        data = self._run(capsys, ["info", "192.168.10.77", "255.255.255.192", "--json"])
        assert isinstance(data, list) and len(data) == 1
        assert data[0]["cidr"] == "192.168.10.64/26"
        assert data[0]["input_address"] == "192.168.10.77"
        assert data[0]["binary_mask"] == "11111111.11111111.11111111.11000000"
        assert data[0]["ip_class"] == "C"
        assert data[0]["prefix"] == 26

    def test_json_flag_before_command(self, capsys):
        data = self._run(capsys, ["--json", "info", "10.0.0.0/8", "172.16.0.0/12"])
        assert [d["cidr"] for d in data] == ["10.0.0.0/8", "172.16.0.0/12"]

    def test_split(self, capsys):
        data = self._run(capsys, ["split", "172.16.0.0/22", "24", "--json"])
        assert data["count"] == 4
        assert data["subnets"][3]["subnet"] == "172.16.3.0/24"

    def test_vlsm(self, capsys):
        data = self._run(capsys, ["vlsm", sc.DEMO_BASE, "Sales=60", "Mgmt=10", "--json"])
        assert data["base"] == "192.168.10.0/24"
        assert [a["subnet"] for a in data["allocations"]] == [
            "192.168.10.0/26",
            "192.168.10.64/28",
        ]
        assert data["allocations"][0]["spare_hosts"] == 2
        assert data["addresses_used"] == 80

    def test_vlsm_file(self, capsys):
        data = self._run(capsys, ["vlsm", "-f", str(ROOT / "vlsm_example.txt"), "--json"])
        assert len(data["allocations"]) == 7

    def test_hosts(self, capsys):
        data = self._run(capsys, ["--hosts", "50", "--network", "192.168.10.0/24", "--json"])
        assert data["prefix"] == 26
        assert data["subnets_available"] == 4

    def test_hosts_subcommand(self, capsys):
        data = self._run(capsys, ["hosts", "2", "--json"])
        assert data["prefix"] == 31

    def test_batch(self, capsys):
        data = self._run(capsys, ["batch", str(ROOT / "sample_inputs.txt"), "--json"])
        assert len(data) == len(sc.read_lines(ROOT / "sample_inputs.txt"))

    def test_error_is_not_json(self, capsys):
        assert sc.main(["info", "bad/24", "--json"]) == 2
        assert capsys.readouterr().out == ""
