# Cisco Show-Command Parser

Parse raw Cisco **IOS / IOS-XE** `show` output into tables, JSON, or CSV using
**hand-written regular expressions** — no third-party packages required.

This is the educational approach: every pattern lives in `show_parser.py` with
comments explaining what it matches. In production networks you would often use
[TextFSM](https://github.com/google/textfsm) +
[ntc-templates](https://github.com/networktocode/ntc-templates) or Cisco
[Genie](https://developer.cisco.com/docs/Genie/) / pyATS instead; this project
optionally supports `--engine textfsm` when `ntc-templates` is installed, but the
default engine is pure stdlib regex.

## Supported commands

| Command | What you get |
|---------|----------------|
| `show ip interface brief` | interface, IP, status, protocol (handles *administratively down*) |
| `show vlan brief` | VLAN, name, status, ports (handles **wrapped** port lists) |
| `show interfaces status` | port, name, status, vlan, duplex, speed, type |
| `show mac address-table` | vlan, MAC, type, ports |
| `show cdp neighbors` | device id, local iface, holdtime, capability, platform, port id |
| `show lldp neighbors` | device id, local iface, holdtime, capability, port id |
| `show ip route` | code, prefix, AD/metric, next hop, age, interface, default flag |
| `show version` | hostname, IOS version, uptime, model, serial, image, config register |

Auto-detects the command from the text, or take `--command` / `-c`.

## Quick start (Linux)

Python 3.10+, nothing to install for the default engine:

```bash
# From this folder:
python3 show_parser.py --demo

# Parse a saved show output:
python3 show_parser.py sample_outputs/show_ip_interface_brief.txt
python3 show_parser.py sample_outputs/show_ip_interface_brief.txt --down
python3 show_parser.py sample_outputs/show_ip_interface_brief.txt --summary --json

# Pipe from stdin (how you often work on a jump host):
cat sample_outputs/show_vlan_brief.txt | python3 show_parser.py --summary
ssh lab-sw1 "show interfaces status" | python3 show_parser.py --down

# Force the command name / emit CSV:
python3 show_parser.py sample_outputs/show_mac_address_table.txt -c "show mac address-table" --csv
```

Optional TextFSM engine (industry templates):

```bash
pip install ntc-templates
python3 show_parser.py sample_outputs/show_ip_interface_brief.txt --engine textfsm --json
```

## Analysis flags

- **`--down`** — for `show ip interface brief` / `show interfaces status`, list only
  interfaces that are down, administratively down, notconnect, or disabled.
- **`--summary`** — for interface brief: up/down/admin-down counts and unassigned
  IPs; for VLAN brief: ports per VLAN and empty VLANs; for interface status:
  connected vs not.

## Demo

```text
$ python3 show_parser.py --demo
=== Cisco show-command parser demo ===

--- show ip interface brief (show_ip_interface_brief.txt) ---
Command: show ip interface brief
Note: summary
  total                 : 8
  up                    : 6
  down                  : 1
  administratively_down : 1
  unassigned_ip         : 2
Down/admin-down interfaces: 2
  GigabitEthernet0/2: administratively down/down ip=unassigned
  Serial0/0/0: down/down ip=unassigned

--- show vlan brief (show_vlan_brief.txt) ---
VLANs: 5, empty: 1
  VLAN 1 (default): 9 port(s)
  VLAN 10 (USERS): 3 port(s)
  VLAN 20 (SERVERS): 2 port(s)
  empty VLAN 30 (GUEST)
  VLAN 99 (MGMT): 1 port(s)

--- show interfaces status (show_interfaces_status.txt) ---
Command: show interfaces status
Note: showing 3 of 8
PORT   NAME          STATUS     VLAN   DUPLEX  SPEED   TYPE             
-----  ------------  ---------  -----  ------  ------  -----------------
Gi0/1  Uplink to R1  connected  trunk  a-full  a-1000  10/100/1000BaseTX
Gi0/2  Mgmt          connected  99     a-full  a-100   10/100/1000BaseTX
Fa0/1  PC1-Users     connected  10     a-full  a-100   10/100BaseTX     
(3 row(s))

--- show mac address-table (show_mac_address_table.txt) ---
Command: show mac address-table
Note: showing 3 of 6
VLAN  MAC             TYPE     PORTS
----  --------------  -------  -----
All   0100.0ccc.cccc  STATIC   CPU  
All   0100.0ccc.cccd  STATIC   CPU  
10    0050.56ab.1234  DYNAMIC  Fa0/1
(3 row(s))

--- show cdp neighbors (show_cdp_neighbors.txt) ---
Command: show cdp neighbors
Note: showing 3 of 3
DEVICE ID          LOCAL INTERFACE  HOLDTIME  CAPABILITY  PLATFORM   PORT ID 
-----------------  ---------------  --------  ----------  ---------  --------
R1-CORE.lab.local  Gig 0/1          148       R S I       CISCO2911  Gig 0/0 
SW2-ACCESS         Fas 0/24         162       S I         WS-C2960   Fas 0/24
AP-LOBBY           Gig 0/2          120       T H         AIR-CAP    Gig 0   
(3 row(s))

--- show lldp neighbors (show_lldp_neighbors.txt) ---
Command: show lldp neighbors
Note: showing 3 of 3
DEVICE ID          LOCAL INTERFACE  HOLDTIME  CAPABILITY  PORT ID
-----------------  ---------------  --------  ----------  -------
R1-CORE.lab.local  Gi0/1            120       R           Gi0/0  
SW2-ACCESS         Fa0/24           120       B           Fa0/24 
phone-ext-1001     Gi0/3            120       T           Port 1 
(3 row(s))

--- show ip route (show_ip_route.txt) ---
Command: show ip route
Note: showing 3 of 10
Meta: gateway_of_last_resort=172.16.20.2
CODE  PREFIX         AD  METRIC  NEXT HOP     AGE  INTERFACE           CANDIDATE DEFAULT
----  -------------  --  ------  -----------  ---  ------------------  -----------------
S     0.0.0.0/0      1   0       172.16.20.2                           yes              
C     10.10.10.0/30              connected         GigabitEthernet0/0  no               
L     10.10.10.1/32              connected         GigabitEthernet0/0  no               
(3 row(s))

--- show version (show_version.txt) ---
Command: show version
  image           : C2900 Software (C2900-UNIVERSALK9-M)
  ios_version     : 15.7(3)M8
  hostname        : R1-CORE
  uptime          : 3 days, 4 hours, 12 minutes
  system_image    : flash0:c2900-universalk9-mz.SPA.157-3.M8.bin
  model           : CISCO2911/K9
  serial          : FTX9999Z0AB
  config_register : 0x2102
```

## Sample data

Synthetic IOS/IOS-XE outputs in `sample_outputs/` (RFC 1918 / RFC 5737 addresses,
lab hostnames only). Edge cases included on purpose:

- Long names: `TenGigabitEthernet1/0/1`, subinterfaces `GigabitEthernet0/2.10`
- `administratively down`
- Wrapped VLAN port lists spanning two lines
- Empty VLAN (GUEST with no ports)
- CDP Device ID wrapped onto its own line
- OSPF `O`, `O IA`, `O E2`, connected `C`/`L`, and static default `S*`

## How the regex parsers work

Each parser in `show_parser.py` is a small function with commented patterns. Example
from `show ip interface brief`:

```python
# Status may be "up", "down", or the two-word "administratively down".
row_re = re.compile(
    r"^(?P<interface>\S+)\s+"
    r"(?P<ip>\d+\.\d+\.\d+\.\d+|unassigned)\s+"
    r"(?P<ok>YES|NO)\s+"
    r"(?P<method>\S+)\s+"
    r"(?P<status>administratively down|up|down)\s+"
    r"(?P<protocol>up|down)\s*$",
    re.IGNORECASE,
)
```

Auto-detection walks an ordered list of header / landmark regexes (for example the
`Interface  IP-Address  OK?  Method  Status  Protocol` banner) so piping unknown
show output still works most of the time.

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest
ruff check . && ruff format --check .
```

Layout:

```text
show_parser.py       # all parsers + CLI
sample_outputs/      # one synthetic file per command
tests/               # detection, each parser, CLI, edge cases
conftest.py
pyproject.toml
requirements.txt
```

## Skills demonstrated

- Reading and interpreting common Cisco **show** commands used in CCNA-style labs
- Hand-written **regex** parsing of fixed-column and wrapped CLI tables
- Auto-detection of command type from output landmarks
- Useful post-processing (`--down`, `--summary`) and structured **JSON/CSV** export
- Stdlib-only design with an optional TextFSM/`ntc-templates` escape hatch
- pytest coverage of edge cases; ruff; GitHub Actions CI across Python 3.10–3.12

## Resume bullet

- Built a Python Cisco show-command parser (stdlib regex) for `show ip int brief`,
  VLAN, interface status, MAC table, CDP/LLDP, IP route, and version, with
  auto-detection, table/JSON/CSV output, and `--down` / `--summary` analysis flags.
- Shipped synthetic IOS sample outputs covering admin-down, wrapped VLAN port lists,
  and CDP line wraps; pytest suite and ruff with GitHub Actions CI on Python 3.10–3.12;
  README documents TextFSM/ntc-templates and Genie as the industry alternatives.

## License

MIT
