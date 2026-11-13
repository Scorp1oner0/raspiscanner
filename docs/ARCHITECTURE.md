# Architecture

```
raspi-scanner.py             Entry point: Flask dashboard (default) or CLI --report
├── scanner/
│   ├── config.py              Shared constants (preset ranges, ports, timeouts)
│   ├── platform_net.py         OS abstraction for network reads (Linux: /sys+ip; Windows: psutil+netsh)
│   ├── auth.py                 Dashboard users: roles, password hashes, must_change_password
│   ├── tls.py                   Self-signed TLS certificate (openssl; pure-Python "cryptography" fallback)
│   ├── vendor.py                Vendor lookup from offline OUI (data/oui.csv)
│   ├── hosts.py                  "is it a Raspberry Pi/PC/printer?" (vendor or typical ports)
│   ├── scan_engine.py            Orchestration: discovery -> fingerprint -> classify -> state
│   ├── storage.py                 Scan history/asset database (SQLite, data/history.db)
│   ├── webhooks.py                 Optional POST notification when a scan ends
│   ├── monitoring.py                Continuous Monitoring: scheduler for automatic scans
│   ├── targets.py                    Scan targets: custom networks beyond the interface ones
│   │
│   ├── discovery/                 Host discovery on a subnet
│   │   ├── arp.py                   ARP scan (scapy) + reverse DNS + 802.1Q VLAN tag
│   │   ├── icmp.py                   ICMP sweep for NOARP links (VPN tunnels)
│   │   ├── nopriv.py                  Fallback without raw sockets (Windows without Npcap): TCP sweep + system ARP table
│   │   ├── mdns.py                   mDNS/Bonjour (friendly name + Apple model)
│   │   ├── snmp.py                    Optional SNMP (sysDescr/sysName) on network gear
│   │   ├── lldp_cdp.py                 Passive LLDP/CDP listening (one-hop topology)
│   │   └── ipv6.py                     IPv6 discovery (ICMPv6 Echo to ff02::1)
│   │
│   ├── fingerprint/               What an already discovered host exposes
│   │   └── ports.py                 TCP port scan + HTTP banners (Server/<title>)
│   │
│   ├── cameras/                   Everything about IP cameras
│   │   ├── onvif.py                 WS-Discovery (multicast) + GetDeviceInformation (SOAP)
│   │   └── classify.py               "is it a camera?" + RTSP/admin URLs + vendor from banner
│   │
│   ├── nvr/                       Recorders (NVR/DVR), kept apart from single cameras
│   │   └── classify.py               "is it an NVR/DVR?" + subtype (DVR/Encoder/Decoder)
│   │
│   ├── network/                   Interface autoconfig + network gear
│   │   ├── setup.py                 DHCP -> preset-range fallback, cable/Wi-Fi monitor (read-only on Windows)
│   │   ├── infra.py                  Default gateway + "is it a router/switch/AP?"
│   │   └── hotspot.py                 Wi-Fi access point (nmcli) for cable-free reachability (not on Windows)
│   │
│   └── reporting/                 The "NETWORK ASSESSMENT" report
│       ├── security.py              Findings from active but non-intrusive probes
│       ├── risk.py                   Severity aggregation -> Critical/High/Medium/Low
│       └── assessment.py              Generates the report text, with optional diff section
│
├── templates/, static/        Web dashboard (HTML/CSS/JS, no external dependency/CDN)
├── data/oui.csv                Offline OUI database (best effort)
├── scripts/update_oui.py       Updates oui.csv from the IEEE registry (needs internet)
├── install.sh                  Installation + systemd service (Raspberry Pi / Linux)
├── start.sh                    Quick trial on Linux / Raspberry Pi (see docs/QUICK-START.md)
├── start.bat                   Startup for the Windows build (see docs/WINDOWS.md)
└── tests/                      Unit tests, all mocked (no hardware/network required)
```

## Flow of a scan

1. `scan_engine._active_networks()` reads from `network.setup.get_status()`
   every active IPv4 address on eth, on **every** Wi-Fi adapter present, and
   on every active VPN tunnel (WireGuard/OpenVPN/PPP/Tailscale/ZeroTier). If
   `scanner.targets` has `auto_interfaces: false`, this step is skipped
   entirely (see "Scan targets vs. network bootstrap" below). "Custom"
   networks configured in `scanner.targets` that do NOT already match an
   active interface are added by `scan_engine._routed_target_networks()`,
   resolved to the real egress interface via `ip route get`
   (`_egress_interface_for()`).
2. For each subnet, in parallel: `discovery.arp_scan()` (or
   `discovery.icmp_scan()` on NOARP links) finds IP+MAC/IP; at the same
   time, in separate threads, `cameras.onvif.onvif_probe()` (WS-Discovery),
   `discovery.mdns_probe()`, `discovery.lldp_cdp_probe()` (passive
   listening), and `discovery.ipv6_discovery()` (ICMPv6 to the all-nodes
   multicast) gather supplementary signals over the same time window.
3. For each host found: `fingerprint.scan_ports()` + `grab_http_banner()`
   collect open ports and banners; if the device answers ONVIF,
   `cameras.onvif.get_device_info()` is tried for a real vendor/model; if
   it's already suspected to be network gear, `discovery.snmp_probe()`
   tries `sysDescr`/`sysName` as a fallback.
4. The device is classified by four independent classifiers
   (`cameras.classify_camera`, `nvr.classify_nvr`,
   `network.infra.classify_network_device`, `hosts.classify_host`) that
   don't exclude each other: scan_engine picks the final label in order of
   specificity. NVR/DVR first, then Camera, then network gear, then hardware
   recognized by vendor or typical ports, and finally "Generic" if no
   signal is available.
5. When the scan ends, `storage.save_scan()` saves a full snapshot
   (SQLite) and updates the asset database; `webhooks.notify_scan_complete()`
   sends the result (including a diff against the previous scan) to an
   optional configured URL. The aggregated result is available through the
   dashboard, the JSON API, or `scanner.reporting.assessment.generate_all()`,
   which groups by network and produces the "NETWORK ASSESSMENT" text report
   with the security findings (`reporting.security`) and the risk summary
   (`reporting.risk`).
6. `monitoring.py` can repeat this whole flow automatically at intervals,
   calling the same `scan_engine.run_scan()` as the "Start scan" button:
   there is no separate scan path for automatic scans.

## Scan targets vs. network bootstrap

Two concepts kept DELIBERATELY separate, which before this feature were
implicitly the same mechanism:

- **Network bootstrap/fallback** (`scanner/network/setup.py`, UNCHANGED):
  which address to give the Raspberry Pi itself when DHCP doesn't answer
  (preset ranges + ARP probe, see the README).
- **Scan targets** (`scanner/targets.py`): which networks a scan actually
  analyzes. By default they match the networks detected on the active
  interfaces (the original behavior, unchanged for anyone who doesn't touch
  `data/targets.json`), but an operator can also turn that automatic
  behavior off and/or add "custom" networks.

A custom network the Raspberry Pi doesn't hold its own address on, on any
interface, can't be reached via ARP (a protocol limit, not an
implementation one): `scan_engine._egress_interface_for()` asks the kernel
(`ip route get`) which interface it would use to reach it, and that network
is then scanned ONLY via ICMP sweep, the same treatment NOARP interfaces
(VPN) already get. No MAC/vendor, no ONVIF/mDNS/LLDP-CDP/IPv6 for the hosts
found there (they'd need a local address in that subnet to make sense).

## Access model

Three roles (`viewer`/`operator`/`admin`, `scanner/auth.py`), checked both
on the dashboard side (hidden tabs) and, independently, on every single API
route (`@require_role` in `raspi-scanner.py`). No route is protected on the
client side only: a client calling the API directly still gets `403` below
the minimum required role.

## Known limitations (by choice, not by oversight)

- All classifications (camera/NVR/network) and security findings are based
  on **active but non-intrusive probes** (ARP/ICMP requests, TCP connection
  attempts, HTTP requests, WS-Discovery multicast, ICMPv6 Echo): they aren't
  "passive" in the strict technical sense (they send real packets), but
  they never log in, test credentials, or attempt exploitation.
- The ARP scan only works on the directly connected L2 subnet: a device
  reachable only through routing (another VLAN/subnet) will never be found
  by this mechanism, because of a structural limit of the ARP protocol, not
  a bug in the tool.
- The loop that processes discovered hosts in
  `scan_engine._run_scan_thread` is sequential (the port scan inside each
  host is already parallel, but there's no parallelism between one host
  and the next): on very large networks (`/16` or more) this dominates the
  total scan time. Not parallelized further without a real network of that
  scale to validate correctness against (state shared between concurrent
  hosts, stop-flag responsiveness mid-batch).
- The network topology (`GET /api/topology`) is deliberately **one hop
  only** (gateway + LLDP/CDP neighbors seen directly): a multi-hop graph
  would need an SNMP walk on remote switches with credentials this tool
  doesn't have and must not guess.
