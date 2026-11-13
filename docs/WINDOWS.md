# RaspiScanner on Windows

RaspiScanner was built to run **unattended on a Raspberry Pi** dropped onto
an unfamiliar network: it auto-configures its Ethernet interface (DHCP, then
fallback to the private ranges), can act as a Wi-Fi hotspot so you can
reach it without a cable, and runs as a `systemd` service.

The **Windows build** serves a different case: a technician already has a
laptop **already connected** to the installation's network and wants to
know, in a few minutes, what's on it and how it stands security-wise,
without Linux, without a command line, and without touching the laptop's
network configuration. It runs the same discovery, classification, and
assessment engine as the Pi.

## Starting it

1. Install **Python 3.9+** from <https://www.python.org/downloads/>, with
   **"Add Python to PATH"** checked.
2. Download or clone the repo, then double-click **`start.bat`**.
   It creates a virtualenv, installs `requirements-windows.txt`, and opens
   the dashboard at <https://127.0.0.1:7332> (self-signed certificate: the
   browser shows a warning you accept once).

A bootstrap admin account and a random password are created on first
launch and printed in the `start.bat` window; the first login then forces a
password change. Same as on Linux.

## How it differs from the Raspberry Pi

| Area | Raspberry Pi | Windows |
|---|---|---|
| Network interface | autoconfig: DHCP, then fallback to private ranges, `ip`/`dhclient` | **read-only**: it uses whatever Windows already set. `mode` is always `manual` or `no-network`. "Reconfigure network" only re-reads the addresses. |
| Wi-Fi hotspot | `nmcli device wifi hotspot` | **not available** (the Windows "hosted network" API is deprecated and unreliable). The panel is hidden. |
| Wi-Fi client | `nmcli` | best-effort via `netsh wlan`: network scanning works; connecting only works if a saved profile already exists for that SSID (connect the first time from the Windows Wi-Fi UI). |
| Layer-2 ARP scan | scapy + root/`cap_net_raw` | scapy + **Npcap** (see below). Without Npcap: automatic fallback to a **TCP-connect sweep + system ARP table** (`arp -a`). |
| Gateway / routes | `ip route` | `route print` + `psutil` |
| TLS certificate | `openssl` | the **`cryptography`** Python library (in `requirements-windows.txt`), no `openssl` to install |
| Startup | `systemd` service | `start.bat` (in the foreground, one window) |

Everything else (port scan, ONVIF/WS-Discovery, mDNS, SNMP, OUI lookup,
camera/NVR/network gear classification, assessment report, history, audit,
webhooks, continuous monitoring) is **identical** to Linux.

## Npcap (optional but recommended)

The "real" layer-2 ARP scan (ARP broadcast across the whole subnet, the MAC
of every host even if it exposes no port) needs **Npcap**:

1. Install it from <https://npcap.com>, leaving
   **"Install Npcap in WinPcap API-compatible Mode"** checked.
2. Run `start.bat` **as administrator** (raw sockets require it).

Without Npcap RaspiScanner **still works**: `GET /api/platform` reports
`arp_raw_available: false` and the dashboard says so. The fallback finds
hosts that answer on at least one common port
(HTTP/HTTPS/RTSP/SSH/Hikvision-Dahua ports/SMB/RDP) and reads their MAC
from the operating system's ARP table. That's enough for a site survey,
where cameras, NVRs, and network gear almost always expose a management
panel, but a completely silent device can slip through.

## Firewall

On first launch Windows may ask whether to allow `python.exe` to accept
connections: you only need that to open the dashboard **from another PC**
(`https://<laptop-ip>:7332`). For local use (`127.0.0.1`) you can deny it.

## Known limitations of the Windows build

- Connecting to a **new password-protected** Wi-Fi network has to be done
  the first time from the Windows UI (the saved profile then lets the
  dashboard reconnect).
- No hotspot: if the laptop sits somewhere awkward, reach the dashboard
  over a cable or over Wi-Fi managed by Windows.
- IPv6 discovery and passive LLDP/CDP listening need Npcap, like the ARP
  scan; without it they're skipped.
