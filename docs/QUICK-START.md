# Trying RaspiScanner without installing it

The path is the same on **all three** systems: a script that creates an
isolated Python environment, installs the dependencies, starts the dashboard
in the foreground, and opens the browser. Stop it with `Ctrl-C` (or by
closing the window) and it leaves nothing behind: no registered service, no
files outside the project folder, **no change to the network
configuration**.

| System | Command |
|---|---|
| Linux (desktop, laptop) | `./start.sh` |
| Raspberry Pi OS | `./start.sh` |
| Windows | double-click `start.bat` |

All you need is Python 3.9+. On Windows, install it from
[python.org](https://www.python.org/downloads/) with **"Add Python to
PATH"** checked; on Debian/Ubuntu/Raspberry Pi OS you also need
`python3-venv` (`sudo apt install python3-venv`).

The dashboard opens at <https://127.0.0.1:7332>. The certificate is
self-signed, so the browser shows a warning you accept once. An admin
account and a random password are created on first launch and printed in
the terminal window; the first login forces a password change.

## How it differs from the installed version

The difference isn't between operating systems but between **trial** and
**appliance**.

| | Trial (`start.sh` / `start.bat`) | Installation (`sudo ./install.sh`, Linux/Pi only) |
|---|---|---|
| Network configuration | **never touched**, only read | the Pi configures its own interface: DHCP, then static fallback addresses |
| Wi-Fi hotspot | not available | available |
| Layer-2 ARP scan | only when started with privileges (see below) | yes |
| Autostart | no | `systemd` service, starts at boot |
| Where it lives | the project folder | `/opt/raspiscanner` |

The installation serves the case RaspiScanner was built for: a dedicated
Raspberry Pi, left unattended on an unfamiliar network. For a site survey
from your own laptop, the trial is all you need.

## Full scan without touching the network

The layer-2 ARP scan also finds devices that expose **no** port at all, but
it needs raw sockets: root or `cap_net_raw` on Linux,
[Npcap](https://npcap.com) on Windows.

Without privileges RaspiScanner **still works**: it falls back to a
TCP-connect sweep plus the system ARP table. Cameras, NVRs, and network
gear almost always expose a management panel, so for a site survey that is
usually enough, but a completely silent device can slip through. The
dashboard says so (`arp_raw_available: false`).

To get the full scan **without** the scanner reconfiguring the network:

```bash
sudo -E RASPISCANNER_NO_NETWORK_CONFIG=1 ./start.sh
```

`RASPISCANNER_NO_NETWORK_CONFIG=1` is the explicit guarantee: even as root,
the interface stays exactly as the system set it up. Without that variable,
a root launch behaves like the appliance, which means it **may reconfigure
the Ethernet interface**, and `start.sh` warns you and gives you five
seconds to cancel.

On Windows: install Npcap (*"WinPcap API compatible"* option) and run
`start.bat` **as administrator**.

## On a headless Raspberry Pi

`start.sh` doesn't try to open a browser when there's no graphical
session: it prints the URL and stays in the foreground. To reach it from
another computer, use the Pi's IP instead of `127.0.0.1`
(`https://192.168.1.42:7332`); the dashboard listens on all interfaces.

## Vendor database (OUI)

On first launch the scripts download the full IEEE registry (~40,000
entries) into `data/oui_full.csv`, which is **not tracked by git**: trying
the scanner from a clone doesn't dirty the checkout. The curated list
`data/oui.csv` shipped with the repo stays and takes precedence for the
names it knows, because they're shorter and easier to read in a report
(`Hikvision` instead of `Hangzhou Hikvision Digital Technology Co.,Ltd.`).
Offline, only the curated list is used.
