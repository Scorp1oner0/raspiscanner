# Contributing to RaspiScanner

## Before you start

This is a small, security-conscious project run on a best-effort basis.
Contributions are welcome, but please open an issue to discuss anything
beyond a small, self-contained fix before investing time in a PR — that
avoids spending effort on something that doesn't fit the project's scope
(see the "not a vulnerability scanner" boundary in
[README, "Security notes"](README.md#security-notes) and
[SECURITY.md](SECURITY.md)) or duplicates work already tracked in
[TODO.md](TODO.md).

**Security issues**: do not open a public issue or PR that describes a
vulnerability — follow [SECURITY.md](SECURITY.md) instead.

## Development setup

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 -m unittest discover -s tests -v
```

The test suite is fully mocked (no root, no real network, no hardware
required) and should run in a few seconds. Running the scanner itself
for real (`sudo venv/bin/python3 raspi-scanner.py`) does need root, for
the same reason the installed service does: raw sockets for ARP/ICMP
discovery, and `ip`/`dhclient`/`nmcli` for network reconfiguration.

## Before opening a PR

- **Run the full test suite** and make sure it's green
  (`python3 -m unittest discover -s tests -v`). Add tests for whatever
  you changed — this project treats "found a bug while testing" as the
  normal way bugs get fixed here, not an afterthought.
- **Prefer fixing the real behavior over adding a workaround.** If you
  hit a limitation that can't be fixed properly without hardware you
  don't have (e.g., something that only shows up on a real Raspberry Pi,
  or needs a large real network to reproduce), say so explicitly in the
  PR description instead of guessing at a fix.
- **No new runtime dependencies** without a strong reason. The project
  deliberately stays on `Flask` + `scapy` plus the Python standard
  library and system tools already used (`ip`, `dhclient`, `nmcli`,
  `openssl`) — adding a library is a bigger ask than it looks, since it
  has to keep working offline, on old/minimal Raspberry Pi OS images,
  and without network access in the field.
- **Untrusted input stays untrusted.** Anything derived from a scanned
  device — ONVIF/mDNS responses, HTTP banners, hostnames, MAC vendor
  strings — must be treated as attacker-controlled: parse it
  defensively (see `scanner/cameras/onvif.py`'s XML parsing and DOCTYPE
  rejection for the pattern this project follows), and never let it
  reach a shell command, a file path, or unescaped HTML in the dashboard.
- **Language convention**: code comments, docstrings, log messages, and
  commit messages are in Italian (this is an Italian-maintained project);
  anything user-facing at runtime — dashboard UI text, CLI `--help` and
  printed output, the generated report, JSON error messages returned by
  the API — is in English. Match whichever you're editing.
- **Don't scope-creep into P4.** [TODO.md](TODO.md) tracks priorities
  (P0 security → P1 hardening → P2 robustness → P3 tests/release → P4
  future features). A PR that quietly adds P4-flavored functionality
  while the project isn't at 1.0 yet will likely be asked to wait.

## Reporting bugs

Open an issue with:

- What you expected vs. what happened.
- How to reproduce it (ideally the exact command or dashboard action).
- Whether it happened on a Raspberry Pi or a Linux PC, and which distro.
- Relevant log lines (`sudo journalctl -u raspiscanner -n 100`) — strip
  anything you consider sensitive (IPs/MACs of your own network) first,
  though for a bug report on your own scan that's rarely necessary.
