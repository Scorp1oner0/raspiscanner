# Security Policy

## Scope

RaspiScanner is a network reconnaissance tool that runs as **root** (it
needs raw sockets for ARP/ICMP discovery and `ip`/`dhclient`/`nmcli` to
reconfigure network interfaces) and exposes a web dashboard on the
network it scans. That combination makes vulnerabilities in this project
higher-impact than in a typical unprivileged tool: a flaw here could give
an attacker on the same network root-equivalent access to the host, or
access to everything the scanner has discovered (IPs, MACs, hostnames,
camera RTSP/admin URLs, security findings).

Treat any of the following as a security issue, not a regular bug:

- Anything that lets a network device (a probe response, an ONVIF/mDNS
  reply, an HTTP banner) influence code execution, file paths, or
  commands run by the scanner (injection, path traversal, SSRF, XXE/
  entity-expansion, deserialization of untrusted data).
- Anything that bypasses dashboard authentication, the CSRF/Origin
  check, or role checks (`viewer`/`operator`/`admin`, see `scanner/auth.py`).
- Anything that exposes `data/users.json` (password hashes) or
  `data/tls_key.pem` (the TLS private key) to an unauthorized party.
- Privilege escalation beyond what the systemd unit's
  `CapabilityBoundingSet` already grants (see `raspiscanner.service`).
- Denial of service specific to how this tool parses untrusted network
  input (e.g., an amplification/resource-exhaustion bug in the ONVIF XML
  or mDNS parsers), as opposed to "the scan generates a lot of traffic,"
  which is expected and documented behavior.

**Out of scope**: this is explicitly *not* a vulnerability scanner (see
[README, "Security notes"](README.md#security-notes)) — it doesn't
attempt exploitation, credential guessing, or CVE matching, so reports
asking it to detect a specific CVE on a scanned device are feature
requests, not security reports about RaspiScanner itself.

## Supported Versions

Pre-1.0: only the latest commit on `main` is supported. There are no
tagged releases yet, so "supported" means "fix lands on `main`," not a
guarantee of backported patches to an older tag.

## Reporting a Vulnerability

Please **do not open a public GitHub issue** for a security report.

Instead, use GitHub's private vulnerability reporting for this
repository (the "Report a vulnerability" button under the repo's
**Security** tab), which reaches the maintainer without disclosing the
issue publicly. If that isn't available for this repository, open an
issue asking to be pointed to a private contact instead of describing
the vulnerability itself.

Please include:

- What you found and where (file/function, or the network condition
  that triggers it — e.g., "a malicious ONVIF probe response with X").
- Impact: what an attacker could actually achieve.
- Steps to reproduce, ideally as a minimal example.
- Whether you've already tested a fix.

Given this is a small project maintained on a best-effort basis, there's
no fixed SLA, but genuine security reports take priority over feature
work and P3/P4 backlog items.
