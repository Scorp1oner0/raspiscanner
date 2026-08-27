# Roadmap

RaspiScanner 1.0 is feature-complete. This file tracks ideas considered
for the future and deliberately deferred — not committed work, not
blockers, not a queue.

## Under consideration

- **Privilege separation.** Run the Flask dashboard as a non-root user,
  with a small privileged helper process handling raw sockets
  (ARP/ICMP), DHCP, and network interface reconfiguration.
- **Multi-hop network topology.** The current topology map is one hop
  (gateway plus directly observed LLDP/CDP neighbors). A full multi-hop
  graph would require SNMP-walking remote switches, which needs
  credentials this tool doesn't have and shouldn't guess — out of scope
  unless a deliberate, opt-in "bring your own credentials" model is
  designed first.
- **Field Technician mode.** A simplified dashboard view with larger
  touch targets for on-site use on a tablet or phone. A first attempt
  didn't behave reliably across browsers and was reverted; worth
  revisiting with a different approach (e.g. a state class scoped
  closer to the affected elements instead of `<body>`).

## Known, accepted limitations

Not on the roadmap because they're architectural tradeoffs, not gaps —
see [README.md](README.md#known-limitations) and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the reasoning:

- Host processing within a scan is sequential, not parallelized across
  hosts — a deliberate tradeoff on a project that can't validate
  concurrent-access correctness without a large real network to test
  against.
- Network topology is one hop by design (see above).
- This is not a vulnerability scanner: no exploitation, credential
  testing, or CVE matching, by design.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) before starting work on any of
the above, or open an issue to discuss it first.
