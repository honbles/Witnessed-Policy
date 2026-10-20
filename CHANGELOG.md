# Changelog

## 1.0.0

First public release, matching the paper.

- TLA+ specifications and TLC configurations for the single-slot core, the abstraction used for three rounds, the one-phase counterexamples and the liveness model.
- Python prototype: signed chain (layer 1), two-phase quorum commit with round change (layer 2), epochs, bootstrap, certified time, freshness and revocation, baselines S0 to S3.
- Real-process edges in network namespaces with WireGuard tunnels and nftables enforcement; scenarios for traffic, hub failover, compromised edge, `kill -9` during install, late join, lease expiry, equivocation, offline edges and scale.
- Trace-to-TLA+ conformance checking, with a negative control.
- Property-based fuzz, E1 and E3 simulations, emulated scale runs.
- Incident corpus of 30 records with codebook and two-coder agreement script.
- `wg_unconfine.sh` for hosts whose AppArmor profile for `wg` blocks key loading and the userspace socket.
