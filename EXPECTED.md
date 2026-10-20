# Reference results

Values from the runs reported in the paper (8-vCPU Google Compute Engine VM, AMD EPYC 7B12, Ubuntu 25.10, kernel 6.17, `netem` 25 ms per side, kernel WireGuard). Exact timings vary by host; the qualitative outcomes should match.

## Emulated checks (`./run_checks.sh`)
- `suite_policy`: 52/52 cases pass (35 traces, 17 faults).
- Fuzz (250 random entries, n=7): S1 and S2 commit 94 and reject 156 with 0 violations; S0 commits all 250 with 6,581 violations.
- Baselines at n=12, b=1: a forged entry is accepted by 12/12 edges under S0, 0 under S1 and S2, and 0 (one bad replica) or 12 (two bad replicas) under S3. Equivocation leaves 36 divergent pairs under S0 and S1, none under S2 and S3. Commit latency 0.059 s (S0, S1), 0.167 s (S2), 0.113 s (S3). P(commit possible) at a_ctl = 0.999, a_edge = 0.9: S0 and S1 0.999, S2 0.9962 (a_ctl times Eq. 1), S3 0.999994.
- E1 sweep: S1 diverges on k(12-k) pairs (at most 36); S2 never diverges. It commits P' for k <= 5, stalls at k = 6 until round change, and commits P for k >= 7.
- E3 outage simulation (n=12, b=1, 20 seeds, `sim/e3_multiseed.json`): commit possible 0.9973 (T=7) and 0.9108 (T=9) for 1 h outages, 0.9971 and 0.9109 for 10 h outages, 0.9931 and 0.9560 with three correlated regions; Eq. 1 gives 0.9972 and 0.9104 for independent edges.
- Emulated scale, n = 100 / 200 / 500: S2 latency about 0.17 s; 20,100 / 80,200 / 500,500 messages per slot.

## TLC (`./run_tlc.sh`, distinct states with symmetry reduction)
See `spec/RESULTS.md`. Key values: `safe_n4_r1` 72,863 (no violation); `absr2` 6,542,584 (exhaustive, no violation); `absn7` 1,048,806 (exhaustive, no violation); `lost_uncounted` violates UniqueCommit; `lost_counted` 61,983 and `lost_observer` 426,322 are clean.

## Trace validation (`python3 proto/validate_traces.py`)
All emulated traces and the real-process traces (n = 16, 32) are ACCEPTED; the final line, the tampered negative control, must say REJECTED.

## Real processes (`sudo ./run_real.sh`)
- Grant then revoke: Guest and Sales:22 stay blocked; rules reach all three data-plane edges about 0.3 s after the first prepare; after the revocation a new connection is blocked and an established session is reset within about 0.4 s.
- Endpoint cut off at commit (T9): the flow is blocked at that edge and allowed about 1 s after its control network returns.
- Hub failure (T10): outage under 1 s, traffic moves to the committed backup tunnel with no chain slot used, switch-back outage about 0.1 s.
- Compromised edge (T26, T27): 0/40 spoofed other-site packets reach the hub's rules; 40/40 for the edge's own prefix.
- `kill -9` during install (T18): the ruleset always equals a prefix of the chain; after restart it equals the full chain in 4 to 5 s.
- Late join: ACTIVE within 0.5 to 2.5 s for 10 to 500 slots; about 1.27 kB of history per slot.
- Equivocation, n=12: S1 36 divergent pairs and a fork alert at about the partition length; S2 none diverge, round change to commit about 0.6 s.
- b=1, c=4 commits with 7 = T edges up; c=5 stalls with 6 and commits after the heal and a re-proposal.
- Partition and lease: the cut-off edge removes the rule at its lease expiry (about 12.5 s after the partition); the other edges remove it within 0.5 s of the revocation.
- Scale (one slot): n=16 S1 0.09 s, S2 0.49 s; n=32 S1 0.09 s, S2 about 2.6 s for the slowest edge (median 0.6 s).

## Incident corpus (`python3 e4/kappa.py`)
Cohen's kappa 1.00 for capability, policy_write and layer1 (30/30).
