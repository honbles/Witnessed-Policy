# Prototype

| File | Role |
|---|---|
| `wpcore.py`, `wp2.py` | Protocol core and full policy model: signed chain (S1), two-phase commit with round change (S2), epochs, bootstrap, gossip, freshness, certified time; baselines S0 and S3 |
| `harness.py`, `harness2.py` | Discrete-event emulated network used by the checks |
| `realnet.py`, `edge_daemon.py` | Real-socket transport (TCP, length-prefixed JSON) and one edge as one OS process |
| `real_dp.py`, `dp.py`, `run_real_dp.sh` | Real-process scenarios: network namespaces, veth and bridges, WireGuard tunnels, nftables, probes; `run_real_dp.sh` is the wrapper (root, or `unshare -Urnm`) |
| `probe.py`, `stream.py`, `spoof.py`, `srv.py` | Traffic probes, long-lived session, spoofed-prefix sender and echo server used by the scenarios |
| `suite_policy.py` | Spec traces T1 to T40 and faults F1 to F17 |
| `baselines.py`, `e1_sweep.py`, `fuzz.py`, `run_all.py`, `scale_emu.py` | Baselines, E1 sweep, property-based fuzz, emulated attack and cost scenarios, emulated scale |
| `trace2tla.py`, `validate_traces.py`, `checker.py` | Conversion of event traces into TLA+ modules checked by TLC, and the conformance checker |

Run the scenarios directly, as root:

```bash
ulimit -n 65536
sudo ./run_real_dp.sh --n 7 --b 1 --scenarios traffic,failover,compromised,crash,join,lease --join-k 10,50,150,500 --delay-ms 50 --out ../real_dp_out
sudo ./run_real_dp.sh --scenarios attack,offline --attack-n 12 --delay-ms 50 --out ../real_dp_out
sudo ./run_real_dp.sh --scenarios scale --scale 16,32 --delay-ms 50 --out ../real_dp_out
```

With `sch_netem` available the link delay is real; otherwise it is applied inside the application. Each edge process uses about 30 MB. Everything is created inside network namespaces and removed on exit.
