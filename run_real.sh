#!/bin/bash
# Real-process runs (edges = OS processes in network namespaces, WireGuard tunnels, nftables).  Run as root (sudo).
# About 10-15 minutes on 8 vCPU.  Run ./diag_wg.sh once beforehand to check that WireGuard tunnels work on the host.
cd "$(dirname "$0")"; ROOT=$(pwd); . ./wg_unconfine.sh; mkdir -p results/logs; L=$ROOT/results/logs; ulimit -n 65536 2>/dev/null
[ -f real_dp_out/dp_results.json ] && mv real_dp_out/dp_results.json real_dp_out/dp_results.$(date +%s).prev.json   # each run starts from a clean result file
rm -f $L/real_dp_*.log
echo "[real data plane: traffic, hub failover, compromised edge, kill -9 during install, late join, lease]"
./proto/run_real_dp.sh --n 7 --b 1 --scenarios traffic,failover,compromised,crash,join,lease --join-k 10,50,150,500 --delay-ms 50 --out $ROOT/real_dp_out > $L/real_dp_main.log 2>&1; tail -1 $L/real_dp_main.log
echo "[real equivocation (S1 / S2 / S2 + Byzantine process) and offline edges]"
./proto/run_real_dp.sh --scenarios attack,offline --attack-n 12 --delay-ms 50 --out $ROOT/real_dp_out > $L/real_dp_attack.log 2>&1; tail -1 $L/real_dp_attack.log
echo "[real scale: 16 and 32 edges, S1 and S2]"
./proto/run_real_dp.sh --scenarios scale --scale 16,32 --delay-ms 50 --out $ROOT/real_dp_out > $L/real_dp_scale.log 2>&1; tail -1 $L/real_dp_scale.log
