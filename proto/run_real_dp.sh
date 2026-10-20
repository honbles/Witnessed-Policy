#!/bin/bash
# Real data plane: edges = OS processes in network namespaces, WireGuard (wireguard-go) tunnels, nftables, real TCP probes.
# usage: ./run_real_dp.sh <args for real_dp.py>      (run as root; otherwise it falls back to `unshare -Urnm`)
cd "$(dirname "$0")"; . ../wg_unconfine.sh; ulimit -n 65536 2>/dev/null
if [ "$(id -u)" -ne 0 ]; then exec unshare -Urnm python3 real_dp.py "$@"; else exec python3 real_dp.py "$@"; fi
