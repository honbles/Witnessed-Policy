#!/bin/bash
# Everything, in order, starting with a WireGuard sanity check.  Total roughly 2-3 hours on 8 vCPU / 31 GiB (the n=7 TLC run is the longest).
#   sudo ./run_all.sh          full
#   sudo ./run_all.sh quick    skips the long TLC run
cd "$(dirname "$0")"; mkdir -p results/logs; date > results/logs/started.txt
(./diag_wg.sh; DELAY=25 ./diag_wg.sh) 2>&1 | tee results/logs/diag_wg.txt
./run_checks.sh 2>&1 | tee results/logs/run_checks.out
./run_real.sh 2>&1 | tee results/logs/run_real.out
(cd proto && python3 validate_traces.py > ../results/logs/validate_traces.log 2>&1; cat ../results/logs/validate_traces.log | cut -c1-200)
./run_tlc.sh $1 2>&1 | tee results/logs/run_tlc.out
./collect_results.sh
