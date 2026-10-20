#!/bin/bash
# Emulated-network checks (no root needed).  About 15-25 minutes on 8 vCPU.
cd "$(dirname "$0")"; ROOT=$(pwd); mkdir -p results/logs
L=results/logs
( cd proto && echo "[suite]" && python3 suite_policy.py > ../$L/suite.log 2>&1; tail -1 ../$L/suite.log )
( cd proto && echo "[baselines]" && python3 baselines.py > ../$L/baselines.log 2>&1; echo done )
( cd proto && echo "[e1 sweep]" && python3 e1_sweep.py > ../$L/e1_sweep.log 2>&1; echo done )
( cd proto && echo "[fuzz]" && python3 fuzz.py > ../$L/fuzz.log 2>&1; tail -3 ../$L/fuzz.log | cut -c1-200 )
( cd proto && echo "[emulated attack/cost scenarios]" && python3 run_all.py > ../$L/run_all.log 2>&1; echo done )
( cd proto && echo "[emulated scale]" && python3 scale_emu.py 100,200,500 > ../$L/scale_emu.log 2>&1; tail -2 ../$L/scale_emu.log | cut -c1-200 )
( cd model && echo "[recovery model]" && python3 rec_only.py > ../$L/recovery.log 2>&1; cat ../$L/recovery.log )
( cd sim && echo "[e1 monte carlo]" && python3 e1_sim.py > e1_results.txt 2>&1; echo "[e3 outage sim]" && python3 e3_sim.py > ../$L/e3.log 2>&1; echo done )
( cd model && echo "[python model]" && python3 wp_model.py check > ../$L/wp_model.log 2>&1; cat ../$L/wp_model.log | cut -c1-160 )
