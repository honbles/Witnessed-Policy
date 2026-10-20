#!/bin/bash
# Gathers every result file into one zip (results archive).
cd "$(dirname "$0")"; R=results/collected; rm -rf $R; mkdir -p $R/logs $R/tlc
cp proto/suite_results.json proto/baselines_results.json proto/fuzz_results.json proto/e1_sweep.json proto/results.json proto/trace_validation.json proto/scale_emu_*.json $R/ 2>/dev/null
cp sim/e3_results.json sim/e1_results.txt $R/ 2>/dev/null
cp real_dp_out/dp_results.json $R/dp_results.json 2>/dev/null
cp results/tlc_results.json $R/ 2>/dev/null; cp results/tlc/*.txt $R/tlc/ 2>/dev/null; cp results/logs/* $R/logs/ 2>/dev/null
mkdir -p $R/errs; for f in real_dp_out/*/*.err real_dp_out/*/wg_*.log; do [ -s $f ] && cp $f $R/errs/$(echo $f | tr '/' '_'); done 2>/dev/null
for d in real_dp_out/scale_S2_16 real_dp_out/scale_S2_32 real_dp_out/crash real_dp_out/traffic; do [ -d $d/trace ] && mkdir -p $R/traces/$(basename $d) && cp $d/trace/*.jsonl $R/traces/$(basename $d)/ 2>/dev/null; done
{ echo "host: $(hostname)"; echo "date: $(date -u)"; echo "kernel: $(uname -r)"; echo "cpus: $(nproc)"; free -g | head -2; echo; python3 --version; java -version 2>&1 | head -1; nft --version; wg --version; wireguard-go --version 2>&1 | head -1; ip -V; lsmod | grep -E "wireguard|netem" ; } > $R/system_info.txt 2>&1
Z=witnessed_policy_results_$(hostname).zip; (cd $R && zip -qr ../../$Z .); echo "wrote $Z  ($(du -h $Z | cut -f1))"
