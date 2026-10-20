#!/bin/bash
# Runs every TLC configuration used in the paper.  Uses all cores and up to 20 GB heap.
#   ./run_tlc.sh            standard set (about 1-2 h on 8 vCPU, dominated by the n=7 run)
#   ./run_tlc.sh quick      skip the n=7 and the explicit 3-round runs
#   ./run_tlc.sh big        also the explicit-knowledge 3-round run (13M+ states, hours)
cd "$(dirname "$0")"; ROOT=$(pwd); JAR=${TLA_JAR:-$ROOT/tla2tools.jar}; W=$(nproc); HEAP=${HEAP:-20g}
mkdir -p results/tlc; cd spec
run() { # module cfg
  echo "== $1 $2"; java -XX:+UseParallelGC -Xmx$HEAP -cp $JAR tlc2.TLC -workers $W -metadir /tmp/m_$2 -config $2.cfg $1.tla > ../results/tlc/$2.txt 2>&1
  grep -E "No error|is violated|Temporal properties were violated|states generated|Finished in" ../results/tlc/$2.txt | tail -3
}
for c in safe_n4_r1 lost_uncounted lost_counted lost_observer live_n6_c1 live_n5_c1 live_n6_c2; do run WitnessedPolicy $c; done
for c in absr1 abs_neg absr2; do run WitnessedPolicyAbs $c; done
for c in op_hi_n4 op_hi_n5 op_m_n4 op_m_n5 op_m_n6_T4 op_m_n6_T5; do run OnePhase $c; done
for c in live_n4 live_n4_r2 live_below; do run WPLiveness $c; done
[ "$1" = quick ] || run WitnessedPolicyAbs absn7
[ "$1" = big ] && run WitnessedPolicy safe_n4
cd ..; python3 tlc_summary.py
