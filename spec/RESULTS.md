# TLC results (single-slot core)

Distinct states as reported by TLC with symmetry reduction (edge permutations and value swap). Run: `java -cp tla2tools.jar tlc2.TLC -config <cfg> <module>.tla`, or `./run_tlc.sh` for the whole set.

| cfg | module | result | distinct states |
|---|---|---|---|
| `safe_n4_r1` (n=4, b=1, T=3, rounds 0..1) | WitnessedPolicy | no violation | 72,863 |
| `absr2` (rounds 0..2) | WitnessedPolicyAbs | clean, exhaustive | 6,542,584 |
| `absn7` (n=7, b=2, T=5, rounds 0..1) | WitnessedPolicyAbs | clean, exhaustive | 1,048,806 |
| `abs_neg` (T=2) | WitnessedPolicyAbs | UniqueCommit violated (negative control) | - |
| `lost_uncounted` (n=4) | WitnessedPolicy | UniqueCommit violated | - |
| `lost_counted` (T=4) | WitnessedPolicy | no violation | 61,983 |
| `lost_observer` (T=3) | WitnessedPolicy | no violation | 426,322 |
| `live_n6_c1` (bound tight) | WitnessedPolicy | commit reachable | 344 |
| `live_n5_c1`, `live_n6_c2` | WitnessedPolicy | no commit possible | 32; 32 |
| `op_hi_n4`, `op_hi_n5` | OnePhase | double commit | 917; 5,175 |
| `op_m_n4`, `op_m_n5`, `op_m_n6_T4`/`T5` | OnePhase | double commit | 1,031; 7,757; 7,730 |
| `live_n4`, `live_n4_r2` | WPLiveness | liveness holds | 2,040; 158,458 |
| `live_below` | WPLiveness | fails (control) | 216 |

The same counts appear in Table II of the paper.
