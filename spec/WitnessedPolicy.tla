------------------------- MODULE WitnessedPolicy -------------------------
(* Single-slot core of Witnessed Policy: two-phase quorum commit with
   administrator-started round change, abstract Byzantine edges,
   offline edges and lost attestation records.                            *)
EXTENDS Integers, FiniteSets, TLC

CONSTANTS
  HA, HL, HD,   \* honest edges: regular, record-losable, offline (idle)
  NBz,          \* Byzantine edges (abstract; counts only)
  T,            \* quorum size
  Values,       \* proposals (>=2 models equivocation)
  MaxRound,
  Silent,       \* TRUE: Byzantine edges contribute nothing (liveness runs)
  Mode          \* "none" | "observer" : behaviour after record loss

H      == HA \cup HL \cup HD
Rounds == 0..MaxRound
Cert   == Rounds \X Values
NOCERT == <<-1, -1>>
Contrib == IF Silent THEN 0 ELSE NBz
Perms  == Permutations(HA) \cup Permutations(HL) \cup Permutations(HD) \cup Permutations(Values)

VARIABLES
  hp, hc,   \* issued prepare/commit attestations (never retracted)
  rp, rc,   \* local lock-once record (can be lost for HL)
  pr,       \* promised round
  held,     \* prepared certificates an edge holds
  rep,      \* reports an edge issued for RESOLVE(r)
  res,      \* RESOLVE entries (round, selected value)
  dead      \* edges that lost their record
vars == <<hp, hc, rp, rc, pr, held, rep, res, dead>>

HP(r,v) == Cardinality({h \in H : v \in hp[h][r]})
HC(r,v) == Cardinality({h \in H : v \in hc[h][r]})
PC(r,v) == HP(r,v) + Contrib >= T
CC(r,v) == HC(r,v) + Contrib >= T
Committed == {v \in Values : \E r \in Rounds : CC(r,v)}

Active(h) == /\ h \notin HD
             /\ (Mode = "observer" => h \notin dead)

Init == /\ hp = [h \in H |-> [r \in Rounds |-> {}]]
        /\ hc = [h \in H |-> [r \in Rounds |-> {}]]
        /\ rp = [h \in H |-> [r \in Rounds |-> {}]]
        /\ rc = [h \in H |-> [r \in Rounds |-> {}]]
        /\ pr = [h \in H |-> 0]
        /\ held = [h \in H |-> {}]
        /\ rep = [h \in H |-> [r \in Rounds |-> {}]]
        /\ res = {}
        /\ dead = {}

Prepare(h,r,v) ==
  /\ Active(h) /\ rp[h][r] = {} /\ r >= pr[h]
  /\ (r = 0 \/ <<r,v>> \in res)
  /\ hp' = [hp EXCEPT ![h][r] = @ \cup {v}]
  /\ rp' = [rp EXCEPT ![h][r] = {v}]
  /\ pr' = [pr EXCEPT ![h] = r]
  /\ UNCHANGED <<hc, rc, held, rep, res, dead>>

Learn(h,r,v) ==
  /\ h \notin HD /\ PC(r,v) /\ <<r,v>> \notin held[h]
  /\ held' = [held EXCEPT ![h] = @ \cup {<<r,v>>}]
  /\ UNCHANGED <<hp, hc, rp, rc, pr, rep, res, dead>>

CommitAtt(h,r,v) ==
  /\ Active(h) /\ <<r,v>> \in held[h] /\ rc[h][r] = {} /\ r >= pr[h]
  /\ hc' = [hc EXCEPT ![h][r] = @ \cup {v}]
  /\ rc' = [rc EXCEPT ![h][r] = {v}]
  /\ UNCHANGED <<hp, rp, pr, held, rep, res, dead>>

Promise(h,r) ==
  /\ Active(h) /\ r \in 1..MaxRound /\ r > pr[h]
  /\ LET cs == {c \in held[h] : c[1] < r} IN
     \/ /\ cs = {}
        /\ rep' = [rep EXCEPT ![h][r] = @ \cup {NOCERT}]
     \/ \E c \in cs : /\ \A d \in cs : d[1] <= c[1]
                      /\ rep' = [rep EXCEPT ![h][r] = @ \cup {c}]
  /\ pr' = [pr EXCEPT ![h] = r]
  /\ UNCHANGED <<hp, hc, rp, rc, held, res, dead>>

RH(r) == {h \in H : rep[h][r] /= {}}
ExPC(r) == {c \in Cert : c[1] < r /\ PC(c[1], c[2])}

Resolve(r,v) ==
  /\ r \in 1..MaxRound /\ <<r,v>> \notin res
  /\ \E S \in SUBSET RH(r), k \in 0..(IF Silent THEN 0 ELSE NBz) :
       /\ Cardinality(S) + k >= T
       /\ \/ \E c \in ((UNION {rep[h][r] : h \in S}) \ {NOCERT})
                      \cup (IF k >= 1 THEN ExPC(r) ELSE {}) :
                /\ v = c[2]
                /\ \A h \in S : \E x \in rep[h][r] : x[1] <= c[1]
          \/ /\ \A h \in S : NOCERT \in rep[h][r]
  /\ res' = res \cup {<<r,v>>}
  /\ UNCHANGED <<hp, hc, rp, rc, pr, held, rep, dead>>

Lose(h) ==
  /\ h \in HL /\ h \notin dead
  /\ rp' = [rp EXCEPT ![h] = [r \in Rounds |-> {}]]
  /\ rc' = [rc EXCEPT ![h] = [r \in Rounds |-> {}]]
  /\ pr' = [pr EXCEPT ![h] = 0]
  /\ dead' = dead \cup {h}
  /\ UNCHANGED <<hp, hc, held, rep, res>>

Next == \/ \E h \in H, r \in Rounds, v \in Values :
              Prepare(h,r,v) \/ Learn(h,r,v) \/ CommitAtt(h,r,v)
        \/ \E h \in H, r \in Rounds : Promise(h,r)
        \/ \E r \in Rounds, v \in Values : Resolve(r,v)
        \/ \E h \in H : Lose(h)

Spec == Init /\ [][Next]_vars

(* ---------------- properties ---------------- *)
UniqueCommit == Cardinality(Committed) <= 1

NoDoubleAttest ==
  \A h \in HA \cup HD : \A r \in Rounds :
     Cardinality(hp[h][r]) <= 1 /\ Cardinality(hc[h][r]) <= 1

PreparedBeforeCommit ==
  \A h \in H : \A r \in Rounds : \A v \in hc[h][r] : PC(r,v)

(* action property: no attestation below a promised round *)
PromiseRespected ==
  [][\A h \in H \ HL : \A r \in Rounds :
        (hp'[h][r] /= hp[h][r] \/ hc'[h][r] /= hc[h][r]) => r >= pr[h]]_vars

NoCommit == Committed = {}

(* recovery runs: honest edges pre-split in round 0, no certificate *)
InitStuck(SplitVal) ==
  /\ hp = [h \in H |-> [r \in Rounds |-> IF r = 0 /\ h \in DOMAIN SplitVal THEN {SplitVal[h]} ELSE {}]]
  /\ hc = [h \in H |-> [r \in Rounds |-> {}]]
  /\ rp = [h \in H |-> [r \in Rounds |-> IF r = 0 /\ h \in DOMAIN SplitVal THEN {SplitVal[h]} ELSE {}]]
  /\ rc = [h \in H |-> [r \in Rounds |-> {}]]
  /\ pr = [h \in H |-> 0]
  /\ held = [h \in H |-> {}]
  /\ rep = [h \in H |-> [r \in Rounds |-> {}]]
  /\ res = {}
  /\ dead = {}
=============================================================================
