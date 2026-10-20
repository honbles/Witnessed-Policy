------------------------- MODULE OnePhase -------------------------
(* One-phase variant: commit at T attestations; round change relies on
   reports "my last attestation" without certificates.  Used to show the
   safety failure that motivates the prepared certificate.                *)
EXTENDS Integers, FiniteSets, TLC
CONSTANTS H, NBz, T, Values, MaxRound, Rule   \* Rule: "highest" | "matching"
Rounds == 0..MaxRound
Cert   == Rounds \X Values
NOCL   == <<-1, -1>>
Perms  == Permutations(H)
VARIABLES at, ra, pr, rep, res
vars == <<at, ra, pr, rep, res>>

AC(r,v) == Cardinality({h \in H : v \in at[h][r]}) + NBz >= T
Committed == {v \in Values : \E r \in Rounds : AC(r,v)}

Init == /\ at  = [h \in H |-> [r \in Rounds |-> {}]]
        /\ ra  = [h \in H |-> [r \in Rounds |-> {}]]
        /\ pr  = [h \in H |-> 0]
        /\ rep = [h \in H |-> [r \in Rounds |-> {}]]
        /\ res = {}

Attest(h,r,v) ==
  /\ ra[h][r] = {} /\ r >= pr[h] /\ (r = 0 \/ <<r,v>> \in res)
  /\ at' = [at EXCEPT ![h][r] = @ \cup {v}]
  /\ ra' = [ra EXCEPT ![h][r] = {v}]
  /\ pr' = [pr EXCEPT ![h] = r]
  /\ UNCHANGED <<rep, res>>

Promise(h,r) ==
  /\ r \in 1..MaxRound /\ r > pr[h]
  /\ LET cs == {<<rr,vv>> \in Cert : rr < r /\ vv \in at[h][rr]} IN
     \/ /\ cs = {} /\ rep' = [rep EXCEPT ![h][r] = {NOCL}]
     \/ \E c \in cs : /\ \A d \in cs : d[1] <= c[1]
                      /\ rep' = [rep EXCEPT ![h][r] = {c}]
  /\ pr' = [pr EXCEPT ![h] = r]
  /\ UNCHANGED <<at, ra, res>>

RH(r) == {h \in H : rep[h][r] /= {}}

Resolve(r,v) ==
  /\ r \in 1..MaxRound /\ <<r,v>> \notin res
  /\ \E S \in SUBSET RH(r), k \in 0..NBz, bz \in {c \in Cert : c[1] < r} \cup {NOCL} :
       /\ Cardinality(S) + k >= T /\ (bz = NOCL => k = 0)
       /\ LET Sup(d) == Cardinality({h \in S : d \in rep[h][r]}) + (IF d = bz THEN k ELSE 0) IN
          IF Rule = "highest" THEN
             \/ \E c \in (UNION {rep[h][r] : h \in S}) \cup {bz} :
                  /\ c /= NOCL /\ v = c[2]
                  /\ \A h \in S : \E x \in rep[h][r] : x[1] <= c[1]
                  /\ (bz = NOCL \/ bz[1] <= c[1])
             \/ /\ \A h \in S : NOCL \in rep[h][r] /\ bz = NOCL
          ELSE
             LET Sp == {d \in Cert : d[1] < r /\ Sup(d) >= NBz + 1} IN
             \/ /\ Sp = {}
             \/ \E c \in Sp : v = c[2] /\ \A d \in Sp : d[1] <= c[1]
  /\ res' = res \cup {<<r,v>>}
  /\ UNCHANGED <<at, ra, pr, rep>>

Next == \/ \E h \in H, r \in Rounds, v \in Values : Attest(h,r,v)
        \/ \E h \in H, r \in Rounds : Promise(h,r)
        \/ \E r \in Rounds, v \in Values : Resolve(r,v)
Spec == Init /\ [][Next]_vars
UniqueCommit == Cardinality(Committed) <= 1
=============================================================================
