---- MODULE TrByz ----
EXTENDS WitnessedPolicyAbs, Sequences
CONSTANTS h0, h1, h10, h2, h3, h4, h5, h6, h7, h8, h9, v1, v2
VARIABLE i
TR == <<[a |-> "prepare", e |-> h1, r |-> 0, v |-> v1], [a |-> "prepare", e |-> h8, r |-> 0, v |-> v2], [a |-> "prepare", e |-> h7, r |-> 0, v |-> v2], [a |-> "prepare", e |-> h4, r |-> 0, v |-> v1], [a |-> "prepare", e |-> h2, r |-> 0, v |-> v1], [a |-> "prepare", e |-> h9, r |-> 0, v |-> v2], [a |-> "prepare", e |-> h3, r |-> 0, v |-> v1], [a |-> "prepare", e |-> h0, r |-> 0, v |-> v1], [a |-> "prepare", e |-> h6, r |-> 0, v |-> v2], [a |-> "prepare", e |-> h10, r |-> 0, v |-> v2], [a |-> "prepare", e |-> h5, r |-> 0, v |-> v1], [a |-> "commit_att", e |-> h0, r |-> 0, v |-> v1], [a |-> "commit_att", e |-> h2, r |-> 0, v |-> v1], [a |-> "commit_att", e |-> h5, r |-> 0, v |-> v1], [a |-> "commit_att", e |-> h7, r |-> 0, v |-> v1], [a |-> "commit_att", e |-> h6, r |-> 0, v |-> v1], [a |-> "commit_att", e |-> h10, r |-> 0, v |-> v1], [a |-> "commit_att", e |-> h3, r |-> 0, v |-> v1], [a |-> "commit_att", e |-> h8, r |-> 0, v |-> v1], [a |-> "commit_att", e |-> h1, r |-> 0, v |-> v1], [a |-> "commit_att", e |-> h4, r |-> 0, v |-> v1], [a |-> "commit_att", e |-> h9, r |-> 0, v |-> v1]>>
varsT == <<vars, i>>
TInit == Init /\ i = 0
Step == /\ i < Len(TR)
        /\ LET x == TR[i+1] IN
           \/ x.a = "prepare" /\ \E h \in H, r \in Rounds, v \in Values : h = x.e /\ r = x.r /\ v = x.v /\ Prepare(h, r, v)
           \/ x.a = "commit_att" /\ \E h \in H, r \in Rounds, v \in Values : h = x.e /\ r = x.r /\ v = x.v /\ CommitAtt(h, r, v)
           \/ x.a = "promise" /\ \E h \in H, r \in Rounds : h = x.e /\ r = x.r /\ Promise(h, r)
           \/ x.a = "res" /\ (IF <<x.r, x.v>> \in res THEN UNCHANGED vars ELSE \E r \in Rounds, v \in Values : r = x.r /\ v = x.v /\ Resolve(r, v))
        /\ i' = i + 1
TSpec == TInit /\ [][Step]_varsT
NotDone == i < Len(TR)
====
