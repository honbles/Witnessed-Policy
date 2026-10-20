------------------------ MODULE WPLiveness ------------------------
(* Liveness under fairness for the abstract-knowledge model: Byzantine edges silent, honest administrator
   (at most one RESOLVE value per round), weak fairness on every honest action.                            *)
EXTENDS WitnessedPolicyAbs
AdminResolve(r,v) == /\ \A w \in Values : <<r,w>> \notin res
                     /\ Resolve(r,v)
LNext == \/ \E h \in H, r \in Rounds, v \in Values : Prepare(h,r,v) \/ CommitAtt(h,r,v)
         \/ \E h \in H, r \in Rounds : Promise(h,r)
         \/ \E r \in Rounds, v \in Values : AdminResolve(r,v)
Fair == /\ \A h \in H, r \in Rounds, v \in Values : WF_vars(Prepare(h,r,v)) /\ WF_vars(CommitAtt(h,r,v))
        /\ \A h \in H, r \in Rounds : WF_vars(Promise(h,r))
        /\ \A r \in Rounds, v \in Values : WF_vars(AdminResolve(r,v))
LSpec == Init /\ [][LNext]_vars /\ Fair
Eventually == <>(Committed /= {})
==================================================================
