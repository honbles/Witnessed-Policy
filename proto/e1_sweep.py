"""E1 sweep: vary the fraction k/12 of edges that receive branch P (the rest receive P'); partition holds for 60 s."""
import json
from harness2 import *
DL = {'L2': 20.0, 'L3': 40.0}
def G(id, src='Finance', dst='Sales', port=443): return dict(id=id, src=src, dst=dst, port=port, qos='best')
rows = []
for mode in ('S1', 'S2'):
    for k in range(1, 12):
        g, ek, ak, net, edges, adm = setup2(12, 1, mode, gossip=5.0, delay=DL); c = Ctl(g, adm, net, edges); ids = list(edges); A, B = ids[:k], ids[k:]
        net.cut.append((set(A), set(B), 60.0)); P = c.build('GRANT', G('gA')); P2 = c.build('GRANT', G('gB', 'Sales', 'Finance'))
        c.send(P, A); c.send(P2, B); net.run(4)
        dg = [e.enforced.get(1) for e in edges.values()]; D = sum(1 for i in range(12) for j in range(i + 1, 12) if dg[i] and dg[j] and dg[i] != dg[j])
        vals = {x for x in dg if x}; onP = sum(1 for x in dg if x and x == dg[0]) if dg[0] else 0
        # grants that took effect on only part of the fabric (exposure): effective at some edges but not at all of them
        eff_counts = {}
        for e in edges.values():
            for gid in e.effective_grants(): eff_counts[gid] = eff_counts.get(gid, 0) + 1
        one_sided = sum(1 for gid, cnt in eff_counts.items() if cnt < 12)
        rows.append(dict(mode=mode, k=k, divergent_pairs=D, values_enforced=len(vals), edges_enforcing=sum(1 for x in dg if x), one_sided_grants=one_sided,
                         committed_value=('P' if (len(vals) == 1 and mode == 'S2' and k >= 7) else ("P'" if len(vals) == 1 and mode == 'S2' else ('none' if mode == 'S2' else 'both')))))
json.dump(rows, open('e1_sweep.json', 'w'), indent=1)
for r in rows: print(r)
