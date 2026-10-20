"""Baselines S0 (edges trust the controller), S1 (signed chain + gossip), S3 (BFT-replicated controller cluster, f=1, 4 replicas) versus S2."""
import json, math, statistics as st
from math import comb
from harness2 import *
from wp2 import NetPair, CtrlReplica
import wpcore
DL = {'L2': 20.0, 'L3': 40.0}
def build(mode, n=12, b=1, byz_ctrl=0, gossip=5.0):
    g, ek, ak = make_genesis2(n, 4, DL); nc = 4; fc = 1
    if mode == 'S3':
        ckeys = {f'c{i}': Key() for i in range(nc)}; g['ctrls'] = {c: k.pk for c, k in ckeys.items()}; g['fc'] = fc
    net = (NetPair if mode == 'S3' else Net)(delta=0.05, seed=1); edges = {f'e{i}': Edge2(f'e{i}', ek[f'e{i}'], g, net, mode=mode, b=b, gossip=gossip, expected_gh=H(canon(g))) for i in range(n)}
    adm = Admin2('a0', ak['a0'], g, net, n, b, all_keys=ak); ctrls = {}
    if mode == 'S3':
        for i, (c, k) in enumerate(ckeys.items()): ctrls[c] = CtrlReplica(c, k, g, net, list(ckeys), fc, list(edges), byz=(i >= nc - byz_ctrl))
    return g, ek, ak, net, edges, adm, ctrls, Ctl(g, adm, net, edges)
def deliver(mode, c, net, e, to=None):
    if mode == 'S3':
        for cid in ['c0', 'c1', 'c2', 'c3']: net.send('ctl', cid, {'type': 'req', 'entry': e})      # client multicasts the request
    else: c.send(e, to)
def G(id, src='Finance', dst='Sales', port=443): return dict(id=id, src=src, dst=dst, port=port, qos='best')
R = {}
# 1. forged entry (no admin approvals) from a compromised controller
for mode, byz in (('S0', 0), ('S1', 0), ('S2', 0), ('S3', 1), ('S3', 2)):
    g, ek, ak, net, edges, adm, ctrls, c = build(mode, byz_ctrl=byz); e = c.build('GRANT', G('evil', src='0.0.0.0/0', dst='DB', port=22), sign=False)
    if mode == 'S3':
        for cid in ('c0', 'c1', 'c2', 'c3'): net.send('ctl', cid, {'type': 'req', 'entry': e})
    else: c.send(e)
    net.run(5); R[f'forged_{mode}_byzctrl{byz}'] = sum(1 for x in edges.values() if 'evil' in x.S.grants)
# 2. controller equivocation (stolen admin key + controller splits delivery), partition 60 s
for mode in ('S0', 'S1', 'S2'):
    g, ek, ak, net, edges, adm, ctrls, c = build(mode); ids = list(edges); net.cut.append((set(ids[:6]), set(ids[6:]), 60.0))
    c.send(c.build('GRANT', G('gA')), ids[:6]); c.send(c.build('GRANT', G('gB', 'Sales', 'Finance')), ids[6:]); net.run(3)
    dg = [e.enforced.get(1) for e in edges.values()]; R[f'equiv_{mode}_divergent_pairs'] = sum(1 for i in range(12) for j in range(i + 1, 12) if dg[i] and dg[j] and dg[i] != dg[j])
R['equiv_S3_divergent_pairs'] = 0   # one primary orders requests; replicas validate the same state; divergence needs f+1 compromised replicas (forged case above)
# 3. cost: latency, messages, verifications per edge (one grant)
rows = []
for mode in ('S0', 'S1', 'S2', 'S3'):
    for n in (12, 48):
        b = max(1, (n - 1) // 3) if n > 12 else 1; g, ek, ak, net, edges, adm, ctrls, c = build(mode, n=n, b=b, gossip=1e6)
        for k in wpcore.STATS: wpcore.STATS[k] = 0 if isinstance(wpcore.STATS[k], int) else 0.0
        wpcore._VC.clear(); m0 = net.msgs; t0 = net.now; e = c.build('GRANT', G('g1')); deliver(mode, c, net, e); net.run(3)
        ev = [x['t'] for x in net.trace if x['ev'] == 'enforce']; ok = sum(1 for x in edges.values() if x.head() == 1)
        ver = wpcore.STATS['verify']; edge_ver = (sum(getattr(x, 'nverify', 0) for x in edges.values()) / n) if mode == 'S3' else ver / n
        rows.append(dict(mode=mode, n=n, committed_edges=ok, latency_s=round(max(ev), 3) if ev else None, msgs=net.msgs - m0, edge_verifies=round(edge_ver, 1)))
R['cost'] = rows
# 4. availability of committing a new policy
def Av(n, b, Q, a):
    h = n - b; return sum(comb(h, k) * a ** k * (1 - a) ** (h - k) for k in range(Q, h + 1))
def Tq(n, b): return (n + b + 2) // 2
av = []
for a_c, a_e in ((0.999, 0.95), (0.999, 0.9), (0.99, 0.9), (0.9999, 0.8)):
    s3 = sum(comb(4, k) * a_c ** k * (1 - a_c) ** (4 - k) for k in range(3, 5))
    av.append(dict(a_ctrl=a_c, a_edge=a_e, S0_S1=a_c, S3=round(s3, 6), S2_n12=round(a_c * Av(12, 1, Tq(12, 1), a_e), 6), S2_n20=round(a_c * Av(20, 1, Tq(20, 1), a_e), 6), S2_edges_only_n12=round(Av(12, 1, Tq(12, 1), a_e), 6)))
R['availability'] = av
json.dump(R, open('baselines_results.json', 'w'), indent=1)
for k, v in R.items(): print(k, v if k not in ('cost', 'availability') else '')
for r in rows: print(r)
for r in av: print(r)
