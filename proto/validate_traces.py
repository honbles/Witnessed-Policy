import json, os, sys, re
from harness2 import *
from trace2tla import validate
DL = {'L2': 20.0, 'L3': 40.0}
def G(id, src='Finance', dst='Sales', port=443): return dict(id=id, src=src, dst=dst, port=port, qos='best')
out = []
def rec(name, res, n_ev, extra=''): out.append(dict(trace=name, result=res, events=n_ev, note=extra)); print(name, res, n_ev, extra, flush=True)
# 1. stuck split + RESOLVE (T20)
g, ek, ak, net, edges, adm = setup2(12, 1, 'S2', gossip=1e6, delay=DL); c = Ctl(g, adm, net, edges); ids = list(edges)
P, P2 = c.build('GRANT', G('gA')), c.build('GRANT', G('gB', 'Sales', 'Finance')); c.send(P, ids[:6]); c.send(P2, ids[6:]); net.run(8); adm.resolve(1, 1, P); net.run(net.now + 6)
r, n = validate(net.trace, 1, ids, 0, 7, 'TrStuck'); rec('emulated: split 6/6, stuck, RESOLVE (T20)', r, n)
# 2. two conflicting RESOLVE entries (T21)
g, ek, ak, net, edges, adm = setup2(12, 1, 'S2', gossip=1e6, delay=DL); c = Ctl(g, adm, net, edges); ids = list(edges)
P, P2 = c.build('GRANT', G('gA')), c.build('GRANT', G('gB', 'Sales', 'Finance')); c.send(P, ids[:6]); c.send(P2, ids[6:]); net.run(5); adm.T = 99; adm.resolve(1, 1, P); net.run(net.now + 3)
reps = list(adm.reports[(1, 1)].values())
def res(e): d = digest2(e); return {'type': 'res', 'admin': 'a0', 'slot': 1, 'r': 1, 'd': d, 'reports': reps, 'entry': e, 'sig': adm.key.sign(canon({'cid': g['chain_id'], 'res': [1, 1, d]}))}
for t in ids[:6]: net.send('adm', t, res(P))
for t in ids[6:]: net.send('adm', t, res(P2))
net.run(net.now + 5); adm.T = 7; adm.resolve(1, 2, P); net.run(net.now + 5)
r, n = validate(net.trace, 1, ids, 0, 7, 'TrTwoRes'); rec('emulated: two RES for one round, then round 2 (T21)', r, n)
# 3. equivocating Byzantine edge, no partition
g, ek, ak, net, edges, adm = setup2(12, 1, 'S2', byz=1, gossip=1e6, delay=DL); c = Ctl(g, adm, net, edges); ids = list(edges); hon_ids = ids[:11]
P, P2 = c.build('GRANT', G('gA')), c.build('GRANT', G('gB', 'Sales', 'Finance')); c.send(P, hon_ids[:6]); c.send(P2, hon_ids[6:]); c.send(P, ['e11']); c.send(P2, ['e11']); net.run(6)
r, n = validate(net.trace, 1, hon_ids, 1, 7, 'TrByz'); rec('emulated: Byzantine edge equivocates, 6/5 split', r, n)
# 4. normal commit with offline edges
g, ek, ak, net, edges, adm = setup2(12, 1, 'S2', gossip=1e6, delay=DL); c = Ctl(g, adm, net, edges); ids = list(edges); net.down.update(ids[8:]); c.send(c.build('GRANT', G('g1'))); net.run(6)
r, n = validate(net.trace, 1, ids, 1, 7, 'TrOff'); rec('emulated: 4 edges offline (c=4), commit with 7 of 12', r, n)
# 5. real-process traces
for tag, nh, nb, T in (('scale_S2_16', 16, 0, 11), ('scale_S2_32', 32, 0, 22), ('scale_S2_64', 64, 0, 43)):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    p = next((q for q in (os.path.join(root, 'real_dp_out', tag, 'trace'), os.path.join(root, 'paper_data', 'traces', tag)) if os.path.isdir(q)), None)   # fresh run first, shipped trace second
    if p is None: continue
    tr = []
    for f in os.listdir(p): tr += [json.loads(l) for l in open(os.path.join(p, f)) if l.strip()]
    tr.sort(key=lambda x: x['t']); r, n = validate(tr, 1, [f'e{i}' for i in range(nh)], nb, T, 'TrReal' + tag.split('_')[-1]); rec(f'real processes (n={nh}), slot 1 of {tag}', r, n, 'wall-clock ordered')
# 6. negative control: tamper with a trace (commit attestation before a certificate exists)
g, ek, ak, net, edges, adm = setup2(12, 1, 'S2', gossip=1e6, delay=DL); c = Ctl(g, adm, net, edges); ids = list(edges); c.send(c.build('GRANT', G('g1'))); net.run(6)
tr = [x for x in net.trace if x.get('slot') == 1 and x['ev'] in ('prepare', 'commit_att')]; first_commit = next(i for i, x in enumerate(tr) if x['ev'] == 'commit_att'); tr.insert(0, tr.pop(first_commit))
r, n = validate(tr, 1, ids, 0, 7, 'TrBad'); rec('NEGATIVE CONTROL: commit attestation moved before any prepare', r, n, 'must be REJECTED')
json.dump(out, open('trace_validation.json', 'w'), indent=1)
