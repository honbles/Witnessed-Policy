import json, time, statistics as st
from harness import *
from checker import check
R = {}; TRACES = []
def hon(edges): return [e for e in edges.values() if not e.byz]
def div_pairs(edges, slot=1):
    d = [e.enforced.get(slot) for e in hon(edges)]; d = [x for x in d if x]
    n = len(d); return sum(1 for i in range(n) for j in range(i + 1, n) if d[i] != d[j])

# ---- A: equivocation attack, S1 vs S2
def attack(mode, byz=0, tau=60.0, g=30.0, n=12, b=1, resolve_at=None):
    G, ek, ak, net, edges, adm = setup(n, b, mode, byz=byz, gossip=g)
    ids = list(edges); E1 = set(ids[:n // 2]); E2 = set(ids[n // 2:])
    net.cut.append((E1, E2, tau)); e0 = edges['e0']
    P = propose(net, adm, ak, edges, e0.S, 1, e0.prev, 'GRANT', dict(id='gA', src='Finance', dst='Sales', port=443), to=sorted(E1))
    P2 = propose(net, adm, ak, edges, e0.S, 1, e0.prev, 'GRANT', dict(id='gB', src='Sales', dst='Finance', port=443), to=sorted(E2))
    net.run(2.0); D = div_pairs(edges)
    if resolve_at is not None:
        net.run(resolve_at); adm.resolve(1, 1, P); t_res = net.now; net.run(resolve_at + 10)
        t_commit = max((x['t'] for x in net.trace if x['ev'] == 'enforce'), default=None)
        return dict(D2s=D, committed=sum(1 for e in hon(edges) if e.head() == 1), distinct=len({e.enforced.get(1) for e in hon(edges)} - {None}),
                    resolve_to_commit_s=round(t_commit - t_res, 2) if t_commit else None, trace=net.trace, byz=byz, T=e0.T)
    net.run(tau + g + 5)
    W = min((e.fork_at for e in edges.values() if e.fork_at), default=None)
    return dict(D2s=D, W=W, distinct=len({e.enforced.get(1) for e in hon(edges)} - {None}), trace=net.trace, T=e0.T, byz=byz)
s1 = attack('S1'); R['attack_S1'] = {k: v for k, v in s1.items() if k != 'trace'}
s2 = attack('S2', resolve_at=70.0); R['attack_S2_stuck_resolve'] = {k: v for k, v in s2.items() if k != 'trace'}; TRACES.append(('attack_S2_stuck_resolve', s2['trace'], 0, s2['T']))
s2b = attack('S2', byz=1, resolve_at=70.0); R['attack_S2_byz_equivocating'] = {k: v for k, v in s2b.items() if k != 'trace'}; TRACES.append(('attack_S2_byz', s2b['trace'], 1, s2b['T']))
# without resolve: nothing enforced
G, ek, ak, net, edges, adm = setup(12, 1, 'S2'); ids = list(edges); e0 = edges['e0']
net.cut.append((set(ids[:6]), set(ids[6:]), 60))
propose(net, adm, ak, edges, e0.S, 1, e0.prev, 'GRANT', dict(id='gA', src='Finance', dst='Sales', port=443), to=ids[:6])
propose(net, adm, ak, edges, e0.S, 1, e0.prev, 'GRANT', dict(id='gB', src='Sales', dst='Finance', port=443), to=ids[6:]); net.run(120)
R['attack_S2_no_resolve'] = dict(enforced=sum(1 for e in edges.values() if e.head()), D=div_pairs(edges)); TRACES.append(('attack_S2_no_resolve', net.trace, 0, e0.T))

# ---- B/C: forged, tier-mismatch, protected-invariant
for mode in ('S1', 'S2'):
    G, ek, ak, net, edges, adm = setup(4, 1, mode); e0 = edges['e0']; rej = {}
    f1 = entry(1, e0.prev, 'GRANT', dict(id='x', src='Finance', dst='Sales', port=22), e0.S)           # no approvals
    f2 = entry(1, e0.prev, 'GRANT', dict(id='x', src='Finance', dst='Sales', port=22), e0.S); f2['tier'] = 'L0'; adm.sign_entry(f2)  # tier downgrade
    f3 = entry(1, e0.prev, 'GRANT', dict(id='x', src='Sales', dst='DB', port=5432), e0.S); adm.sign_entry(f3)   # L2 needs 2 approvals, has 1
    f4 = entry(1, e0.prev, 'GRANT', dict(id='x', src='Guest', dst='Finance', port=443), e0.S); adm.sign_entry(f4, extra=[ak['a1'], ak['a2']])   # protected
    for f in (f1, f2, f3, f4):
        for t in edges: net.send('ctl', t, {'type': 'prop', 'entry': f})
    net.run(3.0); why = [x['why'] for x in net.trace if x['ev'] == 'reject']
    R[f'forged_{mode}'] = dict(heads=[e.head() for e in edges.values()], rejects=sorted(set(why)), per_edge=len(why) // 4)

# ---- D: offline bound n=12,b=1,c=4 (T=7=n-b-c) and c=5
for down in (4, 5):
    G, ek, ak, net, edges, adm = setup(12, 1, 'S2'); ids = list(edges); e0 = edges['e0']
    for x in ids[12 - down - 1:]: net.down.add(x)          # 1 silent Byzantine + c offline
    P1 = propose(net, adm, ak, edges, e0.S, 1, e0.prev, 'GRANT', dict(id='g1', src='Finance', dst='Sales', port=443)); net.run(10)
    up = [e for e in edges.values() if e.id not in net.down]
    R[f'offline_b1_c{down}'] = dict(T=e0.T, up=len(up), n_minus_b_minus_c=12-1-down, committed_up=sum(1 for e in up if e.head() == 1))
    if down == 4: TRACES.append(('offline_c4', net.trace, 0, e0.T))
    if down == 5:
        net.down.clear(); net.run(50); R['offline_b1_c5']['after_heal_no_retransmit'] = sum(1 for e in edges.values() if e.head() == 1)
        for t in edges: net.send('ctl', t, {'type': 'prop', 'entry': P1})
        net.run(60); R['offline_b1_c5']['after_heal_reproposal'] = sum(1 for e in edges.values() if e.head() == 1)

# ---- E: lost attestation record
for obs in (False, True):
    G, ek, ak, net, edges, adm = setup(4, 1, 'S2', byz=1, observer=obs); e2 = edges['e2']; e0 = edges['e0']
    edges['e2'].observer = obs
    P = entry(1, e0.prev, 'GRANT', dict(id='gA', src='Finance', dst='Sales', port=443), e0.S); adm.sign_entry(P)
    P2 = entry(1, e0.prev, 'GRANT', dict(id='gB', src='Sales', dst='Finance', port=443), e0.S); adm.sign_entry(P2)
    net.send('ctl', 'e2', {'type': 'prop', 'entry': P}); net.run(0.06); net.down.add('e2'); e2.lose_record(); e2.on_msg({'type': 'prop', 'entry': P2})
    pre = [x for x in net.trace if x['e'] == 'e2' and x['ev'] == 'prepare']
    v = check(net.trace, e0.T, 1)
    R[f'lost_record_observer={obs}'] = dict(e2_prepares_slot1=len(pre), violations=[x[0] for x in v])

# ---- F: revocation latency, partitioned edge with lease
G, ek, ak, net, edges, adm = setup(12, 1, 'S2', gossip=30.0); ids = list(edges); e0 = edges['e0']
P = propose(net, adm, ak, edges, e0.S, 1, e0.prev, 'GRANT', dict(id='g1', src='Finance', dst='Sales', port=443, lease=100.0)); net.run(5)
net.cut.append((set(ids[9:]), set(ids[:9]), 300.0))
rv = propose(net, adm, ak, edges, e0.S, 2, e0.prev, 'REVOKE', dict(id='g1')); t_c = net.now; net.run(t_c + 1.0)
conn = [x['t'] - t_c for x in net.trace if x['ev'] == 'enforce' and x['slot'] == 2]
e9 = edges['e9']; net.run(60); f60 = e9.forwards('Finance', 'Sales', 443, net.now); net.run(160); f160 = e9.forwards('Finance', 'Sales', 443, net.now)
net.run(400); heal = e9.head(); cu = [x['t'] for x in net.trace if x['ev']=='enforce' and x['slot']==2 and x['e'] in ('e9','e10','e11')]
R['revocation'] = dict(connected_max_s=round(max(conn), 3), connected_n=len(conn), bound_4d_g=round(4 * .06 + 30, 2),
                       partitioned_forwards_t60=f60, partitioned_forwards_t160_after_lease=f160, partitioned_head_after_heal=heal, catchup_after_heal_s=round(min(cu) - 300.0, 2) if cu else None)
TRACES.append(('revocation', net.trace, 0, e0.T))

# ---- G: bootstrap with substituted genesis
g1, ek1, ak1 = make_genesis(4); g2, ek2, ak2 = make_genesis(4)
net = Net(); gh = H(canon(g1)); good = Edge('e0', ek1['e0'], g1, net, expected_gh=gh); bad = Edge('e1', ek2['e1'], g2, net, expected_gh=gh)
R['bootstrap'] = dict(good_state=good.state, substituted_genesis_state=bad.state, bad_forwards=bad.forwards('Finance', 'Sales', 443, 0.0))

# ---- H: certified time with Byzantine skew and +-0.5 s honest clocks
G, ek, ak, net, edges, adm = setup(12, 1, 'S2', byz=1); import random; rr = random.Random(3)
for e in edges.values():
    if not e.byz: e.offset = rr.uniform(-0.5, 0.5)
e0 = edges['e0']; propose(net, adm, ak, edges, e0.S, 1, e0.prev, 'GRANT', dict(id='g1', src='Finance', dst='Sales', port=443)); net.run(5)
ct = [e.cert_time[1] for e in hon(edges) if 1 in e.cert_time]
R['certified_time'] = dict(byz_skew=ByzEdge.skew, max_abs_err_s=round(max(abs(c - 0.15) for c in ct), 3), n=len(ct))
R['certified_time']['max_abs_err_vs_virtual_now'] = round(max(abs(c - net.trace[-1]['t']) for c in ct), 2)

# ---- I: scale / cost
import wpcore as W; k_=Key(); m_=b'x'*200; sg_=[k_.sign(m_+bytes([i])) for i in range(256)]
t0=time.perf_counter(); [Ed25519PublicKey.from_public_bytes(bytes.fromhex(k_.pk)).verify(bytes.fromhex(sg_[i]), m_+bytes([i%256])) for i in range(256)]; VC=(time.perf_counter()-t0)/300
R['ed25519_verify_us']=round(VC*1e6,1)
rows = []
for n in (10, 20, 50, 100):
    for mode in ('S1', 'S2'):
        b = (n - 1) // 3; G, ek, ak, net, edges, adm = setup(n, b, mode); e0 = edges['e0']
        for k in STATS: STATS[k] = 0 if isinstance(STATS[k], int) else 0.0
        import wpcore; wpcore._VC.clear()
        t0 = time.perf_counter(); propose(net, adm, ak, edges, e0.S, 1, e0.prev, 'GRANT', dict(id='g1', src='Finance', dst='Sales', port=443)); net.run(3.0)
        wall = time.perf_counter() - t0; lat = max(x['t'] for x in net.trace if x['ev'] == 'enforce')
        rows.append(dict(n=n, mode=mode, T=e0.T, latency_s=round(lat, 3), msgs=net.msgs, kB=round(net.bytes / 1024), verifies_per_edge=round(STATS['verify'] / n), est_cpu_ms_per_edge=round(1000 * (STATS['verify'] / n * VC + STATS['sign'] / n * VC * 0.8), 2), enforced=sum(1 for e in edges.values() if e.head() == 1)))
        if mode == 'S2' and n <= 20: TRACES.append((f'scale_{n}', net.trace, 0, e0.T))
R['scale'] = rows

# ---- J: conformance replay
conf = {}
for name, tr, bc, T in TRACES: conf[name] = dict(events=len(tr), violations=check(tr, T, bc))
R['conformance'] = conf
json.dump(R, open('results.json', 'w'), indent=1, default=str)
for k, v in R.items(): print(k, json.dumps(v, default=str) if k != 'scale' else '')
for r in rows: print(r)
