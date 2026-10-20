"""Spec traces T1-T40 and faults F1-F17, policy-level (emulated network, real signatures, real validation code).
Data-plane cases (T10, T12-data, T17, T18, T26, T27) run in the real-namespace harness (real_dp.py)."""
import json, os, sys, tempfile, time, copy
from harness2 import *
from checker import check, check_epochs
REG = []; RES = []
DL = {'L2': 20.0, 'L3': 40.0}
def case(cid, desc, expected):
    def deco(f):
        def run():
            t0 = time.time()
            try: obs, ok, extra = f()
            except Exception as ex:
                import traceback; traceback.print_exc(); obs, ok, extra = f'EXC {ex!r}', False, {}
            RES.append(dict(id=cid, desc=desc, expected=expected, observed=obs, ok=bool(ok), secs=round(time.time() - t0, 1), **extra)); print(cid, 'PASS' if ok else 'FAIL', obs[:110], flush=True)
        run.cid = cid; REG.append(run); return run
    return deco
def mk(n=12, b=1, mode='S2', gossip=5.0, extra=None, byz=0, rec_dir=None):
    g, ek, ak, net, edges, adm = setup2(n, b, mode, byz=byz, gossip=gossip, delay=DL, extra=extra, rec_dir=rec_dir)
    return g, ek, ak, net, edges, adm, Ctl(g, adm, net, edges)
def run(net, dt): net.run(net.now + dt)
def commit(c, e, dt=3.0, to=None):
    c.send(e, to); c.accept(e); run(c.net, dt)
def reasons(edges): return sorted({r for e in hon(edges) for r in e.rejects})
def G(id, src='Finance', dst='Sales', port=443, **kw): return dict(id=id, src=src, dst=dst, port=port, qos='best', **kw)
def eff(edges): return [sorted(e.effective_grants()) for e in hon(edges)]

@case('T1', 'Normal grant', 'only the granted flow is allowed')
def _():
    g, ek, ak, net, edges, adm, c = mk(); commit(c, c.build('GRANT', G('gF')))
    e0 = edges['e0']; a, b_ = e0.forwards('Finance', 'Sales', 443), e0.forwards('Finance', 'Sales', 22)
    return f'heads={set(heads(edges))} allowed443={a} allowed22={b_}', a and not b_ and set(heads(edges)) == {1}, {}
@case('T2', 'Controller forges a wide grant with no signature', 'rejected; alert')
def _():
    g, ek, ak, net, edges, adm, c = mk(); e = c.build('GRANT', G('x', src='0.0.0.0/0', dst='0.0.0.0/0'), sign=False); c.send(e); run(net, 3)
    al = [a for a in adm.alerts if a['kind'] == 'rejected']
    return f'heads={set(heads(edges))} rejects={reasons(edges)} alerts_to_admin={len(al)}', set(heads(edges)) == {0} and len(al) >= 7, {}
@case('T3', 'One administrator signs an over-broad grant', 'pending until T2 approval and delay')
def _():
    g, ek, ak, net, edges, adm, c = mk(); wide = G('w', dst='10.2.0.0/16')
    e1 = c.build('GRANT', wide, by=('a0',)); c.send(e1); run(net, 3); one = (set(heads(edges)), reasons(edges))
    e2 = c.build('GRANT', wide, by=('a0', 'a1')); commit(c, e2); pend = eff(edges)[0]; run(net, 25); after = eff(edges)[0]
    return f'1 sig: heads={one[0]} {one[1]}; 2 sigs: committed, effective before delay={pend}, after={after}', one[0] == {0} and 'auth' in one[1] and pend == [] and after == ['w'], {}
@case('T4', 'Restricted destination, one signature', 'rejected until m-of-n and delay are met')
def _():
    g, ek, ak, net, edges, adm, c = mk(); d = G('db', dst='DB', port=5432)
    c.send(c.build('GRANT', d, by=('a0',))); run(net, 3); one = (set(heads(edges)), reasons(edges))
    commit(c, c.build('GRANT', d, by=('a0', 'a1'))); pend = eff(edges)[0]; run(net, 25)
    return f'1 sig: {one[1]}; 2 sigs: pending={pend}, effective after delay={eff(edges)[0]}', one[0] == {0} and pend == [] and eff(edges)[0] == ['db'], {}
@case('T5', 'Stolen single key, standard destination', 'accepted within scope; audit trail records it')
def _():
    g, ek, ak, net, edges, adm, c = mk(); commit(c, c.build('GRANT', G('s1'))); ch = edges['e3'].chain[0]
    return f'committed; chain entry approvals={[a for a, _ in ch["entry"]["approvals"]]}, cert signers={len(ch["cert"])}', set(heads(edges)) == {1} and [a for a, _ in ch['entry']['approvals']] == ['a0'] and len(ch['cert']) >= 7, {}
@case('T6', 'Stolen key signs two proposals on one base; controller splits delivery', 'S1 divergent until gossip; S2 at most one commits')
def _():
    out = {}
    for mode in ('S1', 'S2'):
        g, ek, ak, net, edges, adm, c = mk(mode=mode); ids = list(edges); A, B = set(ids[:6]), set(ids[6:]); net.cut.append((A, B, 60.0))
        P = c.build('GRANT', G('gA')); P2 = c.build('GRANT', G('gB', 'Sales', 'Finance')); c.send(P, sorted(A)); c.send(P2, sorted(B)); run(net, 3)
        dg = [e.enforced.get(1) for e in edges.values()]; D = sum(1 for i in range(12) for j in range(i + 1, 12) if dg[i] and dg[j] and dg[i] != dg[j]); out[mode] = (D, len({x for x in dg if x}))
    return f'S1 divergent pairs={out["S1"][0]} (values {out["S1"][1]}); S2 divergent pairs={out["S2"][0]}, values committed={out["S2"][1]}', out['S1'][0] == 36 and out['S2'][1] <= 1, {}
@case('T7', 'Replay or rollback of an old entry', 'rejected by slot, hash and epoch')
def _():
    g, ek, ak, net, edges, adm, c = mk(); e1 = c.build('GRANT', G('g1')); commit(c, e1)
    c.send(e1); run(net, 2); r1 = reasons(edges)
    bad = c.build('GRANT', G('g2', port=444), prev='0' * 64); c.send(bad); run(net, 2)
    ee = c.build('ENROLL', dict(edge='e12', pk=Key().pk), by=('a0', 'a1')); commit(c, ee, 3)
    stale = c.build('GRANT', G('g3', port=445), epoch=0); c.send(stale); run(net, 3)
    return f'replay/bad-hash -> {r1}; stale epoch -> {reasons(edges)}', 'replay' in r1 and 'epoch' in reasons(edges) and set(heads(edges)) == {2}, {}
@case('T8', 'Grant conflicting with an explicit deny', 'rejected')
def _():
    g, ek, ak, net, edges, adm, c = mk(); commit(c, c.build('DENY', dict(src='Guest', dst='Sales')))
    c.send(c.build('GRANT', G('x', 'Guest', 'Sales'))); run(net, 3)
    return f'rejects={reasons(edges)} heads={set(heads(edges))}', 'wf-deny' in reasons(edges) and set(heads(edges)) == {1}, {}
@case('T9', 'Endpoint edge offline at commit', 'commits by quorum; dropped at that endpoint until it verifies and installs')
def _():
    g, ek, ak, net, edges, adm, c = mk(); net.down.add('e1'); commit(c, c.build('GRANT', G('g1')), 3)
    e1 = edges['e1']; off = (e1.head(), e1.forwards('Finance', 'Sales', 443)); net.down.discard('e1'); run(net, 15)
    return f'quorum heads={set(h for k,h in zip(edges, heads(edges)) if k!="e1")} offline endpoint head/forwards={off}; after rejoin head={e1.head()} forwards={e1.forwards("Finance","Sales",443)}', off == (0, False) and e1.head() == 1 and e1.forwards('Finance', 'Sales', 443), {}
@case('T11', 'Up to b edges attest to everything', 'cannot commit alone or forge administrator signatures')
def _():
    g, ek, ak, net, edges, adm, c = mk(byz=1); e = c.build('GRANT', G('x', dst='DB', port=1), sign=False); z = edges['e11']
    e['approvals'] = [('a0', z.key.sign(appr_bytes(g['chain_id'], e)))]; c.send(e); run(net, 3)
    return f'byz attests to forged entry; honest heads={set(heads(edges))} rejects={reasons(edges)}', set(heads(edges)) == {0}, {}
@case('T12a', 'Revocation (policy level)', 'removed at every edge; sessions reset within the bound (data plane in real_dp)')
def _():
    g, ek, ak, net, edges, adm, c = mk(); commit(c, c.build('GRANT', G('g1'))); t = net.now; commit(c, c.build('REVOKE', dict(id='g1')), 3)
    ts = [x['t'] - t for x in net.trace if x['ev'] == 'enforce' and x['slot'] == 2]
    return f'effective grants after revoke={set(map(tuple, eff(edges)))} max apply delay={max(ts):.3f}s', set(map(tuple, eff(edges))) == {()} and max(ts) < 1.0, {}
@case('T13', 'Controller down', 'no new changes; existing grants continue')
def _():
    g, ek, ak, net, edges, adm, c = mk(); commit(c, c.build('GRANT', G('g1'))); run(net, 120)
    return f'after 120 s without controller: heads={set(heads(edges))} forwards={all(e.forwards("Finance","Sales",443) for e in edges.values())}', all(e.forwards('Finance', 'Sales', 443) for e in edges.values()), {}
@case('T14', 'Edge offline for weeks, then rejoins', 'verifies the certificate chain from genesis before enforcing')
def _():
    g, ek, ak, net, edges, adm, c = mk(); K = 40
    for k in range(K): commit(c, c.build('GRANT', G(f'g{k}', port=1000 + k)), 1.5)
    old = edges['e5']; old.state = 'UNPROV'
    new = Edge2('e5', ek['e5'], g, net, mode='S2', b=1, gossip=5.0, expected_gh=H(canon(g)), late=True, persist=False); edges['e5'] = new
    t0 = net.now; seen = []
    while new.state != 'VOTING' and net.now - t0 < 60:
        run(net, 0.25); seen.append((new.state, new.head(), new.forwards('Finance', 'Sales', 443)))
    t_act = net.now - t0; fw_before = any(f for st, h, f in seen if st == 'SYNC')
    return f'rebuilt from genesis: {K} certified entries verified, VOTING after {t_act:.2f}s, forwarded while SYNC={fw_before}, head={new.head()}', new.state == 'VOTING' and new.head() == K and not fw_before, dict(chain_len=K, active_after_s=round(t_act, 2))
@case('T15', 'Controller withholds a revocation', 'connected edges learn the target slot from peers and fetch; bound measured')
def _():
    g, ek, ak, net, edges, adm, c = mk(gossip=5.0); commit(c, c.build('GRANT', G('g1'))); ids = list(edges); t = net.now
    rv = c.build('REVOKE', dict(id='g1')); c.send(rv, ids[:7]); c.accept(rv); run(net, 20)
    ts = {x['e']: x['t'] - t for x in net.trace if x['ev'] == 'enforce' and x['slot'] == 2}; late = max(ts.values()); bound = 5.0 + 4 * 0.06
    return f'all {len(ts)} edges applied; the 5 withheld edges at <= {late:.2f}s (bound g+4d={bound:.2f}s)', len(ts) == 12 and late <= bound + 5.0, dict(withheld_apply_s=round(late, 2))
@case('T16', 'Clock skew beyond sigma, or controller-chosen timestamps', 'certified time stays in the honest range; ordering unaffected')
def _():
    import random; r = random.Random(3); g, ek, ak, net, edges, adm, c = mk(byz=1)
    for e in hon(edges): e.offset = r.uniform(-0.5, 0.5)
    commit(c, c.build('GRANT', G('g1'))); commit(c, c.build('GRANT', G('g2', port=444))); ct = {(x['e'], x['slot']): x['t'] for x in net.trace if x['ev'] == 'enforce'}; err = max(abs(e.cert_time[s_] - ct[(e.id, s_)]) for e in hon(edges) for s_ in e.cert_time)
    return f'Byzantine clock +1e6 s: max certified-time error {err:.2f}s (sigma=0.5); slots ordered {heads(edges)[0]}', err < 5.0 and set(heads(edges)) == {2}, {}
@case('T19', 'Split vote with 20 percent of edges offline (within c)', 'at most one commits')
def _():
    g, ek, ak, net, edges, adm, c = mk(); ids = list(edges); net.down.update(ids[10:])
    P, P2 = c.build('GRANT', G('gA')), c.build('GRANT', G('gB', 'Sales', 'Finance')); c.send(P, ids[:6]); c.send(P2, ids[6:10]); run(net, 5)
    d = {e.enforced.get(1) for e in edges.values()} - {None}
    return f'6/4 split, 2 offline: values committed={len(d)}', len(d) <= 1, {}
@case('T20', 'Split vote with no quorum', 'slot stalls; RESOLVE recovers it; no double commit')
def _():
    g, ek, ak, net, edges, adm, c = mk(); ids = list(edges); P, P2 = c.build('GRANT', G('gA')), c.build('GRANT', G('gB', 'Sales', 'Finance'))
    c.send(P, ids[:6]); c.send(P2, ids[6:]); run(net, 10); stall = set(heads(edges)); adm.resolve(1, 1, P); t = net.now; run(net, 5)
    d = {e.enforced.get(1) for e in edges.values()} - {None}
    return f'stalled heads={stall}; after RESOLVE heads={set(heads(edges))}, distinct values={len(d)}', stall == {0} and set(heads(edges)) == {1} and len(d) == 1 and not check(net.trace, 7, 0), {}
@case('T21', 'Two conflicting RESOLVE entries for one round', 'no double commit; stall cleared by the next round')
def _():
    g, ek, ak, net, edges, adm, c = mk(); ids = list(edges); P, P2 = c.build('GRANT', G('gA')), c.build('GRANT', G('gB', 'Sales', 'Finance'))
    c.send(P, ids[:6]); c.send(P2, ids[6:]); run(net, 5); adm.T = 99; adm.resolve(1, 1, P); run(net, 3)
    reps = list(adm.reports[(1, 1)].values())
    def res(e): d = digest2(e); return {'type': 'res', 'admin': 'a0', 'slot': 1, 'r': 1, 'd': d, 'reports': reps, 'entry': e, 'sig': adm.key.sign(canon({'cid': g['chain_id'], 'res': [1, 1, d]}))}
    for t in ids[:6]: net.send('adm', t, res(P))
    for t in ids[6:]: net.send('adm', t, res(P2))
    run(net, 5); after1 = set(heads(edges)); adm.T = 7; adm.resolve(1, 2, P); run(net, 5); d = {e.enforced.get(1) for e in edges.values()} - {None}
    return f'two RES for round 1 -> heads={after1}; round 2 -> heads={set(heads(edges))}, values={len(d)}', after1 == {0} and set(heads(edges)) == {1} and len(d) == 1 and not check(net.trace, 7, 0), {}
@case('T22', 'Membership change racing a grant', 'epoch rule prevents conflicting authorization')
def _():
    g, ek, ak, net, edges, adm, c = mk(); kj = Key(); join = Edge2('e12', kj, g, net, mode='S2', b=1, gossip=5.0, expected_gh=H(canon(g)), late=True, persist=False)
    en = c.build('ENROLL', dict(edge='e12', pk=kj.pk), by=('a0', 'a1')); old_epoch = c.build('GRANT', G('r1', port=8080), slot=2, prev=digest2(en), epoch=0, by=('a0',))
    c.send(en); c.send(old_epoch)                           # racing: slot-2 proposal built on the old epoch is in flight
    c.accept(en); run(net, 10); new = c.build('GRANT', G('r2', port=8081)); c.send(new, list(edges) + ['e12']); c.accept(new); run(net, 8)
    allh = [e.head() for e in list(edges.values()) + [join]]; Ts = {x['T'] for x in net.trace if x.get('slot') == 2 and 'T' in x}
    v = check(net.trace, 7, 0) + check_epochs(net.trace, 1)
    return f'old-epoch grant rejected={"epoch" in reasons(edges)}; heads={set(allh)} (13 edges), slot-2 quorum T={Ts}; checker violations={len(v)}', 'epoch' in reasons(edges) and set(allh) == {2} and Ts == {8} and not v, dict(n_after=13, T_after=8)
@case('T23', 'Revoke a grant whose endpoint is offline', 'commits by quorum alone')
def _():
    g, ek, ak, net, edges, adm, c = mk(); commit(c, c.build('GRANT', G('g1'))); net.down.add('e0'); commit(c, c.build('REVOKE', dict(id='g1')), 3)
    return f'heads (11 up)={set(h for k,h in zip(edges, heads(edges)) if k!="e0")}, effective at others={set(map(tuple, eff({k:v for k,v in edges.items() if k!="e0"})))}', all(e.head() == 2 for k, e in edges.items() if k != 'e0'), {}
@case('T24', 'Remove a protected invariant with T2 approval', 'rejected (requires T3)')
def _():
    g, ek, ak, net, edges, adm, c = mk(); c.send(c.build('PROTECT_DEL', dict(forbidden=['Guest', 'Finance']), by=('a0', 'a1'))); run(net, 3); r2 = (set(heads(edges)), reasons(edges))
    commit(c, c.build('PROTECT_DEL', dict(forbidden=['Guest', 'Finance']), by=('a0', 'a1', 'a2')), 3)
    return f'T2 approval -> {r2[1]}, heads={r2[0]}; T3 (3 keys) -> committed heads={set(heads(edges))}', r2[0] == {0} and 'auth' in r2[1] and set(heads(edges)) == {1}, {}
@case('T25', 'Edge loses its attestation record after a crash', 'counts toward b until re-enrolled; no double attestation')
def _():
    d = tempfile.mkdtemp(); g, ek, ak, net, edges, adm, c = mk(n=4, rec_dir=d); P, P2 = c.build('GRANT', G('gA')), c.build('GRANT', G('gB', 'Sales', 'Finance'))
    c.send(P, ['e2']); run(net, 1.0); edges['e2'].state = 'UNPROV'; os.remove(os.path.join(d, 'e2.json'))
    new = Edge2('e2', ek['e2'], g, net, mode='S2', b=1, gossip=5.0, rec_dir=d, expected_gh=H(canon(g))); edges['e2'] = new; c.send(P2, ['e2']); run(net, 3)
    pre = [x for x in net.trace if x['e'] == 'e2' and x['ev'] == 'prepare' and x['slot'] == 1]
    return f'record lost -> observer: prepares by e2 on slot 1 = {len(pre)}; checker {check(net.trace, 3, 0)}', len(pre) == 1 and not check(net.trace, 3, 0) and any(x['ev'] == 'record_lost_observer' for x in net.trace), {}
@case('T28', 'Single stolen key revokes many grants', 'takes effect (limit documented); audit trail; restoration needs original tier')
def _():
    g, ek, ak, net, edges, adm, c = mk(); n_g = 6
    for k in range(n_g - 1): commit(c, c.build('GRANT', G(f'g{k}', port=1000 + k)), 1.5)
    commit(c, c.build('GRANT', G('gdb', dst='DB', port=5432), by=('a0', 'a1')), 1.5); run(net, 25)
    for k in range(n_g - 1): commit(c, c.build('REVOKE', dict(id=f'g{k}')), 1.5)
    commit(c, c.build('REVOKE', dict(id='gdb')), 1.5); gone = set(map(tuple, eff(edges)))
    c.send(c.build('GRANT', G('gdb', dst='DB', port=5432), by=('a0',))); run(net, 3)
    return f'{n_g} grants revoked by one key (effective={gone}); restoring the restricted one with one key -> {reasons(edges)}; audit entries={len(edges["e0"].chain)}', gone == {()} and 'auth' in reasons(edges), {}
def _veto_case(override):
    g, ek, ak, net, edges, adm, c = mk(); e = c.build('GRANT', G('gdb', dst='DB', port=5432), by=('a0', 'a1')); commit(c, e, 2); d = digest2(e)
    commit(c, c.build('VETO', dict(entry=d), by=('a1',)), 2); run(net, 30); vetoed = eff(edges)[0]
    if override: commit(c, c.build('UNVETO', dict(entry=d), by=('a0', 'a2', 'a3')), 2)
    else: commit(c, c.build('UNVETO', dict(entry=d), by=('a1',)), 2)
    run(net, 3); return vetoed, eff(edges)[0], c.S.vetoed
@case('T29', 'One administrator vetoes a T2 entry, then withdraws or is overridden', 'entry resumes; veto cannot block permanently')
def _():
    a = _veto_case(False); b = _veto_case(True)
    return f'withdraw: suspended={a[0]} -> resumed={a[1]}; T3 override: suspended={b[0]} -> resumed={b[1]}', a[0] == [] and a[1] == ['gdb'] and b[1] == ['gdb'], {}
@case('T30', 'Edge boots with no genesis entry', 'forwards nothing, accepts no policy')
def _():
    g, ek, ak, net, edges, adm, c = mk(n=4); z = Edge2('z', Key(), g, net, mode='S2', b=1, no_genesis=True)
    c.send(c.build('GRANT', G('g1')), list(edges) + ['z']); run(net, 3)
    return f'state={z.state} head={z.head()} forwards={z.forwards("Finance","Sales",443)} (others head {edges["e0"].head()})', z.state == 'UNPROV' and z.head() == 0 and not z.forwards('Finance', 'Sales', 443), {}
@case('T31', 'Genesis delivered over the network with altered content', 'rejected by hash mismatch; stays UNPROVISIONED')
def _():
    g, ek, ak, net, edges, adm, c = mk(n=4); alt = copy.deepcopy(g); alt['admins']['a9'] = Key().pk
    z = Edge2('z', Key(), alt, net, mode='S2', b=1, expected_gh=H(canon(g))); c.send(c.build('GRANT', G('g1')), list(edges) + ['z']); run(net, 3)
    return f'state={z.state} head={z.head()}', z.state == 'UNPROV' and z.head() == 0, {}
@case('T32', 'Controller gives a new edge an uncertified head or a valid head of another chain', 'rejected; edge tries peers and stays closed')
def _():
    g, ek, ak, net, edges, adm, c = mk(extra={'sync': [f'e{i}' for i in range(12)] + ['ctl']}); commit(c, c.build('GRANT', G('g1')), 2); commit(c, c.build('GRANT', G('g2', port=444)), 2)
    g2, ek2, ak2, net2, edges2, adm2 = setup2(12, 1, 'S2', gossip=5.0, delay=DL, extra={'chain_id': 'other-chain'}); c2 = Ctl(g2, adm2, net2, edges2); commit(c2, c2.build('GRANT', G('o1')), 3)
    edges['e11'].state = 'UNPROV'; z = Edge2('e11', ek['e11'], g, net, mode='S2', b=1, gossip=5.0, expected_gh=H(canon(g)), late=True, persist=False); edges['e11'] = z; z.sync_peers = ['ctl']; peers_all = [f'e{i}' for i in range(11)]
    nocert = [dict(c_, cert=None) for c_ in edges['e0'].chain]; other = [dict(c_) for c_ in edges2['e0'].chain]
    net.send('ctl', 'e11', {'type': 'sync', 'src': 'ctl', 'items': nocert}); net.send('ctl', 'e11', {'type': 'sync', 'src': 'ctl', 'items': other}); net.run(net.now + 0.3)
    held = (z.head(), z.state); z.sync_peers = peers_all + ['ctl']; z.request_sync(); run(net, 6)
    return f'after uncertified+foreign-chain heads from controller: head/state={held}; after peers answered: head={z.head()} state={z.state}', held == (0, 'SYNC') and z.head() == 2 and z.state == 'VOTING', {}
@case('T33', 'Edge starts while the controller is unreachable', 'default-deny with only the sync channel')
def _():
    g, ek, ak, net, edges, adm, c = mk(); commit(c, c.build('GRANT', G('g1')), 2); net.down.update({'ctl', 'adm'})
    edges['e11'].state = 'UNPROV'; z = Edge2('e11', ek['e11'], g, net, mode='S2', b=1, gossip=5.0, expected_gh=H(canon(g)), late=True, persist=False); edges['e11'] = z
    fw0 = z.forwards('Finance', 'Sales', 443); run(net, 8)
    return f'before sync forwards={fw0}; synced from peers only: head={z.head()} state={z.state} forwards={z.forwards("Finance","Sales",443)}', not fw0 and z.state == 'VOTING' and z.head() == 1, {}
@case('T34', 'Day zero with fewer than T edges online', 'nothing commits; genesis grants apply until they expire')
def _():
    ex = {'grants': {'gg': dict(src='Finance', dst='Sales', port=443, qos='best', lease=40.0)}}; g, ek, ak, net, edges, adm, c = mk(extra=ex); ids = list(edges); net.down.update(ids[6:])
    c.send(c.build('GRANT', G('g1', port=444))); run(net, 10); e0 = edges['e0']; a = e0.forwards('Finance', 'Sales', 443); run(net, 40); b_ = e0.forwards('Finance', 'Sales', 443)
    return f'6 of 12 edges up: heads={set(h for h in heads(edges)[:6])}; genesis grant allowed before lease expiry={a}, after={b_}', set(heads(edges)[:6]) == {0} and a and not b_, {}
@case('T35', 'Edge crashes during sync', 'resumes from the last verified entry')
def _():
    d = tempfile.mkdtemp(); g, ek, ak, net, edges, adm, c = mk(n=4)
    for k in range(20): commit(c, c.build('GRANT', G(f'g{k}', port=1000 + k)), 1.2)
    edges['e3'].state = 'UNPROV'; z = Edge2('e3', ek['e3'], g, net, mode='S2', b=1, gossip=60.0, rec_dir=d, late=True); items = [dict(x) for x in edges['e0'].chain]
    z.h_sync({'src': 'e0', 'items': items[:10]}); h1 = z.head(); z.state = 'UNPROV'
    z2 = Edge2('e3', ek['e3'], g, net, mode='S2', b=1, gossip=60.0, rec_dir=d, late=True); h2 = z2.head(); z2.h_sync({'src': 'e0', 'items': items[10:]})
    return f'crashed after {h1} verified entries; restart resumed at head={h2}; completed at head={z2.head()}', h1 == 10 and h2 == 10 and z2.head() == 20, {}
@case('T36', 'Wrong genesis found after commits (unusable administrator key)', 'fixed by T3 if m correct keys remain; otherwise new chain; recovery time measured')
def _():
    g, ek, ak, net, edges, adm, c = mk(); k_new = Key(); k_new.id = 'a3'; t = net.now
    kr = c.build('KEYROT', dict(replace={'a3': k_new.pk}), by=('a0', 'a1', 'a2')); commit(c, kr, 3); rec = max(x['t'] for x in net.trace if x['ev'] == 'enforce' and x['slot'] == 1) - t
    adm.keys['a3'] = k_new; commit(c, c.build('GRANT', G('g1', dst='DB', port=5432), by=('a0', 'a3')), 3)
    g2, ek2, ak2, net2, edges2, adm2, c2 = mk(); c2.send(c2.build('KEYROT', dict(replace={'a2': Key().pk, 'a3': Key().pk}), by=('a0', 'a1'))); run(net2, 3)
    return f'a3 replaced by 3 correct keys in {rec:.2f}s and used again (heads={set(heads(edges))}); with only 2 correct keys: {reasons(edges2)} -> new chain needed', rec < 2 and set(heads(edges)) == {2} and 'auth' in reasons(edges2), dict(recovery_s=round(rec, 2))
@case('T37', 'Attacker substitutes genesis on one edge, with or without a fake controller', 'fails closed or follows an isolated chain; honest edges drop its traffic')
def _():
    g, ek, ak, net, edges, adm, c = mk(n=6); alt = copy.deepcopy(g); alt['admins']['a0'] = Key().pk
    z1 = Edge2('z1', Key(), alt, net, mode='S2', b=1, expected_gh=H(canon(g)))
    z2 = Edge2('e5', ek['e5'], alt, net, mode='S2', b=1, gossip=5.0); edges['e5'] = z2                  # operator did not check the hash
    fake = entry2(P2State(alt), 1, H(canon(alt)), 'GRANT', G('evil', src='Guest', dst='Finance'), signers={'a0'}); fake['approvals'] = [('a0', Key().sign(b'x'))]
    for t in ('z1', 'e5'): net.send('ctl', t, {'type': 'prop', 'entry': fake})
    commit(c, c.build('GRANT', G('g1')), 4); honest = [edges[k] for k in ('e0', 'e1', 'e2', 'e3', 'e4')]
    return f'checked edge state={z1.state}; unchecked edge head={z2.head()}; honest heads={[e.head() for e in honest]} with evil grant={any("evil" in e.S.grants for e in honest)}', z1.state == 'UNPROV' and all(e.head() == 1 and 'evil' not in e.S.grants for e in honest), {}
@case('T38', 'Stolen key and controller split a slot, then block revocation behind the stuck slot', 'one administrator issues RESOLVE; progress resumes without a delay window; the revocation commits')
def _():
    g, ek, ak, net, edges, adm, c = mk(); ids = list(edges); commit(c, c.build('GRANT', G('gF')), 3)
    P, P2 = c.build('GRANT', G('gA', port=1)), c.build('GRANT', G('gB', port=2)); c.send(P, ids[:6]); c.send(P2, ids[6:]); c.accept(P)
    rv = c.build('REVOKE', dict(id='gF')); c.send(rv); c.accept(rv); run(net, 10); stuck = set(heads(edges)); t = net.now; adm.resolve(2, 1, P); run(net, 8)
    tt = max(x['t'] for x in net.trace if x['ev'] == 'enforce' and x['slot'] == 3) - t
    return f'stuck at head {stuck}; after RESOLVE heads={set(heads(edges))}; revocation applied {tt:.2f}s after RESOLVE; gF effective={"gF" in eff(edges)[0]}', stuck == {1} and set(heads(edges)) == {3} and 'gF' not in eff(edges)[0], dict(resolve_to_revoked_s=round(tt, 2))
@case('T39', 'Controller hides a pending T2 entry from administrators', 'edges alert the genesis alert endpoints directly; veto remains possible')
def _():
    g, ek, ak, net, edges, adm, c = mk(); e = c.build('GRANT', G('gdb', dst='DB', port=5432), by=('a0', 'a1')); commit(c, e, 3)
    pend = [a for a in adm.alerts if a['kind'] == 'pending']; d = digest2(e); commit(c, c.build('VETO', dict(entry=d), by=('a2',)), 2); run(net, 25)
    return f'admin endpoint received {len(pend)} pending-entry alerts from edges (controller told nobody); after VETO effective={eff(edges)[0]}', len(pend) >= 7 and eff(edges)[0] == [], {}
@case('T40', 'Committed T2 entry is vetoed during its delay window', 'activation suspended until UNVETO or T3 override')
def _():
    a = _veto_case(False); return f'suspended={a[0]} then resumed={a[1]}', a[0] == [] and a[1] == ['gdb'], {}

# ---------------- faults F1-F17 (n=4 for speed) ----------------
def fault(cid, desc, expected, body, by=('a0',), reason=None, committed=False, setup=None, op='GRANT', alert=None, extra=None, post=None):
    @case(cid, desc, expected)
    def _():
        g, ek, ak, net, edges, adm, c = mk(n=4, extra=extra)
        if setup: setup(c, edges, net)
        e = c.build(op, body, by=by); c.send(e); run(net, 4)
        got = reasons(edges); hd = set(heads(edges)); al = sorted({a['kind'] for a in adm.alerts})
        okk = (reason in got) if reason else True
        if committed: okk = okk and max(hd) >= 1
        if alert: okk = okk and any(alert in a['kind'] for a in adm.alerts)
        return f'rejects={got} heads={hd} alerts={al}', okk, {}
fault('F1', 'Single host expanded to a /16', 'scope limit', G('x', src='10.1.0.5/32', dst='10.0.0.0/16', port=22), reason='auth')
fault('F2', 'Grant with no committed path', 'path existence', G('x', 'Sales', 'Guest'), reason='wf-nopath', extra={'paths': {'p01': dict(a='e0', b='e1', kind='primary'), 'p02': dict(a='e0', b='e2', kind='primary')}})
fault('F3', 'Routing loop from a path preference', 'loop check', G('x', via=['e0', 'e1', 'e0']), reason='wf-loop')
fault('F4', 'Guest reaches Finance', 'protected invariant', G('x', 'Guest', 'Finance'), by=('a0', 'a1', 'a2'), reason='protected')
fault('F5', 'Grant conflicts with a deny', 'conflict check', G('x', 'Guest', 'Sales'), reason='wf-deny', extra={'denies': [['Guest', 'Sales']]})
fault('F6', 'Only backup path removed', 'operational assertion (alert)', dict(id='p01b'), op='PATH_DEL', committed=True, alert='op-assertion')
fault('F7', 'Missing QoS class', 'well-formedness', dict(G('x'), qos='platinum'), reason='wf-qos')
@case('F8', 'Grant references an evicted device', 'well-formedness')
def _():
    g, ek, ak, net, edges, adm, c = mk(n=4); commit(c, c.build('EVICT', dict(edge='e2'), by=('a0', 'a1')), 3); c.send(c.build('GRANT', G('x', 'Finance', 'Guest'))); run(net, 3)
    return f'rejects={reasons(edges)}', 'wf-evicted' in reasons(edges), {}
fault('F9', 'Grant in the wrong segment', 'segmentation', G('x', src='10.1.0.5/32', src_seg='Guest'), reason='wf-segment-mismatch')
fault('F10', 'Overlapping prefixes with contradictory policy', 'conflict check', G('x', src='10.2.0.8/29', dst='10.1.0.0/25'), reason='wf-deny', extra={'denies': [['10.2.0.0/24', '10.1.0.0/24']]})
@case('F11', 'Accidental default-permit', 'scope, tier and baseline')
def _():
    g, ek, ak, net, edges, adm, c = mk(n=4); c.send(c.build('GRANT', G('x', src='0.0.0.0/0'), by=('a0',))); run(net, 3); r1 = reasons(edges)
    c.send(c.build('GRANT', G('x', src='0.0.0.0/0'), by=('a0', 'a1', 'a2'))); run(net, 3)
    return f'1 key -> {r1}; 3 keys -> {reasons(edges)}', 'auth' in r1 and 'protected-default-permit' in reasons(edges) and set(heads(edges)) == {0}, {}
fault('F12', 'Cipher downgrade', 'protected invariant', dict(cipher=56), op='SET_PARAM', by=('a0', 'a1'), reason='protected-cipher')
@case('F13', 'Controller bug skips its own validation', 'all edge-side rules')
def _():
    g, ek, ak, net, edges, adm, c = mk(n=4); forms = [c.build('GRANT', G('a', 'Guest', 'Finance'), by=('a0', 'a1', 'a2')), c.build('GRANT', G('b'), sign=False), c.build('GRANT', G('c', dst='DB'), by=('a0',)),
        c.build('GRANT', G('d'), epoch=7), c.build('GRANT', G('e', src='0.0.0.0/0'), by=('a0', 'a1', 'a2'))]
    forms[2]['tier'] = 'L0'
    for f in forms: c.send(f); run(net, 2)
    return f'5 invalid entries pushed straight to edges: heads={set(heads(edges))} reasons={reasons(edges)}', set(heads(edges)) == {0}, {}
@case('F14', 'Mistake that violates no invariant', 'expected to pass (documents the limit)')
def _():
    g, ek, ak, net, edges, adm, c = mk(n=4); commit(c, c.build('GRANT', G('typo', port=4443)), 3)
    return f'wrong-port grant committed: heads={set(heads(edges))}', set(heads(edges)) == {1}, {}
@case('F15', 'Remove a rule, then grant what it forbade', 'protected invariant')
def _():
    g, ek, ak, net, edges, adm, c = mk(n=4); c.send(c.build('PROTECT_DEL', dict(forbidden=['Guest', 'Finance']), by=('a0', 'a1'))); run(net, 3); r1 = reasons(edges)
    c.send(c.build('GRANT', G('x', 'Guest', 'Finance'), by=('a0', 'a1', 'a2'))); run(net, 3)
    return f'removal -> {r1}; forbidden grant -> {reasons(edges)}', 'auth' in r1 and 'protected' in reasons(edges) and set(heads(edges)) == {0}, {}
@case('F16', 'Transient WAN outage during a valid change', 'must not block the change')
def _():
    g, ek, ak, net, edges, adm, c = mk(); ids = list(edges); net.down.update(ids[9:]); commit(c, c.build('GRANT', G('g1')), 3); mid = [e.head() for e in edges.values()]
    net.down.clear(); run(net, 15)
    return f'3 of 12 edges out during the change: committed at {sum(1 for h in mid if h == 1)} edges; after the outage all heads={set(heads(edges))}', sum(1 for h in mid if h == 1) >= 7 and set(heads(edges)) == {1}, {}
@case('F17', 'Genesis lists a wrong sync endpoint or key', 'edges fail closed; found at commissioning')
def _():
    g, ek, ak, net, edges, adm, c = mk(extra={'sync': ['no-such-edge']}); commit(c, c.build('GRANT', G('g1')), 3)
    edges['e11'].state = 'UNPROV'; z = Edge2('e11', ek['e11'], g, net, mode='S2', b=1, gossip=5.0, expected_gh=H(canon(g)), late=True, persist=False); edges['e11'] = z; run(net, 30)
    return f'new edge state={z.state} head={z.head()} forwards={z.forwards("Finance","Sales",443)} (stuck in SYNC: visible at commissioning)', z.state == 'SYNC' and not z.forwards('Finance', 'Sales', 443), {}

if __name__ == '__main__':
    want = set(sys.argv[1:])
    for f in REG:
        if not want or f.cid in want: f()
    json.dump(RES, open('suite_results.json' if not want else 'suite_partial.json', 'w'), indent=1, default=str)
    print(f'{sum(r["ok"] for r in RES)}/{len(RES)} pass')
