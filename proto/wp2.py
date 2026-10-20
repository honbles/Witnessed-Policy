"""Witnessed Policy prototype v2: full policy model (tiers, scope, path/loop/QoS/conflict checks, protected invariants,
delay + veto, alerts), epochs (ENROLL/EVICT), bootstrap state machine, persistence, S0/S1/S2 modes.  Extends wpcore."""
import copy, ipaddress, json, os, statistics
from collections import defaultdict
from wpcore import *
import wpcore

THR2 = {'L0': 1, 'L1': 1, 'L2': 2, 'L3': 3}
def N(x, S=None):
    if S is not None and x in S.seg: return ipaddress.ip_network(S.seg[x]['cidr'])
    return ipaddress.ip_network(x, strict=False)
def ov(a, b): return a.version == b.version and a.overlaps(b)

class P2State:
    def __init__(s, g):
        s.seg = copy.deepcopy(g['segments']); s.members = dict(g['members']); s.admins = dict(g['admins']); s.qos = set(g.get('qos', ['best', 'gold']))
        s.paths = copy.deepcopy(g.get('paths', {})); s.grants = copy.deepcopy(g.get('grants', {})); s.denies = set(map(tuple, g.get('denies', [])))
        s.forbidden = set(map(tuple, g.get('forbidden', []))); s.min_cipher = g.get('min_cipher', 128); s.cipher = g.get('cipher', 256)
        s.epoch = 0; s.act = {}; s.vetoed = {}; s.delay = g.get('delay', {'L2': 30.0, 'L3': 60.0})
    def copy(s): return copy.deepcopy(s)
def seg_of(S, net):
    return [k for k, v in S.seg.items() if ov(net, ipaddress.ip_network(v['cidr']))]
def site_of(S, net):
    ss = seg_of(S, net); return {S.seg[k]['site'] for k in ss}
def tier2(S, op, b, signers=()):
    if op in ('REVOKE', 'DENY', 'VETO'): return 'L0'
    if op == 'GRANT':
        try: s_, d_ = N(b['src'], S), N(b['dst'], S)
        except Exception: return 'L1'
        if s_.prefixlen == 0 or d_.prefixlen == 0: return 'L3'
        restricted = any(S.seg[k].get('cls') == 'restricted' for k in seg_of(S, d_))
        return 'L2' if restricted or s_.num_addresses > 256 or d_.num_addresses > 256 else 'L1'
    if op == 'CLASSIFY': return 'L0' if b['cls'] == 'restricted' else 'L2'
    if op in ('ENROLL', 'EVICT', 'SET_PARAM', 'PROTECT_ADD'): return 'L2'
    if op in ('PROTECT_DEL', 'KEYROT'): return 'L3'
    if op == 'UNVETO': return 'L0' if S.vetoed.get(b['entry']) in signers else 'L3'
    return 'L1'
def core2(e): return {k: e[k] for k in ('slot', 'prev', 'epoch', 'op', 'body', 'tier')}
def digest2(e): return H(canon(core2(e)))
def appr_bytes(cid, e): return canon({'cid': cid, 'core': core2(e)})
def check2(S, e, cid, trust=False):
    """Auth /\\ WF /\\ Prot.  Returns reason ('ok' or a failure label) and alerts."""
    op, b = e['op'], e['body']; alerts = []
    if trust: return 'ok', alerts
    if e['epoch'] != S.epoch: return 'epoch', alerts
    ok = {a for a, sig in e['approvals'] if a in S.admins and verify(S.admins[a], appr_bytes(cid, e), sig)}
    if e['tier'] != tier2(S, op, b, ok): return 'tier', alerts
    if len(ok) < THR2[e['tier']]: return 'auth', alerts
    if op == 'GRANT':
        try: s_, d_ = N(b['src'], S), N(b['dst'], S)
        except Exception: return 'wf', alerts
        if b.get('qos', 'best') not in S.qos: return 'wf-qos', alerts
        ss, ds = site_of(S, s_), site_of(S, d_)
        if not ss or not ds: return 'wf-segment', alerts
        if any(x not in S.members for x in ss | ds): return 'wf-evicted', alerts
        if b.get('src_seg') and b['src_seg'] not in seg_of(S, s_): return 'wf-segment-mismatch', alerts
        if ss != ds and not any({p['a'], p['b']} == {x, y} for p in S.paths.values() for x in ss for y in ds): return 'wf-nopath', alerts
        via = b.get('via')
        if via:
            if len(set(via)) != len(via): return 'wf-loop', alerts
        if any(ov(s_, N(a_, S)) and ov(d_, N(b_, S)) for a_, b_ in S.denies): return 'wf-deny', alerts
        if s_.prefixlen == 0 or d_.prefixlen == 0: return 'protected-default-permit', alerts
        if any(A in seg_of(S, s_) and B in seg_of(S, d_) for A, B in S.forbidden): return 'protected', alerts
        if b['id'] in S.grants: return 'wf-dup', alerts
    elif op == 'REVOKE':
        if b['id'] not in S.grants: return 'wf', alerts
    elif op == 'SET_PARAM':
        if b.get('cipher', S.cipher) < S.min_cipher: return 'protected-cipher', alerts
    elif op == 'ENROLL':
        if b['edge'] in S.members: return 'wf', alerts
    elif op == 'EVICT':
        if b['edge'] not in S.members: return 'wf', alerts
    elif op == 'PATH_DEL':
        if b['id'] not in S.paths: return 'wf', alerts
        p = S.paths[b['id']]
        if p['kind'] == 'backup' and not any(q['kind'] == 'backup' and {q['a'], q['b']} == {p['a'], p['b']} and k != b['id'] for k, q in S.paths.items()): alerts.append('op-assertion:last-backup-path')
    elif op == 'VETO':
        if b['entry'] not in S.act or b['entry'] in S.vetoed: return 'wf', alerts
    elif op == 'UNVETO':
        if b['entry'] not in S.vetoed: return 'wf', alerts
    elif op == 'PROTECT_DEL':
        if tuple(b['forbidden']) not in S.forbidden: return 'wf', alerts
    elif op == 'PROTECT_ADD':
        A_, B_ = b['forbidden']
        for gr in S.grants.values():
            try: sn, dn = N(gr['src'], S), N(gr['dst'], S)
            except Exception: continue
            if A_ in seg_of(S, sn) and B_ in seg_of(S, dn): return 'protected-violated', alerts
    return 'ok', alerts
def apply2(S, e, d):
    N_ = S.copy(); op, b = e['op'], e['body']
    if op == 'GRANT': N_.grants[b['id']] = dict(b, _d=d)
    elif op == 'REVOKE': N_.grants.pop(b['id'], None)
    elif op == 'DENY': N_.denies.add((b['src'], b['dst']))
    elif op == 'CLASSIFY': N_.seg[b['seg']]['cls'] = b['cls']
    elif op == 'ENROLL': N_.members[b['edge']] = b['pk']; N_.epoch += 1
    elif op == 'EVICT': N_.members.pop(b['edge'], None); N_.epoch += 1
    elif op == 'SET_PARAM': N_.cipher = b.get('cipher', N_.cipher)
    elif op == 'PROTECT_ADD': N_.forbidden.add(tuple(b['forbidden']))
    elif op == 'PROTECT_DEL': N_.forbidden.discard(tuple(b['forbidden']))
    elif op == 'KEYROT': N_.admins.update(b['replace'])
    elif op == 'PATH_ADD': N_.paths[b['id']] = dict(b)
    elif op == 'PATH_DEL': N_.paths.pop(b['id'], None)
    elif op == 'QOS_ADD': N_.qos.add(b['cls'])
    elif op == 'VETO': N_.vetoed[b['entry']] = (e['approvals'][0][0] if e['approvals'] else None)
    elif op == 'UNVETO': N_.vetoed.pop(b['entry'], None)
    if e['tier'] in ('L2', 'L3') and op not in ('VETO', 'UNVETO'): N_.act[d] = None
    return N_
def effective(S, cert_now):
    """grants that are enforceable at certified time cert_now (activation delay and vetoes applied)."""
    out = {}
    for gid, gr in S.grants.items():
        d = gr.get('_d')
        if d is not None and d in S.act:
            t = S.act[d]
            if t is None or cert_now < t or d in S.vetoed: continue
        out[gid] = gr
    return out

def entry2(S, slot, prev, op, body, adm=None, signers=()):
    e = dict(slot=slot, prev=prev, epoch=S.epoch, op=op, body=body, approvals=[]); e['tier'] = tier2(S, op, body, signers); return e

class Edge2(Edge):
    def __init__(s, eid, key, g, net, mode='S2', b=1, gossip=30.0, offset=0.0, rec_dir=None, observer=False, expected_gh=None, late=False, persist=True, no_genesis=False):
        s.id, s.key, s.g, s.net, s.mode, s.b = eid, key, g, net, mode, b
        s.cid = g.get('chain_id', '?'); s.gh = H(canon(g)); s.S = P2State(g) if not no_genesis else None; s.chain = []; s.prev = s.gh
        s.n = len(g['members']); s.T = quorum(s.n, b); s.offset = offset; s.gossip = gossip
        s.rec_dir = rec_dir; s.rec_path = os.path.join(rec_dir, eid + '.json') if rec_dir else None; s.chain_path = os.path.join(rec_dir, eid + '.chain.jsonl') if rec_dir and persist else None
        s.rec = dict(prep={}, com={}, promised={}); s.sent = {}; s.delta_w = 90.0; s.on_enforce = None; s.observer = observer; s.abstain_until = -1
        s.preps = defaultdict(dict); s.coms = defaultdict(dict); s.props = {}; s.certs = {}; s.res = defaultdict(set)
        s.heads = {}; s.enforced = {}; s.cert_time = {}; s.alerts = []; s.pending_future = []; s.fork_at = None; s.frozen = False; s.log_nft = None
        s.state = 'UNPROV' if (no_genesis or expected_gh not in (None, s.gh)) else 'ANCHORED'; s.late = late; s.rejects = []
        s.sync_peers = g.get('sync', list(g['members'])); s.alert_to = g.get('alert', ['adm'])
        sent_path = os.path.join(rec_dir, eid + '.sentinel') if rec_dir else None
        lost_rec = bool(sent_path and os.path.exists(sent_path) and not (s.rec_path and os.path.exists(s.rec_path)))
        if sent_path: open(sent_path, 'w').write('x')
        if s.chain_path and os.path.exists(s.chain_path): s.reload()
        if lost_rec and mode == 'S2': s.abstain_until = len(s.chain) + 1; s.net.log(e=s.id, ev='record_lost_observer', slot=len(s.chain))
        if s.state == 'ANCHORED': s.set_state('SYNC' if late else 'VOTING')
        net.nodes[eid] = s; net.at(net.now + net.rng.uniform(0, gossip), s.tick)
        if late: net.at(net.now + 0.05, s.request_sync)
    def set_state(s, st):
        if s.state != st: s.state = st; s.net.log(e=s.id, ev='state', to=st)
    def lt(s): return s.net.now + s.offset
    def alert(s, kind, **kw):
        s.alerts.append((kind, kw)); s.net.log(e=s.id, ev='alert', kind=kind, **kw)
        for a in s.alert_to: s.net.send(s.id, a, dict(type='alert', e=s.id, kind=kind, **kw))
    def reload(s):
        items = [json.loads(l) for l in open(s.chain_path) if l.strip()]
        for it in items:
            it['cert'] = it['cert']; e = it['entry']
            r, _ = check2(s.S, e, s.cid, trust=False)
            if r != 'ok' or e['slot'] != len(s.chain) + 1 or e['prev'] != s.prev: break
            s.install(e, it['cert'], digest2(e), it.get('r', 0), persist=False)
    # ---- install a verified entry
    def install(s, e, cert, d, r, persist=True):
        _, alerts = check2(s.S, e, s.cid); s.S = apply2(s.S, e, d)
        s.chain.append(dict(entry=e, cert=cert, d=d, r=r)); s.prev = d; s.enforced[e['slot']] = d
        ct = statistics.median(ts for ts, _ in cert.values()) if cert else s.lt()
        s.cert_time[e['slot']] = ct
        if d in s.S.act: s.S.act[d] = ct + s.S.delay[e['tier']]
        if persist and s.chain_path:
            with open(s.chain_path, 'a') as f: f.write(json.dumps(dict(entry=e, cert=cert, d=d, r=r)) + '\n')
        s.n = len(s.S.members); s.T = quorum(s.n, s.b)
        s.net.log(e=s.id, ev='enforce', slot=e['slot'], d=d[:8], ep=s.S.epoch)
        for a in alerts: s.alert(a, slot=e['slot'])
        if e['tier'] in ('L2', 'L3') and e['op'] not in ('VETO', 'UNVETO'): s.alert('pending', slot=e['slot'], d=d[:8], op=e['op'], active_at=round(s.S.act[d], 3))
        if s.on_enforce: s.on_enforce()
    def append(s, e, cert, d, r=0):
        if s.state not in ('VOTING', 'SYNC', 'VERIFIED') or s.S is None: return
        reason, _ = check2(s.S, e, s.cid, trust=(s.mode in ('S0', 'S3')))
        if reason != 'ok': return
        s.install(e, cert, d, r)
        pend, s.pending_future = s.pending_future, []
        for m in pend: s.on_msg(m)
        for k in [k for k in s.coms if k[0] == s.head() + 1]: s.try_finalize(k)
        if s.state == 'SYNC': s.maybe_verified()
    # ---- proposals
    def h_prop(s, m):
        if s.S is None or s.state == 'UNPROV' or s.frozen or s.mode == 'S3': return
        e = m['entry']; slot = e['slot']
        if slot > s.head() + 1: s.pending_future.append(m); return
        if slot != s.head() + 1 or e['prev'] != s.prev: s.rejects.append('replay'); s.net.log(e=s.id, ev='reject', slot=slot, why='replay'); return
        reason, alerts = check2(s.S, e, s.cid, trust=(s.mode == 'S0'))
        if reason != 'ok':
            s.rejects.append(reason); s.net.log(e=s.id, ev='reject', slot=slot, why=reason); s.alert('rejected', slot=slot, why=reason); return
        d = digest2(e); s.props[d] = e
        for kind in ('prep', 'com'):
            old = s.sent.get((kind, slot, 0))
            if old and old['d'] == d: s.bcast(old)
        if s.mode in ('S0', 'S1'): s.append(e, None, d); return
        s.prepare(slot, 0, d)
    def can_attest(s, slot): return s.state == 'VOTING' and not s.frozen and slot > s.abstain_until and s.id in s.S.members
    def _tag(s, ev):
        t = s.net.trace
        if t and t[-1].get('e') == s.id and t[-1].get('ev') == ev and 'ep' not in t[-1]: t[-1].update(ep=s.S.epoch, T=s.T, n=s.n)
    def prepare(s, slot, r, d):
        if s.S is None: return
        Edge.prepare(s, slot, r, d); s._tag('prepare')
    def commit(s, slot, r, d):
        Edge.commit(s, slot, r, d); s._tag('commit_att')
    def h_prep(s, m):
        if s.S is None or m['slot'] != s.head() + 1 and m['slot'] > s.head() + 1: pass
        if s.S is None: return
        Edge.h_prep(s, m)
    def try_finalize(s, k):
        slot, r, d = k
        if len(s.coms[k]) >= s.T and d in s.props and slot == s.head() + 1 and s.props[d]['prev'] == s.prev and not s.frozen:
            s.append(s.props[d], dict(list(s.coms[k].items())[:s.T]), d, r)
    def h_com(s, m):
        if s.S is None: return
        Edge.h_com(s, m)
    def h_res(s, m):
        if s.S is None: return
        Edge.h_res(s, m)
    # ---- sync / bootstrap
    def request_sync(s):
        for p in s.sync_peers + ['ctl']:
            if p != s.id: s.net.send(s.id, p, {'type': 'sync_req', 'e': s.id, 'from': s.head() + 1})
        if s.state == 'SYNC': s.net.at(s.net.now + 2.0, s.request_sync)
    def h_sync_req(s, m):
        if s.S is not None and s.state in ('VOTING', 'VERIFIED'): s.net.send(s.id, m['e'], {'type': 'sync', 'src': s.id, 'items': [dict(c) for c in s.chain[m['from'] - 1:]]})
    def h_sync(s, m):
        if s.S is None or s.state == 'UNPROV': return
        if m.get('src', 'ctl') not in s.sync_peers: s.net.log(e=s.id, ev='sync_rejected', why='not-pinned', src=m.get('src', 'ctl')); return
        for it in m['items']:
            e = it['entry']
            if e['slot'] != s.head() + 1 or e['prev'] != s.prev: continue
            if s.mode == 'S2':
                cert = it.get('cert')
                if not cert: continue
                good = {x for x, (ts, sg) in cert.items() if x in s.S.members and verify(s.S.members[x], att_bytes(s.cid, 'com', e['slot'], it['r'], digest2(e), ts), sg)}
                if len(good) < s.T: continue
            reason, _ = check2(s.S, e, s.cid)
            if reason != 'ok': continue
            s.install(e, it.get('cert'), digest2(e), it.get('r', 0))
        if s.state == 'SYNC': s.maybe_verified()
    def maybe_verified(s):
        vouched = [h[0] for h in s.heads.values()]
        tgt = max((x for x in vouched if sum(1 for y in vouched if y >= x) >= s.b + 1), default=0)
        if s.head() >= tgt and (tgt > 0 or not s.late) and s.id in s.S.members:
            s.set_state('VERIFIED'); s.set_state('VOTING')
    def h_head(s, m):
        if s.S is None or m['e'] not in s.S.members or not verify(s.S.members[m['e']], canon({'cid': s.cid, 'head': [m['h'], m['hash'], m['ts']]}), m['sig']): return
        s.heads[m['e']] = (m['h'], m['hash'], s.net.now)
        if m['h'] == s.head() and m['hash'] != s.prev and s.fork_at is None:
            s.fork_at = s.net.now; s.frozen = True; s.alerts.append(('fork', m['h'], round(s.net.now, 3))); s.net.log(e=s.id, ev='fork_alert', slot=m['h'])
        elif m['h'] > s.head() and not s.frozen and m['e'] in s.sync_peers: s.net.send(s.id, m['e'], {'type': 'sync_req', 'e': s.id, 'from': s.head() + 1})
        if s.state == 'SYNC': s.maybe_verified()
    def tick(s):
        if s.id in s.net.down or s.S is None or s.state == 'UNPROV': s.net.at(s.net.now + s.gossip, s.tick); return
        h = len(s.chain); ts = s.lt(); sig = s.key.sign(canon({'cid': s.cid, 'head': [h, s.prev, ts]}))
        s.bcast({'type': 'head', 'e': s.id, 'h': h, 'hash': s.prev, 'ts': ts, 'sig': sig}); s.net.at(s.net.now + s.gossip, s.tick)
    def peers(s): return list(s.S.members) if s.S else []
    def fresh(s, delta_w=None):
        if s.S is None: return False
        return Edge.fresh(s, delta_w)
    def effective_grants(s): return effective(s.S, s.lt())
    def forwards(s, src, dst, port, now=None):
        if s.S is None or s.state not in ('VERIFIED', 'VOTING'): return False
        now = s.lt() if now is None else now
        for gr in s.effective_grants().values():
            if gr['src'] == src and gr['dst'] == dst and gr['port'] == port and (s.fresh() or now < gr.get('lease', 1e18)): return True
        return False

class Admin2(Admin):
    def __init__(s, aid, key, g, net, edges_n, b, all_keys=None):
        super().__init__(aid, key, g, net, edges_n, b); s.alerts = []; s.keys = all_keys or {aid: key}
    def sign_entry(s, e, extra=(), by=None):
        ids = [by] if by else [s.id]
        sigs = [(i, s.keys[i].sign(appr_bytes(s.cid, e))) for i in ids]
        for k in extra: sigs.append((k.id if hasattr(k, 'id') else k, (k if not isinstance(k, str) else s.keys[k]).sign(appr_bytes(s.cid, e))))
        e['approvals'] = sigs; return e
    def on_msg(s, m):
        if m['type'] == 'alert': s.alerts.append(m); return
        super().on_msg(m)

def make_genesis2(n, n_admins=4, delay=None, extra=None):
    ekeys = {f'e{i}': Key() for i in range(n)}; akeys = {}
    for i in range(n_admins): k = Key(); k.id = f'a{i}'; akeys[k.id] = k
    g = dict(chain_id='wp2-demo', admins={a: k.pk for a, k in akeys.items()}, members={e: k.pk for e, k in ekeys.items()},
             segments={'Finance': dict(cidr='10.1.0.0/24', site='e0', cls='normal'), 'Sales': dict(cidr='10.2.0.0/24', site='e1', cls='normal'),
                       'Guest': dict(cidr='10.3.0.0/24', site='e2', cls='normal'), 'DB': dict(cidr='10.4.0.0/28', site='e1', cls='restricted')},
             paths={'p01': dict(a='e0', b='e1', kind='primary'), 'p02': dict(a='e0', b='e2', kind='primary'), 'p12': dict(a='e1', b='e2', kind='primary'), 'p01b': dict(a='e0', b='e1', kind='backup')},
             forbidden=[['Guest', 'Finance']], qos=['best', 'gold'], delay=delay or {'L2': 30.0, 'L3': 60.0}, alert=['adm'], sync=list(ekeys))
    if extra: g.update(extra)
    return g, ekeys, akeys

# make the shared protocol code (RES, reports, admin tool) use the v2 entry digest
wpcore.digest = digest2; wpcore.core = core2; wpcore.approval_bytes = appr_bytes

class ByzEdge2(Edge2):
    """attests to everything it sees, ignores lock-once, skewed timestamps."""
    byz = True; skew = 1e6
    def h_prop(s, m): s.seen(m['entry'])
    def h_prep(s, m): s.seen(m['entry'], m['r'])
    def seen(s, e, r=0):
        d = digest2(e); s.props[d] = e; k = (e['slot'], r, d)
        if k in s.rec['prep']: return
        s.rec['prep'][k] = 1
        for kind in ('prep', 'com'):
            ts = s.lt() + s.skew; sig = s.key.sign(att_bytes(s.cid, kind, e['slot'], r, d, ts))
            s.bcast({'type': kind, 'e': s.id, 'slot': e['slot'], 'r': r, 'd': d, 'ts': ts, 'sig': sig, 'entry': e})
    def h_resolve_req(s, m): pass
    def h_res(s, m): pass
    def h_com(s, m): pass
    def h_head(s, m): pass
    def tick(s): s.net.at(s.net.now + s.gossip, s.tick)


# ---------------- baseline S3: BFT-replicated controller cluster (PBFT-style) ----------------
class NetPair(Net):
    """controller replicas are co-located: 1 ms between them"""
    def send(s, a, b, m):
        if a != b and s.blocked(a, b): return
        s.msgs += 1; s.bytes += len(canon(m))
        d = 0.0 if a == b else (0.001 if (a[:1] == 'c' and b[:1] == 'c' and a != 'ctl' and b != 'ctl') else s.delta + s.rng.uniform(0, s.jitter))
        s.at(s.now + d, lambda: s.nodes[b].on_msg(m) if b in s.nodes and b not in s.down else None)
def edge_h_push(s, m):
    if s.mode != 'S3' or s.S is None: return
    c = m['c']; ck = s.g.get('ctrls', {}).get(c); d = m['d']; s.nverify = getattr(s, 'nverify', 0) + 1
    if ck is None or not verify(ck, canon({'cid': s.cid, 'push': d}), m['sig']): return
    if not hasattr(s, 'pushes'): s.pushes = defaultdict(set)
    s.pushes[d].add(c); s.props[d] = m['entry']; e = m['entry']
    if len(s.pushes[d]) >= s.g.get('fc', 1) + 1 and e['slot'] == s.head() + 1 and e['prev'] == s.prev and d not in s.enforced.values(): s.append(e, None, d)
Edge2.h_push = edge_h_push
class CtrlReplica:
    def __init__(s, cid, key, g, net, cids, f, edges, byz=False):
        s.id, s.key, s.g, s.net, s.cids, s.f, s.edges, s.byz = cid, key, g, net, cids, f, edges, byz
        s.S = P2State(g); s.prev = H(canon(g)); s.slot = 0; s.cid = g['chain_id']; s.pr = defaultdict(set); s.cm = defaultdict(set); s.ent = {}; s.sentcm = set(); s.done = set(); s.nverify = 0
        net.nodes[cid] = s
    def bc(s, m):
        for c in s.cids: s.net.send(s.id, c, m)
    def sg(s, kind, d): return s.key.sign(canon({'cid': s.cid, 'k': kind, 'd': d}))
    def vf(s, c, kind, d, sig): s.nverify += 1; return verify(s.g['ctrls'][c], canon({'cid': s.cid, 'k': kind, 'd': d}), sig)
    def on_msg(s, m):
        t = m['type']
        if t == 'req':
            e = m['entry']
            if s.byz:                                  # compromised replica pushes whatever it likes straight to the edges
                d = digest2(e)
                for x in s.edges: s.net.send(s.id, x, {'type': 'push', 'c': s.id, 'd': d, 'entry': e, 'sig': s.key.sign(canon({'cid': s.cid, 'push': d}))})
                return
            if s.id != s.cids[0]: s.net.send(s.id, s.cids[0], m); return
            if e['slot'] != s.slot + 1 or check2(s.S, e, s.cid)[0] != 'ok': return
            d = digest2(e); s.ent[d] = e; s.bc({'type': 'pp', 'c': s.id, 'd': d, 'entry': e, 'sig': s.sg('pp', d)})
        elif t == 'pp' and not s.byz:
            e = m['entry']; d = m['d']
            if m['c'] != s.cids[0] or not s.vf(m['c'], 'pp', d, m['sig']) or e['slot'] != s.slot + 1 or check2(s.S, e, s.cid)[0] != 'ok': return
            s.ent[d] = e; s.bc({'type': 'pr', 'c': s.id, 'd': d, 'sig': s.sg('pr', d)})
        elif t == 'pr' and not s.byz:
            if s.vf(m['c'], 'pr', m['d'], m['sig']): s.pr[m['d']].add(m['c'])
            if len(s.pr[m['d']]) >= 2 * s.f + 1 and m['d'] not in s.sentcm: s.sentcm.add(m['d']); s.bc({'type': 'cm', 'c': s.id, 'd': m['d'], 'sig': s.sg('cm', m['d'])})
        elif t == 'cm' and not s.byz:
            if s.vf(m['c'], 'cm', m['d'], m['sig']): s.cm[m['d']].add(m['c'])
            d = m['d']
            if len(s.cm[d]) >= 2 * s.f + 1 and d not in s.done and d in s.ent:
                s.done.add(d); e = s.ent[d]; s.S = apply2(s.S, e, d); s.prev = d; s.slot = e['slot']
                for x in s.edges: s.net.send(s.id, x, {'type': 'push', 'c': s.id, 'd': d, 'entry': e, 'sig': s.key.sign(canon({'cid': s.cid, 'push': d}))})
