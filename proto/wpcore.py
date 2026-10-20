"""Witnessed Policy prototype core: signed chain (S1) + two-phase quorum commit with round change (S2).
Real Ed25519 signatures, durable attestation records, deterministic discrete-event network emulator."""
import json, hashlib, heapq, os, time, statistics
from collections import defaultdict
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

STATS = dict(sign=0, verify=0, verify_uncached=0, t_sign=0.0, t_verify=0.0)
_VC = {}
def H(b): return hashlib.sha256(b).hexdigest()
def canon(o): return json.dumps(o, sort_keys=True, separators=(',', ':')).encode()
class Key:
    def __init__(s):
        s.sk = Ed25519PrivateKey.generate()
        s.pk = s.sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    def hex(s): return s.sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()
    @staticmethod
    def from_hex(h):
        k = Key.__new__(Key); k.sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(h))
        k.pk = k.sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(); return k
    def sign(s, msg):
        t = time.perf_counter(); r = s.sk.sign(msg).hex()
        STATS['sign'] += 1; STATS['t_sign'] += time.perf_counter() - t; return r
def verify(pk, msg, sig):
    STATS['verify'] += 1; k = (pk, msg, sig)
    if k in _VC: return _VC[k]
    t = time.perf_counter()
    try: Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk)).verify(bytes.fromhex(sig), msg); ok = True
    except Exception: ok = False
    STATS['verify_uncached'] += 1; STATS['t_verify'] += time.perf_counter() - t; _VC[k] = ok; return ok

# ---------------- policy state and validity ----------------
THR = {'L0': 1, 'L1': 1, 'L2': 2, 'L3': 3}
class State:
    def __init__(s, g):
        s.segments = set(g['segments']); s.protected = set(map(tuple, g['protected']))
        s.grants = {}; s.denies = set(); s.members = dict(g['members']); s.restricted = set(g.get('restricted', []))
        s.pending = {}; s.vetoed = set()
    def copy(s):
        n = State.__new__(State); n.segments = set(s.segments); n.protected = set(s.protected)
        n.grants = dict(s.grants); n.denies = set(s.denies); n.members = dict(s.members)
        n.restricted = set(s.restricted); n.pending = dict(s.pending); n.vetoed = set(s.vetoed); return n
def tier_of(S, op, body):
    if op in ('REVOKE', 'DENY', 'VETO'): return 'L0'
    if op == 'GRANT': return 'L2' if body['dst'] in S.restricted else 'L1'
    if op in ('CLASSIFY', 'ENROLL', 'EVICT'): return 'L2'
    return 'L3'
def core(e): return {k: e[k] for k in ('slot', 'prev', 'op', 'body', 'tier')}
def digest(e): return H(canon(core(e)))
def approval_bytes(cid, e): return canon({'cid': cid, 'core': core(e)})
def valid(S, e, g, cid):
    """Valid(S,e) = Auth /\\ WF /\\ Prot.  Returns (S', reason)."""
    op, b = e['op'], e['body']
    if e['tier'] != tier_of(S, op, b): return None, 'tier'
    ok = {a for a, sig in e['approvals'] if a in g['admins'] and verify(g['admins'][a], approval_bytes(cid, e), sig)}
    if len(ok) < THR[e['tier']]: return None, 'auth'
    N = S.copy()
    if op == 'GRANT':
        if b['src'] not in S.segments or b['dst'] not in S.segments: return None, 'wf'
        if (b['src'], b['dst']) in S.denies: return None, 'wf-deny'
        N.grants[b['id']] = dict(b)
        if (b['src'], b['dst']) in S.protected: return None, 'protected'
    elif op == 'REVOKE':
        if b['id'] not in S.grants: return None, 'wf'
        del N.grants[b['id']]
    elif op == 'DENY': N.denies.add((b['src'], b['dst']))
    elif op == 'VETO': N.vetoed.add(b['entry'])
    elif op == 'ENROLL':
        if b['edge'] in S.members: return None, 'wf'
        N.members[b['edge']] = b['pk']
    elif op == 'EVICT':
        if b['edge'] not in S.members: return None, 'wf'
        del N.members[b['edge']]
    elif op == 'CLASSIFY': N.restricted.add(b['seg'])
    return N, 'ok'

def compile_nft(S, edge, transit=()):
    L = ['table inet wp { chain forward { type filter hook forward priority 0; policy drop;',
         '  ct state established,related accept', '  udp dport 51820 accept comment "pinned sync/tunnel"']
    for gid, gr in sorted(S.grants.items()):
        L.append(f'  ip saddr @{gr["src"]} ip daddr @{gr["dst"]} tcp dport {gr["port"]} accept comment "{gid}"')
    L.append('} }'); return '\n'.join(L)

# ---------------- network emulator ----------------
class Net:
    def __init__(s, delta=0.05, jitter=0.01, seed=1):
        import random
        s.now = 0.0; s.q = []; s.seq = 0; s.nodes = {}; s.delta = delta; s.jitter = jitter; s.rng = random.Random(seed)
        s.down = set(); s.cut = []      # cut: list of (A,B,until)
        s.msgs = 0; s.trace = []; s.bytes = 0
    def at(s, t, fn): s.seq += 1; heapq.heappush(s.q, (t, s.seq, fn))
    def blocked(s, a, b):
        if a in s.down or b in s.down: return True
        return any(((a in A and b in B) or (a in B and b in A)) and s.now < u for A, B, u in s.cut)
    def send(s, a, b, m):
        if a != b and s.blocked(a, b): return
        s.msgs += 1; s.bytes += len(canon(m))
        d = 0.0 if a == b else s.delta + s.rng.uniform(0, s.jitter)
        s.at(s.now + d, lambda: s.nodes[b].on_msg(m) if b in s.nodes and b not in s.down else None)
    def run(s, until):
        while s.q and s.q[0][0] <= until:
            t, _, fn = heapq.heappop(s.q); s.now = t; fn()
        s.now = max(s.now, until)
    def log(s, **k): k['t'] = round(s.now, 4); s.trace.append(k)

def att_bytes(cid, kind, slot, r, d, ts): return canon({'cid': cid, 'k': kind, 's': slot, 'r': r, 'd': d, 'ts': ts})
def quorum(n, b): return (n + b + 2) // 2          # ceil((n+b+1)/2)

# ---------------- edge ----------------
class Edge:
    byz = False
    def __init__(s, eid, key, g, net, mode='S2', b=1, gossip=30.0, offset=0.0, rec_dir=None, observer=False, expected_gh=None):
        s.id, s.key, s.g, s.net, s.mode, s.b = eid, key, g, net, mode, b
        s.cid = g['chain_id']; s.gh = H(canon(g)); s.S = State(g); s.chain = []; s.prev = s.gh
        s.n = len(g['members']); s.T = quorum(s.n, b); s.offset = offset; s.gossip = gossip
        s.rec = dict(prep={}, com={}, promised={}); s.rec_path = os.path.join(rec_dir, eid + '.json') if rec_dir else None
        s.preps = defaultdict(dict); s.coms = defaultdict(dict); s.props = {}; s.certs = {}; s.res = defaultdict(set)
        s.heads = {}; s.enforced = {}; s.cert_time = {}; s.alerts = []; s.pending_future = []; s.state = 'VOTING' if expected_gh in (None, s.gh) else 'UNPROV'
        s.sent = {}; s.delta_w = 90.0; s.on_enforce = None; s.observer = observer; s.abstain_until = -1; s.fork_at = None; s.frozen = False; s.log_nft = None
        net.nodes[eid] = s; net.at(net.now + net.rng.uniform(0, gossip), s.tick)
    # --- helpers
    def lt(s): return s.net.now + s.offset
    def peers(s): return list(s.S.members)
    def bcast(s, m):
        for p in s.peers(): s.net.send(s.id, p, m)
    def persist(s):
        if s.rec_path:
            with open(s.rec_path, 'w') as f: json.dump({k: {str(x): y for x, y in v.items()} for k, v in s.rec.items()}, f)
    def lose_record(s):
        s.rec = dict(prep={}, com={}, promised={}); s.persist()
        if s.observer: s.abstain_until = len(s.chain) + 1     # attests only at slots >= head+2
    def can_attest(s, slot):
        return s.state == 'VOTING' and not s.frozen and slot > s.abstain_until
    # --- dispatch
    def on_msg(s, m):
        getattr(s, 'h_' + m['type'], lambda m: None)(m)
    def head(s): return len(s.chain)
    def next_prev(s): return s.prev
    # --- proposals
    def h_prop(s, m):
        e = m['entry']; slot = e['slot']
        if s.frozen: return
        if slot > s.head() + 1: s.pending_future.append(m); return
        if slot != s.head() + 1 or e['prev'] != s.prev: return
        N, why = valid(s.S, e, s.g, s.cid)
        if N is None: s.net.log(e=s.id, ev='reject', slot=slot, why=why); return
        d = digest(e); s.props[d] = e
        for kind in ('prep', 'com'):                 # idempotent retransmit of already-issued attestations
            old = s.sent.get((kind, slot, 0))
            if old and old['d'] == d: s.bcast(old)
        if s.mode == 'S1': s.append(e, None, d); return
        s.prepare(slot, 0, d)
    def prepare(s, slot, r, d):
        if not s.can_attest(slot): return
        if (slot, r) in s.rec['prep'] or r < s.rec['promised'].get(slot, 0): return
        if r > 0 and d not in s.res[(slot, r)]: return
        s.rec['prep'][(slot, r)] = d; s.rec['promised'][slot] = max(s.rec['promised'].get(slot, 0), r); s.persist()
        ts = self_ts = s.lt(); sig = s.key.sign(att_bytes(s.cid, 'prep', slot, r, d, ts))
        s.net.log(e=s.id, ev='prepare', slot=slot, r=r, d=d[:8])
        m_ = {'type': 'prep', 'e': s.id, 'slot': slot, 'r': r, 'd': d, 'ts': ts, 'sig': sig, 'entry': s.props[d]}; s.sent[('prep', slot, r)] = m_; s.bcast(m_)
    def h_prep(s, m):
        if m['e'] not in s.S.members or not verify(s.S.members[m['e']], att_bytes(s.cid, 'prep', m['slot'], m['r'], m['d'], m['ts']), m['sig']): return
        d = m['d']; s.props.setdefault(d, m['entry'])
        s.preps[(m['slot'], m['r'], d)][m['e']] = (m['ts'], m['sig'])
        k = (m['slot'], m['r'], d)
        if len(s.preps[k]) >= s.T and k not in s.certs:
            s.certs[k] = dict(list(s.preps[k].items())[:s.T]); s.commit(*k)
    def commit(s, slot, r, d):
        if not s.can_attest(slot): return
        if (slot, r) in s.rec['com'] or r < s.rec['promised'].get(slot, 0): return
        s.rec['com'][(slot, r)] = d; s.persist()
        ts = s.lt(); sig = s.key.sign(att_bytes(s.cid, 'com', slot, r, d, ts))
        s.net.log(e=s.id, ev='commit_att', slot=slot, r=r, d=d[:8])
        m_ = {'type': 'com', 'e': s.id, 'slot': slot, 'r': r, 'd': d, 'ts': ts, 'sig': sig}; s.sent[('com', slot, r)] = m_; s.bcast(m_)
    def h_com(s, m):
        if m['e'] not in s.S.members or not verify(s.S.members[m['e']], att_bytes(s.cid, 'com', m['slot'], m['r'], m['d'], m['ts']), m['sig']): return
        k = (m['slot'], m['r'], m['d']); s.coms[k][m['e']] = (m['ts'], m['sig'])
        s.try_finalize(k)
    def try_finalize(s, k):
        slot, r, d = k
        if len(s.coms[k]) >= s.T and d in s.props and slot == s.head() + 1 and s.props[d]['prev'] == s.prev and not s.frozen:
            cert = dict(list(s.coms[k].items())[:s.T]); s.append(s.props[d], cert, d, r)
    def append(s, e, cert, d, r=0):
        N, why = valid(s.S, e, s.g, s.cid)
        if N is None: return
        s.S = N; s.chain.append(dict(entry=e, cert=cert, d=d, r=r)); s.prev = d; s.enforced[e['slot']] = d
        if cert: s.cert_time[e['slot']] = statistics.median(ts for ts, _ in cert.values())
        s.net.log(e=s.id, ev='enforce', slot=e['slot'], d=d[:8]); s.log_nft = compile_nft(s.S, s.id)
        if s.on_enforce: s.on_enforce()
        pend, s.pending_future = s.pending_future, []
        for m in pend: s.on_msg(m)
        for k in [k for k in s.coms if k[0] == s.head() + 1]: s.try_finalize(k)
    # --- round change
    def h_resolve_req(s, m):
        slot, r = m['slot'], m['r']
        if m['admin'] not in s.g['admins'] or not verify(s.g['admins'][m['admin']], canon({'cid': s.cid, 'resolve': [slot, r]}), m['sig']): return
        if slot != s.head() + 1 or r <= s.rec['promised'].get(slot, 0) or not s.can_attest(slot): return
        s.rec['promised'][slot] = r; s.persist()
        best = None
        for (sl, rr, d), cert in s.certs.items():
            if sl == slot and rr < r and (best is None or rr > best[0]): best = (rr, d, cert)
        rep = {'type': 'report', 'e': s.id, 'slot': slot, 'r': r, 'cert': None if best is None else {'r': best[0], 'd': best[1], 'sigs': best[2], 'entry': s.props[best[1]]}}
        rep['sig'] = s.key.sign(canon({'cid': s.cid, 'rep': [slot, r, None if best is None else [best[0], best[1]]]}))
        s.net.log(e=s.id, ev='promise', slot=slot, r=r); s.net.send(s.id, 'adm', rep)
    def cert_ok(s, slot, rr, d, sigs):
        good = {e for e, (ts, sg) in sigs.items() if e in s.S.members and verify(s.S.members[e], att_bytes(s.cid, 'prep', slot, rr, d, ts), sg)}
        return len(good) >= s.T
    def h_res(s, m):
        slot, r, d, reps, e = m['slot'], m['r'], m['d'], m['reports'], m['entry']
        if m['admin'] not in s.g['admins'] or not verify(s.g['admins'][m['admin']], canon({'cid': s.cid, 'res': [slot, r, d]}), m['sig']): return
        seen = set(); top = None
        for rp in reps:
            if rp['e'] in seen or rp['e'] not in s.S.members or rp['slot'] != slot or rp['r'] != r: continue
            c = rp['cert']
            if not verify(s.S.members[rp['e']], canon({'cid': s.cid, 'rep': [slot, r, None if c is None else [c['r'], c['d']]]}), rp['sig']): continue
            if c is not None:
                if c['r'] >= r or not s.cert_ok(slot, c['r'], c['d'], c['sigs']): continue
                if top is None or c['r'] > top[0]: top = (c['r'], c['d'])
            seen.add(rp['e'])
        if len(seen) < s.T: return
        if top is not None and top[1] != d: s.net.log(e=s.id, ev='res_reject', slot=slot, r=r); return
        if digest(e) != d: return
        s.net.log(e=s.id, ev='res', slot=slot, r=r, d=d[:8]); s.props[d] = e; s.res[(slot, r)].add(d); s.rec['promised'][slot] = max(s.rec['promised'].get(slot, 0), r)
        s.prepare(slot, r, d)
    # --- gossip, sync, freshness
    def tick(s):
        if s.id in s.net.down: s.net.at(s.net.now + s.gossip, s.tick); return
        h = len(s.chain); ts = s.lt(); sig = s.key.sign(canon({'cid': s.cid, 'head': [h, s.prev, ts]}))
        s.bcast({'type': 'head', 'e': s.id, 'h': h, 'hash': s.prev, 'ts': ts, 'sig': sig}); s.net.at(s.net.now + s.gossip, s.tick)
    def h_head(s, m):
        if m['e'] not in s.S.members or not verify(s.S.members[m['e']], canon({'cid': s.cid, 'head': [m['h'], m['hash'], m['ts']]}), m['sig']): return
        s.heads[m['e']] = (m['h'], m['hash'], s.net.now)
        if m['h'] == s.head() and m['hash'] != s.prev and s.fork_at is None:
            s.fork_at = s.net.now; s.frozen = True; s.alerts.append(('fork', m['h'], round(s.net.now, 3)))
            s.net.log(e=s.id, ev='fork_alert', slot=m['h'])
        elif m['h'] > s.head() and not s.frozen:
            s.net.send(s.id, m['e'], {'type': 'sync_req', 'e': s.id, 'from': s.head() + 1})
    def h_sync_req(s, m):
        s.net.send(s.id, m['e'], {'type': 'sync', 'items': [dict(c) for c in s.chain[m['from'] - 1:]]})
    def h_sync(s, m):
        for it in m['items']:
            e = it['entry']
            if e['slot'] != s.head() + 1 or e['prev'] != s.prev: continue
            if s.mode == 'S2':
                cert = it['cert']
                if not cert: continue
                good = {x for x, (ts, sg) in cert.items() if x in s.S.members and verify(s.S.members[x], att_bytes(s.cid, 'com', e['slot'], it['r'], digest(e), ts), sg)}
                if len(good) < s.T: continue
            s.append(e, it['cert'], digest(e), it['r'])
    def fresh(s, delta_w=None):
        delta_w = s.delta_w if delta_w is None else delta_w
        """Fresh iff heads from >= T distinct edges (self included) within delta_w and applied >= target slot
        (target = max slot vouched by >= b+1 edges).  A b+1 rule is NOT enough: a partitioned minority can vouch for itself."""
        d_ = {e: h for e, h in s.heads.items() if s.net.now - h[2] <= delta_w}; d_[s.id] = (s.head(), s.prev, s.net.now)   # distinct edges, self counted once
        recent = list(d_.values())
        if len(recent) < s.T: return False
        tgt = max((h[0] for h in recent if sum(1 for x in recent if x[0] >= h[0]) >= s.b + 1), default=0)
        return s.head() >= tgt
    def forwards(s, src, dst, port, now):
        if s.state == 'UNPROV': return False
        for gr in s.S.grants.values():
            if (gr['src'], gr['dst'], gr['port']) == (src, dst, port) and (s.fresh() or now < gr.get('lease', 1e18)): return True
        return False

class ByzEdge(Edge):
    """attests to everything it sees, ignores lock-once, skewed timestamps."""
    byz = True
    skew = 1e6
    def h_prop(s, m): s.seen(m['entry'])
    def h_prep(s, m): s.seen(m['entry'], m['r'])
    def seen(s, e, r=0):
        d = digest(e); s.props[d] = e; k = (e['slot'], r, d)
        if k in s.rec['prep']: return
        s.rec['prep'][k] = 1
        for kind in ('prep', 'com'):
            ts = s.lt() + s.skew; sig = s.key.sign(att_bytes(s.cid, kind, e['slot'], r, d, ts))
            m2 = {'type': kind, 'e': s.id, 'slot': e['slot'], 'r': r, 'd': d, 'ts': ts, 'sig': sig, 'entry': e}
            s.bcast(m2)
    def h_resolve_req(s, m): pass
    def h_res(s, m): pass
    def tick(s): s.net.at(s.net.now + s.gossip, s.tick)

# ---------------- admin tool / controller ----------------
class Admin:
    def __init__(s, aid, key, g, net, edges_n, b):
        s.id, s.key, s.g, s.net, s.cid = aid, key, g, net, g['chain_id']; s.reports = defaultdict(dict); s.T = quorum(edges_n, b); s.cands = {}
        net.nodes['adm'] = s
    def sign_entry(s, e, extra=()):
        sigs = [(s.id, s.key.sign(approval_bytes(s.cid, e)))] + [(k.id, k.sign(approval_bytes(s.cid, e))) for k in extra]
        e['approvals'] = sigs; return e
    def resolve(s, slot, r, candidate):
        s.cands[(slot, r)] = candidate
        m = {'type': 'resolve_req', 'admin': s.id, 'slot': slot, 'r': r, 'sig': s.key.sign(canon({'cid': s.cid, 'resolve': [slot, r]}))}
        for e in s.g['members']: s.net.send('adm', e, m)
    def on_msg(s, m):
        if m['type'] != 'report': return
        k = (m['slot'], m['r']); s.reports[k][m['e']] = m
        if len(s.reports[k]) == s.T:
            reps = list(s.reports[k].values()); top = None
            for rp in reps:
                if rp['cert'] and (top is None or rp['cert']['r'] > top['r']): top = rp['cert']
            e = top['entry'] if top else s.cands[k]; d = digest(e)
            res = {'type': 'res', 'admin': s.id, 'slot': k[0], 'r': k[1], 'd': d, 'reports': reps, 'entry': e,
                   'sig': s.key.sign(canon({'cid': s.cid, 'res': [k[0], k[1], d]}))}
            for x in s.g['members']: s.net.send('adm', x, res)

def make_genesis(n, n_admins=3, segments=('Guest', 'Finance', 'Sales', 'DB'), protected=(('Guest', 'Finance'),), restricted=('DB',)):
    ekeys = {f'e{i}': Key() for i in range(n)}; akeys = {}
    for i in range(n_admins): k = Key(); k.id = f'a{i}'; akeys[k.id] = k
    g = dict(chain_id='wp-demo-1', admins={a: k.pk for a, k in akeys.items()}, members={e: k.pk for e, k in ekeys.items()},
             segments=list(segments), protected=[list(p) for p in protected], restricted=list(restricted))
    return g, ekeys, akeys

def entry(slot, prev, op, body, S):
    return dict(slot=slot, prev=prev, op=op, body=body, tier=tier_of(S, op, body), approvals=[])


def compile_nft_real(grants, cidrs):
    """Loadable nftables ruleset (default-deny forward) for the given active grants."""
    segs = sorted({x for gr in grants.values() for x in (gr['src'], gr['dst'])})
    L = ['table inet wp', 'delete table inet wp', 'table inet wp {']
    for sg in segs: L.append(f'  set {sg} {{ type ipv4_addr; flags interval; elements = {{ {cidrs[sg]} }} }}')
    L += ['  chain forward { type filter hook forward priority 0; policy drop;', '    ct state established,related accept']
    for gid, gr in sorted(grants.items()):
        L.append(f'    ip saddr @{gr["src"]} ip daddr @{gr["dst"]} tcp dport {gr["port"]} accept comment "{gid}"')
    L += ['  }', '}']; return '\n'.join(L) + '\n'
