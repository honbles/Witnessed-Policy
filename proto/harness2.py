from wp2 import *
def setup2(n, b, mode='S2', byz=0, seed=1, gossip=30.0, delta=0.05, delay=None, extra=None, rec_dir=None, observer=False, n_admins=4):
    g, ek, ak = make_genesis2(n, n_admins, delay, extra); net = Net(delta=delta, seed=seed); edges = {}
    for i in range(n):
        cls = ByzEdge2 if i >= n - byz else Edge2
        edges[f'e{i}'] = cls(f'e{i}', ek[f'e{i}'], g, net, mode=mode, b=b, gossip=gossip, rec_dir=rec_dir, expected_gh=H(canon(g))) if cls is Edge2 else ByzEdge2(f'e{i}', ek[f'e{i}'], g, net, mode=mode, b=b, gossip=gossip, expected_gh=H(canon(g)))
    adm = Admin2('a0', ak['a0'], g, net, n, b, all_keys=ak)
    return g, ek, ak, net, edges, adm
class Ctl:
    """shadow of the committed chain, used to build the next proposal"""
    def __init__(s, g, adm, net, edges): s.g, s.adm, s.net, s.edges = g, adm, net, edges; s.S = P2State(g); s.prev = H(canon(g)); s.slot = 0
    def build(s, op, body, by=('a0',), slot=None, prev=None, epoch=None, sign=True):
        e = entry2(s.S, slot or s.slot + 1, prev or s.prev, op, body, signers=set(by))
        if epoch is not None: e['epoch'] = epoch
        if sign: s.adm.sign_entry(e, by=by[0], extra=list(by[1:]))
        return e
    def send(s, e, to=None):
        for t in (to if to is not None else list(s.edges)): s.net.send('ctl', t, {'type': 'prop', 'entry': e})
    def accept(s, e):
        d = digest2(e); s.S = apply2(s.S, e, d); s.prev = d; s.slot = e['slot']
def hon(edges): return [e for e in edges.values() if not getattr(e, 'byz', False)]
def heads(edges): return [e.head() for e in hon(edges)]
