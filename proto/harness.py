from wpcore import *
def setup(n, b, mode='S2', byz=0, seed=1, gossip=30.0, delta=0.05, observer=False):
    g, ek, ak = make_genesis(n); net = Net(delta=delta, seed=seed); edges = {}
    for i in range(n):
        cls = ByzEdge if i >= n - byz else Edge
        edges[f'e{i}'] = cls(f'e{i}', ek[f'e{i}'], g, net, mode=mode, b=b, gossip=gossip)
    adm = Admin('a0', ak['a0'], g, net, n, b)
    return g, ek, ak, net, edges, adm
def honest(edges): return [e for e in edges.values() if not e.byz]
def propose(net, adm, ak, edges, S, slot, prev, op, body, to=None, extra=()):
    e = entry(slot, prev, op, body, S); adm.sign_entry(e, extra=[ak[x] for x in extra])
    for t in (to if to is not None else list(edges)): net.send('ctl', t, {'type': 'prop', 'entry': e})
    return e
