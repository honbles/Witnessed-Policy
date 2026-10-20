from harness import *
for mode in ('S1', 'S2'):
    g, ek, ak, net, edges, adm = setup(4, 1, mode)
    e0 = edges['e0']
    e1 = propose(net, adm, ak, edges, e0.S, 1, e0.prev, 'GRANT', dict(id='g1', src='Sales', dst='Finance', port=443))
    net.run(2.0)
    print(mode, 'heads', [e.head() for e in edges.values()], 'msgs', net.msgs, 'grants', [list(e.S.grants) for e in edges.values()][:2])
