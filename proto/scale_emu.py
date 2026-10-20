import sys, json, time
from baselines import build, deliver, G
import wpcore
rows = []
for n in [int(x) for x in sys.argv[1].split(',')]:
    for mode in ('S1', 'S2'):
        b = max(1, (n - 1) // 3); g, ek, ak, net, edges, adm, ctrls, c = build(mode, n=n, b=b, gossip=1e9)
        for k in wpcore.STATS: wpcore.STATS[k] = 0 if isinstance(wpcore.STATS[k], int) else 0.0
        wpcore._VC.clear(); t0 = time.time(); e = c.build('GRANT', G('g1')); deliver(mode, c, net, e); net.run(5)
        ev = [x['t'] for x in net.trace if x['ev'] == 'enforce']; wall = time.time() - t0
        rows.append(dict(n=n, mode=mode, b=b, T=(n + b + 2) // 2, committed=sum(1 for x in edges.values() if x.head() == 1), latency_s=round(max(ev), 3) if ev else None, msgs=net.msgs, MB=round(net.bytes / 1e6, 1), verifies_per_edge=round(wpcore.STATS['verify'] / n), wall_s=round(wall, 1)))
        print(rows[-1], flush=True)
json.dump(rows, open(f'scale_emu_{sys.argv[1].replace(",", "_")}.json', 'w'))
