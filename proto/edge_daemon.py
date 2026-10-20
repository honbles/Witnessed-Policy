"""One Witnessed Policy edge as a real OS process (run inside its own network namespace)."""
import sys, json, argparse, os, threading, time, subprocess, resource
from wp2 import *
from realnet import RealNet
from dp import DP
ap = argparse.ArgumentParser()
ap.add_argument('--id'); ap.add_argument('--run'); ap.add_argument('--mode', default='S2'); ap.add_argument('--b', type=int, default=1)
ap.add_argument('--gossip', type=float, default=5.0); ap.add_argument('--delta-w', type=float, default=30.0)
ap.add_argument('--app-delay', type=float, default=0.0); ap.add_argument('--datapath', action='store_true'); ap.add_argument('--byz', action='store_true'); ap.add_argument('--dpcfg', default=None); ap.add_argument('--late', action='store_true')
a = ap.parse_args(); R = a.run
g = json.load(open(f'{R}/genesis.json')); peers = json.load(open(f'{R}/peers.json'))
key = Key.from_hex(open(f'{R}/keys/{a.id}.key').read().strip())
net = RealNet(a.id, peers, peers[a.id], trace_path=f'{R}/trace/{a.id}.jsonl', app_delay=a.app_delay)
cls = ByzEdge2 if a.byz else Edge2
e = cls(a.id, key, g, net, mode=a.mode, b=a.b, gossip=a.gossip, rec_dir=f'{R}/rec', expected_gh=H(canon(g)), late=a.late)
e.delta_w = a.delta_w; dp = None
if a.dpcfg:
    dp = DP(e, g, json.load(open(a.dpcfg)), net); dp.start(); e.on_enforce = dp.refresh
    def dp_tick(): dp.refresh(); net.at(net.now + 0.25, dp_tick)
    net.at(net.now + 0.1, dp_tick)
def status():
    ru = resource.getrusage(resource.RUSAGE_SELF)
    st = dict(id=a.id, head=e.head(), enforced={str(k): v[:8] for k, v in e.enforced.items()}, alerts=e.alerts, fork_at=e.fork_at, state=e.state,
              fresh=e.fresh(), msgs=net.msgs, bytes=net.bytes, cpu_s=round(ru.ru_utime + ru.ru_stime, 3), rss_mb=round(ru.ru_maxrss / 1024, 1),
              cert_time={str(k): v for k, v in e.cert_time.items()}, wall=time.time(), verifies=STATS['verify'], chain_bytes=(os.path.getsize(e.chain_path) if e.chain_path and os.path.exists(e.chain_path) else 0), epoch=(e.S.epoch if e.S else None), n=e.n, T=e.T, nverify=getattr(e, 'nverify', 0), tx_ok=net.tx_ok, tx_fail=net.tx_fail, rx_err=net.rx_err, last_err=net.last_err, dp=(dp.info() if dp else None))
    tmp = f'{R}/status/{a.id}.json.tmp'; json.dump(st, open(tmp, 'w')); os.replace(tmp, f'{R}/status/{a.id}.json')
    net.at(net.now + 0.25, status)
net.at(0.05, status); net.run()
