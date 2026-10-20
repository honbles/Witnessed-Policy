#!/usr/bin/env python3
"""Real data-plane tests: every edge is an OS process in its own network namespace; data-plane edges run userspace WireGuard
(peers/allowed-ips derived from committed paths) and load nftables rules (default-deny, ingress binding, per-grant return rules).
Run: ./run_real.sh-style wrapper:  unshare -Urnm python3 real_dp.py --scenarios traffic,failover,compromised,crash,join,scale"""
import argparse, json, os, re, shutil, signal, statistics as st, subprocess, sys, threading, time, random
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
from wp2 import *
from harness2 import Ctl
from realnet import RealNet
from checker import check, check_epochs
def sh(cmd, ok=True, inp=None):
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, input=inp)
    if ok and p.returncode: raise RuntimeError(f'{cmd}\n{p.stderr}')
    return p
def ip_of(i): return f'10.9.0.{10 + i}'
SEGS = {'Finance': dict(cidr='10.1.0.0/24', cidr6='fd00:1::/64', site='e0', cls='normal'), 'Guest': dict(cidr='10.3.0.0/24', site='e0', cls='normal'),
        'Sales': dict(cidr='10.2.0.0/24', cidr6='fd00:2::/64', site='e2', cls='normal'), 'DB': dict(cidr='10.4.0.0/28', site='e2', cls='restricted')}
PATHS = {'p01': dict(a='e0', b='e1', kind='primary'), 'p12': dict(a='e1', b='e2', kind='primary'), 'p02': dict(a='e0', b='e2', kind='backup')}
LOCALS = {'e0': [dict(iface='dpf', segs=['Finance']), dict(iface='dpg', segs=['Guest'])], 'e1': [], 'e2': [dict(iface='dps', segs=['Sales', 'DB'])]}
def G(id, src='Finance', dst='Sales', port=443, **kw): return dict(id=id, src=src, dst=dst, port=port, qos='best', **kw)

class Dep:
    def __init__(s, out, n, mode='S2', b=1, gossip=3.0, delta_w=15.0, delay_ms=50.0, dp=True, tag='run', skip=(), delay=None, byz=()):
        s.n, s.mode, s.b, s.dp, s.out = n, mode, b, dp, os.path.join(out, tag); s.procs = {}; s.aux = []; s.skip = set(skip); s.byz = set(byz); s.delay_ms = delay_ms
        shutil.rmtree(s.out, ignore_errors=True)
        for d_ in ('keys', 'trace', 'status', 'rec', 'wgkeys'): os.makedirs(f'{s.out}/{d_}')
        s.cleanup(); s.topology(delay_ms)
        extra = {}
        if dp:
            wg = {}
            for i in range(3):
                k = sh('wg genkey').stdout.strip(); open(f'{s.out}/wgkeys/e{i}.key', 'w').write(k + '\n'); pk = sh(f'echo {k} | wg pubkey').stdout.strip()
                wg[f'e{i}'] = dict(pk=pk, ep=f'10.8.0.{10 + i}:51820', tip=f'10.99.0.{i + 1}')
            extra = dict(segments=SEGS, paths=PATHS, wg=wg, forbidden=[['Guest', 'Finance']])
        s.g, ek, s.ak = make_genesis2(n, 4, delay or {'L2': 8.0, 'L3': 16.0}, extra)
        for e, k in ek.items(): open(f'{s.out}/keys/{e}.key', 'w').write(k.hex())
        s.ek = ek; json.dump(s.g, open(f'{s.out}/genesis.json', 'w'))
        s.peers = {f'e{i}': [ip_of(i), 7000] for i in range(n)}; s.peers['adm'] = ['10.9.0.254', 7000]; json.dump(s.peers, open(f'{s.out}/peers.json', 'w'))
        s.app_delay = 0.0 if s.netem_ok else delay_ms / 1000.0
        s.net = RealNet('adm', s.peers, s.peers['adm'], app_delay=s.app_delay); s.adm = Admin2('a0', s.ak['a0'], s.g, s.net, n, b, all_keys=s.ak)
        threading.Thread(target=s.net.run, daemon=True).start(); s.gossip, s.delta_w = gossip, delta_w
        for i in range(n):
            if f'e{i}' not in s.skip: s.spawn(f'e{i}')
        s.ctl = Ctl(s.g, s.adm, s.net, s.procs)
        s.wait(lambda st_: all(st_[e] is not None for e in s.procs), 120, 'daemons up'); s.ready()
        if dp: s.tunnels_ready()
    def spawn(s, eid, late=False):
        i = int(eid[1:]); cmd = ['ip', 'netns', 'exec', eid, sys.executable, os.path.join(HERE, 'edge_daemon.py'), '--id', eid, '--run', s.out, '--mode', s.mode, '--b', str(s.b),
                                 '--gossip', str(s.gossip), '--delta-w', str(s.delta_w), '--app-delay', str(s.app_delay)]
        if s.dp and i < 3:
            json.dump(dict(wgkey=f'{s.out}/wgkeys/{eid}.key', locals=LOCALS[eid], log=f'{s.out}/wg_{eid}.log', rtt_hint=(2 * s.delay_ms / 1000.0 if s.netem_ok else 0.0), grace=8.0), open(f'{s.out}/dp_{eid}.json', 'w')); cmd += ['--dpcfg', f'{s.out}/dp_{eid}.json']
        if late: cmd.append('--late')
        if eid in s.byz: cmd.append('--byz')
        s.procs[eid] = subprocess.Popen(cmd, cwd=HERE, stdout=subprocess.DEVNULL, stderr=open(f'{s.out}/{eid}.err', 'a'))
        return s.procs[eid]
    def cleanup(s):
        sh('pkill -f edge_daemon.py', ok=False); sh('pkill -x wireguard-go', ok=False); time.sleep(0.2)
        for i in range(260):
            sh(f'ip netns del e{i}', ok=False)
        for ns in ('fin', 'guest', 'sales'): sh(f'ip netns del {ns}', ok=False)
        sh('ip link del br0', ok=False); sh('ip link del br1', ok=False); time.sleep(0.3)
        for i in range(3): sh(f'ip link del vq{i}', ok=False)
        for _ in range(100):                                                              # netns teardown is asynchronous: wait for veth ends and namespaces to vanish
            left = sh("ip -o link show | grep -E ' (vm|vq)[0-9]+(@|:)' ; ip netns list | grep -E '^(e[0-9]+|fin|guest|sales)( |$)'", ok=False).stdout.strip()
            if not left: break
            for ln in left.splitlines():
                m = re.search(r' (v[mq]\d+)[@:]', ln)
                if m: sh(f'ip link del {m.group(1)}', ok=False)
                m = re.match(r'(e\d+|fin|guest|sales)\b', ln)
                if m: sh(f'ip netns del {m.group(1)}', ok=False)
            time.sleep(0.2)
        for i in range(260):
            if sh(f'ip link show vm{i}', ok=False).returncode: break
            sh(f'ip link del vm{i}', ok=False)
        sh('rm -f /var/run/wireguard/*.sock', ok=False)
    def nsx(s, ns, cmd, ok=True): return sh(f'ip netns exec {ns} {cmd}', ok=ok)
    def topology(s, delay_ms):
        sh('ip link set lo up'); sh('ip link add br0 type bridge'); sh('ip addr add 10.9.0.254/24 dev br0'); sh('ip link set br0 up'); s.netem_ok = False
        for i in range(s.n):
            sh(f'ip netns add e{i}'); sh(f'ip link add vm{i} type veth peer name m0 netns e{i}'); sh(f'ip link set vm{i} master br0'); sh(f'ip link set vm{i} up')
            s.nsx(f'e{i}', f'sh -c "ip link set lo up; ip addr add {ip_of(i)}/24 dev m0; ip link set m0 up"')
        if delay_ms > 0:
            h = delay_ms / 2
            if s.nsx('e0', f'tc qdisc add dev m0 root netem delay {h}ms', ok=False).returncode == 0:
                s.netem_ok = True
                for i in range(1, s.n): s.nsx(f'e{i}', f'tc qdisc add dev m0 root netem delay {h}ms')
                for i in range(s.n): sh(f'tc qdisc add dev vm{i} root netem delay {h}ms')
        if not s.dp: return
        sh('ip link add br1 type bridge'); sh('ip addr add 10.8.0.254/24 dev br1'); sh('ip link set br1 up')           # data underlay: WireGuard endpoints live here, so cutting the control network (m0) leaves tunnels up
        for i in range(3):
            sh(f'ip link add vq{i} type veth peer name m1 netns e{i}'); sh(f'ip link set vq{i} master br1'); sh(f'ip link set vq{i} up')
            s.nsx(f'e{i}', f'sh -c "ip addr add 10.8.0.{10 + i}/24 dev m1; ip link set m1 up"')
            if s.netem_ok: s.nsx(f'e{i}', f'tc qdisc add dev m1 root netem delay {delay_ms / 2}ms'); sh(f'tc qdisc add dev vq{i} root netem delay {delay_ms / 2}ms')
        s.v6 = sh('ip -6 addr add fd00:ffff::1/128 dev lo', ok=False).returncode == 0
        if s.v6: sh('ip -6 addr del fd00:ffff::1/128 dev lo', ok=False)
        for ns in ('fin', 'guest', 'sales'): sh(f'ip netns add {ns}')
        def leg(host, edge, ifc, a4, a6=None, gw4=None, gw6=None):
            sh(f'ip link add {ifc} type veth peer name p0 netns {host}'); sh(f'ip link set {ifc} netns {edge}')
            s.nsx(edge, f'sh -c "ip addr add {a4[0]}/24 dev {ifc}; {("ip -6 addr add " + a6[0] + "/64 dev " + ifc + ";") if a6 else ""} ip link set {ifc} up"')
            s.nsx(host, f'sh -c "ip link set lo up; ip addr add {a4[1]}/24 dev p0; {("ip -6 addr add " + a6[1] + "/64 dev p0;") if a6 else ""} ip link set p0 up; ip route add default via {a4[0]}; {("ip -6 route add default via " + a6[0] + ";") if a6 else ""}"')
        leg('fin', 'e0', 'dpf', ('10.1.0.1', '10.1.0.2'), ('fd00:1::1', 'fd00:1::2') if s.v6 else None); leg('guest', 'e0', 'dpg', ('10.3.0.1', '10.3.0.2'))
        leg('sales', 'e2', 'dps', ('10.2.0.1', '10.2.0.2'), ('fd00:2::1', 'fd00:2::2') if s.v6 else None); s.nsx('sales', 'ip addr add 10.4.0.2/28 dev lo')
        for e in ('e0', 'e1', 'e2'): s.nsx(e, 'sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0' + (' net.ipv6.conf.all.forwarding=1' if s.v6 else ''))
        s.aux.append(subprocess.Popen(['ip', 'netns', 'exec', 'sales', sys.executable, os.path.join(HERE, 'srv.py')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    def ready(s, timeout=90):
        """every edge accepts a connection (avoids losing the first messages during the process start-up storm)"""
        import socket as so
        t0 = time.time(); pend = set(s.procs)
        while pend and time.time() - t0 < timeout:
            for e in list(pend):
                try: so.create_connection((ip_of(int(e[1:])), 7000), timeout=1).close(); pend.discard(e)
                except Exception: pass
            if pend: time.sleep(0.3)
        if pend: raise RuntimeError(f'edges not accepting connections: {sorted(pend)}')
        time.sleep(0.5 + 0.03 * s.n)
    def tunnels_ready(s, timeout=40):
        t0 = time.time()
        while time.time() - t0 < timeout:
            st_ = s.statuses(['e0', 'e1', 'e2']); hs = [(v or {}).get('dp') or {} for v in st_.values()]
            if all(h.get('handshakes', 0) >= (2 if k == 'e1' else 1) for k, h in zip(st_, hs)): s.tunnel_info = hs; return
            time.sleep(0.3)
        diag = [x for x in s.events('wg_diag')][:2] + [dict(e=x['e'], ev=x['ev'], rc=x.get('rc'), err=x.get('err'), method=x.get('method')) for x in s.events('wg_start') + s.events('wg_apply') if x.get('rc')][:4]
        raise RuntimeError('WireGuard tunnels did not come up within %ds; status=%s; diag=%s' % (timeout, json.dumps(hs)[:300], json.dumps(diag)[:900]))
    def status(s, eid):
        try: return json.load(open(f'{s.out}/status/{eid}.json'))
        except Exception: return None
    def statuses(s, ids=None): return {e: s.status(e) for e in (ids or s.procs)}
    def wait(s, cond, timeout, what=''):
        t0 = time.time()
        while time.time() - t0 < timeout:
            if cond(s.statuses()): return time.time() - t0
            time.sleep(0.05)
        raise TimeoutError(what)
    def heads(s, ids=None): return {e: (v['head'] if v else -1) for e, v in s.statuses(ids).items()}
    def wait_head(s, slot, ids=None, timeout=40, resend=None):
        """wait until every edge in ids has head >= slot; if `resend` (an entry) is given, re-deliver it to the stragglers every 3 s"""
        ids = ids or list(s.procs); t0 = time.time(); last = t0
        while time.time() - t0 < timeout:
            st_ = s.statuses(ids)
            if all(st_[e] and st_[e]['head'] >= slot for e in ids): return time.time() - t0
            if resend is not None and time.time() - last > 3.0:
                lag = [e for e in ids if not st_[e] or st_[e]['head'] < slot]; s.ctl.send(resend, lag); last = time.time()
            time.sleep(0.05)
        raise TimeoutError(f'head>={slot} {s.heads()}')
    def commit(s, op, body, by=('a0',), ids=None, timeout=40):
        e = s.ctl.build(op, body, by=by); t0 = time.time(); s.ctl.send(e, list(s.procs)); s.ctl.accept(e); s.wait_head(e['slot'], ids, timeout, resend=e); return e, t0
    def events(s, ev, slot=None, eid=None):
        out = []
        for p in os.listdir(f'{s.out}/trace'):
            if eid and p != eid + '.jsonl': continue
            for line in open(f'{s.out}/trace/{p}'):
                try: x = json.loads(line)
                except Exception: continue
                if x.get('ev') == ev and (slot is None or x.get('slot') == slot): out.append(x)
        return out
    def trace(s):
        tr = []
        for p in os.listdir(f'{s.out}/trace'): tr += [json.loads(l) for l in open(f'{s.out}/trace/{p}') if l.strip()]
        return sorted(tr, key=lambda x: x['t'])
    def link(s, ids, up):
        for e in ids: s.nsx(e, f'ip link set m0 {"up" if up else "down"}')
    def partition(s, A, B):
        ipsB = ', '.join(ip_of(int(x[1:])) for x in B); ipsA = ', '.join(ip_of(int(x[1:])) for x in A)
        for grp, oth in ((A, ipsB), (B, ipsA)):
            rules = ('table inet part\ndelete table inet part\ntable inet part {\n'
                     f'  chain o {{ type filter hook output priority 0; policy accept;\n    ip daddr {{ {oth} }} drop\n  }}\n'
                     f'  chain i {{ type filter hook input priority 0; policy accept;\n    ip saddr {{ {oth} }} drop\n  }}\n}}\n')
            for e in grp:
                p = subprocess.run(['ip', 'netns', 'exec', e, 'nft', '-f', '-'], input=rules, capture_output=True, text=True)
                if p.returncode: raise RuntimeError(p.stderr)
    def heal(s):
        for i in range(s.n): s.nsx(f'e{i}', 'nft delete table inet part', ok=False)
    def probe(s, ns, tgt='10.2.0.2', port=443, src=None, tag=None):
        tag = tag or f'{ns}_{tgt}_{port}'; log = f'{s.out}/pr_{tag}.log'; stop = f'{s.out}/pr_{tag}.stop'
        env = dict(os.environ, WP_PROBE_TO=str(max(0.15, round(8 * s.delay_ms / 1000.0 + 0.3, 2)) if s.netem_ok else 0.15))
        p = subprocess.Popen(['ip', 'netns', 'exec', ns, sys.executable, os.path.join(HERE, 'probe.py'), log, stop, tgt, str(port)] + ([src] if src else []), env=env)
        return (p, log, stop)
    def stream(s, tag='stream'):
        log = f'{s.out}/{tag}.log'; stop = f'{s.out}/{tag}.stop'
        env = dict(os.environ, WP_PROBE_TO=str(max(0.3, round(8 * s.delay_ms / 1000.0 + 0.3, 2)) if s.netem_ok else 0.3)); return (subprocess.Popen(['ip', 'netns', 'exec', 'fin', sys.executable, os.path.join(HERE, 'stream.py'), log, stop], env=env), log, stop)
    def finish(s, h):
        p, log, stop = h; open(stop, 'w').write('x'); p.wait(timeout=8); return [(float(a), int(b)) for a, b in (l.split() for l in open(log))]
    def once(s, ns, tgt='10.2.0.2', port=443):
        r = s.nsx(ns, f'{sys.executable} -c "import socket,sys;x=socket.socket(socket.AF_INET6 if \':\' in \'{tgt}\' else socket.AF_INET);x.settimeout(1.0);\ntry: x.connect((\'{tgt}\',{port}));print(1)\nexcept Exception: print(0)"', ok=False)
        return r.stdout.strip() == '1'
    def nft_grants(s, eid):
        t = s.nsx(eid, 'nft list table inet wp', ok=False).stdout; return sorted(set(re.findall(r'comment "(g[^"]*?)(?:-ret)?"', t)))
    def counter(s, eid, comment):
        t = s.nsx(eid, 'nft list chain inet wp forward', ok=False).stdout
        for line in t.splitlines():
            if f'comment "{comment}"' in line:
                m = re.search(r'packets (\d+)', line); return int(m.group(1)) if m else 0
        return 0
    def stop(s):
        s.net.close()
        for p in list(s.procs.values()) + s.aux:
            try: p.terminate()
            except Exception: pass
        for p in list(s.procs.values()) + s.aux:
            try: p.wait(timeout=3)
            except Exception: pass
        s.cleanup()
def first_after(sm, t, ok): return next((ts for ts, o in sm if ts >= t and o == ok), None)
def last_ok_before(sm, t): return max((ts for ts, o in sm if ts < t and o == 1), default=None)

def scen_traffic(a, R):
    d = Dep(a.out, a.n, 'S2', a.b, tag='traffic', delay_ms=a.delay_ms); X = {}
    try:
        pf = d.probe('fin', tag='fin'); pg = d.probe('guest', tag='guest'); time.sleep(2.0)
        t_g = time.time(); e, _ = d.commit('GRANT', G('gF')); X['grant_committed_all_s'] = round(time.time() - t_g, 3); time.sleep(1.5)
        X['guest_blocked'] = not d.once('guest'); X['finance_port22_blocked'] = not d.once('fin', port=22)
        nftg = {k: d.nft_grants(k) for k in ('e0', 'e1', 'e2')}
        # T9: endpoint offline at commit
        d.link(['e2'], False); e2_, _ = d.commit('GRANT', G('gX', port=8080), ids=[f'e{i}' for i in range(a.n) if i != 2]); time.sleep(1.0); blocked_off = not d.once('fin', port=8080)
        t_h = time.time(); d.link(['e2'], True); d.wait_head(e2_['slot'], ['e2'], 40); tb = time.time()
        while not d.once('fin', port=8080) and time.time() - tb < 20: pass
        X['T9_endpoint_offline'] = dict(blocked_while_offline=blocked_off, allowed_after_heal_s=round(time.time() - t_h, 2))
        # revocation with an established session
        st_ = d.stream(); time.sleep(2.5); t_r = time.time(); rv, _ = d.commit('REVOKE', dict(id='gF')); X['revoke_committed_all_s'] = round(time.time() - t_r, 3); time.sleep(1.5)
        sf, ss, sg_ = d.finish(pf), d.finish(st_), d.finish(pg)
        t_open = first_after(sf, t_g, 1); t_block = first_after(sf, t_r, 0); s_stop = first_after(ss, t_r, 0); f_ = lambda a_, b_: round(a_ - b_, 3) if a_ is not None else None
        X.update(t_open_s=f_(t_open, t_g), t_new_conn_blocked_s=f_(t_block, t_r), t_session_reset_s=f_(s_stop, t_r),
                 stream_ok_before=all(o for ts, o in ss if ts < t_r - 0.2 and ts > t_r - 2.0), nft_grants_all_edges=nftg, nft_after_revoke={k: d.nft_grants(k) for k in ('e0', 'e1', 'e2')},
                 guest_never_allowed=all(o == 0 for ts, o in sg_), conformance=[v[0] for v in check(d.trace(), d.ctl_T if hasattr(d, 'ctl_T') else quorum(a.n, a.b), 0)])
        R['dp_traffic'] = X; R['dp_traffic_timeline'] = dict(fin=[(round(t - t_g, 3), o) for t, o in sf if t > t_g - 2], stream=[(round(t - t_g, 3), o) for t, o in ss if t > t_g - 2], grant=0.0, revoke=t_r - t_g)
    finally: d.stop()
def scen_failover(a, R):
    d = Dep(a.out, a.n, 'S2', a.b, tag='failover', delay_ms=a.delay_ms)
    try:
        d.commit('GRANT', G('gF')); time.sleep(1.5); h0 = d.heads(); pf = d.probe('fin', tag='fin'); st_ = d.stream(); time.sleep(2.0)
        t0 = time.time(); d.nsx('e1', 'ip link set wg_e1 down'); time.sleep(4.0); t1 = time.time(); d.nsx('e1', 'ip link set wg_e1 up'); time.sleep(5.0)
        sm = d.finish(pf); ss = d.finish(st_); h1 = d.heads()
        def outage(smp, t_from, t_to):
            bad = [ts for ts, o in smp if t_from <= ts <= t_to and o == 0]; return (min(bad), max(bad)) if bad else None
        o1 = outage(sm, t0, t0 + 3.0); o2 = outage(sm, t1, t1 + 4.0); path = [x for x in d.events('path_down')] + [x for x in d.events('path_up')]
        R['dp_failover'] = dict(hub_down_outage_s=round(o1[1] - o1[0] + 0.1, 2) if o1 else 0.0, first_fail_after_s=round(o1[0] - t0, 2) if o1 else None,
                                recovery_outage_s=round(o2[1] - o2[0] + 0.1, 2) if o2 else 0.0, chain_slots_consumed=sum(h1.values()) - sum(h0.values()),
                                traffic_ok_on_backup=all(o for ts, o in sm if t0 + 2.5 < ts < t1), events=sorted((x['e'], x['ev'], x['peer'], round(x['t'] - t0, 2)) for x in path)[:8])
    finally: d.stop()
def scen_compromised(a, R):
    d = Dep(a.out, a.n, 'S2', a.b, tag='compromised', delay_ms=a.delay_ms); X = {}
    try:
        d.commit('GRANT', G('gF')); time.sleep(2.0); X['legit_allowed'] = d.once('fin')
        d.nsx('e0', 'nft delete table inet wp'); d.nsx('e0', "sh -c 'nft add table inet x; nft add chain inet x f { type filter hook forward priority 0 \\; policy accept \\; }'")
        pre_drop = d.counter('e1', 'default-deny') if False else None
        def hub_default_deny():
            t = d.nsx('e1', 'nft list chain inet wp forward', ok=False).stdout; m = re.search(r'packets (\d+) bytes \d+ drop comment "default-deny"', t); return int(m.group(1)) if m else 0
        b0 = hub_default_deny(); ok22 = d.once('fin', port=22); time.sleep(0.5); b1 = hub_default_deny()
        X['T27_nongranted_flow_through_compromised_edge'] = dict(connected=ok22, hub_default_deny_packets=b1 - b0)
        g0 = d.counter('e1', 'gF'); out = d.nsx('e0', f'{sys.executable} {HERE}/spoof.py 10.2.0.5 10.2.0.2 443 40').stdout.strip(); time.sleep(0.5); g1 = d.counter('e1', 'gF')
        out2 = d.nsx('e0', f'{sys.executable} {HERE}/spoof.py 10.1.0.99 10.2.0.2 443 40').stdout.strip(); time.sleep(0.5); g2 = d.counter('e1', 'gF')
        X['T26_spoof'] = dict(other_site_prefix_packets_reaching_hub_rules=g1 - g0, own_site_prefix_packets_reaching_hub_rules=g2 - g1)
        R['dp_compromised'] = X
    finally: d.stop()
def scen_crash(a, R):
    d = Dep(a.out, a.n, 'S2', a.b, tag='crash', delay_ms=a.delay_ms); rnd = random.Random(4); X = dict(rounds=[]); prefixes = [set()]
    try:
        for rd in range(3):
            t_b = time.time(); t_kill = t_b + rnd.uniform(0.7, 2.0); killed = False
            for k in range(14):
                e = d.ctl.build('GRANT', G(f'g{rd}x{k}', port=3000 + rd * 20 + k)); d.ctl.send(e, list(d.procs)); d.ctl.accept(e)
                prefixes.append(prefixes[-1] | {f'g{rd}x{k}'}); time.sleep(rnd.uniform(0.05, 0.2))
                if not killed and time.time() >= t_kill: d.procs['e0'].kill(); killed = True
            if not killed: d.procs['e0'].kill()
            d.procs['e0'].wait(); time.sleep(0.4); mid = set(d.nft_grants('e0')); ok_prefix = any(mid == p for p in prefixes)
            d.spawn('e0'); t0 = time.time(); target = d.ctl.slot
            d.wait_head(target, None, 90); time.sleep(1.5)
            fin = set(d.nft_grants('e0')); head_e0 = d.status('e0')['head']
            X['rounds'].append(dict(grants_in_ruleset_after_kill=len(mid), consistent_with_some_chain_prefix=ok_prefix, restart_to_head_s=round(time.time() - t0, 2), ruleset_equals_chain_after_restart=(fin == prefixes[-1]), restored_head=head_e0, chain_slots=target))
        R['dp_crash'] = X
    finally: d.stop()
def scen_join(a, R):
    d = Dep(a.out, a.n, 'S2', a.b, tag='join', delay_ms=a.delay_ms, skip=[f'e{a.n - 1}'], dp=False); late = f'e{a.n - 1}'; rows = []; slot = 0
    try:
        for K in a.join_k:
            while slot < K:
                d.commit('GRANT', G(f'j{slot}', port=1000 + slot), ids=[f'e{i}' for i in range(a.n - 1)]); slot += 1
            for f_ in os.listdir(f'{d.out}/rec'):
                if f_.startswith(late + '.'): os.remove(f'{d.out}/rec/{f_}')
            if os.path.exists(f'{d.out}/status/{late}.json'): os.remove(f'{d.out}/status/{late}.json')
            t0 = time.time(); d.spawn(late, late=True)
            def active(st_): return st_[late] and st_[late]['head'] >= K and st_[late]['state'] == 'VOTING'
            try: d.wait(active, 120, 'join')
            except TimeoutError: pass
            s_ = d.status(late); ev = sorted([x for x in d.events('state', eid=late) if x.get('to') == 'VOTING' and x['t'] >= t0], key=lambda x: x['t'])
            rows.append(dict(chain_len=K, power_on_to_active_s=round((ev[0]['t'] - t0), 2) if ev else None, chain_bytes=d.status('e0')['chain_bytes'], rss_mb=s_['rss_mb'] if s_ else None, joiner_head=s_['head'] if s_ else None))
            print(rows[-1], flush=True); d.procs[late].terminate(); d.procs[late].wait(); time.sleep(0.5)
        R['dp_join'] = rows
    finally: d.stop()
def scen_scale(a, R):
    rows = []
    for n in a.scale:
        for mode in ('S1', 'S2'):
            b = max(1, (n - 1) // 3); d = Dep(a.out, n, mode, b, gossip=60.0, delta_w=30.0, delay_ms=a.delay_ms, dp=False, tag=f'scale_{mode}_{n}')
            try:
                time.sleep(1.0); b0 = d.statuses(); e = d.ctl.build('GRANT', G('g1')); t0 = time.time(); d.ctl.send(e, list(d.procs)); d.ctl.accept(e); d.wait_head(1, None, 90); time.sleep(0.5)
                s1 = d.statuses(); ev = d.events('enforce', 1)
                rows.append(dict(n=n, mode=mode, b=b, T=quorum(n, b), latency_all_s=round(max(x['t'] for x in ev) - t0, 3), latency_median_s=round(st.median(x['t'] - t0 for x in ev), 3),
                                 msgs_per_edge=round(st.mean(s1[k]['msgs'] - b0[k]['msgs'] for k in s1)), kB_per_edge=round(st.mean(s1[k]['bytes'] - b0[k]['bytes'] for k in s1) / 1024, 1),
                                 cpu_ms_per_edge=round(1000 * st.mean(s1[k]['cpu_s'] - b0[k]['cpu_s'] for k in s1), 1), rss_mb=round(st.mean(s1[k]['rss_mb'] for k in s1), 1), verifies_per_edge=round(st.mean(s1[k]['verifies'] - b0[k]['verifies'] for k in s1))))
                print(rows[-1], flush=True); R['dp_scale'] = list(rows); json.dump(R, open(f'{a.out}/dp_results.json', 'w'), indent=1, default=str)
            except Exception as ex: rows.append(dict(n=n, mode=mode, error=repr(ex)[:300])); print('FAILED', n, mode, repr(ex)[:200], flush=True)
            finally: d.stop()
    R['dp_scale'] = rows
def scen_attack(a, R):
    for mode, byz in (('S1', 0), ('S2', 0), ('S2', 1)):
        tag = f'attack_{mode}_byz{byz}'; n = a.attack_n; ids = [f'e{i}' for i in range(n)]; A, B = ids[:n // 2], ids[n // 2:]
        d = Dep(a.out, n, mode, 1, gossip=5.0, delta_w=30.0, delay_ms=a.delay_ms, dp=False, byz=[ids[-1]] if byz else (), tag=tag)
        try:
            d.partition(A, B); P = d.ctl.build('GRANT', G('gA')); P2 = d.ctl.build('GRANT', G('gB', 'Sales', 'Finance')); t_att = time.time(); d.ctl.send(P, A); d.ctl.send(P2, B); time.sleep(4.0)
            hon = [e for e in ids if e not in d.byz]; sts = d.statuses(hon); dig = [sts[e]['enforced'].get('1') for e in hon]
            D = sum(1 for i in range(len(dig)) for j in range(i + 1, len(dig)) if dig[i] and dig[j] and dig[i] != dig[j])
            r = dict(mode=mode, byz=byz, T=quorum(n, 1), divergent_pairs_4s=D, enforced_4s=sum(1 for x in dig if x), distinct=len({x for x in dig if x}))
            if mode == 'S1':
                time.sleep(max(0.0, a.tau - 4.0)); d.heal(); time.sleep(5.0 * 2 + 3); fk = [x['t'] for x in d.events('fork_alert')]
                r.update(tau=a.tau, W_first_fork_alert=round(min(fk) - t_att, 2) if fk else None, forks_alerted=len(fk))
            else:
                d.heal(); t_res = time.time(); d.adm.resolve(1, 1, P)
                try: d.wait_head(1, hon, 30); ev = d.events('enforce', 1); r.update(resolve_to_all_commit_s=round(max(x['t'] for x in ev) - t_res, 2), distinct_after=len({d.statuses(hon)[e]['enforced'].get('1') for e in hon}))
                except TimeoutError: r.update(resolve_to_all_commit_s=None)
                r['conformance'] = [v[0] for v in check(d.trace(), quorum(n, 1), byz)]
            R[tag] = r
        except Exception as ex: R[tag + '_error'] = repr(ex)[:300]
        finally: d.stop()
def scen_offline(a, R):
    n = 12; b = 1
    for c in (4, 5):
        d = Dep(a.out, n, 'S2', b, gossip=5.0, delay_ms=a.delay_ms, dp=False, tag=f'offline_c{c}')
        try:
            ids = list(d.procs); dead = ids[n - 1 - c:]; d.link(dead, False); up = [x for x in ids if x not in dead]
            e = d.ctl.build('GRANT', G('g1')); d.ctl.accept(e); t0 = time.time(); d.ctl.send(e, ids); r = dict(T=quorum(n, b), up=len(up), n_minus_b_minus_c=n - b - c)
            try: d.wait_head(1, up, 15, resend=e); r.update(committed=True, latency_s=round(time.time() - t0, 2))
            except TimeoutError: r.update(committed=False, latency_s=None)
            if not r['committed']:
                d.link(dead, True); time.sleep(1.0); d.ctl.send(e, ids)
                try: d.wait_head(1, ids, 30, resend=e); r['after_heal_reproposal'] = True
                except TimeoutError: r['after_heal_reproposal'] = False
            R[f'offline_b{b}_c{c}'] = r
        except Exception as ex: R[f'offline_c{c}_error'] = repr(ex)[:300]
        finally: d.stop()
def scen_lease(a, R):
    """An edge cut off from the control network keeps its tunnels but must stop forwarding at lease expiry.  Each edge's loaded ruleset is sampled
    (end-to-end traffic also stops as soon as ANY edge on the path applies the revocation: two-sided enforcement)."""
    d = Dep(a.out, a.n, 'S2', a.b, gossip=3.0, delta_w=6.0, tag='lease', delay_ms=a.delay_ms)
    try:
        pf = d.probe('fin', tag='fin'); time.sleep(1.5); t_g = time.time(); lease = t_g + a.lease
        d.commit('GRANT', G('gF', lease=lease)); time.sleep(1.0); samples = {'e0': [], 'e1': [], 'e2': []}; stop = threading.Event()
        def sampler():
            while not stop.is_set():
                for e in samples: samples[e].append((time.time(), 'gF' in d.nft_grants(e)))
                time.sleep(0.2)
        th = threading.Thread(target=sampler, daemon=True); th.start()
        t_part = time.time(); d.link(['e0'], False)                                      # control network of e0 cut; its WireGuard tunnels (data underlay) stay up
        others = [f'e{i}' for i in range(1, a.n)]; t_rv = time.time(); d.commit('REVOKE', dict(id='gF'), ids=others)
        time.sleep(max(0.0, lease - time.time()) + 3.0); t_heal = time.time(); d.link(['e0'], True)
        d.wait(lambda s_: s_['e0'] and s_['e0']['head'] >= 2, 40, 'e0 catch-up'); t_catch = time.time(); time.sleep(1.0); stop.set(); th.join(timeout=3)
        sm = d.finish(pf); gone = lambda e: next((t - t_part for t, ok in samples[e] if t > t_part and not ok), None); t_block = first_after(sm, t_part + 0.05, 0)
        R['dp_lease'] = dict(lease_s=a.lease, lease_expiry_after_partition_s=round(lease - t_part, 2), rule_removed_after_partition_s={e: (round(gone(e), 2) if gone(e) is not None else None) for e in samples},
                             end_to_end_blocked_after_partition_s=round(t_block - t_part, 2) if t_block else None, revoke_committed_elsewhere_after_partition_s=round(t_rv - t_part, 2),
                             e0_catchup_after_heal_s=round(t_catch - t_heal, 2), e0_head_after=d.status('e0')['head'])
        R['dp_lease_timeline'] = dict(probe=[(round(t - t_g, 3), o) for t, o in sm], rules={e: [(round(t - t_g, 3), int(ok)) for t, ok in v] for e, v in samples.items()}, partition=t_part - t_g, expiry=lease - t_g, heal=t_heal - t_g, catchup=t_catch - t_g)
    finally: d.stop()
if __name__ == '__main__':
    ap = argparse.ArgumentParser(); ap.add_argument('--n', type=int, default=7); ap.add_argument('--b', type=int, default=1); ap.add_argument('--out', default='real_dp_out')
    ap.add_argument('--scenarios', default='traffic,failover,compromised,crash,join,scale,attack,offline,lease'); ap.add_argument('--attack-n', type=int, default=12); ap.add_argument('--tau', type=float, default=20.0); ap.add_argument('--lease', type=float, default=14.0); ap.add_argument('--delay-ms', type=float, default=50.0)
    ap.add_argument('--join-k', type=lambda x: [int(v) for v in x.split(',')], default=[10, 50, 150]); ap.add_argument('--scale', type=lambda x: [int(v) for v in x.split(',')], default=[8, 16])
    a = ap.parse_args(); a.out = os.path.abspath(a.out); os.makedirs(a.out, exist_ok=True)
    R = json.load(open(f'{a.out}/dp_results.json')) if os.path.exists(f'{a.out}/dp_results.json') else {}
    for sc in a.scenarios.split(','):
        print('== scenario', sc, flush=True)
        R.pop(f'{sc}_error', None); R[f'{sc}_ran_at'] = time.strftime('%Y-%m-%dT%H:%M:%S%z')      # stale errors/results from earlier runs must not look current
        try: globals()['scen_' + sc](a, R)
        except Exception as ex:
            import traceback; traceback.print_exc(); R[f'{sc}_error'] = repr(ex)
        json.dump(R, open(f'{a.out}/dp_results.json', 'w'), indent=1, default=str)
        print(json.dumps({k: v for k, v in R.items() if 'timeline' not in k}, default=str)[:1800], flush=True)
    print('done')
