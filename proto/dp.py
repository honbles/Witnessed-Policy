"""Data plane of one edge: userspace WireGuard (wireguard-go) peers derived from committed paths + nftables default-deny
with ingress binding and per-grant return rules.  Everything is rebuilt from the committed chain state."""
import ipaddress, json, os, shutil, socket, subprocess, threading, time
from collections import deque
def sh(cmd): return subprocess.run(cmd, shell=True, capture_output=True, text=True)
def sites_beyond(S, me, nbr, kinds=('primary',)):
    adj = {}
    for p in S.paths.values():
        if p['kind'] in kinds: adj.setdefault(p['a'], set()).add(p['b']); adj.setdefault(p['b'], set()).add(p['a'])
    seen = {me, nbr}; q = deque([nbr])
    while q:
        x = q.popleft()
        for y in adj.get(x, ()):
            if y not in seen: seen.add(y); q.append(y)
    return seen - {me}
def prefixes(S, sites):
    out = []
    for sg in S.seg.values():
        if sg['site'] in sites: out.append(sg['cidr']); out += [sg['cidr6']] if sg.get('cidr6') else []
    return out
def compile_dp(grants, S, locals_):
    segs = sorted({x for gr in grants.values() for x in (gr['src'], gr['dst'])} | {sg for l in locals_ for sg in l['segs']})
    segs = [x for x in segs if x in S.seg]
    L = ['table inet wp', 'delete table inet wp', 'table inet wp {']
    for sg in segs: L.append(f'  set {sg} {{ type ipv4_addr; flags interval; elements = {{ {S.seg[sg]["cidr"]} }} }}')
    L += ['  chain forward { type filter hook forward priority 0; policy drop;']
    for l in locals_: L.append(f'    iifname "{l["iface"]}" ip saddr != {{ {", ".join(S.seg[x]["cidr"] for x in l["segs"])} }} counter drop comment "ingress-binding"')
    for gid, gr in sorted(grants.items()):
        if gr['src'] in S.seg and gr['dst'] in S.seg:
            L.append(f'    ip saddr @{gr["src"]} ip daddr @{gr["dst"]} tcp dport {gr["port"]} counter accept comment "{gid}"')
            L.append(f'    ip saddr @{gr["dst"]} ip daddr @{gr["src"]} tcp sport {gr["port"]} ct state established accept comment "{gid}-ret"')
    L += ['    counter drop comment "default-deny"', '  }', '}']
    return '\n'.join(L) + '\n'
class DP:
    def __init__(s, e, g, cfg, net):
        s.e, s.g, s.cfg, s.net = e, g, cfg, net; s.id = e.id; s.ifn = f'wg_{e.id}'; s.tip = g['wg'][e.id]['tip']; s.lock = threading.RLock()
        s.down = set(); s.applied = None; s.rules = None; s.proc = None; s.live = True
    def start(s):
        have = sh(f'ip -d link show {s.ifn}')
        if have.returncode == 0 and 'wireguard' in have.stdout: s.kernel = True          # device survived a kill -9 of this edge: reuse it (it is rebuilt from the chain)
        else:
            if have.returncode == 0: sh(f'ip link del {s.ifn}')
            s.kernel = sh(f'ip link add dev {s.ifn} type wireguard').returncode == 0       # prefer the kernel module; fall back to userspace wireguard-go
        if not s.kernel:
            env = dict(os.environ, WG_PROCESS_FOREGROUND='1'); s.logf = open(s.cfg.get('log', os.devnull), 'a')
            s.proc = subprocess.Popen(['wireguard-go', '-f', s.ifn], env=env, stdout=s.logf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
            for _ in range(150):
                if sh(f'ip link show {s.ifn}').returncode == 0: break
                time.sleep(0.1)
        key = open(s.cfg['wgkey']).read().strip()                                           # key goes over stdin: some hosts deny `wg` access to key files by path
        r1 = subprocess.run(['wg', 'set', s.ifn, 'private-key', '/dev/stdin', 'listen-port', '51820'], input=key + '\n', capture_output=True, text=True); method = 'stdin'
        if r1.returncode: r1 = sh(f'wg set {s.ifn} private-key {s.cfg["wgkey"]} listen-port 51820'); method = 'file'
        sh(f'ip addr add {s.tip}/24 dev {s.ifn}'); sh(f'ip link set {s.ifn} up mtu 1380')
        hint = 'AppArmor profile wg may be blocking /usr/bin/wg: source wg_unconfine.sh (run_real.sh does) or WP_FORCE_UNCONFINE=1' if r1.returncode and 'denied' in (r1.stderr or '').lower() else ''
        s.net.log(e=s.id, ev='wg_start', kernel=s.kernel, rc=r1.returncode, method=method, err=r1.stderr[:200], wg=shutil.which('wg'), hint=hint)
        sh('sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0'); sh('sysctl -qw net.ipv6.conf.all.forwarding=1')
        s.t_start = time.time(); s.rtt = {}
        threading.Thread(target=s.echo, daemon=True).start(); threading.Thread(target=s.monitor, daemon=True).start()
    def handshakes(s):
        out = sh(f'wg show {s.ifn} latest-handshakes').stdout.split()
        return sum(1 for i in range(1, len(out), 2) if out[i].isdigit() and int(out[i]) > 0)
    def diag(s):
        return dict(wg=sh(f'wg show {s.ifn}').stdout[-900:], addr=sh(f'ip -br addr').stdout[-400:], route=sh('ip route').stdout[-300:], link=sh(f'ip -s link show {s.ifn}').stdout[-500:])
    def info(s): return dict(kernel=getattr(s, 'kernel', None), handshakes=s.handshakes(), down=sorted(s.down), rtt_ms={k: round(1000 * v, 1) for k, v in getattr(s, 'rtt', {}).items()})
    def echo(s):
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind((s.tip, 7777))
        while True:
            d, a = u.recvfrom(64); u.sendto(b'pong', a)
    def desired(s):
        S = s.e.S; peers = {}; nb = {}
        for p in S.paths.values():
            if s.id in (p['a'], p['b']):
                o = p['b'] if p['a'] == s.id else p['a']
                if o in S.members: nb.setdefault(o, set()).add(p['kind'])
        for o, kinds in nb.items():
            allowed = [f'{s.g["wg"][o]["tip"]}/32']
            if 'primary' in kinds and o not in s.down: allowed += prefixes(S, sites_beyond(S, s.id, o))
            peers[o] = allowed
        for d in s.down:                                  # failover: hand the prefixes beyond a dead primary neighbour to a live backup neighbour
            lost = prefixes(S, sites_beyond(S, s.id, d)); alt = [o for o, k in nb.items() if 'backup' in k and o not in s.down and 'primary' not in k]
            if alt:
                for pr in lost: peers[alt[0]].append(pr)
        return peers
    def apply(s):
        with s.lock:
            peers = s.desired(); key = json.dumps(peers, sort_keys=True)
            if key == s.applied: return
            args = [f'peer {s.g["wg"][o]["pk"]} allowed-ips {",".join(sorted(al))} endpoint {s.g["wg"][o]["ep"]} persistent-keepalive 1' for o, al in peers.items()]
            cur = sh(f'wg show {s.ifn} peers').stdout.split(); want = {s.g['wg'][o]['pk'] for o in peers}
            args += [f'peer {pk} remove' for pk in cur if pk not in want]
            rs = sh(f'wg set {s.ifn} ' + ' '.join(args))
            routes = {pr for al in peers.values() for pr in al if not pr.endswith('/32') or ':' in pr and False}
            have = {l.split()[0] for l in sh(f'ip route show dev {s.ifn}').stdout.splitlines() if l.strip()} - {f'{s.tip.rsplit(".",1)[0]}.0/24'}
            for pr in routes - have: sh(f'ip route replace {pr} dev {s.ifn}')
            for pr in have - routes: sh(f'ip route del {pr} dev {s.ifn}')
            for pr6 in [r for r in routes if ':' in r]: sh(f'ip -6 route replace {pr6} dev {s.ifn}')
            s.applied = key; s.net.log(e=s.id, ev='wg_apply', peers={o: len(a) for o, a in peers.items()}, down=sorted(s.down), rc=rs.returncode, err=rs.stderr[:200])
    def nft(s, force=False):
        with s.lock:
            now = time.time(); fresh = s.e.fresh()
            grants = {k: v for k, v in s.e.effective_grants().items() if fresh or now < v.get('lease', 1e18)}
            if s.e.state not in ('VERIFIED', 'VOTING'): grants = {}
            rules = compile_dp(grants, s.e.S, s.cfg['locals'])
            if rules != s.rules or force:
                p = sh('nft -f - <<\'EOF\'\n' + rules + 'EOF'); s.rules = rules; s.net.log(e=s.id, ev='nft_apply', grants=sorted(grants), fresh=fresh, rc=p.returncode, err=p.stderr[:160])
    def refresh(s): s.apply(); s.nft()
    def monitor(s):
        """Heartbeat over the tunnel to each primary neighbour.  The reply timeout adapts to the measured RTT (a fixed 80 ms
        timeout declared every healthy tunnel dead when the links carried 50 ms of delay)."""
        miss = {}; okc = {}; hint = float(s.cfg.get('rtt_hint', 0.0)); grace_until = time.time() + float(s.cfg.get('grace', 6.0)); diag_done = False
        while s.live:
            time.sleep(0.1)
            if not s.e.S: continue
            if not diag_done and time.time() - s.t_start > 10 and s.handshakes() == 0:
                diag_done = True; s.net.log(e=s.id, ev='wg_diag', **s.diag())
            for p in list(s.e.S.paths.values()):
                if s.id in (p['a'], p['b']) and p['kind'] == 'primary':
                    o = p['b'] if p['a'] == s.id else p['a']; to = max(0.15, 2 * s.rtt.get(o, hint) + 0.1, 0.1 + 2 * hint)
                    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(to); t0 = time.time()
                    try: u.sendto(b'ping', (s.g['wg'][o]['tip'], 7777)); u.recvfrom(16); ok = True; s.rtt[o] = 0.7 * s.rtt.get(o, time.time() - t0) + 0.3 * (time.time() - t0)
                    except Exception: ok = False
                    u.close()
                    if not ok and time.time() < grace_until and o not in s.rtt: continue          # tunnel still handshaking: not a failure yet
                    miss[o] = 0 if ok else miss.get(o, 0) + 1; okc[o] = okc.get(o, 0) + 1 if ok else 0
                    if miss[o] >= 3 and o not in s.down: s.down.add(o); s.net.log(e=s.id, ev='path_down', peer=o, timeout_ms=round(1000 * to)); s.apply()
                    if okc[o] >= 5 and o in s.down: s.down.discard(o); s.net.log(e=s.id, ev='path_up', peer=o); s.apply()
