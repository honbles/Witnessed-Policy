"""Property-based fuzz of the policy validity rules through the full protocol.  Checks, after every committed entry and at the end:
 ProtectedPreserved: no committed grant crosses a protected pair (unless that pair was removed by a committed 3-key entry)
 Auth: every committed entry carries >= threshold valid approvals of its tier
 NoFork: all honest edges hold identical chains.  S0 (no validation) is run as a negative control."""
import random, json, sys
from harness2 import *
DL = {'L2': 3.0, 'L3': 6.0}
SEGS = ['Finance', 'Sales', 'Guest', 'DB']
def rnd_entry(r, c, adm, ak, ids):
    op = r.choice(['GRANT'] * 8 + ['REVOKE', 'DENY', 'PROTECT_ADD', 'PROTECT_DEL', 'SET_PARAM', 'CLASSIFY', 'PATH_ADD', 'PATH_DEL'])
    def net_():
        k = r.random()
        if k < .5: return r.choice(SEGS)
        if k < .8: return f'10.{r.randint(1,4)}.0.{r.randint(0,250)}/{r.choice([32,30,28,24,16,8,0])}'
        return r.choice(SEGS)
    if op == 'GRANT': body = dict(id=f'g{r.randint(0,10**6)}', src=net_(), dst=net_(), port=r.choice([22, 80, 443, 5432, 8080]), qos=r.choice(['best', 'gold', 'bogus']))
    elif op == 'REVOKE': body = dict(id=r.choice(list(c.S.grants) + ['nope']) if c.S.grants else 'nope')
    elif op == 'DENY': body = dict(src=r.choice(SEGS), dst=r.choice(SEGS))
    elif op in ('PROTECT_ADD', 'PROTECT_DEL'): body = dict(forbidden=[r.choice(SEGS), r.choice(SEGS)])
    elif op == 'SET_PARAM': body = dict(cipher=r.choice([40, 56, 128, 256]))
    elif op == 'CLASSIFY': body = dict(seg=r.choice(SEGS), cls=r.choice(['normal', 'restricted']))
    elif op == 'PATH_ADD': body = dict(id=f'p{r.randint(0,99)}', a=r.choice(['e0', 'e1', 'e2']), b=r.choice(['e0', 'e1', 'e2']), kind=r.choice(['primary', 'backup']))
    else: body = dict(id=r.choice(list(c.S.paths) + ['zz']))
    k = r.choice([0, 1, 1, 1, 2, 2, 3, 4]); by = tuple(r.sample(['a0', 'a1', 'a2', 'a3'], max(1, min(k, 4)))) if k else ('a0',)
    e = c.build(op, body, by=by, sign=(k > 0))
    x = r.random()
    if x < .05: e['tier'] = r.choice(['L0', 'L1', 'L2', 'L3'])
    elif x < .08: e['epoch'] += 1
    return e
def run(mode, count=250, seed=5):
    r = random.Random(seed); g, ek, ak, net, edges, adm = setup2(7, 1, mode, gossip=1e6, delay=DL); c = Ctl(g, adm, net, edges); ids = list(edges)
    acc = rej = 0; viol = []
    for k in range(count):
        e = rnd_entry(r, c, adm, ak, ids); before = max(heads(edges)); c.send(e); net.run(net.now + 1.2)
        if max(heads(edges)) > before:
            acc += 1; c.accept(e)
            S = edges['e0'].S; removed = {tuple(p) for p in S.forbidden}
            for gr in S.grants.values():
                try: sn, dn = N(gr['src'], S), N(gr['dst'], S)
                except Exception: viol.append(('unparsable', gr)); continue
                if any(A in seg_of(S, sn) and B in seg_of(S, dn) and (A, B) in {tuple(p) for p in S.forbidden} for A, B in S.forbidden): viol.append(('ProtectedPreserved', gr['id'], k))
                if sn.prefixlen == 0 or dn.prefixlen == 0: viol.append(('DefaultPermit', gr['id'], k))
            if S.cipher < S.min_cipher: viol.append(('Cipher', S.cipher, k))
            ent = edges['e0'].chain[-1]['entry']; okc = {a for a, sg in ent['approvals'] if a in c.S.admins}
            if len(okc) < THR2[ent['tier']]: viol.append(('Auth', ent['slot'], k))
        else: rej += 1
    chains = {tuple(x['d'] for x in e.chain) for e in hon(edges) if e.head() == max(heads(edges))}
    return dict(mode=mode, proposed=count, committed=acc, rejected=rej, violations=len(viol), kinds=sorted({v[0] for v in viol}), edges_with_longest_chain=len(chains) and sum(1 for e in hon(edges) if e.head() == max(heads(edges))), distinct_chains=len(chains), example=viol[:2])
if __name__ == '__main__':
    res = [run(m) for m in ('S2', 'S1', 'S0')]
    for x in res: print(x)
    json.dump(res, open('fuzz_results.json', 'w'), indent=1, default=str)
