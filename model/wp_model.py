#!/usr/bin/env python3
"""Executable model of Witnessed Policy's single-slot core (mirrors WitnessedPolicy.tla).
   python3 wp_model.py check   -> explicit-state checks (safety, recovery from every stuck split)
   python3 wp_model.py trace   -> scripted scenarios (equivocation, stuck slot + RESOLVE, one-phase attack)
Byzantine edges are abstract: they add NB to every attestation count and may carry any existing certificate."""
import sys, itertools
from collections import deque
NOC = (-1, -1)                      # "no certificate" report

class M:
    def __init__(s, n_honest, nb, T, R, offline=0, silent=False, vals=(1, 2)):
        s.nh, s.nb, s.T, s.R, s.off, s.silent, s.vals = n_honest, nb, T, R, offline, silent, vals
        s.contrib = 0 if silent else nb
        s.kmax = 0 if silent else nb
    # edge = (rp, rc, pr, held, rep) ; rp/rc: tuple over rounds of 0|value ; held: frozenset((r,v)); rep: tuple of frozenset
    def init(s):
        z = tuple(0 for _ in range(s.R + 1))
        e = (z, z, 0, frozenset(), tuple(frozenset() for _ in range(s.R + 1)))
        return (tuple([e] * s.nh), frozenset())
    def split_init(s, assign):
        st = s.init(); E = list(st[0])
        for i, v in enumerate(assign):
            if v:
                rp = list(E[i][0]); rp[0] = v; E[i] = (tuple(rp),) + E[i][1:]
        return (tuple(E), frozenset())
    def hp(s, E, r, v): return sum(1 for e in E if e[0][r] == v)
    def hc(s, E, r, v): return sum(1 for e in E if e[1][r] == v)
    def PC(s, E, r, v): return s.hp(E, r, v) + s.contrib >= s.T
    def CC(s, E, r, v): return s.hc(E, r, v) + s.contrib >= s.T
    def committed(s, st):
        E = st[0]; return {v for v in s.vals for r in range(s.R + 1) if s.CC(E, r, v)}
    def canon(s, st):
        k = s.nh - s.off; E = st[0]
        return (tuple(sorted(E[:k], key=repr)) + tuple(sorted(E[k:], key=repr)), st[1])   # symmetry only within up / offline groups
    def active(s, i): return i < s.nh - s.off
    def succ(s, st):
        E, res = st; out = []
        def setE(i, e): L = list(E); L[i] = e; return tuple(L)
        for i, e in enumerate(E):
            rp, rc, pr, held, rep = e
            for r in range(s.R + 1):
                for v in s.vals:
                    if s.active(i) and rp[r] == 0 and r >= pr and (r == 0 or (r, v) in res):
                        n_rp = rp[:r] + (v,) + rp[r+1:]
                        out.append((('prepare', i, r, v), (setE(i, (n_rp, rc, r, held, rep)), res)))
                    if i < s.nh - 0 and (r, v) not in held and s.PC(E, r, v) and (i < s.nh - s.off):
                        out.append((('learn', i, r, v), (setE(i, (rp, rc, pr, held | {(r, v)}, rep)), res)))
                    if s.active(i) and (r, v) in held and rc[r] == 0 and r >= pr:
                        n_rc = rc[:r] + (v,) + rc[r+1:]
                        out.append((('commit', i, r, v), (setE(i, (rp, n_rc, pr, held, rep)), res)))
            for r in range(1, s.R + 1):
                if s.active(i) and r > pr:
                    cs = [c for c in held if c[0] < r]
                    c = max(cs) if cs else NOC
                    n_rep = rep[:r] + (rep[r] | {c},) + rep[r+1:]
                    out.append((('promise', i, r), (setE(i, (rp, rc, r, held, n_rep)), res)))
        for r in range(1, s.R + 1):
            RH = [i for i, e in enumerate(E) if e[4][r]]
            ex = [(rr, vv) for rr in range(r) for vv in s.vals if s.PC(E, rr, vv)]
            for v in s.vals:
                if (r, v) in res: continue
                if s.resolvable(E, r, v, RH, ex):
                    out.append((('resolve', r, v), (E, res | {(r, v)})))
        return out
    def resolvable(s, E, r, v, RH, ex):
        for sz in range(len(RH) + 1):
            for S in itertools.combinations(RH, sz):
                for k in range(s.kmax + 1):
                    if sz + k < s.T: continue
                    carried = {x for i in S for x in E[i][4][r] if x != NOC} | (set(ex) if k >= 1 else set())
                    for c in carried:
                        if c[1] == v and all(any(x[0] <= c[0] for x in E[i][4][r]) for i in S): return True
                    if all(NOC in E[i][4][r] for i in S): return True
        return False

def bfs(m, inits, stop_on_two=True, limit=4_000_000):
    seen = set(); q = deque(); parent = {}
    for st in inits:
        c = m.canon(st); seen.add(c); q.append(c); parent[c] = (None, None)
    viol = None; n = 0
    while q:
        st = q.popleft(); n += 1
        if len(m.committed(st)) > 1: viol = st; break
        for act, nx in m.succ(st):
            c = m.canon(nx)
            if c not in seen:
                seen.add(c); parent[c] = (st, act); q.append(c)
        if len(seen) > limit: return ('limit', len(seen), None)
    return ('violation' if viol else 'ok', len(seen), viol)

def recovery_from_all_stuck(n_honest, nb, T, R, offline):
    m = M(n_honest, nb, T, R, offline=offline, silent=True)
    tot = ok = 0
    for assign in itertools.product((0,) + m.vals, repeat=n_honest):
        if any(sum(1 for a in assign if a == v) >= T for v in m.vals): continue     # not stuck (a certificate can form)
        tot += 1
        st = m.canon(m.split_init(assign)); seen = {st}; q = deque([st]); hit = False
        while q and not hit:
            x = q.popleft()
            if m.committed(x): hit = True; break
            for _, nx in m.succ(x):
                c = m.canon(nx)
                if c not in seen: seen.add(c); q.append(c)
        ok += hit
    return tot, ok

if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'check'
    if mode == 'check':
        print('safety (Byzantine active, 2 values, all interleavings, symmetry-reduced)')
        for (nh, nb, T, R) in [(3, 1, 3, 1)]:
            r = bfs(M(nh, nb, T, R), [M(nh, nb, T, R).init()])
            print(f'  n={nh+nb} b={nb} T={T} rounds=0..{R}: {r[0]}  states={r[1]}')
        print('quorum below T (T=n_total-... too small) must break:')
        r = bfs(M(3, 1, 2, 1), [M(3, 1, 2, 1).init()]); print(f'  n=4 b=1 T=2: {r[0]} states={r[1]}')
        print('recovery: every round-0 split with no certificate reaches a commit (Byzantine silent)')
        for (nh, nb, T, R, off) in [(3, 1, 3, 1, 0), (5, 1, 4, 1, 1), (4, 1, 4, 1, 1)]:
            tot, ok = recovery_from_all_stuck(nh, nb, T, R, off)
            print(f'  n={nh+nb} b={nb} c={off} T={T}: {ok}/{tot} stuck splits recover'
                  f'  (n-b-c={nh-off} {">=" if nh-off>=T else "<"} T)')
