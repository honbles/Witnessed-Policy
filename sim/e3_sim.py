"""E3: synthetic outage traces -> commit availability and time-to-commit for quorum T(n,b) vs T(n,b+c).
No public SD-WAN outage traces are used: edges follow a two-state up/down Markov process (optionally with correlated regional outages)."""
import random, bisect, json, statistics as st
H_ = 20000.0     # hours simulated
def timeline(rnd, mu, md, H):
    t = 0.0; up = rnd.random() < mu / (mu + md); iv = []; s = 0.0 if up else None
    while t < H:
        t += rnd.expovariate(1.0 / (mu if up else md))
        if up: iv.append((s, min(t, H)))
        else: s = t
        up = not up
    if up and s is not None and s < H and (not iv or iv[-1][1] < H): iv.append((s, H))
    return iv
def intersect(a, b):
    i = j = 0; out = []
    while i < len(a) and j < len(b):
        lo, hi = max(a[i][0], b[j][0]), min(a[i][1], b[j][1])
        if lo < hi: out.append((lo, hi))
        if a[i][1] < b[j][1]: i += 1
        else: j += 1
    return out
def run(n, b, mu, md, regions=0, mu_r=None, md_r=None, seed=1, attempts=40000):
    rnd = random.Random(seed); H = H_; ev = []
    reg = [timeline(rnd, mu_r, md_r, H) for _ in range(regions)] if regions else []
    for i in range(b, n):                                  # edges 0..b-1 are Byzantine and silent
        iv = timeline(rnd, mu, md, H)
        if regions: iv = intersect(iv, reg[i % regions])
        for s, e in iv: ev += [(s, 1), (e, -1)]
    ev.sort(); cnt = 0; pts = []
    for t, d in ev: cnt += d; pts.append((t, cnt))
    out = {}
    for name, Q in (('sep', (n + b + 2) // 2), ('simple', (n + b + 4 + 2 * 0 + 0) // 2)):
        pass
    return pts, rnd, H
def analyse(pts, Q, rnd, H, attempts):
    ts = [p[0] for p in pts]; ok = []; start = None
    for t, c in pts:
        if c >= Q and start is None: start = t
        elif c < Q and start is not None: ok.append((start, t)); start = None
    if start is not None: ok.append((start, H))
    starts = [a for a, _ in ok]; waits = []
    for _ in range(attempts):
        t = rnd.uniform(0, H - 1000); k = bisect.bisect_right(starts, t) - 1
        if k >= 0 and ok[k][0] <= t < ok[k][1]: waits.append(0.0)
        elif k + 1 < len(ok): waits.append(ok[k + 1][0] - t)
        else: waits.append(H - t)
    waits.sort(); N = len(waits)
    return dict(P_available=round(sum(1 for w in waits if w == 0) / N, 5), mean_wait_h=round(st.mean(waits), 4), p99_h=round(waits[int(.99 * N)], 3), p999_h=round(waits[int(.999 * N)], 3), max_h=round(waits[-1], 2)), waits
SC = {'iid-like (a=0.90, 1 h outages)': dict(mu=9.0, md=1.0), 'long outages (a=0.90, 10 h)': dict(mu=90.0, md=10.0),
      'regional correlated (a=0.95 + 3 regions)': dict(mu=19.0, md=1.0, regions=3, mu_r=300.0, md_r=3.0)}
out = {}; cdf = {}
for name, kw in SC.items():
    for (n, b, c) in ((12, 1, 4), (16, 1, 4)):
        T_sep = (n + b + 2) // 2; T_sim = (n + (b + c) + 2) // 2
        pts, rnd, H = run(n, b, seed=7, **kw)
        for lab, Q in (('separated', T_sep), ('simple', T_sim)):
            if Q > n - b: out[f'{name} | n={n} | {lab}'] = dict(Q=Q, note='infeasible (Q > n-b)'); continue
            r, w = analyse(pts, Q, random.Random(11), H, 40000); r['Q'] = Q; out[f'{name} | n={n} | {lab}'] = r; cdf[f'{name} | n={n} | {lab}'] = w[::40]
json.dump(out, open('e3_results.json', 'w'), indent=1); json.dump(cdf, open('e3_cdf.json', 'w'))
for k, v in out.items(): print(k, v)

# 20-seed means with 95% confidence intervals for the n=12, b=1 availability and 99.9th-percentile wait (Table V)
import math
ms = {}
for name, kw in {'1h': dict(mu=9.0, md=1.0), '10h': dict(mu=90.0, md=10.0), 'regional': dict(mu=19.0, md=1.0, regions=3, mu_r=300.0, md_r=3.0)}.items():
    for lab, Q in (('sep', (12 + 1 + 2) // 2), ('simple', (12 + 1 + 4 + 2) // 2)):
        P, Wt = [], []
        for seed in range(1, 21):
            pts, rnd, H = run(12, 1, seed=seed, **kw); r, _ = analyse(pts, Q, random.Random(11), H, 40000); P.append(r['P_available']); Wt.append(r['p999_h'])
        ms[f'{name}|{lab}'] = dict(Q=Q, P_mean=round(st.mean(P), 4), P_ci95=round(2.093 * st.stdev(P) / math.sqrt(len(P)), 4), p999_mean_h=round(st.mean(Wt), 2), seeds=20)
json.dump(ms, open('e3_multiseed.json', 'w'), indent=1)
