#!/usr/bin/env python3
"""E1 (attack-model Monte Carlo): divergent-enforcement window of S1 vs S2.
Stolen key signs P != P' on one base; controller splits E=E1+E2 (|E1|=n/2) and partitions them for tau_p seconds.
Every edge gossips its signed head every g s with independent uniform phase; one-way delay delta.
S1: both sides validate+enforce at t=0 => D(t)=|E1||E2| until the first cross-side head arrives.
S2: neither value reaches T prepares (each side <= n/2 < T) => D(t)=0 for all t."""
import random, statistics as st, math
def window(n, g, tau, delta, rng):
    best = 1e18
    for _ in range(n):
        ph = rng.uniform(0, g)
        t = ph if ph >= tau else ph + math.ceil((tau - ph) / g) * g
        best = min(best, t + delta)
    return best
rng = random.Random(1); n = 12; delta = 0.05; N = 20000
print(f"n={n} |E1|=|E2|={n//2} pairs diverging={n//2*n//2}  delta={delta}s  trials={N}")
print("g(s) tau_p(s)  mean_W(s)  p99_W(s)  edge-pair-seconds(mean)")
for g in (10, 30, 60, 300):
    for tau in (0, 60, 600, 3600):
        w = [window(n, g, tau, delta, rng) for _ in range(N)]
        w.sort(); m = st.mean(w); p99 = w[int(.99 * N)]
        print(f"{g:4d} {tau:6d}  {m:9.2f} {p99:9.2f}  {m*(n//2)**2:10.1f}")
