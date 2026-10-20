import json, math, re, os, sys
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
from math import comb
plt.rcParams.update({'font.size': 7.5, 'axes.grid': True, 'grid.alpha': .3, 'figure.dpi': 150, 'savefig.bbox': 'tight', 'font.family': 'serif'})
W, Hh = 3.45, 2.35
def T(n, b): return (n + b + 2) // 2
def Av(n, b, Q, a):
    h = n - b
    return sum(comb(h, k) * a**k * (1 - a)**(h - k) for k in range(Q, h + 1)) if Q <= h else 0.0
def save(fig, name):
    fig.savefig(name + '.pdf'); fig.savefig(name + '.png'); plt.close(fig)

# Fig 1: feasible (b,c) region, separated vs simple
fig, ax = plt.subplots(1, 2, figsize=(W, 2.3), sharey=True)
for a_, n in zip(ax, (12, 20)):
    bs = list(range(0, n // 3 + 1))
    sep = [max(-1, (n - 3 * b - 1) // 2) for b in bs]; sim = [max(-1, (n - 1) // 3 - b) for b in bs]
    a_.step(bs, sep, where='mid', color='C0', label='separated: $n\\geq3b+2c+1$'); a_.fill_between(bs, sim, sep, step='mid', color='C0', alpha=.25)
    a_.step(bs, sim, where='mid', color='C3', ls='--', label='simple: $n\\geq3(b+c)+1$')
    a_.set_title(f'$n={n}$'); a_.set_xlabel('Byzantine $b$'); a_.set_ylim(0, (n - 1) // 2 + .6)
ax[0].set_ylabel('max offline $c$'); fig.legend(*ax[0].get_legend_handles_labels(), fontsize=5.5, loc='lower center', ncol=2, bbox_to_anchor=(0.5, -0.02)); fig.subplots_adjust(bottom=0.32, wspace=.1)
save(fig, 'fig_region')

# Fig 2: availability vs per-edge availability
fig, ax = plt.subplots(figsize=(W, Hh)); xs = [0.5 + 0.005 * i for i in range(0, 100)]
for (n, b, c), col in (((12, 1, 4), 'C0'), ((20, 2, 6), 'C2')):
    ax.plot(xs, [Av(n, b, T(n, b), a) for a in xs], color=col, label=f'separated $T={T(n,b)}$ ($n{{=}}{n},b{{=}}{b},c{{=}}{c}$)')
    f = b + c
    if T(n, f) <= n - b: ax.plot(xs, [Av(n, b, T(n, f), a) for a in xs], color=col, ls='--', label=f'simple $T={T(n,f)}$')
ax.set_xlabel('per-edge availability $a$'); ax.set_ylabel('P(commit possible)'); ax.legend(fontsize=5.5, loc='lower right'); ax.set_ylim(0, 1.02)
save(fig, 'fig_avail')

# Fig 3: divergence window
mc = {}
for line in open('../sim/e1_results.txt'):
    m = re.match(r'\s*(\d+)\s+(\d+)\s+([\d.]+)\s+([\d.]+)', line)
    if m: mc[(int(m[1]), int(m[2]))] = (float(m[3]), float(m[4]))
fig, ax = plt.subplots(figsize=(W, Hh)); taus = [0, 60, 600, 3600]
for g, col in ((10, 'C0'), (30, 'C1'), (300, 'C3')):
    ax.plot(taus, [mc[(g, t)][0] for t in taus], 'o-', color=col, ms=3, label=f'S1, $g={g}$ s')
ax.plot(taus, [0] * 4, 's-', color='k', ms=3, label='S2 (no divergence)')
R = json.load(open('../proto/results.json')); w = R['attack_S1']['W']
ax.plot([60], [w], '*', color='m', ms=8, label='emulated S1 ($\\tau_p{=}60$)')
ax.set_xscale('symlog', linthresh=10); ax.set_yscale('symlog', linthresh=1); ax.set_xlabel('partition length $\\tau_p$ (s)'); ax.set_ylabel('window of divergent policy $W$ (s)'); ax.legend(fontsize=5.5)
save(fig, 'fig_window')

# Fig 4: cost scaling
rows = R['scale']; ns = sorted({r['n'] for r in rows})
g = lambda mode, k: [next(r[k] for r in rows if r['n'] == n and r['mode'] == mode) for n in ns]
fig, ax = plt.subplots(1, 2, figsize=(W, 2.1))
ax[0].loglog(ns, g('S1', 'msgs'), 'o-', label='S1', ms=3); ax[0].loglog(ns, g('S2', 'msgs'), 's-', label='S2', ms=3)
ax[0].loglog(ns, [2 * n * n for n in ns], 'k:', label='$2n^2$'); ax[0].set_xlabel('edges $n$'); ax[0].set_ylabel('messages / slot'); ax[0].legend(fontsize=5.5)
ax[1].plot(ns, g('S1', 'est_cpu_ms_per_edge'), 'o-', ms=3, label='S1'); ax[1].plot(ns, g('S2', 'est_cpu_ms_per_edge'), 's-', ms=3, label='S2')
ax[1].set_xlabel('edges $n$'); ax[1].set_ylabel('CPU ms / edge / slot'); ax[1].legend(fontsize=5.5)
fig.tight_layout(); save(fig, 'fig_cost')
# E1 sweep
sw = json.load(open('../proto/e1_sweep.json')); fig, ax = plt.subplots(figsize=(W, 2.0))
ax.plot([r['k'] for r in sw if r['mode'] == 'S1'], [r['divergent_pairs'] for r in sw if r['mode'] == 'S1'], 'o-', ms=3, color='C3', label='S1: divergent pairs $k(n{-}k)$')
ax.plot([r['k'] for r in sw if r['mode'] == 'S2'], [r['divergent_pairs'] for r in sw if r['mode'] == 'S2'], 's-', ms=3, color='k', label='S2: divergent pairs')
for r in sw:
    if r['mode'] == 'S2': ax.text(r['k'], 2.5, {'P': 'P', "P'": "P'", 'none': 'stall'}[r['committed_value']], ha='center', fontsize=5.5, color='C0')
ax.set_xlabel('edges $k$ receiving branch $P$ (of 12); S2 commits the labelled value'); ax.set_ylabel('divergent edge pairs'); ax.legend(fontsize=5.5, loc='upper center'); ax.set_ylim(-1, 42)
save(fig, 'fig_e1sweep')
# E3 CDF of time-to-commit
cd = json.load(open('../sim/e3_cdf.json')); fig, ax = plt.subplots(figsize=(W, 2.0))
for key, col, ls in (('long outages (a=0.90, 10 h) | n=12 | separated', 'C0', '-'), ('long outages (a=0.90, 10 h) | n=12 | simple', 'C0', '--'), ('regional correlated (a=0.95 + 3 regions) | n=12 | separated', 'C2', '-'), ('regional correlated (a=0.95 + 3 regions) | n=12 | simple', 'C2', '--')):
    w = sorted(cd[key]); n = len(w); xs = [max(x, 1e-3) for x in w]; ax.plot(xs, [(i + 1) / n for i in range(n)], color=col, ls=ls, label=key.split(' | ')[0].split(' (')[0] + (', $T{=}7$' if 'separated' in key else ', $T{=}9$'))
ax.set_xscale('log'); ax.set_xlabel('wait until a commit is possible (h)'); ax.set_ylabel('CDF'); ax.set_ylim(0.88, 1.002); ax.legend(fontsize=5, loc='lower right')
save(fig, 'fig_e3cdf')
if os.path.exists(os.environ.get('DP_FILE', '../paper_data/dp_merged.json')): exec(open('plots_real.py').read())
print('plots ok', sorted(f for f in os.listdir('.') if f.endswith('.png')))
