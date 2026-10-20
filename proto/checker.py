"""Trace conformance checker: replays an event trace against the guards of WitnessedPolicy.tla
(NoDoubleAttest, PromiseRespected, PreparedBeforeCommit, UniqueCommit)."""
from collections import defaultdict
def check(trace, T, byz_count, lost_ok=()):
    v = []; seen = set(); promised = {}; preps = defaultdict(set); enf = defaultdict(set)
    for ev in trace:
        k = ev.get('ev'); e = ev.get('e')
        if k in ('prepare', 'commit_att'):
            key = (e, k, ev['slot'], ev['r'])
            if key in seen and e not in lost_ok: v.append(('NoDoubleAttest', key, ev['t']))
            seen.add(key)
            if ev['r'] < promised.get((e, ev['slot']), 0): v.append(('PromiseRespected', key, ev['t']))
            if k == 'prepare':
                promised[(e, ev['slot'])] = max(promised.get((e, ev['slot']), 0), ev['r']); preps[(ev['slot'], ev['r'], ev['d'])].add(e)
            else:
                if len(preps[(ev['slot'], ev['r'], ev['d'])]) + byz_count < T: v.append(('PreparedBeforeCommit', key, ev['t']))
        elif k == 'promise': promised[(e, ev['slot'])] = max(promised.get((e, ev['slot']), 0), ev['r'])
        elif k == 'enforce': enf[ev['slot']].add(ev['d'])
    for s, ds in enf.items():
        if len(ds) > 1: v.append(('UniqueCommit', s, sorted(ds)))
    return v

def check_epochs(trace, b):
    """EpochSafety: all attestations of a slot use one (epoch, n, T) and T = ceil((n+b+1)/2)."""
    v = []; per = {}
    for ev in trace:
        if ev.get('ev') in ('prepare', 'commit_att') and 'ep' in ev:
            k = (ev['ep'], ev['n'], ev['T']); per.setdefault(ev['slot'], set()).add(k)
            if ev['T'] != (ev['n'] + b + 2) // 2: v.append(('quorum-size', ev['slot'], k))
    for s, ks in per.items():
        if len(ks) > 1: v.append(('mixed-epoch-slot', s, sorted(ks)))
    return v
