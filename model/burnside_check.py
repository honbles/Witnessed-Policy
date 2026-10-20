"""TLC quotients the state space by permuting edges AND swapping the two values; the Python model only by permuting edges.
By Burnside the TLC count must equal (python_count + number_of_value-swap-invariant_states) / 2.  Checks that for n=4, b=1, T=3, rounds 0..1."""
from collections import deque
from wp_model import M, NOC
def sw(v): return 0 if v == 0 else 3 - v
def swap(st):
    E, res = st; out = []
    for rp, rc, pr, held, rep in E:
        out.append((tuple(map(sw, rp)), tuple(map(sw, rc)), pr, frozenset((r, sw(v)) for r, v in held), tuple(frozenset(x if x == NOC else (x[0], sw(x[1])) for x in rr) for rr in rep)))
    return (tuple(out), frozenset((r, sw(v)) for r, v in res))
m = M(3, 1, 3, 1); st0 = m.canon(m.init()); seen = {st0}; q = deque([st0])
while q:
    x = q.popleft()
    for _, nx in m.succ(x):
        c = m.canon(nx)
        if c not in seen: seen.add(c); q.append(c)
fixed = sum(1 for x in seen if m.canon(swap(x)) == x)
print('python (edge symmetry only):', len(seen), ' swap-invariant:', fixed, ' Burnside orbits:', (len(seen) + fixed) // 2, ' TLC (edge+value symmetry): 72863')
