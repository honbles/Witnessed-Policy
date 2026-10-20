"""Cohen's kappa between coder A and coder B once e4_incidents.csv columns capability_B / policy_write_B / layer1_B are filled in."""
import csv, collections, sys
rows = list(csv.DictReader(open(sys.argv[1] if len(sys.argv) > 1 else 'e4_incidents.csv')))
def kappa(a, b):
    n = len(a); po = sum(x == y for x, y in zip(a, b)) / n; ca, cb = collections.Counter(a), collections.Counter(b)
    pe = sum(ca[k] * cb[k] for k in set(ca) | set(cb)) / n ** 2; return (po - pe) / (1 - pe) if pe < 1 else 1.0
for fa, fb in (('capability_A', 'capability_B'), ('policy_write_A', 'policy_write_B'), ('layer1_A', 'layer1_B')):
    pairs = [(r[fa], r[fb]) for r in rows if r[fb]]
    print(fa, 'n=', len(pairs), 'kappa=', round(kappa([p[0] for p in pairs], [p[1] for p in pairs]), 3) if pairs else 'coder B not filled in')
