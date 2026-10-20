import glob, json, os, re
out = {}
for f in sorted(glob.glob(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results', 'tlc', '*.txt'))):
    t = open(f).read(); name = os.path.basename(f)[:-4]
    m = re.search(r'(\d[\d,]*) states generated, (\d[\d,]*) distinct states found, (\d[\d,]*) states left on queue', t)
    viol = re.search(r'Invariant (\w+) is violated', t); temporal = 'Temporal properties were violated' in t
    fin = re.search(r'Finished in (\S+)', t)
    out[name] = dict(result=('INVARIANT ' + viol.group(1) + ' VIOLATED') if viol else ('TEMPORAL PROPERTY VIOLATED' if temporal else ('no error' if 'No error has been found' in t else 'incomplete / error')),
                     generated=m.group(1) if m else None, distinct=m.group(2) if m else None, queue_left=m.group(3) if m else None, time=fin.group(1) if fin else None)
json.dump(out, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results', 'tlc_results.json'), 'w'), indent=1)
for k, v in out.items(): print(f'{k:16s} {v["result"]:34s} distinct={v["distinct"]} time={v["time"]}')
